// SPDX-License-Identifier: Apache-2.0

mod config;
mod dhcp;
mod ip;

use std::{path::Path, process::ExitCode};

use futures::StreamExt as _;
use tokio::{
    signal,
    signal::unix::{SignalKind, signal as unix_signal},
};

const DEFAULT_CONFIG: &str = "/etc/shuli/config.yml";

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_CONFIG.to_string());

    match run(Path::new(&config_path)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(config_path: &Path) -> Result<(), shuli::WifiError> {
    let shuli_config = config::ShuliConfig::load(config_path)?;
    let wifis = &shuli_config.wifis;
    if wifis.is_empty() {
        return Err(shuli::WifiError::new(
            shuli::ErrorKind::InvalidConfig,
            "no wifis in config",
        ));
    }

    // M7 (G5): run one WifiClient per distinct interface. Entries with
    // `interface: any` (or absent) all bind to the first WiFi NIC found;
    // entries with an explicit interface bind to that one.
    let needs_any = wifis
        .iter()
        .any(|entry| entry.interface.as_deref().is_none_or(|i| i == "any"));
    let any_iface = if needs_any {
        resolve_iface_name(None).await?
    } else {
        String::new()
    };
    let groups = group_by_interface(wifis, &any_iface);
    log::info!(
        "shulid: {} interface(s): {}",
        groups.len(),
        groups
            .iter()
            .map(|(iface, entries)| format!("{iface} ({} ssid)", entries.len()))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Init every client up front so an invalid interface fails fast
    // instead of only part of the daemon running.
    let mut clients = Vec::new();
    for (iface_name, entries) in &groups {
        let wifi_config =
            config::ShuliConfig::wifi_config_for_entries(iface_name, entries);
        let client = shuli::WifiClient::init(wifi_config).await?;
        clients.push((iface_name.clone(), entries.clone(), client));
    }

    // One task per interface; a watch channel broadcasts shutdown.
    // `tasks` is polled in the select so the daemon also exits when
    // every interface task ends on its own (e.g. the event channel
    // closed) instead of idling with zero live tasks.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut sigterm = unix_signal(SignalKind::terminate()).map_err(|e| {
        shuli::WifiError::new(
            shuli::ErrorKind::ConnectFailed,
            format!("failed to register SIGTERM handler: {e}"),
        )
    })?;

    let mut tasks = futures::stream::FuturesUnordered::new();
    for (iface_name, entries, client) in clients {
        let shutdown_rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            run_interface(&iface_name, &entries, client, shutdown_rx).await
        }));
    }

    let mut results = Vec::new();
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                log::info!("received SIGINT, shutting down");
                break;
            }
            _ = sigterm.recv() => {
                log::info!("received SIGTERM, shutting down");
                break;
            }
            result = tasks.next(), if !tasks.is_empty() => {
                if let Some(result) = result {
                    results.push(result);
                }
                if tasks.is_empty() {
                    log::warn!(
                        "all interface tasks ended; shutting down"
                    );
                    break;
                }
                log::warn!(
                    "an interface task ended ({} remain)",
                    tasks.len()
                );
            }
        }
    }
    // Wake the tasks still waiting on events; then collect them all.
    let _ = shutdown_tx.send(true);
    drop(shutdown_tx); // wake tasks whose `changed()` missed the send
    while let Some(result) = tasks.next().await {
        results.push(result);
    }

    let mut any_connected = false;
    let mut task_err: Option<shuli::WifiError> = None;
    for result in results {
        match result {
            Ok(Ok(connected)) => any_connected |= connected,
            Ok(Err(e)) => {
                log::warn!("interface task failed: {e}");
                if task_err.is_none() {
                    task_err = Some(e);
                }
            }
            Err(e) => log::warn!("interface task panicked: {e}"),
        }
    }

    if any_connected {
        Ok(())
    } else {
        Err(task_err.unwrap_or_else(|| {
            shuli::WifiError::new(
                shuli::ErrorKind::ConnectFailed,
                "shutdown before connection established",
            )
        }))
    }
}

/// Drive one interface's `WifiClient` until shutdown: apply the
/// network's IP config whenever a connection lands, keep retrying
/// otherwise. Returns whether a connection was ever established.
async fn run_interface(
    iface_name: &str,
    entries: &[config::WifiEntry],
    mut client: shuli::WifiClient,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<bool, shuli::WifiError> {
    // SSID whose IP config was last applied; lets us re-apply when a
    // later connection lands on a different configured network.
    let mut applied_ssid: Option<String> = None;
    let mut connected = false;
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                // The sender dropped the channel or signalled shutdown.
                log::info!("shutting down interface {iface_name}");
                client.shutdown().await;
                return Ok(connected);
            }
            result = client.run() => {
                match result {
                    Ok(state) => match state {
                        shuli::WifiState::ConnectedWithoutOffloadRekey
                        | shuli::WifiState::ConnectedWithOffloadRekey => {
                            connected = true;
                            let ssid = client.current_ssid().to_string();
                            if applied_ssid.as_deref() != Some(ssid.as_str()) {
                                applied_ssid = Some(ssid.clone());
                                log::info!(
                                    "connection established to '{ssid}' on \
                                     {iface_name} - link up"
                                );
                                // Apply the IP config of the network we
                                // actually connected to; never fall back
                                // to another network's config silently.
                                match entries
                                    .iter()
                                    .find(|entry| entry.ssid == ssid)
                                {
                                    Some(entry) => {
                                        if let Err(e) = apply_network_config(
                                            iface_name,
                                            entry,
                                        )
                                        .await
                                        {
                                            log::warn!("IP config failed: {e}");
                                        }
                                        log::info!(
                                            "holding connection on {iface_name} \
                                             (Ctrl-C to disconnect)"
                                        );
                                    }
                                    None => log::warn!(
                                        "no wifis config entry for connected \
                                         SSID '{ssid}'; skipping IP config"
                                    ),
                                }
                            }
                        }
                        shuli::WifiState::Failed => {
                            log::warn!(
                                "connection failed on {iface_name} - retrying"
                            );
                        }
                        shuli::WifiState::FailedAuthentication => {
                            log::warn!(
                                "authentication failed on {iface_name} - \
                                 retrying in 10 minutes"
                            );
                        }
                        _ => {}
                    },
                    Err(e) => {
                        log::warn!("{e}");
                    }
                }
            }
        }
    }
}

/// Resolve the interface name.  `"any"` or absent picks the first
/// available wifi interface via nispor.
async fn resolve_iface_name(
    interface: Option<&str>,
) -> Result<String, shuli::WifiError> {
    if let Some(name) = interface
        && name != "any"
    {
        return Ok(name.to_string());
    }
    // Find the first wifi interface.
    let mut filter = nispor::NetStateFilter::minimum();
    filter.iface = Some(nispor::NetStateIfaceFilter::minimum());
    let np_state = nispor::NetState::retrieve_with_filter_async(&filter)
        .await
        .map_err(|e| {
            shuli::WifiError::new(
                shuli::ErrorKind::Nl80211,
                format!("nispor: {e}"),
            )
        })?;
    for np_iface in np_state.ifaces.values() {
        if np_iface.iface_type == nispor::IfaceType::Wifi {
            return Ok(np_iface.name.to_string());
        }
    }
    Err(shuli::WifiError::new(
        shuli::ErrorKind::InterfaceNotFound,
        "no wifi interface found",
    ))
}

/// Apply network configuration after WiFi connection: static IP,
/// DHCP, and/or IPv6 RA depending on the config.
async fn apply_network_config(
    iface_name: &str,
    wifi_entry: &config::WifiEntry,
) -> Result<(), shuli::WifiError> {
    let mut dns = wifi_entry.dns.clone();

    // IPv4: static or DHCP.
    if let Some(ref ipv4) = wifi_entry.ipv4
        && ipv4.auto
    {
        let lease_dns = dhcp::run_dhcpv4(iface_name).await?;
        if dns.is_none() {
            dns = lease_dns;
        }
    }

    // IPv6: enable RA (SLAAC) when auto.
    if let Some(ref ipv6) = wifi_entry.ipv6
        && ipv6.auto
    {
        dhcp::enable_ipv6_ra(iface_name)?;
    }

    // Apply static IP config (addresses/gateway for non-auto, and
    // DNS from either config or DHCP lease).
    ip::apply_ip_config(
        iface_name,
        wifi_entry.ipv4.as_ref(),
        wifi_entry.ipv6.as_ref(),
        dns.as_ref(),
    )
    .await
}

/// Group configured networks by their resolved interface (M7): one
/// `WifiClient` per distinct interface. `any_iface` is the concrete
/// NIC that `interface: any` / absent entries bind to.
fn group_by_interface(
    wifis: &[config::WifiEntry],
    any_iface: &str,
) -> Vec<(String, Vec<config::WifiEntry>)> {
    let mut groups: Vec<(String, Vec<config::WifiEntry>)> = Vec::new();
    for entry in wifis {
        let iface = match entry.interface.as_deref() {
            None | Some("any") => any_iface.to_string(),
            Some(name) => name.to_string(),
        };
        match groups.iter_mut().find(|(name, _)| *name == iface) {
            Some((_, entries)) => entries.push(entry.clone()),
            None => groups.push((iface, vec![entry.clone()])),
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ssid: &str, interface: Option<&str>) -> config::WifiEntry {
        config::WifiEntry {
            ssid: ssid.to_string(),
            password: None,
            roaming: true,
            roaming_threshold: shuli::DEFAULT_ROAM_THRESHOLD_DBM,
            wowlan: false,
            sae_pwe: config::SaePweConfig::Auto,
            interface: interface.map(|s| s.to_string()),
            dns: None,
            ipv4: None,
            ipv6: None,
        }
    }

    #[test]
    fn group_absent_and_any_entries_to_the_same_iface() {
        let wifis = vec![
            entry("Home", None),
            entry("Guest", Some("any")),
            entry("Office", Some("wlan1")),
        ];
        let groups = group_by_interface(&wifis, "wlan0");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0, "wlan0");
        assert_eq!(
            groups[0]
                .1
                .iter()
                .map(|e| e.ssid.as_str())
                .collect::<Vec<_>>(),
            ["Home", "Guest"]
        );
        assert_eq!(groups[1].0, "wlan1");
        assert_eq!(groups[1].1[0].ssid, "Office");
    }

    #[test]
    fn group_keeps_wifis_config_order() {
        let wifis = vec![
            entry("A", Some("wlan1")),
            entry("B", None),
            entry("C", Some("wlan1")),
        ];
        let groups = group_by_interface(&wifis, "wlan0");
        assert_eq!(groups.len(), 2);
        // First-seen interface order, entries in config order.
        assert_eq!(groups[0].0, "wlan1");
        assert_eq!(
            groups[0]
                .1
                .iter()
                .map(|e| e.ssid.as_str())
                .collect::<Vec<_>>(),
            ["A", "C"]
        );
        assert_eq!(groups[1].0, "wlan0");
        assert_eq!(groups[1].1[0].ssid, "B");
    }

    #[test]
    fn explicit_only_config_ignores_any_iface() {
        let wifis = vec![entry("X", Some("wlan3"))];
        let groups = group_by_interface(&wifis, "");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "wlan3");
    }
}
