// SPDX-License-Identifier: Apache-2.0

mod config;
mod dhcp;
mod ip;

use std::{collections::HashMap, path::Path, process::ExitCode};

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

async fn run(config_path: &Path) -> Result<(), shuli_core::WifiError> {
    let shuli_config = config::ShuliConfig::load(config_path)?;
    let wifis = &shuli_config.wifis;
    if wifis.is_empty() && shuli_config.ethernets.is_empty() {
        return Err(shuli_core::WifiError::new(
            shuli_core::ErrorKind::InvalidConfig,
            "no wifis or ethernets in config",
        ));
    }

    // Entries with `interface: any` (or absent) all bind to the first
    // WiFi NIC found; entries with an explicit interface bind to that
    // one. All interfaces share a single WifiClient.
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

    // Init the single client up front so an invalid interface fails
    // fast instead of only part of the daemon running.
    let wifi_configs: Vec<shuli_wifi::WifiConfig> = groups
        .iter()
        .map(|(iface_name, entries)| {
            config::ShuliConfig::wifi_config_for_entries(iface_name, entries)
        })
        .collect();
    let client = shuli_wifi::WifiClient::init(wifi_configs).await?;

    // A watch channel broadcasts shutdown.
    // `tasks` is polled in the select so the daemon also exits when
    // every interface task ends on its own (e.g. the event channel
    // closed) instead of idling with zero live tasks.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut sigterm = unix_signal(SignalKind::terminate()).map_err(|e| {
        shuli_core::WifiError::new(
            shuli_core::ErrorKind::ConnectFailed,
            format!("failed to register SIGTERM handler: {e}"),
        )
    })?;

    let mut tasks = futures::stream::FuturesUnordered::new();
    let wifi_shutdown_rx = shutdown_rx.clone();
    tasks.push(tokio::spawn(run_wifi_interfaces(
        client,
        groups,
        wifi_shutdown_rx,
    )));
    // one wired 802.1X task per configured Ethernet port.
    for entry in &shuli_config.ethernets {
        let shutdown_rx = shutdown_rx.clone();
        let entry = entry.clone();
        tasks.push(tokio::spawn(async move {
            run_wired_interface(&entry, shutdown_rx).await
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
    let mut task_err: Option<shuli_core::WifiError> = None;
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
            shuli_core::WifiError::new(
                shuli_core::ErrorKind::ConnectFailed,
                "shutdown before connection established",
            )
        }))
    }
}

/// Drive the single multi-interface `WifiClient` until shutdown: apply
/// each interface's IP config whenever a connection lands, keep
/// retrying otherwise. Returns whether any connection was ever
/// established.
async fn run_wifi_interfaces(
    mut client: shuli_wifi::WifiClient,
    groups: Vec<(String, Vec<config::WifiEntry>)>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<bool, shuli_core::WifiError> {
    // SSID whose IP config was last applied per interface; lets us
    // re-apply when a later connection lands on a different configured
    // network.
    let mut applied_ssid: HashMap<String, String> = HashMap::new();
    let mut connected = false;
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                // The sender dropped the channel or signalled shutdown.
                log::info!("shutting down wifi interfaces");
                client.shutdown().await;
                return Ok(connected);
            }
            result = client.run() => {
                match result {
                    Ok(run_result) => {
                        let iface_name = &run_result.iface_name;
                        match run_result.state {
                        shuli_wifi::WifiState::ConnectedWithoutOffloadRekey
                        | shuli_wifi::WifiState::ConnectedWithOffloadRekey => {
                            connected = true;
                            let Some(ssid) =
                                client.current_ssid(iface_name)
                            else {
                                log::warn!(
                                    "WIFI {iface_name} connected but no \
                                     current SSID"
                                );
                                continue;
                            };
                            let ssid = ssid.to_string();
                            if applied_ssid
                                .get(iface_name)
                                .map(String::as_str)
                                != Some(ssid.as_str())
                            {
                                applied_ssid
                                    .insert(iface_name.clone(), ssid.clone());
                                log::info!(
                                    "connection established to '{ssid}' on \
                                     {iface_name} - link up"
                                );
                                // Apply the IP config of the network we
                                // actually connected to; never fall back
                                // to another network's config silently.
                                let entries = groups
                                    .iter()
                                    .find(|(name, _)| name == iface_name)
                                    .map(|(_, entries)| entries.as_slice())
                                    .unwrap_or(&[]);
                                match entries
                                    .iter()
                                    .find(|entry| entry.ssid == ssid)
                                {
                                    Some(entry) => {
                                        if let Err(e) = apply_network_config(
                                            iface_name,
                                            entry.dns.as_ref(),
                                            entry.ipv4.as_ref(),
                                            entry.ipv6.as_ref(),
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
                        shuli_wifi::WifiState::Failed => {
                            log::warn!(
                                "connection failed on {iface_name} - retrying"
                            );
                        }
                        shuli_wifi::WifiState::FailedAuthentication => {
                            log::warn!(
                                "authentication failed on {iface_name} - \
                                 retrying in 10 minutes"
                            );
                        }
                        _ => {}
                    }
                    }
                    Err(e) => log::warn!("WIFI client error: {e}"),
                }
            }
        }
    }
}

/// Resolve the interface name.  `"any"` or absent picks the first
/// available wifi interface via nispor.
async fn resolve_iface_name(
    interface: Option<&str>,
) -> Result<String, shuli_core::WifiError> {
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
            shuli_core::WifiError::new(
                shuli_core::ErrorKind::Nl80211,
                format!("nispor: {e}"),
            )
        })?;
    for np_iface in np_state.ifaces.values() {
        if np_iface.iface_type == nispor::IfaceType::Wifi {
            return Ok(np_iface.name.to_string());
        }
    }
    Err(shuli_core::WifiError::new(
        shuli_core::ErrorKind::InterfaceNotFound,
        "no wifi interface found",
    ))
}

/// Apply network configuration after a WiFi or wired 802.1X
/// connection: static IP, DHCP, and/or IPv6 RA depending on the
/// config.
async fn apply_network_config(
    iface_name: &str,
    dns_cfg: Option<&config::DnsConfig>,
    ipv4: Option<&config::IpConfig>,
    ipv6: Option<&config::IpConfig>,
) -> Result<(), shuli_core::WifiError> {
    let mut dns = dns_cfg.cloned();

    // IPv4: static or DHCP.
    if let Some(ipv4) = ipv4
        && ipv4.auto
    {
        let lease_dns = dhcp::run_dhcpv4(iface_name).await?;
        if dns.is_none() {
            dns = lease_dns;
        }
    }

    // IPv6: enable RA (SLAAC) when auto.
    if let Some(ipv6) = ipv6
        && ipv6.auto
    {
        dhcp::enable_ipv6_ra(iface_name)?;
    }

    // Apply static IP config (addresses/gateway for non-auto, and
    // DNS from either config or DHCP lease).
    ip::apply_ip_config(iface_name, ipv4, ipv6, dns.as_ref()).await
}

/// Pick the wired authentication mode for `entry` and the interface
/// that carries the IP configuration: the physical port for 802.1X and
/// the MACsec netdev for MKA.
fn wired_auth_and_ip_iface(
    entry: &config::EthernetEntry,
) -> Result<(shuli_wired::WiredAuth, String), shuli_core::WifiError> {
    match (&entry.eap, &entry.macsec) {
        (Some(_), Some(_)) => Err(shuli_core::WifiError::new(
            shuli_core::ErrorKind::InvalidConfig,
            format!(
                "ethernet {}: 'eap' and 'macsec' are mutually exclusive",
                entry.name
            ),
        )),
        (None, None) => Err(shuli_core::WifiError::new(
            shuli_core::ErrorKind::InvalidConfig,
            format!("ethernet {}: 'eap' or 'macsec' is required", entry.name),
        )),
        (Some(eap), None) => Ok((
            shuli_wired::WiredAuth::Eap(eap.to_lib()),
            entry.name.clone(),
        )),
        (None, Some(macsec)) => {
            let config = macsec.to_lib()?;
            let iface = config.macsec_iface_name().to_string();
            Ok((shuli_wired::WiredAuth::Macsec(config), iface))
        }
    }
}

/// Drive one wired port until shutdown: authenticate with EAP or
/// establish MACsec/MKA, apply the port's IP config, and retry with
/// backoff on failure.
async fn run_wired_interface(
    entry: &config::EthernetEntry,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<bool, shuli_core::WifiError> {
    let (auth, ip_iface) = wired_auth_and_ip_iface(entry)?;
    let is_macsec = matches!(auth, shuli_wired::WiredAuth::Macsec(_));
    let mut connected = false;
    loop {
        let mut client = match shuli_wired::WiredClient::init_with_auth(
            &entry.name,
            auth.clone(),
        ) {
            Ok(client) => client,
            Err(e) => {
                log::warn!("wired init {} failed: {e}", entry.name);
                tokio::select! {
                    _ = shutdown_rx.changed() => return Ok(connected),
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
                }
                continue;
            }
        };
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    log::info!("shutting down wired port {}", entry.name);
                    if let Err(e) = client.shutdown().await {
                        log::warn!(
                            "wired shutdown {} failed: {e}", entry.name
                        );
                    }
                    return Ok(connected);
                }
                result = client.run() => {
                    match result {
                        Ok(shuli_wired::WiredState::Connected) => {
                            if !connected {
                                connected = true;
                                log::info!(
                                    "wired authentication authorized on {} \
                                     - link up ({ip_iface})",
                                    entry.name
                                );
                                if let Err(e) = apply_network_config(
                                    &ip_iface,
                                    entry.dns.as_ref(),
                                    entry.ipv4.as_ref(),
                                    entry.ipv6.as_ref(),
                                )
                                .await
                                {
                                    log::warn!(
                                        "IP config failed on {ip_iface}: {e}"
                                    );
                                }
                            }
                            if !is_macsec {
                                // The 802.1X port stays authorized;
                                // hold until shutdown instead of
                                // polling an already-Connected client.
                                let _ = shutdown_rx.changed().await;
                                if let Err(e) = client.shutdown().await {
                                    log::warn!(
                                        "wired shutdown {} failed: {e}",
                                        entry.name
                                    );
                                }
                                return Ok(connected);
                            }
                            // Keep driving MACsec/MKA (SAK rotation,
                            // liveness) after the first Connected.
                            tokio::time::sleep(
                                std::time::Duration::from_millis(100),
                            )
                            .await;
                        }
                        Ok(shuli_wired::WiredState::Failed) => {
                            log::warn!(
                                "wired authentication failed on {}; retrying",
                                entry.name
                            );
                            if let Err(e) = client.shutdown().await {
                                log::warn!(
                                    "wired shutdown {} failed: {e}",
                                    entry.name
                                );
                            }
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            log::warn!(
                                "wired authentication error on {}: {e}",
                                entry.name
                            );
                            if let Err(e) = client.shutdown().await {
                                log::warn!(
                                    "wired shutdown {} failed: {e}",
                                    entry.name
                                );
                            }
                            break;
                        }
                    }
                }
            }
        }
        // Backoff before the next attempt.
        tokio::select! {
            _ = shutdown_rx.changed() => return Ok(connected),
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
        }
    }
}

/// Group configured networks by their resolved interface: one
/// `WifiConfig` per distinct interface. `any_iface` is the concrete
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
            bssid: None,
            hidden: false,
            prefered: false,
            roaming: true,
            roaming_threshold: shuli_wifi::DEFAULT_ROAM_THRESHOLD_DBM,
            switch_ssid_lower_than_dbm:
                shuli_wifi::DEFAULT_SWITCH_SSID_LOWER_THAN_DBM,
            wowlan: false,
            eap: None,
            sae_pwe: config::SaePweConfig::Auto,
            sae_password_id: None,
            ocv: false,
            ext_key_id: false,
            interface: interface.map(|s| s.to_string()),
            dns: None,
            ipv4: None,
            ipv6: None,
        }
    }

    fn ethernet_entry(name: &str) -> config::EthernetEntry {
        config::EthernetEntry {
            name: name.to_string(),
            eap: None,
            macsec: None,
            dns: None,
            ipv4: None,
            ipv6: None,
        }
    }

    fn macsec_entry(iface: Option<&str>) -> config::MacsecEntry {
        config::MacsecEntry {
            cak: "00112233445566778899aabbccddeeff".to_string(),
            ckn: "00112233445566778899aabbccddeeff".to_string(),
            key_server_priority: 0xff,
            can_be_key_server: false,
            macsec_iface: iface.map(str::to_string),
            replay_window: 0,
            encrypt: true,
        }
    }

    #[test]
    fn wired_macsec_ip_configures_macsec_dev() {
        let mut entry = ethernet_entry("eth0");
        entry.macsec = Some(macsec_entry(None));
        let (auth, iface) = wired_auth_and_ip_iface(&entry).unwrap();
        assert!(matches!(auth, shuli_wired::WiredAuth::Macsec(_)));
        assert_eq!(iface, shuli_wired::DEFAULT_MACSEC_IFACE);

        entry.macsec = Some(macsec_entry(Some("ms1")));
        let (_, iface) = wired_auth_and_ip_iface(&entry).unwrap();
        assert_eq!(iface, "ms1");
    }

    #[test]
    fn wired_eap_ip_configures_physical_dev() {
        let mut entry = ethernet_entry("eth0");
        entry.eap = Some(config::EapEntry::default());
        let (auth, iface) = wired_auth_and_ip_iface(&entry).unwrap();
        assert!(matches!(auth, shuli_wired::WiredAuth::Eap(_)));
        assert_eq!(iface, "eth0");
    }

    #[test]
    fn wired_auth_requires_exactly_one_mode() {
        let entry = ethernet_entry("eth0");
        assert!(wired_auth_and_ip_iface(&entry).is_err());

        let mut entry = ethernet_entry("eth0");
        entry.eap = Some(config::EapEntry::default());
        entry.macsec = Some(macsec_entry(None));
        assert!(wired_auth_and_ip_iface(&entry).is_err());
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
