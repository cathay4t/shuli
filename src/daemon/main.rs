// SPDX-License-Identifier: Apache-2.0

mod config;
mod dhcp;
mod ip;

use std::{path::Path, process::ExitCode};

use config::ShuliConfig;
use shuli::{WifiClient, WifiState};
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
    let shuli_config = ShuliConfig::load(config_path)?;
    let wifi_entry = shuli_config.wifis.first().ok_or_else(|| {
        shuli::WifiError::new(
            shuli::ErrorKind::InvalidConfig,
            "no wifis in config",
        )
    })?;

    let iface_name =
        resolve_iface_name(wifi_entry.interface.as_deref()).await?;
    let wifi_config = wifi_entry.to_wifi_config(&iface_name);
    log::info!("shulid: iface={iface_name}, ssid={}", wifi_entry.ssid);

    let mut client = WifiClient::init(wifi_config).await?;
    let mut connected = false;
    let mut sigterm = unix_signal(SignalKind::terminate()).map_err(|e| {
        shuli::WifiError::new(
            shuli::ErrorKind::ConnectFailed,
            format!("failed to register SIGTERM handler: {e}"),
        )
    })?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                log::info!("received SIGINT, shutting down");
                client.shutdown().await;
                break;
            }
            _ = sigterm.recv() => {
                log::info!("received SIGTERM, shutting down");
                client.shutdown().await;
                break;
            }
            result = client.run() => {
                match result {
                    Ok(state) => match state {
                        WifiState::ConnectedWithoutOffloadRekey
                        | WifiState::ConnectedWithOffloadRekey => {
                            if !connected {
                                connected = true;
                                log::info!(
                                    "connection established - link up"
                                );
                                // Apply IP config: static or DHCP.
                                if let Err(e) = apply_network_config(
                                    &iface_name,
                                    wifi_entry,
                                )
                                .await
                                {
                                    log::warn!("IP config failed: {e}");
                                }
                                log::info!(
                                    "holding connection \
                                     (Ctrl-C to disconnect)"
                                );
                            }
                        }
                        WifiState::Failed => {
                            log::warn!("connection failed - retrying");
                        }
                        WifiState::FailedAuthentication => {
                            log::warn!(
                                "authentication failed - retrying in \
                                 10 minutes"
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

    if connected {
        log::info!("connection established");
        Ok(())
    } else {
        Err(shuli::WifiError::new(
            shuli::ErrorKind::ConnectFailed,
            "shutdown before connection established",
        ))
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
