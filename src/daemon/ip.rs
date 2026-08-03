// SPDX-License-Identifier: Apache-2.0

//! Static IP configuration via rtnetlink.
//!
//! Applies addresses, default routes, and DNS settings to the
//! WiFi interface after authentication completes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use shuli::{ErrorKind, WifiError};

use crate::config::{DnsConfig, IpConfig};

/// Apply static IP configuration to an interface.
pub(crate) async fn apply_ip_config(
    iface_name: &str,
    ipv4: Option<&IpConfig>,
    ipv6: Option<&IpConfig>,
    dns: Option<&DnsConfig>,
) -> Result<(), WifiError> {
    let (conn, handle, _) = rtnetlink::new_connection().map_err(|e| {
        WifiError::new(ErrorKind::Nl80211, format!("rtnetlink: {e}"))
    })?;
    tokio::spawn(conn);

    let if_index = resolve_if_index(&handle, iface_name).await?;

    if let Some(ipv4_cfg) = ipv4
        && !ipv4_cfg.auto
    {
        apply_static_ip(&handle, if_index, ipv4_cfg, false).await?;
    }

    if let Some(ipv6_cfg) = ipv6
        && !ipv6_cfg.auto
    {
        apply_static_ip(&handle, if_index, ipv6_cfg, true).await?;
    }

    if let Some(dns_cfg) = dns {
        write_resolv_conf(dns_cfg)?;
    }

    Ok(())
}

async fn resolve_if_index(
    handle: &rtnetlink::Handle,
    iface_name: &str,
) -> Result<u32, WifiError> {
    use futures::TryStreamExt;
    let mut links = handle
        .link()
        .get()
        .match_name(iface_name.to_string())
        .execute();
    if let Some(msg) = links.try_next().await.map_err(|e| {
        WifiError::new(ErrorKind::Nl80211, format!("link get: {e}"))
    })? {
        return Ok(msg.header.index);
    }
    Err(WifiError::new(
        ErrorKind::InterfaceNotFound,
        format!("interface {iface_name} not found"),
    ))
}

async fn apply_static_ip(
    handle: &rtnetlink::Handle,
    if_index: u32,
    ip_cfg: &IpConfig,
    is_ipv6: bool,
) -> Result<(), WifiError> {
    let family = if is_ipv6 { "IPv6" } else { "IPv4" };

    // Add addresses.
    for addr in &ip_cfg.address {
        let ip: IpAddr = addr.ip.parse().map_err(|e| {
            WifiError::new(
                ErrorKind::InvalidConfig,
                format!("invalid IP {}: {e}", addr.ip),
            )
        })?;
        handle
            .address()
            .add(if_index, ip, addr.prefix_length)
            .execute()
            .await
            .map_err(|e| {
                WifiError::new(
                    ErrorKind::Nl80211,
                    format!("addr add {}: {e}", addr.ip),
                )
            })?;
        log::info!(
            "Added {family} address {}/{} on if_index {if_index}",
            addr.ip,
            addr.prefix_length
        );
    }

    // Add default gateway route.
    if let Some(ref gateway) = ip_cfg.gateway {
        let gw: IpAddr = gateway.parse().map_err(|e| {
            WifiError::new(
                ErrorKind::InvalidConfig,
                format!("invalid gateway {gateway}: {e}"),
            )
        })?;

        let route_msg = if is_ipv6 {
            let gw6 = match gw {
                IpAddr::V6(v6) => v6,
                _ => {
                    return Err(WifiError::new(
                        ErrorKind::InvalidConfig,
                        format!("IPv6 gateway must be v6: {gateway}"),
                    ));
                }
            };
            rtnetlink::RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
                .gateway(gw6)
                .output_interface(if_index)
                .build()
        } else {
            let gw4 = match gw {
                IpAddr::V4(v4) => v4,
                _ => {
                    return Err(WifiError::new(
                        ErrorKind::InvalidConfig,
                        format!("IPv4 gateway must be v4: {gateway}"),
                    ));
                }
            };
            rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                .gateway(gw4)
                .output_interface(if_index)
                .build()
        };

        handle
            .route()
            .add(route_msg)
            .execute()
            .await
            .map_err(|e| {
                WifiError::new(
                    ErrorKind::Nl80211,
                    format!("route add via {gateway}: {e}"),
                )
            })
            .or_else(|e| {
                // EEXIST: route already present (e.g. from a prior
                // run or the connected subnet).  Not fatal.
                if e.to_string().contains("File exists") {
                    log::debug!("default route via {gateway} already exists");
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
        log::info!("Added default route via {gateway}");
    }

    Ok(())
}

fn write_resolv_conf(dns: &DnsConfig) -> Result<(), WifiError> {
    let mut content = String::new();
    for search in &dns.searches {
        content.push_str(&format!("search {search}\n"));
    }
    for ns in &dns.nameservers {
        content.push_str(&format!("nameserver {ns}\n"));
    }
    std::fs::write("/etc/resolv.conf", &content).map_err(|e| {
        WifiError::new(ErrorKind::Io, format!("write /etc/resolv.conf: {e}"))
    })?;
    log::info!("Updated /etc/resolv.conf");
    Ok(())
}
