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
        let valid = if is_ipv6 {
            matches!(gw, IpAddr::V6(_))
        } else {
            matches!(gw, IpAddr::V4(_))
        };
        if !valid {
            return Err(WifiError::new(
                ErrorKind::InvalidConfig,
                format!(
                    "{} gateway must be {}: {gateway}",
                    if is_ipv6 { "IPv6" } else { "IPv4" },
                    if is_ipv6 { "v6" } else { "v4" }
                ),
            ));
        }
        add_default_route(handle, if_index, gw).await?;
    }

    Ok(())
}

/// Add a default route via `gateway` on `if_index`.
///
/// Linux keeps at most one route per (table, prefix, metric) key, so on
/// a host that already has a default route the plain add fails with
/// EEXIST and the configured gateway would silently never be installed.
/// To let both coexist, the new route gets a metric (priority) larger
/// than the current default route's - i.e. less preferred - or 500
/// when the current route has no metric.  With no default route in the
/// table the add keeps the kernel-default priority.  Re-applying an
/// already installed gateway is a no-op.
pub(crate) async fn add_default_route(
    handle: &rtnetlink::Handle,
    if_index: u32,
    gateway: IpAddr,
) -> Result<(), WifiError> {
    let existing = current_default_routes(handle).await?;

    if existing
        .iter()
        .any(|(gw, _, oif)| *gw == gateway && *oif == if_index)
    {
        log::debug!("default route via {gateway} already exists");
        return Ok(());
    }

    // Less preferred than the highest existing metric; 500 when none of
    // the existing default routes carries a metric.
    let metric = if existing.is_empty() {
        None
    } else {
        Some(
            existing
                .iter()
                .filter_map(|(_, metric, _)| *metric)
                .max()
                .map_or(500, |m| m.saturating_add(1)),
        )
    };

    let route_msg = match gateway {
        IpAddr::V4(gw4) => {
            let mut builder = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                .gateway(gw4)
                .output_interface(if_index);
            if let Some(metric) = metric {
                builder = builder.priority(metric);
            }
            builder.build()
        }
        IpAddr::V6(gw6) => {
            let mut builder = rtnetlink::RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
                .gateway(gw6)
                .output_interface(if_index);
            if let Some(metric) = metric {
                builder = builder.priority(metric);
            }
            builder.build()
        }
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
            // EEXIST: an identical route appeared concurrently.  Not
            // fatal - the gateway is already routed.
            if e.to_string().contains("File exists") {
                log::debug!("default route via {gateway} already exists");
                Ok(())
            } else {
                Err(e)
            }
        })?;
    match metric {
        Some(m) => log::info!("Added default route via {gateway} (metric {m})"),
        None => log::info!("Added default route via {gateway}"),
    }
    Ok(())
}

/// Default routes currently installed in the main table, as
/// `(gateway, metric, output_ifindex)` tuples.
async fn current_default_routes(
    handle: &rtnetlink::Handle,
) -> Result<Vec<(IpAddr, Option<u32>, u32)>, WifiError> {
    use futures::TryStreamExt;
    use rtnetlink::packet_route::route::{
        RouteAddress, RouteAttribute, RouteMessage, RouteType,
    };

    let mut routes = handle.route().get(RouteMessage::default()).execute();
    let mut result = Vec::new();
    while let Some(msg) = routes.try_next().await.map_err(|e| {
        WifiError::new(ErrorKind::Nl80211, format!("route get: {e}"))
    })? {
        // The kernel only emits RTA_TABLE for non-main tables; a
        // missing attribute means the main table (RT_TABLE_MAIN=254).
        // Ignore policy-routing defaults so they can't skew the metric.
        if let Some(RouteAttribute::Table(table)) = msg
            .attributes
            .iter()
            .find(|attr| matches!(attr, RouteAttribute::Table(_)))
            && *table != 254
        {
            continue;
        }
        if msg.header.destination_prefix_length != 0
            || msg.header.kind != RouteType::Unicast
        {
            continue;
        }
        let mut gateway = None;
        let mut metric = None;
        let mut oif = None;
        for attr in &msg.attributes {
            match attr {
                RouteAttribute::Gateway(RouteAddress::Inet(v4)) => {
                    gateway = Some(IpAddr::V4(*v4));
                }
                RouteAttribute::Gateway(RouteAddress::Inet6(v6)) => {
                    gateway = Some(IpAddr::V6(*v6));
                }
                RouteAttribute::Priority(m) => metric = Some(*m),
                RouteAttribute::Oif(index) => oif = Some(*index),
                _ => {}
            }
        }
        if let Some(gateway) = gateway {
            result.push((gateway, metric, oif.unwrap_or(0)));
        }
    }
    Ok(result)
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
