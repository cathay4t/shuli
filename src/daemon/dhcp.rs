// SPDX-License-Identifier: Apache-2.0

//! DHCP via mozim.
//!
//! When `ipv4.auto: true`, runs DHCPv4 to acquire a lease and
//! applies it (address, gateway, DNS).  When `ipv6.auto: true`,
//! enables kernel Router Advertisement (accept_ra=2) so the
//! kernel handles SLAAC; DHCPv6 is run on a best-effort basis.

use std::net::{IpAddr, Ipv4Addr};

use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4Lease, DhcpV4State};
use shuli_core::{ErrorKind, WifiError};

use crate::config::DnsConfig;

const DHCP_TIMEOUT_SEC: u32 = 30;

/// Run DHCPv4 and apply the lease.  Returns the DNS config derived
/// from the lease (if any).
pub(crate) async fn run_dhcpv4(
    iface_name: &str,
) -> Result<Option<DnsConfig>, WifiError> {
    log::info!("Starting DHCPv4 on {iface_name}");

    let mut dhcp_config = DhcpV4Config::new(iface_name);
    dhcp_config.set_timeout_sec(DHCP_TIMEOUT_SEC);

    let mut dhcp_client =
        DhcpV4Client::init(dhcp_config, None).await.map_err(|e| {
            WifiError::new(
                ErrorKind::ConnectFailed,
                format!("DHCPv4 init on {iface_name}: {e}"),
            )
        })?;

    let lease = loop {
        match dhcp_client.run().await {
            Ok(DhcpV4State::Done(lease)) => {
                log::info!(
                    "DHCPv4 lease acquired: {}/{}",
                    lease.yiaddr,
                    lease.prefix_length()
                );
                break *lease;
            }
            Ok(state) => {
                log::debug!("DHCPv4 state: {state:?}");
            }
            Err(e) => {
                return Err(WifiError::new(
                    ErrorKind::ConnectFailed,
                    format!("DHCPv4 failed on {iface_name}: {e}"),
                ));
            }
        }
    };

    apply_dhcpv4_lease(iface_name, &lease).await?;

    // Build DNS config from the lease.
    let dns = lease.dns_srvs.as_ref().map(|dns_srvs| DnsConfig {
        nameservers: dns_srvs.iter().map(|ip| ip.to_string()).collect(),
        ..Default::default()
    });

    Ok(dns)
}

async fn apply_dhcpv4_lease(
    iface_name: &str,
    lease: &DhcpV4Lease,
) -> Result<(), WifiError> {
    let (conn, handle, _) = rtnetlink::new_connection().map_err(|e| {
        WifiError::new(ErrorKind::Nl80211, format!("rtnetlink: {e}"))
    })?;
    tokio::spawn(conn);

    let if_index = resolve_if_index(&handle, iface_name).await?;

    // Add the leased address.
    let ip = IpAddr::V4(lease.yiaddr);
    handle
        .address()
        .add(if_index, ip, lease.prefix_length())
        .execute()
        .await
        .map_err(|e| {
            WifiError::new(
                ErrorKind::Nl80211,
                format!("DHCP addr add {}: {e}", lease.yiaddr),
            )
        })?;
    log::info!(
        "Applied DHCP address {}/{}",
        lease.yiaddr,
        lease.prefix_length()
    );

    // RFC 3442: when Classless Static Routes (option 121) are present,
    // the Router option must be ignored.  A 0.0.0.0/0 entry is the
    // default route; every other entry is installed as given.
    for (destination, prefix_length, gateway) in dhcp_routes(lease) {
        if prefix_length == 0 {
            crate::ip::add_default_route(
                &handle,
                if_index,
                IpAddr::V4(gateway),
            )
            .await?;
        } else {
            crate::ip::add_route(
                &handle,
                if_index,
                destination,
                prefix_length,
                gateway,
            )
            .await?;
        }
    }

    Ok(())
}

/// Turn a DHCPv4 lease into the routes to install.  Option 121 takes
/// precedence over the Router option (RFC 3442 section 3.1).
fn dhcp_routes(lease: &DhcpV4Lease) -> Vec<(Ipv4Addr, u8, Ipv4Addr)> {
    if let Some(routes) = &lease.classless_routes {
        return routes
            .iter()
            .map(|route| (route.destination, route.prefix_length, route.router))
            .collect();
    }
    lease
        .gateways
        .as_ref()
        .and_then(|gateways| gateways.first())
        .map(|gateway| vec![(Ipv4Addr::UNSPECIFIED, 0, *gateway)])
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use mozim::DhcpV4ClasslessRoute;

    use super::*;

    #[test]
    fn classless_routes_override_the_router_option() {
        let mut lease = DhcpV4Lease::default();
        lease.gateways = Some(vec![Ipv4Addr::new(192, 0, 2, 254)]);
        assert_eq!(
            dhcp_routes(&lease),
            vec![(Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::new(192, 0, 2, 254))]
        );

        lease.classless_routes = Some(vec![
            DhcpV4ClasslessRoute {
                destination: Ipv4Addr::UNSPECIFIED,
                prefix_length: 0,
                router: Ipv4Addr::new(198, 51, 100, 1),
            },
            DhcpV4ClasslessRoute {
                destination: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 8,
                router: Ipv4Addr::new(198, 51, 100, 2),
            },
        ]);
        assert_eq!(
            dhcp_routes(&lease),
            vec![
                (Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::new(198, 51, 100, 1)),
                (
                    Ipv4Addr::new(10, 0, 0, 0),
                    8,
                    Ipv4Addr::new(198, 51, 100, 2)
                ),
            ]
        );
    }
}

/// Enable IPv6 Router Advertisement (SLAAC) on the interface by
/// setting accept_ra=2 and re-enabling IPv6.
pub(crate) fn enable_ipv6_ra(iface_name: &str) -> Result<(), WifiError> {
    let base = format!("/proc/sys/net/ipv6/conf/{iface_name}");
    // Re-enable IPv6 (flip disable_ipv6 1 -> 0).
    std::fs::write(format!("{base}/disable_ipv6"), "1").ok();
    std::fs::write(format!("{base}/disable_ipv6"), "0").map_err(|e| {
        WifiError::new(
            ErrorKind::Io,
            format!("enable IPv6 on {iface_name}: {e}"),
        )
    })?;
    // accept_ra=2: accept RA even when forwarding is enabled.
    std::fs::write(format!("{base}/accept_ra"), "2").map_err(|e| {
        WifiError::new(
            ErrorKind::Io,
            format!("set accept_ra on {iface_name}: {e}"),
        )
    })?;
    log::info!("Enabled IPv6 RA (SLAAC) on {iface_name}");
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
