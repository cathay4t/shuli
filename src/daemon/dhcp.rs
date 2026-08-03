// SPDX-License-Identifier: Apache-2.0

//! DHCP via mozim.
//!
//! When `ipv4.auto: true`, runs DHCPv4 to acquire a lease and
//! applies it (address, gateway, DNS).  When `ipv6.auto: true`,
//! enables kernel Router Advertisement (accept_ra=2) so the
//! kernel handles SLAAC; DHCPv6 is run on a best-effort basis.

use std::net::IpAddr;

use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4Lease, DhcpV4State};
use shuli::{ErrorKind, WifiError};

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

    // Add default route via the lease gateway.
    if let Some(ref gateways) = lease.gateways
        && let Some(gw) = gateways.first()
    {
        let route_msg =
            rtnetlink::RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                .destination_prefix(std::net::Ipv4Addr::UNSPECIFIED, 0)
                .gateway(*gw)
                .output_interface(if_index)
                .build();
        if let Err(e) = handle.route().add(route_msg).execute().await {
            // EEXIST is fine (route may already exist).
            if !e.to_string().contains("File exists") {
                return Err(WifiError::new(
                    ErrorKind::Nl80211,
                    format!("DHCP route add via {gw}: {e}"),
                ));
            }
        }
        log::info!("Applied DHCP default route via {gw}");
    }

    Ok(())
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
