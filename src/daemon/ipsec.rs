// SPDX-License-Identifier: Apache-2.0

//! IPsec connection lifecycle: IKE negotiation, XFRM installation, and
//! address/route/DNS application.
//!
//! The shuli-ipsec library never touches ordinary addresses, routes, or
//! DNS.  This module is the shulid side of that split: it consumes
//! `IpsecLease` events, creates the XFRM interface, installs the Child SA,
//! and applies the daemon-owned network configuration.

use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
};

use shuli_core::{ErrorKind, WifiError};
use shuli_ipsec::{
    ChildMode, ChildSaHandle, InstallSpec, InstalledChildSa, IpsecClient,
    IpsecConfig, IpsecEvent, IpsecLease, TrafficSelector, XfrmInterface,
    XfrmInterfaceSpec, XfrmManager,
};
use tokio::sync::watch;

use crate::config::DnsConfig;

struct Applied {
    installed: InstalledChildSa,
    interface: Option<XfrmInterface>,
    routes: Vec<(IpAddr, u8, u32)>,
}

/// Drive all configured IPsec connections until shutdown.
pub(crate) fn run_ipsec(
    configs: Vec<IpsecConfig>,
    shutdown_rx: watch::Receiver<bool>,
) -> Pin<Box<dyn Future<Output = Result<bool, WifiError>> + Send + 'static>> {
    Box::pin(async move {
        let mut shutdown_rx = shutdown_rx;
        let config_map: HashMap<String, IpsecConfig> = configs
            .iter()
            .map(|config| (config.name.clone(), config.clone()))
            .collect();
        let mut client =
            IpsecClient::init(configs).await.map_err(ipsec_error)?;
        let mut manager = XfrmManager::new().await.map_err(ipsec_error)?;
        let mut applied: HashMap<(String, usize), Applied> = HashMap::new();
        let mut connected = false;

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    log::info!("shutting down IPsec connections");
                    client.shutdown().await;
                    break;
                }
                event = client.run() => {
                    let event = match event {
                        Ok(event) => event,
                        Err(error) => {
                            log::warn!("IPsec event stream ended: {error}");
                            break;
                        }
                    };
                    match event {
                        IpsecEvent::State { connection, state } => {
                            log::info!("IPsec {connection}: {state:?}");
                        }
                        IpsecEvent::Error { connection, error } => {
                            log::warn!("IPsec {connection}: {error}");
                        }
                        IpsecEvent::ChildSaReady { connection, peer_index, child, lease }
                        | IpsecEvent::ChildSaRefreshed { connection, peer_index, child, lease } => {
                            connected = true;
                            let Some(config) = config_map.get(&connection).cloned() else {
                                log::warn!("IPsec {connection}: no configuration");
                                continue;
                            };
                            match apply_child(&mut manager, &config, &child, &lease).await {
                                Ok(new) => {
                                    let same_interface = applied
                                        .get(&(connection.clone(), peer_index))
                                        .is_some_and(|old| match (&old.interface, &new.interface) {
                                            (Some(old), Some(new)) => old.name == new.name,
                                            _ => false,
                                        });
                                    let new_routes = new.routes.clone();
                                    if let Some(old) = applied.insert((connection.clone(), peer_index), new) {
                                        let _ = remove_child(
                                            &mut manager,
                                            old,
                                            !same_interface,
                                            &new_routes,
                                        )
                                        .await;
                                    }
                                }
                                Err(error) => {
                                    log::warn!("IPsec {connection}: install failed: {error}");
                                }
                            }
                            if let Some(lease) = client_lease(&lease) {
                                apply_dns(&lease);
                            }
                        }
                        IpsecEvent::ChildSaRemoved { connection, peer_index, reason } => {
                            log::info!("IPsec {connection}: Child SA removed: {reason:?}");
                            if let Some(old) = applied.remove(&(connection, peer_index)) {
                                let _ = remove_child(&mut manager, old, true, &[]).await;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        for (_, old) in applied.drain() {
            let _ = remove_child(&mut manager, old, true, &[]).await;
        }
        let _ = manager.cleanup_owned().await;
        Ok(connected)
    })
}

fn client_lease(lease: &IpsecLease) -> Option<DnsConfig> {
    if lease.dns.is_empty() {
        return None;
    }
    Some(DnsConfig {
        nameservers: lease.dns.iter().map(ToString::to_string).collect(),
        searches: Vec::new(),
    })
}

fn apply_dns(dns: &DnsConfig) {
    if let Err(error) = crate::ip::write_resolv_conf(dns) {
        log::warn!("IPsec DNS configuration failed: {error}");
    }
}

async fn apply_child(
    manager: &mut XfrmManager,
    config: &IpsecConfig,
    child: &ChildSaHandle,
    lease: &IpsecLease,
) -> Result<Applied, WifiError> {
    let mode = config.child.mode;
    let interface = if mode == ChildMode::Tunnel {
        let spec = XfrmInterfaceSpec {
            name: config.xfrm.interface.clone(),
            if_id: Some(lease.if_id),
            underlay_interface: config.xfrm.underlay_interface.clone(),
        };
        Some(manager.ensure_interface(&spec).await.map_err(ipsec_error)?)
    } else {
        None
    };

    let local_address = lease
        .local_address
        .or(config.local.address)
        .ok_or_else(|| {
            ipsec_config_error("IPsec local underlay address is unknown")
        })?;
    let remote_address = lease.remote_address.or_else(|| {
        config
            .peers
            .get(lease.peer_index)
            .and_then(|peer| peer.remote.address)
    });
    let remote_address = remote_address.ok_or_else(|| {
        ipsec_config_error("IPsec remote underlay address is unknown")
    })?;

    let install = InstallSpec {
        interface: interface.clone(),
        if_id: if interface.is_some() { lease.if_id } else { 0 },
        reqid: lease.reqid,
        local_address,
        remote_address,
        mode,
        lifetime: config.child.lifetime,
        priority: config.xfrm.priority,
        replay_window: config.child.replay_window,
        mark: config.xfrm.mark,
        mark_mask: config.xfrm.mark_mask,
        forward: config.topology == shuli_ipsec::Topology::SiteToSite,
        nat_t: lease.nat_t,
    };
    let installed = manager
        .install(child, &install)
        .await
        .map_err(ipsec_error)?;

    let mut routes = Vec::new();
    if let Some(interface) = &interface {
        apply_link_addresses(interface, lease).await?;
        for selector in &lease.remote_selectors {
            if let Some(route) = add_route(interface.if_index, selector).await?
            {
                routes.push(route);
            }
        }
    }
    Ok(Applied {
        installed,
        interface,
        routes,
    })
}

async fn remove_child(
    manager: &mut XfrmManager,
    applied: Applied,
    remove_interface: bool,
    keep_routes: &[(IpAddr, u8, u32)],
) -> Result<(), WifiError> {
    if let Err(error) = manager.remove(&applied.installed).await {
        log::warn!("remove IPsec Child SA: {error}");
    }
    if let Some(interface) = &applied.interface {
        let routes: Vec<(IpAddr, u8, u32)> = applied
            .routes
            .iter()
            .filter(|route| !keep_routes.contains(route))
            .copied()
            .collect();
        remove_routes(interface.if_index, &routes).await;
    }
    if remove_interface
        && let Some(interface) = applied.interface
        && let Err(error) = manager.remove_interface(&interface).await
    {
        log::debug!("remove XFRM interface {}: {error}", interface.name);
    }
    Ok(())
}

async fn apply_link_addresses(
    interface: &XfrmInterface,
    lease: &IpsecLease,
) -> Result<(), WifiError> {
    let (conn, handle, _) =
        rtnetlink::new_connection().map_err(netlink_error)?;
    tokio::spawn(conn);
    for address in &lease.local_inner_addresses {
        let host_prefix = if address.address.is_ipv4() { 32 } else { 128 };
        if address.prefix_len != host_prefix {
            continue;
        }
        let result = handle
            .address()
            .add(interface.if_index, address.address, address.prefix_len)
            .execute()
            .await;
        if let Err(error) = result {
            if error.to_string().contains("File exists") {
                continue;
            }
            log::warn!(
                "add address {} to {}: {error}",
                address,
                interface.name
            );
        }
    }
    Ok(())
}

async fn add_route(
    if_index: u32,
    selector: &TrafficSelector,
) -> Result<Option<(IpAddr, u8, u32)>, WifiError> {
    let network = shuli_ipsec::IpNet::from(*selector);
    if network.prefix_len == 0 {
        // Do not hijack the system default route; multi-selector
        // deployments must configure explicit remote prefixes.
        log::debug!("skipping default route for IPsec selector {selector:?}");
        return Ok(None);
    }
    let (conn, handle, _) =
        rtnetlink::new_connection().map_err(netlink_error)?;
    tokio::spawn(conn);
    let message = match network.address {
        IpAddr::V4(address) => {
            rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(address, network.prefix_len)
                .output_interface(if_index)
                .build()
        }
        IpAddr::V6(address) => {
            rtnetlink::RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(address, network.prefix_len)
                .output_interface(if_index)
                .build()
        }
    };
    if let Err(error) = handle.route().add(message).execute().await {
        if error.to_string().contains("File exists") {
            return Ok(None);
        }
        return Err(netlink_error(error));
    }
    log::info!("added route {network} via XFRM interface {if_index}");
    Ok(Some((network.address, network.prefix_len, if_index)))
}

async fn remove_routes(if_index: u32, routes: &[(IpAddr, u8, u32)]) {
    if routes.is_empty() {
        return;
    }
    let Ok((conn, handle, _)) = rtnetlink::new_connection() else {
        return;
    };
    tokio::spawn(conn);
    for (address, prefix_len, index) in routes {
        if *index != if_index {
            continue;
        }
        let message = match address {
            IpAddr::V4(address) => {
                rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(*address, *prefix_len)
                    .output_interface(*index)
                    .build()
            }
            IpAddr::V6(address) => {
                rtnetlink::RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(*address, *prefix_len)
                    .output_interface(*index)
                    .build()
            }
        };
        if let Err(error) = handle.route().del(message).execute().await {
            log::debug!("remove IPsec route {address}/{prefix_len}: {error}");
        }
    }
}

fn ipsec_error(error: shuli_ipsec::IpsecError) -> WifiError {
    let kind = match error.kind {
        shuli_ipsec::IpsecErrorKind::Config => ErrorKind::InvalidConfig,
        shuli_ipsec::IpsecErrorKind::Authentication
        | shuli_ipsec::IpsecErrorKind::Identity => ErrorKind::AuthFailed,
        shuli_ipsec::IpsecErrorKind::Timeout => ErrorKind::ConnectFailed,
        shuli_ipsec::IpsecErrorKind::Io => ErrorKind::Io,
        _ => ErrorKind::ConnectFailed,
    };
    WifiError::new(kind, error.to_string())
}

fn ipsec_config_error(message: impl Into<String>) -> WifiError {
    WifiError::new(ErrorKind::InvalidConfig, message.into())
}

fn netlink_error(error: impl std::fmt::Display) -> WifiError {
    WifiError::new(ErrorKind::Nl80211, error.to_string())
}
