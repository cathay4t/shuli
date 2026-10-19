// SPDX-License-Identifier: Apache-2.0

//! Minimal nipart-like consumer of the public shuli-ipsec API.
//!
//! It negotiates one PSK point-to-point tunnel, creates the XFRM
//! interface, installs the Child SA, and removes exactly the objects it
//! installed on teardown.  Configuration is read from:
//!
//! - `IPSEC_LOCAL` (local underlay IP),
//! - `IPSEC_REMOTE` (remote underlay IP),
//! - `IPSEC_PSK` (pre-shared key),
//! - `IPSEC_IFACE` (optional XFRM interface name).
//!
//! Run with `cargo run -p shuli-ipsec --example nipart_flow` as root.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use shuli_ipsec::{
    AuthConfig, ChildConfig, DpdConfig, Identity, IkeConfig, InstallSpec,
    InstalledChildSa, IpsecClient, IpsecConfig, IpsecEvent, IpsecLease,
    LocalConfig, PeerConfig, RekeyConfig, RemoteConfig, Secret, Topology,
    TrafficSelectorPair, XfrmConfig, XfrmInterface, XfrmInterfaceSpec,
    XfrmManager,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let local: IpAddr = std::env::var("IPSEC_LOCAL")?.parse()?;
    let remote: IpAddr = std::env::var("IPSEC_REMOTE")?.parse()?;
    let psk = std::env::var("IPSEC_PSK")?;
    let interface_name = std::env::var("IPSEC_IFACE").ok();

    let local_inner = IpAddr::V4(std::net::Ipv4Addr::new(10, 99, 0, 1));
    let remote_inner = IpAddr::V4(std::net::Ipv4Addr::new(10, 99, 0, 2));
    let config = IpsecConfig {
        name: "example".to_string(),
        topology: Topology::PointToPoint,
        local: LocalConfig {
            address: Some(local),
            interface: None,
            identity: Identity::Fqdn("local.example".to_string()),
            port: 500,
            nat_t: true,
            request_inner_address: false,
            request_dns: false,
        },
        peers: vec![PeerConfig {
            remote: RemoteConfig {
                address: Some(remote),
                identity: Identity::Fqdn("remote.example".to_string()),
                port: 500,
            },
            selectors: TrafficSelectorPair::hosts(local_inner, remote_inner),
            auth: AuthConfig::Psk(Secret::from(psk.as_str())),
        }],
        ike: IkeConfig::default(),
        child: ChildConfig::default(),
        xfrm: XfrmConfig {
            interface: interface_name,
            ..XfrmConfig::default()
        },
        rekey: RekeyConfig::default(),
        dpd: DpdConfig::default(),
    };

    let mut client = IpsecClient::init(vec![config.clone()]).await?;
    let mut manager = XfrmManager::new().await?;
    let mut installed: HashMap<
        (String, usize),
        (InstalledChildSa, XfrmInterface),
    > = HashMap::new();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = client.run() => match event? {
                IpsecEvent::ChildSaReady { connection, peer_index, child, lease } => {
                    let applied = install(&mut manager, &config, &child, &lease).await?;
                    if let Some((old, _)) = installed.insert((connection.clone(), peer_index), applied) {
                        manager.remove(&old).await?;
                    }
                    println!("Child SA ready for {connection} peer {peer_index}");
                }
                IpsecEvent::ChildSaRefreshed { connection, peer_index, child, lease } => {
                    let applied = install(&mut manager, &config, &child, &lease).await?;
                    if let Some((old, _)) = installed.insert((connection, peer_index), applied) {
                        manager.remove(&old).await?;
                    }
                }
                IpsecEvent::ChildSaRemoved { connection, peer_index, .. } => {
                    if let Some((old, _)) = installed.remove(&(connection, peer_index)) {
                        manager.remove(&old).await?;
                    }
                }
                IpsecEvent::Error { connection, error } => {
                    eprintln!("{connection}: {error}");
                }
                IpsecEvent::State { .. } => {}
                _ => {}
            },
        }
    }

    client.shutdown().await;
    for ((_, _), (old, interface)) in installed.drain() {
        manager.remove(&old).await?;
        manager.remove_interface(&interface).await?;
    }
    manager.cleanup_owned().await?;
    Ok(())
}

async fn install(
    manager: &mut XfrmManager,
    config: &IpsecConfig,
    child: &shuli_ipsec::ChildSaHandle,
    lease: &IpsecLease,
) -> Result<(InstalledChildSa, XfrmInterface), Box<dyn std::error::Error>> {
    let spec = XfrmInterfaceSpec {
        name: config.xfrm.interface.clone(),
        if_id: Some(lease.if_id),
        underlay_interface: config.xfrm.underlay_interface.clone(),
    };
    let interface = manager.ensure_interface(&spec).await?;
    let local_address = lease
        .local_address
        .ok_or("missing local underlay address")?;
    let remote_address = lease
        .remote_address
        .ok_or("missing remote underlay address")?;
    let installed = manager
        .install(
            child,
            &InstallSpec {
                interface: Some(interface.clone()),
                if_id: lease.if_id,
                reqid: lease.reqid,
                local_address,
                remote_address,
                mode: config.child.mode,
                lifetime: config.child.lifetime,
                priority: config.xfrm.priority,
                replay_window: config.child.replay_window,
                mark: config.xfrm.mark,
                mark_mask: config.xfrm.mark_mask,
                forward: true,
                nat_t: lease.nat_t,
            },
        )
        .await?;
    println!(
        "installed SAs on {} ({}) local={} remote={}",
        interface.name,
        SocketAddr::new(local_address, 0),
        lease.local_selectors.len(),
        lease.remote_selectors.len()
    );
    Ok((installed, interface))
}
