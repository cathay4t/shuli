// SPDX-License-Identifier: Apache-2.0

//! Linux XFRM manager.
//!
//! The manager owns one netlink socket for XFRM state/policies and one
//! rtnetlink socket for XFRM interfaces.  Cleanup is always scoped to
//! objects recorded by this instance; the code never calls flush.

mod interface;
mod monitor;
mod policy;
mod state;

use std::{
    collections::HashMap, future::Future, net::IpAddr, pin::Pin, time::Duration,
};

use futures::StreamExt;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_xfrm::{IPPROTO_ESP, XfrmMessage};
use netlink_proto::{
    ConnectionHandle,
    sys::{SocketAddr, protocols::NETLINK_XFRM},
};
use tokio::task::JoinHandle;

pub use self::{interface::XfrmInterface, monitor::XfrmEvent};
use crate::{
    client::ChildSaHandle,
    config::{ChildMode, TrafficSelector, XfrmConfig},
    error::{IpsecError, IpsecErrorKind},
};

/// Specification for an XFRM interface.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XfrmInterfaceSpec {
    /// Explicit interface name.  When absent, `xfrm<if_id>` is used.
    pub name: Option<String>,
    /// Explicit `if_id`.  When absent, an unused value is allocated.
    pub if_id: Option<u32>,
    /// Underlay interface name used as the link base.  Defaults to
    /// `lo`, which is sufficient for route-based tunnels whose SAs
    /// carry the real endpoint addresses.
    pub underlay_interface: Option<String>,
}

impl XfrmInterfaceSpec {
    pub fn from_config(config: &XfrmConfig) -> Self {
        Self {
            name: config.interface.clone(),
            if_id: config.if_id,
            underlay_interface: config.underlay_interface.clone(),
        }
    }
}

/// Parameters for installing one Child SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSpec {
    /// XFRM interface for route-based tunnels.
    pub interface: Option<XfrmInterface>,
    pub if_id: u32,
    pub reqid: u32,
    /// Underlay addresses of the local and remote peers.
    pub local_address: IpAddr,
    pub remote_address: IpAddr,
    pub mode: ChildMode,
    pub lifetime: Duration,
    pub priority: u32,
    pub replay_window: u32,
    pub mark: Option<u32>,
    pub mark_mask: u32,
    /// Install forward policies (site-to-site gateways).
    pub forward: bool,
    /// Enable UDP encapsulation for NAT-T.
    pub nat_t: bool,
}

impl InstallSpec {
    fn direction_addr(&self) -> u16 {
        if self.local_address.is_ipv4() {
            netlink_packet_xfrm::AF_INET
        } else {
            netlink_packet_xfrm::AF_INET6
        }
    }
}

/// A Child SA installed by this manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledChildSa {
    pub if_id: u32,
    pub reqid: u32,
    pub local_address: IpAddr,
    pub remote_address: IpAddr,
    pub local_spi: u32,
    pub remote_spi: u32,
    local_policies: Vec<PolicyRecord>,
    remote_policies: Vec<PolicyRecord>,
    forward_policies: Vec<PolicyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SaRecord {
    source: IpAddr,
    destination: IpAddr,
    spi: u32,
    proto: u8,
    family: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyRecord {
    direction: u8,
    selector: netlink_packet_xfrm::Selector,
    if_id: u32,
    message: netlink_packet_xfrm::policy::ModifyMessage,
}

/// Async XFRM manager.
pub struct XfrmManager {
    handle: ConnectionHandle<XfrmMessage>,
    _conn_task: JoinHandle<()>,
    rtnl: rtnetlink::Handle,
    _rtnl_task: JoinHandle<()>,
    monitor: Option<monitor::XfrmMonitor>,
    interfaces: HashMap<String, XfrmInterface>,
    sas: HashMap<SaRecord, ()>,
    policies: Vec<PolicyRecord>,
}

impl XfrmManager {
    /// Open the XFRM and rtnetlink sockets.
    pub async fn new() -> Result<Self, IpsecError> {
        let (conn, handle, _messages) = netlink_proto::new_connection::<
            XfrmMessage,
        >(NETLINK_XFRM)
        .map_err(|e| IpsecError::new(IpsecErrorKind::Netlink, e.to_string()))?;
        let conn_task = tokio::spawn(conn);

        let (rtnl_conn, rtnl, _events) =
            rtnetlink::new_connection().map_err(|e| {
                IpsecError::new(IpsecErrorKind::Netlink, e.to_string())
            })?;
        let rtnl_task = tokio::spawn(rtnl_conn);

        Ok(Self {
            handle,
            _conn_task: conn_task,
            rtnl,
            _rtnl_task: rtnl_task,
            monitor: None,
            interfaces: HashMap::new(),
            sas: HashMap::new(),
            policies: Vec::new(),
        })
    }

    /// Open the XFRM event monitor (ACQUIRE, EXPIRE, SA, POLICY,
    /// REPORT groups).  Safe to call more than once.
    pub fn enable_monitor(&mut self) -> Result<(), IpsecError> {
        if self.monitor.is_none() {
            self.monitor = Some(monitor::XfrmMonitor::new()?);
        }
        Ok(())
    }

    /// Return the next XFRM event, if the monitor is enabled.
    pub async fn next_event(&mut self) -> Option<XfrmEvent> {
        let monitor = self.monitor.as_mut()?;
        monitor.next().await
    }

    /// Create or reuse an XFRM interface with the given `if_id`.
    pub async fn ensure_interface(
        &mut self,
        spec: &XfrmInterfaceSpec,
    ) -> Result<XfrmInterface, IpsecError> {
        let if_id = match spec.if_id {
            Some(if_id) => if_id,
            None => self.allocate_if_id().await?,
        };
        let name = spec.name.clone().unwrap_or_else(|| format!("xfrm{if_id}"));

        if let Some(existing) = interface::query(&self.rtnl, &name).await? {
            if existing.if_id != if_id {
                return Err(IpsecError::xfrm(format!(
                    "interface {name} already exists with if_id {} (requested \
                     {if_id})",
                    existing.if_id
                )));
            }
            self.interfaces.insert(name, existing.clone());
            return Ok(existing);
        }

        let interface = interface::create(
            &self.rtnl,
            &name,
            if_id,
            spec.underlay_interface.as_deref(),
        )
        .await?;
        self.interfaces
            .insert(interface.name.clone(), interface.clone());
        Ok(interface)
    }

    /// Install one Child SA and its policies.
    pub fn install<'a>(
        &'a mut self,
        child: &'a ChildSaHandle,
        spec: &'a InstallSpec,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<InstalledChildSa, IpsecError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if child.mode != spec.mode {
                return Err(IpsecError::xfrm(
                    "Child SA mode does not match the install specification",
                ));
            }
            if spec.local_address.is_ipv4() != spec.remote_address.is_ipv4() {
                return Err(IpsecError::xfrm(
                    "local and remote underlay addresses use different \
                     families",
                ));
            }
            if let Some(interface) = &spec.interface
                && interface.if_id != spec.if_id
            {
                return Err(IpsecError::xfrm(
                    "XFRM interface if_id does not match the install \
                     specification",
                ));
            }

            let outbound = self.state_message(child, spec, true)?;
            let inbound = self.state_message(child, spec, false)?;
            let outbound_id = SaRecord {
                source: spec.local_address,
                destination: spec.remote_address,
                spi: child.local_spi,
                proto: IPPROTO_ESP,
                family: spec.direction_addr(),
            };
            let inbound_id = SaRecord {
                source: spec.remote_address,
                destination: spec.local_address,
                spi: child.remote_spi,
                proto: IPPROTO_ESP,
                family: spec.direction_addr(),
            };

            self.add_or_update_sa(outbound).await?;
            if let Err(error) = self.add_or_update_sa(inbound).await {
                let _ = self.delete_sa(&outbound_id).await;
                return Err(error);
            }

            let mut installed = InstalledChildSa {
                if_id: spec.if_id,
                reqid: spec.reqid,
                local_address: spec.local_address,
                remote_address: spec.remote_address,
                local_spi: child.local_spi,
                remote_spi: child.remote_spi,
                local_policies: Vec::new(),
                remote_policies: Vec::new(),
                forward_policies: Vec::new(),
            };

            let policy_result =
                self.install_policies(child, spec, &mut installed).await;
            if let Err(error) = policy_result {
                let _ = self.delete_sa(&inbound_id).await;
                let _ = self.delete_sa(&outbound_id).await;
                return Err(error);
            }

            self.sas.insert(inbound_id.clone(), ());
            self.sas.insert(outbound_id, ());
            for record in installed
                .local_policies
                .iter()
                .chain(installed.remote_policies.iter())
                .chain(installed.forward_policies.iter())
            {
                self.policies.push(record.clone());
            }
            Ok(installed)
        })
    }

    /// Remove exactly the SAs and policies recorded in `installed`.
    pub async fn remove(
        &mut self,
        installed: &InstalledChildSa,
    ) -> Result<(), IpsecError> {
        let mut first_error = None;

        for policy in installed
            .forward_policies
            .iter()
            .chain(installed.remote_policies.iter())
            .chain(installed.local_policies.iter())
        {
            if let Err(error) = policy::delete(&self.handle, policy).await {
                first_error.get_or_insert(error);
            } else {
                self.policies.retain(|owned| owned != policy);
            }
        }

        let outbound = SaRecord {
            source: installed.local_address,
            destination: installed.remote_address,
            spi: installed.local_spi,
            proto: IPPROTO_ESP,
            family: if installed.local_address.is_ipv4() {
                netlink_packet_xfrm::AF_INET
            } else {
                netlink_packet_xfrm::AF_INET6
            },
        };
        let inbound = SaRecord {
            source: installed.remote_address,
            destination: installed.local_address,
            spi: installed.remote_spi,
            proto: IPPROTO_ESP,
            family: outbound.family,
        };
        for id in [&inbound, &outbound] {
            if let Err(error) = self.delete_sa(id).await {
                first_error.get_or_insert(error);
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Remove an XFRM interface created or adopted by this manager.
    pub async fn remove_interface(
        &mut self,
        interface: &XfrmInterface,
    ) -> Result<(), IpsecError> {
        interface::delete(&self.rtnl, interface).await?;
        self.interfaces.remove(&interface.name);
        Ok(())
    }

    /// Remove every object still owned by this manager.
    pub async fn cleanup_owned(&mut self) -> Result<(), IpsecError> {
        let mut first_error = None;

        let policies = self.policies.clone();
        for policy in &policies {
            if let Err(error) = policy::delete(&self.handle, policy).await {
                first_error.get_or_insert(error);
            }
        }
        self.policies.clear();

        let sas: Vec<SaRecord> = self.sas.keys().cloned().collect();
        for sa in &sas {
            if let Err(error) = self.delete_sa(sa).await {
                first_error.get_or_insert(error);
            }
        }
        self.sas.clear();

        let interfaces: Vec<XfrmInterface> =
            self.interfaces.values().cloned().collect();
        for interface in &interfaces {
            if let Err(error) = interface::delete(&self.rtnl, interface).await {
                first_error.get_or_insert(error);
            }
        }
        self.interfaces.clear();

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Allocate an unused `if_id` by inspecting existing XFRM links.
    pub async fn allocate_if_id(&self) -> Result<u32, IpsecError> {
        let used = interface::used_if_ids(&self.rtnl).await?;
        let mut candidate = 1u32;
        while used.contains(&candidate) {
            candidate = candidate.wrapping_add(1);
            if candidate == 0 {
                return Err(IpsecError::xfrm("no free if_id"));
            }
        }
        Ok(candidate)
    }

    async fn add_or_update_sa(
        &self,
        message: netlink_packet_xfrm::state::ModifyMessage,
    ) -> Result<(), IpsecError> {
        let mut request =
            NetlinkMessage::from(XfrmMessage::AddSa(message.clone()));
        request.header.flags =
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
        match self.request(request).await {
            Ok(_) => Ok(()),
            Err(error) if is_exists(&error) => {
                let mut update =
                    NetlinkMessage::from(XfrmMessage::UpdateSa(message));
                update.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE;
                self.request(update).await.map(|_| ())
            }
            Err(error) => Err(error),
        }
    }

    async fn delete_sa(&mut self, id: &SaRecord) -> Result<(), IpsecError> {
        state::delete(
            &self.handle,
            id.source,
            id.destination,
            id.spi,
            id.proto,
            id.family,
        )
        .await?;
        self.sas.remove(id);
        Ok(())
    }

    fn install_policies<'a>(
        &'a self,
        child: &'a ChildSaHandle,
        spec: &'a InstallSpec,
        installed: &'a mut InstalledChildSa,
    ) -> Pin<Box<dyn Future<Output = Result<(), IpsecError>> + Send + 'a>> {
        Box::pin(async move {
            let pairs: Vec<(TrafficSelector, TrafficSelector)> = child
                .local_selectors
                .iter()
                .flat_map(|local| {
                    child
                        .remote_selectors
                        .iter()
                        .map(move |remote| (*local, *remote))
                })
                .collect();
            for (local, remote) in &pairs {
                let out = policy::build(
                    policy::Direction::Out,
                    *local,
                    *remote,
                    spec,
                    child,
                )?;
                let in_ = policy::build(
                    policy::Direction::In,
                    *remote,
                    *local,
                    spec,
                    child,
                )?;
                policy::add(&self.handle, &out).await?;
                installed.local_policies.push(out);
                if let Err(error) = policy::add(&self.handle, &in_).await {
                    for record in &installed.local_policies {
                        let _ = policy::delete(&self.handle, record).await;
                    }
                    installed.local_policies.clear();
                    return Err(error);
                }
                installed.remote_policies.push(in_);

                if spec.forward && spec.mode == ChildMode::Tunnel {
                    let forward = policy::build(
                        policy::Direction::Forward,
                        *remote,
                        *local,
                        spec,
                        child,
                    )?;
                    policy::add(&self.handle, &forward).await?;
                    installed.forward_policies.push(forward);
                }
            }
            Ok(())
        })
    }

    fn state_message(
        &self,
        child: &ChildSaHandle,
        spec: &InstallSpec,
        outbound: bool,
    ) -> Result<netlink_packet_xfrm::state::ModifyMessage, IpsecError> {
        state::build(child, spec, outbound)
    }

    /// Send one netlink request and wait for its acknowledgement or
    /// response messages.
    async fn request(
        &self,
        request: NetlinkMessage<XfrmMessage>,
    ) -> Result<Vec<XfrmMessage>, IpsecError> {
        request_once(&self.handle, request).await
    }
}

pub(crate) async fn request(
    handle: &ConnectionHandle<XfrmMessage>,
    request: NetlinkMessage<XfrmMessage>,
) -> Result<Vec<XfrmMessage>, IpsecError> {
    request_once(handle, request).await
}

async fn request_once(
    handle: &ConnectionHandle<XfrmMessage>,
    request: NetlinkMessage<XfrmMessage>,
) -> Result<Vec<XfrmMessage>, IpsecError> {
    let mut stream = handle
        .request(request, SocketAddr::new(0, 0))
        .map_err(|e| IpsecError::new(IpsecErrorKind::Netlink, e.to_string()))?;
    let mut responses = Vec::new();
    while let Some(message) = stream.next().await {
        match message.payload {
            NetlinkPayload::Error(error) => {
                if let Some(code) = error.code {
                    return Err(IpsecError::new(
                        IpsecErrorKind::Netlink,
                        format!(
                            "netlink request failed: {}",
                            std::io::Error::from_raw_os_error(code.get().abs())
                        ),
                    ));
                }
            }
            NetlinkPayload::InnerMessage(message) => responses.push(message),
            NetlinkPayload::Done(_) => break,
            _ => {}
        }
    }
    Ok(responses)
}

pub(crate) fn is_exists(error: &IpsecError) -> bool {
    error.msg.contains("File exists") || error.msg.contains("EEXIST")
}

impl Drop for XfrmManager {
    fn drop(&mut self) {
        // Kernel objects are removed by explicit cleanup; dropping the
        // manager only closes the sockets.  This matches the ownership
        // contract: a crashed process may leave state behind, and a
        // subsequent start removes only state recorded by that new
        // instance.
        self._conn_task.abort();
        self._rtnl_task.abort();
    }
}
