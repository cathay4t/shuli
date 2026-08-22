// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use futures::{StreamExt, channel::mpsc::UnboundedReceiver};
use netlink_packet_core::NetlinkPayload;
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle};
use wl_nl80211::{Nl80211Attr, Nl80211Message, Nl80211MulticastGroup};

use super::{Nl80211EventMsg, Nl80211EventSender, WifiIface};
use crate::{
    ETH_ALEN, ErrorKind, NetworkConfig, ShuliNl80211Connection, WifiConfig,
    WifiError, WifiState,
};

#[derive(Debug)]
#[non_exhaustive]
pub struct WifiIfaceState {
    pub iface_name: String,
    pub state: WifiState,
}

/// A single WiFi client managing one or more wifi-phy interfaces.
///
/// All interfaces share one nl80211 socket and one multicast event
/// subscription. The event dispatcher routes each kernel event to the
/// interface it belongs to, so concurrent interfaces do not see each
/// other's scan/auth/disconnect/CQM events.
#[non_exhaustive]
pub struct WifiClient {
    pub(crate) ifaces: HashMap<String, WifiIface>,
    dispatcher_shutdown_tx: UnboundedSender<()>,
}

impl WifiClient {
    /// Create one client managing every wifi-phy in `configs`.
    ///
    /// All interfaces share one nl80211 socket and one multicast event
    /// subscription. Run one `WifiClient` per network namespace.
    pub async fn init_multi(
        configs: Vec<WifiConfig>,
    ) -> Result<Self, WifiError> {
        if configs.is_empty() {
            return Err(WifiError::new(
                ErrorKind::InvalidConfig,
                "WifiClient::init_multi(): at least one WifiConfig required",
            ));
        }
        let mut iface_names = std::collections::HashSet::new();
        for config in &configs {
            if !iface_names.insert(&config.iface_name) {
                return Err(WifiError::new(
                    ErrorKind::InvalidConfig,
                    format!(
                        "WifiClient::init_multi(): duplicate interface {}",
                        config.iface_name
                    ),
                ));
            }
        }

        let (conn, handle, event_receiver) =
            wl_nl80211::new_multicast_connection(&[
                Nl80211MulticastGroup::Scan,
                Nl80211MulticastGroup::Mlme,
                Nl80211MulticastGroup::Config,
            ])
            .map_err(|e| WifiError::new(ErrorKind::Config, e.to_string()))?;
        tokio::spawn(conn);

        let mut ifaces = HashMap::new();
        let mut iface_tx_by_if_index: HashMap<u32, Nl80211EventSender> =
            HashMap::new();
        for config in configs {
            let (event_tx, event_rx) = futures::channel::mpsc::unbounded();
            let nl = ShuliNl80211Connection::from_handle(
                handle.clone(),
                &config.iface_name,
            )
            .await?;
            let iface = WifiIface::init(nl, event_rx, config).await?;
            iface_tx_by_if_index.insert(iface.core.nl.if_index, event_tx);
            ifaces.insert(iface.core.config.iface_name.clone(), iface);
        }

        let (dispatcher_shutdown_tx, dispatcher_shutdown_rx) =
            tokio::sync::mpsc::unbounded_channel();
        let _dispatcher = run_event_dispatcher(
            event_receiver,
            iface_tx_by_if_index,
            dispatcher_shutdown_rx,
        );

        Ok(Self {
            ifaces,
            dispatcher_shutdown_tx,
        })
    }

    /// Drive every managed interface until one of them reports a state
    /// change or an interface error, then return that result.
    pub async fn run(&mut self) -> Result<WifiIfaceState, WifiError> {
        if self.ifaces.is_empty() {
            return Err(WifiError::new(
                ErrorKind::Config,
                "WifiClient has no interfaces",
            ));
        }
        type IfaceRunFuture<'a> = std::pin::Pin<
            Box<
                dyn futures::Future<Output = Result<WifiIfaceState, WifiError>>
                    + Send
                    + 'a,
            >,
        >;
        let mut futures: Vec<IfaceRunFuture<'_>> = Vec::new();
        for (iface_name, iface) in &mut self.ifaces {
            let iface_name = iface_name.clone();
            futures.push(Box::pin(async move {
                match iface.run().await {
                    Ok(state) => {
                        if let Some(e) = iface.last_error.take() {
                            return Err(e.with_iface_name(iface_name));
                        }
                        Ok(WifiIfaceState { iface_name, state })
                    }
                    Err(e) => {
                        iface.last_error = None;
                        Err(e.with_iface_name(iface_name))
                    }
                }
            }));
        }
        let (result, _index, _remaining) =
            futures::future::select_all(futures).await;
        result
    }

    pub fn current_ssid(&self, iface_name: &str) -> Option<&str> {
        self.ifaces
            .get(iface_name)
            .map(|iface| iface.current_ssid())
    }

    pub fn current_bssid(&self, iface_name: &str) -> Option<[u8; ETH_ALEN]> {
        self.ifaces
            .get(iface_name)
            .map(|iface| iface.current_bssid())
    }

    pub async fn update_networks(
        &mut self,
        iface_name: &str,
        networks: Vec<NetworkConfig>,
    ) -> Result<(), WifiError> {
        let iface = self.ifaces.get_mut(iface_name).ok_or_else(|| {
            WifiError::new(
                ErrorKind::InterfaceNotFound,
                format!("wifi interface {iface_name} not found"),
            )
        })?;
        iface.update_networks(networks).await
    }

    pub fn wowlan_supported(&self, iface_name: &str) -> bool {
        self.ifaces
            .get(iface_name)
            .map(WifiIface::wowlan_supported)
            .unwrap_or(false)
    }

    pub async fn arm_wowlan(
        &mut self,
        iface_name: &str,
    ) -> Result<bool, WifiError> {
        let iface = self.ifaces.get_mut(iface_name).ok_or_else(|| {
            WifiError::new(
                ErrorKind::InterfaceNotFound,
                format!("wifi interface {iface_name} not found"),
            )
        })?;
        iface.arm_wowlan().await
    }

    pub async fn disarm_wowlan_of(
        &mut self,
        iface_name: &str,
    ) -> Result<(), WifiError> {
        let iface = self.ifaces.get_mut(iface_name).ok_or_else(|| {
            WifiError::new(
                ErrorKind::InterfaceNotFound,
                format!("wifi interface {iface_name} not found"),
            )
        })?;
        iface.disarm_wowlan().await
    }

    /// Cleanly disconnect every managed interface and stop the event
    /// dispatcher. Call this before dropping the client.
    pub async fn shutdown(&mut self) {
        let _ = self.dispatcher_shutdown_tx.send(());
        for iface in self.ifaces.values_mut() {
            iface.shutdown().await;
        }
    }
}

impl Drop for WifiClient {
    fn drop(&mut self) {
        let _ = self.dispatcher_shutdown_tx.send(());
    }
}

fn run_event_dispatcher(
    mut event_receiver: UnboundedReceiver<(
        Nl80211EventMsg,
        netlink_sys::SocketAddr,
    )>,
    iface_tx_by_if_index: HashMap<u32, Nl80211EventSender>,
    mut shutdown_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => break,
                event = event_receiver.next() => {
                    let Some((raw_msg, _addr)) = event else {
                        break;
                    };
                    let Some(if_index) = event_if_index(&raw_msg) else {
                        // A few events may lack IFINDEX; keep the old
                        // broadcast behaviour for those rare messages.
                        for tx in iface_tx_by_if_index.values() {
                            if tx.unbounded_send(raw_msg.clone()).is_err() {
                                log::debug!("wifi event queue closed");
                            }
                        }
                        continue;
                    };
                    if let Some(tx) = iface_tx_by_if_index.get(&if_index)
                        && tx.unbounded_send(raw_msg).is_err()
                    {
                        log::debug!(
                            "wifi event queue closed for if_index {if_index}"
                        );
                    }
                }
            }
        }
    })
}

fn event_if_index(msg: &Nl80211EventMsg) -> Option<u32> {
    if let NetlinkPayload::InnerMessage(raw_genlmsg) = &msg.payload
        && let Ok(genl_msg) = raw_genlmsg.parse_into_genlmsg::<Nl80211Message>()
    {
        return genl_msg.payload.attributes.iter().find_map(
            |attr| match attr {
                Nl80211Attr::IfIndex(if_index) => Some(*if_index),
                _ => None,
            },
        );
    }
    None
}
