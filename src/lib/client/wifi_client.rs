// SPDX-License-Identifier: Apache-2.0

use super::*;

pub struct WifiRunResult {
    pub iface_name: String,
    pub state: WifiState,
    pub error: Option<WifiError>,
}

/// A single WiFi client managing one or more wifi-phy interfaces.
///
/// All interfaces share one nl80211 socket and one multicast event
/// subscription. The event dispatcher routes each kernel event to the
/// interface it belongs to, so concurrent interfaces do not see each
/// other's scan/auth/disconnect/CQM events.
pub struct WifiClient {
    ifaces: HashMap<String, WifiIface>,
    dispatcher_shutdown_tx: UnboundedSender<()>,
}

impl WifiClient {
    /// Create a client managing the single wifi-phy in `config`.
    pub async fn init(config: WifiConfig) -> Result<Self, WifiError> {
        Self::init_multi(vec![config]).await
    }

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
            let conn_handle = handle.connection();
            let iface =
                WifiIface::init(handle.clone(), conn_handle, event_rx, config)
                    .await?;
            iface_tx_by_if_index.insert(iface.core.if_index, event_tx);
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
    /// change, then return that change.
    pub async fn run_multi(&mut self) -> Result<WifiRunResult, WifiError> {
        if self.ifaces.is_empty() {
            return Err(WifiError::new(
                ErrorKind::Config,
                "WifiClient has no interfaces",
            ));
        }
        let mut futures: Vec<
            std::pin::Pin<
                Box<dyn futures::Future<Output = WifiRunResult> + Send + '_>,
            >,
        > = Vec::new();
        for (iface_name, iface) in &mut self.ifaces {
            let iface_name = iface_name.clone();
            futures.push(Box::pin(async move {
                let (state, error) = match iface.run().await {
                    Ok(state) => (state, iface.last_error.take()),
                    Err(e) => {
                        iface.last_error = None;
                        (iface.state, Some(e))
                    }
                };
                WifiRunResult {
                    iface_name,
                    state,
                    error,
                }
            }));
        }
        let (result, _index, _remaining) =
            futures::future::select_all(futures).await;
        Ok(result)
    }

    /// Convenience for a single-interface client: see
    /// [`WifiClient::run_multi`] when managing more than one interface.
    ///
    /// Authentication failures such as a wrong password are returned as
    /// `Err(WifiError)` with `ErrorKind::WrongPassword`; the client
    /// still retries on the next call.
    pub async fn run(&mut self) -> Result<WifiState, WifiError> {
        if self.ifaces.len() != 1 {
            return Err(WifiError::new(
                ErrorKind::Config,
                "WifiClient::run() requires exactly one interface; use \
                 run_multi() for multiple interfaces",
            ));
        }
        let result = self.run_multi().await?;
        match result.error {
            Some(e) => Err(e),
            None => Ok(result.state),
        }
    }

    pub fn current_ssid(&self) -> &str {
        self.ifaces
            .values()
            .next()
            .map(|iface| iface.current_ssid())
            .unwrap_or("")
    }

    #[cfg(test)]
    pub(crate) fn iface(&self) -> Option<&WifiIface> {
        self.ifaces.values().next()
    }

    #[cfg(test)]
    pub(crate) fn iface_mut(&mut self) -> Option<&mut WifiIface> {
        self.ifaces.values_mut().next()
    }

    pub fn current_ssid_of(&self, iface_name: &str) -> Option<&str> {
        self.ifaces
            .get(iface_name)
            .map(|iface| iface.current_ssid())
    }

    pub fn current_bssid(&self) -> [u8; ETH_ALEN] {
        self.ifaces
            .values()
            .next()
            .map(|iface| iface.current_bssid())
            .unwrap_or([0; ETH_ALEN])
    }

    pub fn current_bssid_of(&self, iface_name: &str) -> Option<[u8; ETH_ALEN]> {
        self.ifaces
            .get(iface_name)
            .map(|iface| iface.current_bssid())
    }

    /// Convenience for a single-interface client.
    pub async fn update_networks(
        &mut self,
        networks: Vec<NetworkConfig>,
    ) -> Result<(), WifiError> {
        if self.ifaces.len() != 1 {
            return Err(WifiError::new(
                ErrorKind::Config,
                "WifiClient::update_networks() requires exactly one \
                 interface; use update_networks_of() for multiple",
            ));
        }
        let iface = self.ifaces.values_mut().next().expect("len checked");
        iface.update_networks(networks).await
    }

    pub async fn update_networks_of(
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

    pub fn wowlan_supported(&self) -> bool {
        self.ifaces
            .values()
            .next()
            .map(WifiIface::wowlan_supported)
            .unwrap_or(false)
    }

    pub fn wowlan_supported_of(&self, iface_name: &str) -> bool {
        self.ifaces
            .get(iface_name)
            .map(WifiIface::wowlan_supported)
            .unwrap_or(false)
    }

    /// Convenience for a single-interface client.
    pub async fn arm_wowlan(&mut self) -> Result<bool, WifiError> {
        if self.ifaces.len() != 1 {
            return Err(WifiError::new(
                ErrorKind::Config,
                "WifiClient::arm_wowlan() requires exactly one interface; use \
                 arm_wowlan_of() for multiple",
            ));
        }
        let iface = self.ifaces.values_mut().next().expect("len checked");
        iface.arm_wowlan().await
    }

    pub async fn arm_wowlan_of(
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

    /// Convenience for a single-interface client.
    pub async fn disarm_wowlan(&mut self) -> Result<(), WifiError> {
        if self.ifaces.len() != 1 {
            return Err(WifiError::new(
                ErrorKind::Config,
                "WifiClient::disarm_wowlan() requires exactly one interface; \
                 use disarm_wowlan_of() for multiple",
            ));
        }
        let iface = self.ifaces.values_mut().next().expect("len checked");
        iface.disarm_wowlan().await
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
    mut event_receiver: futures::channel::mpsc::UnboundedReceiver<(
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
