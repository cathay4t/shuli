// SPDX-License-Identifier: Apache-2.0

//! Public IKE client API.

use std::{collections::HashMap, net::IpAddr, sync::Arc, time::SystemTime};

use tokio::sync::{Mutex, RwLock, mpsc, watch};
use zeroize::Zeroizing;

use crate::{
    config::{
        ChildMode, EncryptionAlgorithm, IntegrityAlgorithm, IpNet, IpsecConfig,
        TrafficSelector,
    },
    error::IpsecError,
    ikev2::engine,
};

/// Connection state as reported to the API consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpsecState {
    /// No IKE exchange is running.
    Idle,
    /// An IKE SA is being negotiated.
    Connecting,
    /// At least one Child SA is installed.
    Established,
    /// A rekey exchange is in progress.
    Rekeying,
    /// The last attempt failed; a retry may still be scheduled.
    Failed,
    /// The connection was shut down.
    Closed,
}

/// Reason a Child SA was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChildSaRemovalReason {
    /// The peer deleted the SA.
    PeerDelete,
    /// The local side deleted the SA (rekey or shutdown).
    LocalDelete,
    /// The SA lifetime expired.
    Expired,
    /// Dead peer detection declared the peer dead.
    PeerDead,
    /// The connection was reconfigured.
    Reconfigured,
}

/// Lease information published for the daemon's IP layer.
///
/// This is an output type.  It is non-exhaustive so future releases can
/// report new lease data (for example Configuration Payload options)
/// without breaking consumers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsecLease {
    pub connection: String,
    pub peer_index: usize,
    pub xfrm_interface: Option<String>,
    pub if_id: u32,
    pub reqid: u32,
    pub local_selectors: Vec<TrafficSelector>,
    pub remote_selectors: Vec<TrafficSelector>,
    pub local_inner_addresses: Vec<IpNet>,
    pub remote_inner_addresses: Vec<IpNet>,
    /// Underlay addresses of the two endpoints, when known.
    pub local_address: Option<IpAddr>,
    pub remote_address: Option<IpAddr>,
    /// Whether the Child SA must use UDP encapsulation (NAT-T).
    pub nat_t: bool,
    pub dns: Vec<IpAddr>,
    pub expires_at: Option<SystemTime>,
}

/// Event stream item.
#[derive(Debug)]
#[non_exhaustive]
pub enum IpsecEvent {
    State {
        connection: String,
        state: IpsecState,
    },
    ChildSaReady {
        connection: String,
        peer_index: usize,
        child: ChildSaHandle,
        lease: IpsecLease,
    },
    ChildSaRefreshed {
        connection: String,
        peer_index: usize,
        child: ChildSaHandle,
        lease: IpsecLease,
    },
    ChildSaRemoved {
        connection: String,
        peer_index: usize,
        reason: ChildSaRemovalReason,
    },
    Error {
        connection: String,
        error: IpsecError,
    },
}

/// Opaque Child SA handle carrying negotiated selectors and key material.
///
/// The handle intentionally implements neither `Debug` nor `Clone`.  Keys
/// are zeroized on drop.  Consumers pass it to
/// [`crate::XfrmManager::install`] and never see the raw bytes through the
/// public API.
pub struct ChildSaHandle {
    pub(crate) local_spi: u32,
    pub(crate) remote_spi: u32,
    pub(crate) encryption: EncryptionAlgorithm,
    pub(crate) integrity: Option<IntegrityAlgorithm>,
    pub(crate) esn: bool,
    pub(crate) mode: ChildMode,
    pub(crate) local_selectors: Vec<TrafficSelector>,
    pub(crate) remote_selectors: Vec<TrafficSelector>,
    pub(crate) outbound_key: Zeroizing<Vec<u8>>,
    pub(crate) outbound_integrity_key: Option<Zeroizing<Vec<u8>>>,
    pub(crate) inbound_key: Zeroizing<Vec<u8>>,
    pub(crate) inbound_integrity_key: Option<Zeroizing<Vec<u8>>>,
}

impl ChildSaHandle {
    /// Local ESP SPI.
    pub fn local_spi(&self) -> u32 {
        self.local_spi
    }

    /// Remote ESP SPI.
    pub fn remote_spi(&self) -> u32 {
        self.remote_spi
    }

    /// ESP mode.
    pub fn mode(&self) -> ChildMode {
        self.mode
    }

    /// Negotiated local selectors.
    pub fn local_selectors(&self) -> &[TrafficSelector] {
        &self.local_selectors
    }

    /// Negotiated remote selectors.
    pub fn remote_selectors(&self) -> &[TrafficSelector] {
        &self.remote_selectors
    }
}

impl std::fmt::Debug for ChildSaHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildSaHandle")
            .field("local_spi", &self.local_spi)
            .field("remote_spi", &self.remote_spi)
            .field("encryption", &self.encryption)
            .field("integrity", &self.integrity)
            .field("mode", &self.mode)
            .field("selectors", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Async IKEv2 client.
pub struct IpsecClient {
    configs: Arc<RwLock<Vec<IpsecConfig>>>,
    events_rx: mpsc::UnboundedReceiver<IpsecEvent>,
    events_tx: mpsc::UnboundedSender<IpsecEvent>,
    states: Arc<Mutex<HashMap<String, IpsecState>>>,
    shutdown: watch::Sender<bool>,
    tasks: HashMap<String, tokio::task::JoinHandle<()>>,
}

impl IpsecClient {
    /// Validate `configs`, open the IKE sockets, and start negotiating.
    pub async fn init(configs: Vec<IpsecConfig>) -> Result<Self, IpsecError> {
        for config in &configs {
            config.validate()?;
        }
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (shutdown, _) = watch::channel(false);
        let states = Arc::new(Mutex::new(HashMap::new()));
        let desired = Arc::new(RwLock::new(configs.clone()));
        let mut client = Self {
            configs: desired,
            events_rx,
            events_tx,
            states,
            shutdown,
            tasks: HashMap::new(),
        };
        for config in configs {
            client.start_connection(config).await?;
        }
        Ok(client)
    }

    /// Wait for the next event.
    pub async fn run(&mut self) -> Result<IpsecEvent, IpsecError> {
        match self.events_rx.recv().await {
            Some(event) => Ok(event),
            None => Err(IpsecError::ike("event stream closed")),
        }
    }

    /// Replace the desired configuration set.
    pub async fn update(
        &mut self,
        configs: Vec<IpsecConfig>,
    ) -> Result<(), IpsecError> {
        for config in &configs {
            config.validate()?;
        }
        let desired: Vec<String> =
            configs.iter().map(|config| config.name.clone()).collect();
        let removed: Vec<String> = self
            .tasks
            .keys()
            .filter(|name| !desired.contains(name))
            .cloned()
            .collect();
        for name in removed {
            if let Some(task) = self.tasks.remove(&name) {
                task.abort();
            }
            self.set_state(&name, IpsecState::Closed).await;
        }

        *self.configs.write().await = configs.clone();
        for config in configs {
            if let Some(task) = self.tasks.remove(&config.name) {
                task.abort();
            }
            self.start_connection(config).await?;
        }
        Ok(())
    }

    /// Stop all IKE activity.  Each engine gets a short grace period to
    /// send Delete notifications before it is aborted.
    pub async fn shutdown(&mut self) {
        let _ = self.shutdown.send(true);
        let tasks = std::mem::take(&mut self.tasks);
        for (name, task) in tasks {
            let mut task = task;
            if tokio::time::timeout(
                std::time::Duration::from_secs(2),
                &mut task,
            )
            .await
            .is_err()
            {
                task.abort();
            }
            self.set_state(&name, IpsecState::Closed).await;
        }
    }

    /// Current state of one connection.
    pub fn state_of(&self, connection: &str) -> Option<IpsecState> {
        self.states
            .try_lock()
            .ok()
            .and_then(|states| states.get(connection).copied())
    }

    async fn start_connection(
        &mut self,
        config: IpsecConfig,
    ) -> Result<(), IpsecError> {
        let name = config.name.clone();
        self.set_state(&name, IpsecState::Connecting).await;
        let task = engine::spawn(
            config,
            self.events_tx.clone(),
            self.states.clone(),
            self.shutdown.subscribe(),
        )
        .await?;
        self.tasks.insert(name, task);
        Ok(())
    }

    async fn set_state(&self, connection: &str, state: IpsecState) {
        self.states
            .lock()
            .await
            .insert(connection.to_string(), state);
        let _ = self.events_tx.send(IpsecEvent::State {
            connection: connection.to_string(),
            state,
        });
    }
}

impl Drop for IpsecClient {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        let tasks = std::mem::take(&mut self.tasks);
        for (_, task) in tasks {
            task.abort();
        }
    }
}

pub(crate) fn error_event(connection: &str, error: IpsecError) -> IpsecEvent {
    IpsecEvent::Error {
        connection: connection.to_string(),
        error: error.with_connection(connection),
    }
}
