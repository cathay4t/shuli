// SPDX-License-Identifier: Apache-2.0

//! WPA client core: one `WifiIface` per wifi-phy, multiplexed by the
//! shared `WifiClient` event dispatcher.
//!
//! The flow is a simple linear walk over [`WifiState`] - Init -> Scanning ->
//! Authenticating -> Connected - driven by repeated calls to
//! [`WifiIface::run`]. There is no internal transition table; events
//! (SAE frames, association results, EAPOL-Key messages) advance the
//! current state directly. Scan specifics live in `scan.rs`,
//! pre-association authentication (SAE today, WPA2/EAP later) in
//! `auth.rs`, and nl80211 details in `nl80211/`.

use std::collections::HashMap;

use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle};
use wl_nl80211::{
    Ieee80211ReasonCode, Ieee80211StatusCode, Nl80211Associate, Nl80211Attr,
    Nl80211AuthType, Nl80211Authenticate, Nl80211Command,
    Nl80211ConnectionHandle, Nl80211ControlPortFrame, Nl80211Event,
    Nl80211Handle, Nl80211Key, Nl80211KeyDefaultType, Nl80211Message,
    Nl80211MulticastGroup, Nl80211Pmksa, Nl80211RekeyOffload,
    Nl80211SchedScanMatch, Nl80211SchedScanMatchAttr, Nl80211SchedScanPlan,
    Nl80211SchedScanPlanAttr, Nl80211UseMfp, Nl80211Wowlan,
    Nl80211WowlanTriggersSupport, Nl80211WowlanWakeup,
};

use crate::{
    ETH_ALEN, ErrorKind, NetworkConfig, WifiError,
    auth::{AuthAction, AuthMethod},
    config::WifiConfig,
    crypto::{
        handshake4::{FourWayState, MicAlg},
        kdf,
        owe::{self, OweAuth},
    },
    eap::{EapAction, EapPacket, EapPeer},
    ieee80211::{auth, eapol, elements},
    nl80211::connect,
    pmksa::{
        PMK_LIFETIME_SECS, PMK_REAUTH_THRESHOLD_PERCENT, PmksaCache,
        PmksaEntry, entry_with_fresh_lifetime,
    },
    scan::{BssInfo, SecurityType, format_ssids},
};

type Nl80211EventMsg = NetlinkMessage<genetlink::message::RawGenlMessage>;
type Nl80211EventSender =
    futures::channel::mpsc::UnboundedSender<Nl80211EventMsg>;
type Nl80211EventReceiver =
    futures::channel::mpsc::UnboundedReceiver<Nl80211EventMsg>;

/// Initial scan-retry backoff (seconds) used while hunting for the
/// configured SSID. Doubles after each failed scan, capped at
/// [`RETRY_BACKOFF_MAX_SEC`].
pub(crate) const RETRY_BACKOFF_INIT_SEC: u64 = 10;
/// Cap (seconds) for the scan-retry backoff; mirrors iwd's
/// `MaximumPeriodicScanInterval` default.
const RETRY_BACKOFF_MAX_SEC: u64 = 300;
/// Interval (seconds) between hardware scheduled scan (PNO) iterations
/// while hunting for the configured SSID. The firmware scans this often
/// while the host sleeps; shuli only wakes on
/// `NL80211_CMD_SCHED_SCAN_RESULTS`.
const SCHED_SCAN_INTERVAL_SEC: u32 = 10;
/// Cap on specific-SSID probes in one scheduled-scan request, matching
/// wpa_supplicant's `WPAS_MAX_SCAN_SSIDS` (16).
const MAX_SCHED_SCAN_SSIDS: usize = 16;
/// Watchdog (seconds) for [`WifiState::SchedScanWait`]: with an SSID
/// match set the firmware only reports on a match, so an absent AP
/// produces no results events at all. If none arrives this long, the
/// scan is re-armed via the host fallback (the firmware may have
/// silently stopped). Longer than the firmware's scan interval, so a
/// match (present AP) always wakes us first.
const SCHED_SCAN_WATCHDOG_SECS: u64 = 60;
/// How long to wait for our own `SCHED_SCAN_STOPPED` echo while
/// rotating a PNO chunk before force-starting the next chunk.
const SCHED_SCAN_STOP_ECHO_TIMEOUT_SECS: u64 = 5;
/// Backoff (seconds) after a fatal authentication failure (wrong
/// password, unknown SAE password identifier, SAE-PK required, ...):
/// retrying is futile, but the wait must stay short enough that the
/// connection recovers without operator intervention when the AP-side
/// state changes. Transient rejections (e.g. status 30) do not use
/// this; they retry on the short `Failed` backoff.
const RETRY_AUTH_SEC: u64 = 120;
/// Max time to wait for the next authentication event (SAE frame, association
/// result, 4-way handshake message) before giving up and retrying.
const AUTH_EVENT_TIMEOUT_SECS: u64 = 15;
/// Interval (seconds) at which the connected state polls the AP's signal
/// when the driver has no kernel connection quality monitor (CQM) support:
/// the fallback to the CQM event-driven roam trigger.
pub(crate) const ROAM_SIGNAL_CHECK_SECS: u64 = 5;
/// SAE retransmission period (seconds): 802.11-2020 §12.4.8.6.2 sets
/// the t0 (retransmission) timer to `dot11RSNASAERetransPeriod`, whose
/// MIB default is 2000 ms (iwd uses the same 2 s). While the SAE
/// commit is in flight, a lost frame - or a rejection with a temporary
/// status (see §12.4.8.6.4) - is answered with a retransmission after
/// this period instead of the full `AUTH_EVENT_TIMEOUT_SECS` + rescan.
const SAE_COMMIT_RETRANSMIT_TIMEOUT_SECS: u64 = 2;
/// maximum SAE Sync counter (commit retransmissions), matching
/// iwd's `SAE_SYNC_MAX` of 3.
const SAE_SYNC_MAX: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WifiState {
    /// Initial state; the next `process()` call triggers a scan.
    #[default]
    Init,
    /// Scan in flight / waiting for results.
    Scanning,
    /// Hardware scheduled scan (PNO) active: the firmware scans
    /// periodically and the host sleeps until the configured SSID shows
    /// up (`NL80211_CMD_SCHED_SCAN_RESULTS`).
    SchedScanWait,
    /// SAE + association + 4-way handshake in progress.
    Authenticating,
    /// Ready for communication, but shuli must stay running to follow up
    /// group rekeys.
    ConnectedWithoutOffloadRekey,
    /// Ready for communication; rekey is offloaded to kernel firmware/driver
    /// and shuli can be terminated.
    ConnectedWithOffloadRekey,
    /// Connection failed; retried after a short delay.
    Failed,
    /// Connection failed during authentication; retried after a long delay.
    FailedAuthentication,
}

pub(crate) struct WifiIface {
    pub(crate) handle: Nl80211Handle,
    pub(crate) conn_handle: Nl80211ConnectionHandle,
    pub(crate) event_receiver: Nl80211EventReceiver,
    pub(crate) state: WifiState,
    /// The most recent connection/auth error attached to a state
    /// change, surfaced once to the caller by `run_multi()` (e.g. a
    /// wrong-password rejection). Cleared when reported.
    pub(crate) last_error: Option<WifiError>,
    /// Current scan-retry backoff in seconds; doubles after each scan
    /// that fails to find the SSID (capped at `RETRY_BACKOFF_MAX_SEC`)
    /// and resets to `RETRY_BACKOFF_INIT_SEC` once the SSID is found or
    /// a connection is established.
    pub(crate) scan_retry_interval: u64,
    /// Whether the driver advertises hardware scheduled scan (PNO)
    /// support.
    pub(crate) sched_scan_supported: bool,
    /// Whether a scheduled scan is currently running in the firmware.
    pub(crate) sched_scan_active: bool,
    /// the WoWLAN triggers the wiphy advertises (e.g.
    /// `GtkRekeyFailure`), as reported by
    /// `NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED`. Empty when the driver
    /// has no WoWLAN support.
    pub(crate) wowlan_supported_triggers: Vec<Nl80211WowlanTriggersSupport>,
    /// whether WoWLAN triggers are currently armed on the device.
    pub(crate) wowlan_armed: bool,
    /// A stop was requested and the kernel's `SCHED_SCAN_STOPPED` echo
    /// has not been consumed yet. The kernel multicasts that event for
    /// every stop - including our own - so this flag lets
    /// [`WifiState::SchedScanWait`] tell our own echo from a genuine
    /// firmware abort.
    pub(crate) sched_scan_stop_pending: bool,
    /// Maximum number of SSIDs the wiphy accepts in one scheduled-scan
    /// request (`NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS`).
    pub(crate) max_sched_scan_ssids: usize,
    /// Maximum number of match sets the wiphy accepts in one scheduled
    /// scan (`NL80211_ATTR_MAX_MATCH_SETS`); 0 means no filtering.
    pub(crate) max_match_sets: usize,
    /// Index of the next hidden SSID for the next PNO chunk
    /// (wpa_supplicant's `prev_sched_ssid`).
    pub(crate) sched_scan_cursor: usize,
    /// Whether the current PNO chunk did not cover every hidden SSID,
    /// so it must be rotated to the next chunk after
    /// `sched_scan_timeout_secs`.
    pub(crate) sched_scan_more: bool,
    /// A stop in flight was requested to rotate to the next PNO chunk.
    pub(crate) sched_scan_rotate: bool,
    /// Current PNO plan interval; doubles as chunks rotate and resets
    /// with the timeout (wpa_supplicant behaviour).
    pub(crate) sched_scan_interval_sec: u32,
    /// How long (seconds) the current PNO chunk runs before rotating.
    pub(crate) sched_scan_timeout_secs: u64,
    /// Whether the next PNO start begins a fresh rotation cycle (and
    /// resets interval/timeout).
    pub(crate) sched_scan_first: bool,
    /// Maximum number of SSIDs the wiphy accepts in one scan request
    /// (`NL80211_ATTR_MAX_NUM_SCAN_SSIDS`). Hidden SSIDs are rotated
    /// through this cap with a wildcard entry reserved, exactly like
    /// wpa_supplicant.
    pub(crate) max_scan_ssids: usize,
    /// Index of the next hidden SSID to probe (wpa_supplicant-style
    /// rotation across scans).
    pub(crate) scan_ssid_cursor: usize,
    /// Drivers accepting only one SSID per scan get wildcard and
    /// specific-SSID scans interleaved (wpa_supplicant's
    /// `prev_scan_wildcard`); true when the next round should be the
    /// wildcard probe.
    pub(crate) scan_wildcard_next: bool,
    pub(crate) if_index: u32,
    pub(crate) mac: [u8; ETH_ALEN],
    pub(crate) config: WifiConfig,
    /// The configured network whose BSS the scan phase selected; carries
    /// the passphrase used for authentication.
    pub(crate) network: NetworkConfig,
    /// Best BSS found by the scan phase.
    pub(crate) bss_info: BssInfo,
    /// Active pre-association authentication method.
    pub(crate) auth: Option<AuthMethod>,
    /// OWE DH exchange state (only for OWE networks).
    pub(crate) owe: Option<OweAuth>,
    /// WPA2-PSK PMK derived via PBKDF2 (only for WPA2-PSK networks).
    pub(crate) psk_pmk: Option<[u8; 32]>,
    /// EAP peer state machine for 802.1X networks
    /// (WPA2-Enterprise / later wired 802.1X).
    pub(crate) eap_peer: Option<EapPeer>,
    /// PMK derived from the EAP MSK after EAP-Success (enterprise).
    pub(crate) eap_pmk: Option<[u8; 32]>,
    /// 4-way handshake state (shared by all auth methods).
    pub(crate) fourway: Option<FourWayState>,
    /// PMKSA cache: reconnects and roams to a cached BSS
    /// skip the full authentication.
    pub(crate) pmksa_cache: PmksaCache,
    /// The PMKSA entry of the connection attempt in flight, when the
    /// association is (to be) done with a cached PMKID.
    pub(crate) pmksa_in_use: Option<PmksaEntry>,
    /// FT key context of the current connection (802.11r roaming).
    pub(crate) ft: Option<crate::roam::FtContext>,
    /// FT roam in flight (target BSS, nonces, derived keys).
    pub(crate) ft_roam: Option<crate::roam::FtRoam>,
    /// The scan in progress was triggered to find roam candidates (not
    /// to connect); its results go through the roam decision instead of
    /// the normal authentication flow.
    pub(crate) roam_scan: bool,
    /// The connected state the client was in when the roam scan started;
    /// restored when the roam scan decides to stay on the current BSS
    /// (otherwise the state machine would fall through into a fresh
    /// authentication to the AP it is already connected to).
    pub(crate) pre_roam_state: Option<WifiState>,
    /// BSSID the next connection attempt should prefer (set before a
    /// roam-induced disconnect steers the retry loop to the target).
    pub(crate) roam_target: Option<[u8; ETH_ALEN]>,
    /// Every BSS matching a configured network from the last scan (with
    /// the matched network) - the roam decision picks among these.
    pub(crate) last_scan_candidates: Vec<(BssInfo, NetworkConfig)>,
    /// Frequencies where the connected ESS (or its BTM neighbor-report
    /// entries) has been seen. The first roam scan of a signal-triggered
    /// episode is restricted to these; only the fallback sweeps all
    /// channels.
    pub(crate) roam_freqs: Vec<u32>,
    /// Whether the current roam episode has already started a full
    /// all-channel scan (quick-scan-first is the normal path; the full
    /// scan runs once per episode as the fallback).
    pub(crate) roam_scan_full: bool,
    /// Dialog token of the 802.11k Neighbor Report Request in flight,
    /// if any. Cleared when the matching response arrives or the wait
    /// times out.
    pub(crate) pending_nr_dialog: Option<u8>,
    /// Number of 802.11k Neighbor Report Responses received and parsed.
    /// Test-observable proof that the active neighbor-report path ran.
    pub(crate) neighbor_report_responses: u64,
    /// A 4-way Message 1 that arrived before the FT context could be
    /// built from the association response event (the two can race).
    pub(crate) pending_ft_msg1: Option<Vec<u8>>,
    /// When the last roam finished: signal-triggered roaming pauses for
    /// `ROAM_COOLDOWN_SECS` afterwards so equal-signal BSSes do not
    /// ping-pong the client.
    pub(crate) last_roam: Option<std::time::Instant>,
    /// Whether the kernel connection quality monitor (CQM) is armed with
    /// the roam threshold; when true the connected state waits for
    /// `NL80211_CMD_NOTIFY_CQM` events instead of polling the signal.
    pub(crate) cqm_armed: bool,
    /// Whether the scan in flight was started by the low-frequency
    /// proactive background scan: only a strictly stronger BSS qualifies
    /// for a same-ESS roam (an equal-signal one would ping-pong on every
    /// scan interval), whereas a signal-degraded roam (CQM / poll)
    /// accepts an equal-signal peer. The background scan may also switch
    /// to a different configured SSID when the current link is critical.
    pub(crate) background_scan: bool,
    /// Number of roam scans whose candidate dump was collected. Used by
    /// the integration tests to observe scans that `run()` now keeps
    /// internal (no `Scanning` state is surfaced when the scan stays).
    pub(crate) roam_scan_count: u64,
    /// SAE commit retransmission state. `sae_commit_sent` is true
    /// while we await the AP's commit; on a timeout the same commit is
    /// re-sent (the 802.11 SAE Sync counter, max 3) instead of paying a
    /// full rescan cycle for one lost frame.
    pub(crate) sae_commit_sent: bool,
    /// SAE Sync counter: number of commit retransmissions so far.
    pub(crate) sae_sync: u8,
    /// The last SAE commit auth_data, re-sent verbatim on a timeout.
    pub(crate) sae_commit_auth_data: Vec<u8>,
    /// an H2E commit was rejected and the exchange restarted with
    /// hunting-and-pecking (never retried a second time).
    pub(crate) sae_hnp_attempted: bool,
}

/// One state change reported by [`WifiClient::run_multi`].
///
/// `error` is set when the interface's state machine hit an error; the
/// client keeps running and will retry. Authentication failures such as
/// a wrong password are reported here with the exact `WifiError` (for
/// example `ErrorKind::WrongPassword`).
#[derive(Debug)]
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
            iface_tx_by_if_index.insert(iface.if_index, event_tx);
            ifaces.insert(iface.config.iface_name.clone(), iface);
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

impl WifiIface {
    /// Validate the configuration and prepare one interface state machine.
    /// The nl80211 connection is shared with every other interface in the
    /// parent [`WifiClient`].
    pub(crate) async fn init(
        handle: Nl80211Handle,
        mut conn_handle: Nl80211ConnectionHandle,
        event_receiver: Nl80211EventReceiver,
        config: WifiConfig,
    ) -> Result<Self, WifiError> {
        let (if_index, mac, wiphy_idx) =
            get_if_index_and_mac(&handle, &config.iface_name).await?;

        log::info!(
            "interface {} if_index={}, mac={mac:02x?}, wiphy={wiphy_idx}",
            config.iface_name,
            if_index
        );

        // Detect hardware scheduled scan (PNO) support and its caps
        // once: when available, the firmware keeps scanning while the
        // host sleeps. The caps bound each PNO chunk, which shuli
        // rotates through like wpa_supplicant.
        let (sched_scan_supported, max_sched_scan_ssids, max_match_sets) =
            match wiphy_sched_scan_caps(&handle, wiphy_idx).await {
                Ok(caps) => {
                    if caps.supported {
                        log::info!(
                            "wiphy {wiphy_idx} supports scheduled scan (PNO): \
                             max_ssids={}, max_match_sets={}",
                            caps.max_ssids,
                            caps.max_match_sets
                        );
                    } else {
                        log::info!(
                            "wiphy {wiphy_idx} has no scheduled scan support; \
                             using host-side scan backoff"
                        );
                    }
                    (caps.supported, caps.max_ssids, caps.max_match_sets)
                }
                Err(e) => {
                    log::debug!("could not query sched scan support: {e}");
                    (false, 0, 0)
                }
            };

        // Query the per-scan SSID cap once. Hidden networks are rotated
        // through it (wpa_supplicant reserves one slot for the wildcard
        // entry); when the kernel advertises no cap, fall back to
        // wildcard-only scans so a request can never be rejected for
        // asking the driver to probe too many SSIDs.
        let max_scan_ssids =
            match wiphy_max_scan_ssids(&handle, wiphy_idx).await {
                Ok(n) if n > 0 => n as usize,
                Ok(_) => {
                    log::debug!(
                        "wiphy {wiphy_idx} advertises no per-scan SSID cap; \
                         using wildcard-only scans"
                    );
                    1
                }
                Err(e) => {
                    log::debug!(
                        "could not query max scan SSIDs: {e}; using \
                         wildcard-only scans"
                    );
                    1
                }
            };

        // detect WoWLAN trigger support once, so arming a
        // `wowlan: true` network is a no-op (and clearly logged) on
        // drivers without it.
        let wowlan_supported_triggers =
            match wiphy_wowlan_support(&handle, wiphy_idx).await {
                Ok(triggers) if !triggers.is_empty() => {
                    log::info!(
                        "wiphy {wiphy_idx} supports WoWLAN: {triggers:?}"
                    );
                    triggers
                }
                Ok(_) => {
                    log::info!(
                        "wiphy {wiphy_idx} has no WoWLAN trigger support; \
                         triggers will not be armed"
                    );
                    Vec::new()
                }
                Err(e) => {
                    log::debug!("could not query WoWLAN support: {e}");
                    Vec::new()
                }
            };

        // clear any WoWLAN triggers a previous (possibly crashed)
        // run left armed. The daemon arms them again right before the
        // next suspend; a leftover configuration would keep the device
        // in WoWLAN mode with nobody handling the wake.
        if !wowlan_supported_triggers.is_empty() {
            let attrs =
                Nl80211Wowlan::new(if_index).triggers(Vec::new()).build();
            match drain_request(conn_handle.set_wowlan(attrs).execute().await)
                .await
            {
                Ok(()) => log::info!(
                    "cleared stale WoWLAN triggers from a previous run"
                ),
                Err(e) => {
                    log::debug!("clear stale WoWLAN triggers failed: {e}")
                }
            }
        }

        let network = config.networks.first().cloned().ok_or_else(|| {
            WifiError::new(
                ErrorKind::InvalidConfig,
                "WifiConfig: no networks configured",
            )
        })?;

        let mut client = WifiIface {
            handle,
            conn_handle,
            event_receiver,
            state: WifiState::Init,
            last_error: None,
            scan_retry_interval: RETRY_BACKOFF_INIT_SEC,
            sched_scan_supported,
            sched_scan_active: false,
            sched_scan_stop_pending: false,
            max_sched_scan_ssids,
            max_match_sets,
            sched_scan_cursor: 0,
            sched_scan_more: false,
            sched_scan_rotate: false,
            sched_scan_interval_sec: SCHED_SCAN_INTERVAL_SEC,
            sched_scan_timeout_secs: SCHED_SCAN_WATCHDOG_SECS,
            sched_scan_first: true,
            max_scan_ssids,
            scan_ssid_cursor: 0,
            scan_wildcard_next: true,
            wowlan_supported_triggers,
            wowlan_armed: false,
            if_index,
            mac,
            config,
            network,
            bss_info: BssInfo::default(),
            auth: None,
            owe: None,
            psk_pmk: None,
            eap_peer: None,
            eap_pmk: None,
            fourway: None,
            pmksa_cache: PmksaCache::default(),
            pmksa_in_use: None,
            ft: None,
            ft_roam: None,
            roam_scan: false,
            pre_roam_state: None,
            roam_target: None,
            last_scan_candidates: Vec::new(),
            roam_freqs: Vec::new(),
            roam_scan_full: false,
            pending_nr_dialog: None,
            neighbor_report_responses: 0,
            pending_ft_msg1: None,
            last_roam: None,
            cqm_armed: false,
            background_scan: false,
            roam_scan_count: 0,
            sae_commit_sent: false,
            sae_sync: 0,
            sae_commit_auth_data: Vec::new(),
            sae_hnp_attempted: false,
        };

        // Receive WNM action frames (BTM Requests) for roaming.
        client.register_roam_frames().await;

        Ok(client)
    }

    /// Drive the connection flow until a state change worth reporting
    /// happens and return it.  On transient errors the client falls back
    /// to a retry state instead of failing hard.
    ///
    /// Roam scans started from the connected state (CQM event or the
    /// low-frequency background safety net) are internal housekeeping:
    /// when they find no better BSS the client stays connected, so
    /// [`WifiIface::run`] keeps driving without surfacing the
    /// `Connected -> Scanning -> Connected` round trip to the caller.
    pub async fn run(&mut self) -> Result<WifiState, WifiError> {
        // The state to which an in-flight roam scan will return. A scan
        // that decides to stay is invisible to callers, so remember the
        // connected state (or the pre-scan state when this call starts
        // mid-scan) and suppress every transition back to it.
        let baseline = if self.state == WifiState::Scanning {
            self.pre_roam_state.unwrap_or(self.state)
        } else {
            self.state
        };
        loop {
            let prev_state = self.state;
            if let Err(e) = self._run().await {
                log::warn!("WPA process error: {e}");
                self.last_error = None;
                self.state = if self.state == WifiState::Authenticating {
                    WifiState::FailedAuthentication
                } else {
                    WifiState::Failed
                };
                return Err(e);
            }
            let roaming_scan = self.state == WifiState::Scanning
                && self.pre_roam_state.is_some();
            if self.state != prev_state
                && self.state != baseline
                && !roaming_scan
            {
                return Ok(self.state);
            }
        }
    }

    /// Move into [`WifiState::FailedAuthentication`] and record the
    /// error for the caller.
    fn fail_auth(&mut self, error: WifiError) {
        self.last_error = Some(error);
        self.state = WifiState::FailedAuthentication;
    }

    async fn _run(&mut self) -> Result<(), WifiError> {
        // With no configured networks the client idles: never start a
        // scan with an empty SSID list. Sleep instead of busy-looping so
        // a multi-interface `WifiClient` can keep an empty interface
        // without spinning the runtime.
        if self.config.networks.is_empty() {
            self.state = WifiState::Init;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            return Ok(());
        }
        match self.state {
            WifiState::Init => {
                self.send_out_scan_request().await?;
                self.state = WifiState::Scanning;
            }
            WifiState::Scanning => {
                self.wait_scan_finish().await;
                if self.state != WifiState::Scanning {
                    // An event observed while the scan was running (e.g. a
                    // disconnect during a roam scan) advanced the state
                    // machine; honor it instead of running the scan-results
                    // flow on top.
                    return Ok(());
                }
                if self.roam_scan {
                    // Roam scan: evaluate candidates while staying on the
                    // current BSS.
                    self.roam_scan = false;
                    self.process_roam_scan_results().await;
                    // The roam scan fell back to a full scan and it is
                    // already in flight: keep Scanning (and the recorded
                    // pre-roam state) for the next iteration.
                    if self.roam_scan {
                        return Ok(());
                    }
                    // When the roam scan stays on the current BSS (or
                    // failed to gather candidates), restore the connected
                    // state recorded before the scan. Otherwise the next
                    // `run()` iteration would treat the scan results as a
                    // fresh connection attempt and re-authenticate to the
                    // AP the client is already connected to, which the
                    // kernel rejects with -EALREADY.
                    if self.state == WifiState::Scanning
                        && let Some(prev) = self.pre_roam_state.take()
                    {
                        self.state = prev;
                    }
                    self.pre_roam_state = None;
                    return Ok(());
                }
                if let Err(e) = self.process_scan_results().await {
                    // SSID not found: hand the periodic scanning over to
                    // the firmware (PNO) when supported, otherwise fall
                    // back to host-side scans with exponential backoff.
                    if e.kind == ErrorKind::SsidNotFound {
                        // A fresh PNO session starts from the first
                        // hidden SSID with reset rotation timing
                        // (wpa_supplicant resets `prev_sched_ssid`).
                        self.sched_scan_cursor = 0;
                        self.sched_scan_more = false;
                        self.sched_scan_rotate = false;
                        self.sched_scan_first = true;
                        if self.start_sched_scan().await? {
                            log::info!(
                                "no configured SSID ([{}]) found; entering \
                                 scheduled scan mode",
                                self.config
                                    .ssids()
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            );
                            self.state = WifiState::SchedScanWait;
                            return Ok(());
                        }
                    }
                    return Err(e);
                }
                // SSID found - reset the scan-retry backoff.
                self.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
                self.send_out_auth_request().await?;
                self.state = WifiState::Authenticating;
            }
            WifiState::SchedScanWait => {
                // The firmware scans on the configured interval while the
                // host sleeps here; only sched-scan events wake us. The
                // watchdog catches a firmware that silently stopped, and
                // a shorter chunk timeout rotates to the next SSID chunk
                // when more hidden SSIDs are configured than fit in one
                // PNO request (wpa_supplicant behaviour).
                let wait_secs = if self.sched_scan_stop_pending {
                    SCHED_SCAN_STOP_ECHO_TIMEOUT_SECS
                } else if self.sched_scan_more {
                    self.sched_scan_timeout_secs
                } else {
                    SCHED_SCAN_WATCHDOG_SECS
                };
                let timed = tokio::time::timeout(
                    std::time::Duration::from_secs(wait_secs),
                    self.event_receiver.next(),
                )
                .await;
                match timed {
                    Ok(Some(raw_msg)) => {
                        if let Some(event) =
                            wl_nl80211::Nl80211Event::parse(raw_msg)
                        {
                            match event {
                                Nl80211Event::Unknown {
                                    cmd: Nl80211Command::SchedScanResults,
                                } => {
                                    self.handle_sched_scan_results().await?;
                                }
                                Nl80211Event::Unknown {
                                    cmd: Nl80211Command::SchedScanStopped,
                                } => {
                                    if self.sched_scan_stop_pending {
                                        // Echo of our own stop request
                                        // (rotation or watchdog fallback);
                                        // the firmware scan is gone.
                                        self.sched_scan_stop_pending = false;
                                        if self.sched_scan_rotate {
                                            self.sched_scan_rotate = false;
                                            log::info!(
                                                "rotating scheduled scan to \
                                                 the next SSID chunk"
                                            );
                                            if !self.start_sched_scan().await? {
                                                self.state = WifiState::Failed;
                                            }
                                        }
                                    } else {
                                        // The kernel/firmware aborted the
                                        // scan on its own (e.g. regulatory
                                        // change); restart it or fall back
                                        // to host-side backoff.
                                        log::warn!(
                                            "scheduled scan stopped by \
                                             kernel; restarting"
                                        );
                                        self.sched_scan_active = false;
                                        if !self.start_sched_scan().await? {
                                            self.state = WifiState::Failed;
                                        }
                                    }
                                }
                                other => self.handle_event(other).await,
                            }
                        }
                    }
                    Ok(None) => {
                        return Err(WifiError::new(
                            ErrorKind::Nl80211,
                            "event channel closed",
                        ));
                    }
                    Err(_) => {
                        if self.sched_scan_stop_pending {
                            // The stop echo was lost; force the rotation
                            // (or restart) that was in flight.
                            self.sched_scan_stop_pending = false;
                            if self.sched_scan_rotate {
                                self.sched_scan_rotate = false;
                                log::info!(
                                    "scheduled scan stop echo lost; rotating \
                                     to the next SSID chunk"
                                );
                                if !self.start_sched_scan().await? {
                                    self.state = WifiState::Failed;
                                }
                            }
                        } else if self.sched_scan_more {
                            // This chunk ran long enough: stop it and let
                            // the STOPPED echo start the next chunk.
                            log::info!(
                                "scheduled scan chunk timed out after {}s; \
                                 rotating to the next SSID chunk",
                                self.sched_scan_timeout_secs
                            );
                            self.sched_scan_rotate = true;
                            self.stop_sched_scan().await?;
                        } else {
                            log::warn!(
                                "no scheduled scan results for {}s; falling \
                                 back to host scans",
                                SCHED_SCAN_WATCHDOG_SECS
                            );
                            self.state = WifiState::Failed;
                        }
                    }
                }
            }
            WifiState::Authenticating => {
                // Wait for the next authentication event. While the SAE
                // commit is in flight a timeout means the frame was
                // lost: re-send the same commit (SAE Sync counter, max 3)
                // instead of failing over to a full rescan cycle.
                loop {
                    let wait_secs = if self.sae_commit_sent
                        && self.sae_sync < SAE_SYNC_MAX
                    {
                        SAE_COMMIT_RETRANSMIT_TIMEOUT_SECS
                    } else {
                        AUTH_EVENT_TIMEOUT_SECS
                    };
                    let timed = tokio::time::timeout(
                        std::time::Duration::from_secs(wait_secs),
                        self.event_receiver.next(),
                    )
                    .await;
                    match timed {
                        Ok(Some(raw_msg)) => {
                            if let Some(event) =
                                wl_nl80211::Nl80211Event::parse(raw_msg)
                            {
                                self.handle_event(event).await;
                            }
                            break;
                        }
                        Ok(None) => {
                            return Err(WifiError::new(
                                ErrorKind::Nl80211,
                                "event channel closed",
                            ));
                        }
                        Err(_) => {
                            if self.sae_commit_sent
                                && self.sae_sync < SAE_SYNC_MAX
                            {
                                // retransmit the pending SAE commit.
                                self.sae_sync += 1;
                                log::info!(
                                    "SAE commit timed out - retransmitting \
                                     (sync {}/{})",
                                    self.sae_sync,
                                    SAE_SYNC_MAX
                                );
                                self.send_sae_commit(
                                    &self.sae_commit_auth_data.clone(),
                                )
                                .await;
                                continue;
                            }
                            // Some APs silently drop the H2E commit
                            // instead of answering with a rejection
                            // status.  Retry once with
                            // hunting-and-pecking before giving up.
                            if let Some(AuthMethod::Sae(sae)) =
                                self.auth.as_ref()
                                && sae.is_h2e()
                                && sae.hnp_fallback_allowed()
                                && !self.sae_hnp_attempted
                            {
                                log::info!(
                                    "SAE commit timed out with no AP \
                                     response; retrying with \
                                     hunting-and-pecking"
                                );
                                self.restart_sae_with_hnp().await;
                                continue;
                            }
                            if self.is_psk_4way_in_progress()
                                && self.fourway.is_some()
                            {
                                let err = WifiError::wrong_password(
                                    &self.network.ssid,
                                );
                                log::warn!(
                                    "WPA2-PSK 4-way handshake timed out; \
                                     treating as wrong password"
                                );
                                self.fail_auth(err);
                                break;
                            }
                            log::warn!("authentication timed out; will retry");
                            self.state = WifiState::Failed;
                            break;
                        }
                    }
                }
            }
            WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey => {
                // Keep draining events so group rekeys, disconnects and
                // BTM Requests are handled while the connection stays up.
                // Signal-triggered roaming runs only against an AP that
                // advertises a managed-roaming capability (802.11v BSS
                // Transition / 802.11k Neighbor Report): for such APs the
                // kernel CQM reports `NL80211_CMD_NOTIFY_CQM` events when
                // the beacon signal drops below the roam threshold (a
                // stable, beacon-only measurement - not the last-frame
                // station signal that dips under power save). A
                // low-frequency background scan is kept as a fallback
                // safety net for cases CQM cannot catch. Drivers without
                // CQM support fall back to polling the signal. Neither
                // runs for an AP that does not advertise a managed-roaming
                // capability (the wait is unbounded).
                let ap_roams = self.network.roaming
                    && self.bss_info.ap_supports_signal_roam();
                if !self.cqm_armed && ap_roams {
                    self.cqm_armed = self.arm_cqm().await;
                }
                let wait_secs = if ap_roams {
                    if self.cqm_armed {
                        crate::roam::BACKGROUND_SCAN_SECS
                    } else {
                        ROAM_SIGNAL_CHECK_SECS
                    }
                } else {
                    0
                };
                let next = if wait_secs > 0 {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(wait_secs),
                        self.event_receiver.next(),
                    )
                    .await
                } else {
                    Ok(self.event_receiver.next().await)
                };
                match next {
                    Ok(Some(raw_msg)) => {
                        if let Some(event) =
                            wl_nl80211::Nl80211Event::parse(raw_msg)
                        {
                            self.handle_event(event).await;
                        }
                    }
                    Ok(None) => {
                        return Err(WifiError::new(
                            ErrorKind::Nl80211,
                            "event channel closed",
                        ));
                    }
                    // Roam engine tick: the low-frequency background scan
                    // (CQM armed) or, without CQM support, the signal poll.
                    Err(_) => {
                        if self.cqm_armed {
                            self.check_background_roam().await;
                        } else {
                            self.check_roam_conditions().await;
                        }
                    }
                }
            }
            WifiState::Failed | WifiState::FailedAuthentication => {
                // Ensure no firmware scheduled scan keeps running when we
                // leave scan-wait mode (e.g. after an error).
                if self.sched_scan_active {
                    let _ = self.stop_sched_scan().await;
                }
                let secs = if self.state == WifiState::FailedAuthentication {
                    RETRY_AUTH_SEC
                } else {
                    self.scan_retry_interval
                };
                log::info!("{:?}; retrying in {} seconds", self.state, secs);
                // Pump events instead of sleeping blindly: the kernel
                // delivers MLME notifications with considerable lag
                // (AP deauth/disassoc and the reply to our own
                // CMD_DISCONNECT can trail seconds behind). Consuming
                // them here, before the next attempt starts, is what
                // keeps the reconnect flow from tripping over stale
                // events.
                let deadline = tokio::time::Instant::now()
                    + std::time::Duration::from_secs(secs);
                loop {
                    let remaining = deadline
                        .saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match tokio::time::timeout(
                        remaining,
                        self.event_receiver.next(),
                    )
                    .await
                    {
                        Ok(Some(raw_msg)) => {
                            if let Some(event) =
                                wl_nl80211::Nl80211Event::parse(raw_msg)
                            {
                                self.handle_event(event).await;
                            }
                            if !matches!(
                                self.state,
                                WifiState::Failed
                                    | WifiState::FailedAuthentication
                            ) {
                                // An event advanced the state machine
                                // (e.g. a scheduled-scan result); honour
                                // it instead of running the retry path.
                                return Ok(());
                            }
                        }
                        Ok(None) => {
                            return Err(WifiError::new(
                                ErrorKind::Nl80211,
                                "event channel closed",
                            ));
                        }
                        Err(_) => break, // backoff elapsed
                    }
                }
                if self.state == WifiState::Failed {
                    // Exponential backoff: 10 -> 20 -> 40 -> ... -> 300.
                    self.scan_retry_interval = (self.scan_retry_interval * 2)
                        .min(RETRY_BACKOFF_MAX_SEC);
                }
                self.state = WifiState::Init;
            }
        }
        Ok(())
    }

    /// Hand the periodic scanning over to the firmware (PNO): ask it to
    /// scan for a chunk of the configured SSIDs on a fixed interval
    /// while the host sleeps. Like wpa_supplicant, the chunk reserves
    /// one slot for the wildcard probe when visible networks exist and
    /// rotates through hidden SSIDs within the driver's
    /// `max_sched_scan_ssids` cap. Returns true when a scheduled scan
    /// is now running.
    async fn start_sched_scan(&mut self) -> Result<bool, WifiError> {
        if !self.sched_scan_supported {
            return Ok(false);
        }
        let cap = self.max_sched_scan_ssids.min(MAX_SCHED_SCAN_SSIDS);
        if cap == 0 {
            return Ok(false);
        }

        let hidden_ssids: Vec<String> =
            self.config.hidden_ssids().map(str::to_string).collect();
        let wildcard = self.config.networks.iter().any(|n| !n.hidden);
        let specific_cap = cap - if wildcard { 1 } else { 0 };
        if !hidden_ssids.is_empty() && specific_cap == 0 {
            // A one-SSID PNO driver cannot probe hidden networks while
            // reserving the wildcard slot; fall back to host scans.
            log::debug!(
                "sched scan cap {cap} leaves no slot for hidden SSIDs; using \
                 host scan backoff"
            );
            return Ok(false);
        }

        // Fresh rotation cycle: reset interval and chunk timeout
        // (wpa_supplicant starts with `max_sched_scan_ssids * 2`).
        if self.sched_scan_first {
            self.sched_scan_interval_sec = SCHED_SCAN_INTERVAL_SEC;
            self.sched_scan_timeout_secs = (cap as u64) * 2;
            self.sched_scan_first = false;
        }

        let (ssids, more) = next_sched_scan_ssids(
            &hidden_ssids,
            wildcard,
            &mut self.sched_scan_cursor,
            cap,
        );
        self.sched_scan_more = more;

        // Match sets wake the host only for configured SSIDs; when more
        // are configured than the driver can filter, drop the filter
        // entirely (wpa_supplicant does the same) so every scan result
        // is reported instead of silently missing networks.
        let match_sets = if self.max_match_sets > 0
            && self.config.networks.len() <= self.max_match_sets
        {
            Some(
                self.config
                    .networks
                    .iter()
                    .map(|network| {
                        Nl80211SchedScanMatch(vec![
                            Nl80211SchedScanMatchAttr::Ssid(
                                network.ssid.clone(),
                            ),
                        ])
                    })
                    .collect(),
            )
        } else {
            None
        };

        let mut attrs = vec![
            Nl80211Attr::IfIndex(self.if_index),
            // Active probe for this chunk's hidden SSIDs plus the
            // wildcard entry for visible networks...
            Nl80211Attr::ScanSsids(ssids.clone()),
            Nl80211Attr::SchedScanPlans(vec![Nl80211SchedScanPlan(vec![
                Nl80211SchedScanPlanAttr::Interval(
                    self.sched_scan_interval_sec,
                ),
            ])]),
            // Tie the scan to this socket so the kernel stops it if shuli
            // dies without a chance to clean up.
            Nl80211Attr::SocketOwner,
        ];
        if let Some(match_sets) = match_sets {
            attrs.insert(2, Nl80211Attr::SchedScanMatch(match_sets));
        }

        // Drive the request manually so a permanent "not supported"
        // (-EOPNOTSUPP) can be told apart from transient failures; the
        // errno is lost once the error is converted into `WifiError`.
        let mut stream =
            self.handle.scan().schedule_start(attrs).execute().await;
        let result = loop {
            match stream.try_next().await {
                Ok(Some(_)) => {}
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        match result {
            Ok(()) => {
                self.sched_scan_active = true;
                log::info!(
                    "scheduled scan started: ssids=[{}], interval={}s, \
                     chunk_timeout={}s{}",
                    format_ssids(&ssids),
                    self.sched_scan_interval_sec,
                    self.sched_scan_timeout_secs,
                    if more { ", more SSIDs pending" } else { "" }
                );
                if more {
                    // Throttle the rotation like wpa_supplicant: each
                    // subsequent chunk runs for a shorter timeout with a
                    // longer scan interval, resetting when the interval
                    // grows too large.
                    self.sched_scan_timeout_secs =
                        (self.sched_scan_timeout_secs / 2).max(2);
                    self.sched_scan_interval_sec =
                        (self.sched_scan_interval_sec * 2)
                            .min(RETRY_BACKOFF_MAX_SEC as u32);
                    if self.sched_scan_timeout_secs
                        < self.sched_scan_interval_sec as u64
                    {
                        self.sched_scan_interval_sec = SCHED_SCAN_INTERVAL_SEC;
                        self.sched_scan_timeout_secs = (cap as u64) * 2;
                    }
                } else {
                    // Full coverage in one chunk: the next start begins a
                    // fresh cycle with reset timing.
                    self.sched_scan_first = true;
                }
                Ok(true)
            }
            Err(e) => {
                if is_eopnotsupp(&e) {
                    // Driver has no sched_scan_start op: fall back to
                    // host-side scans with exponential backoff for good.
                    log::debug!(
                        "scheduled scan unsupported; using host scan backoff: \
                         {e}"
                    );
                    self.sched_scan_supported = false;
                } else {
                    // Transient failure (e.g. -EBUSY): keep PNO enabled
                    // and retry on the next scan cycle.
                    log::debug!("scheduled scan start failed: {e}");
                }
                Ok(false)
            }
        }
    }

    /// Stop the firmware scheduled scan. Best-effort: failures are only
    /// logged since a lingering scan is not fatal.
    async fn stop_sched_scan(&mut self) -> Result<(), WifiError> {
        if !self.sched_scan_active {
            return Ok(());
        }
        self.sched_scan_active = false;
        self.sched_scan_stop_pending = true;
        match drain_request(
            self.handle
                .scan()
                .schedule_stop_all(self.if_index)
                .execute()
                .await,
        )
        .await
        {
            Ok(()) => {
                log::info!("scheduled scan stopped");
                Ok(())
            }
            Err(e) => {
                log::debug!("stop scheduled scan failed: {e}");
                Ok(())
            }
        }
    }

    /// A `NL80211_CMD_SCHED_SCAN_RESULTS` event arrived: dump the
    /// firmware's results and check whether the configured SSID is there.
    async fn handle_sched_scan_results(&mut self) -> Result<(), WifiError> {
        log::debug!("scheduled scan results event");
        match self.process_scan_results().await {
            Ok(()) => {
                // SSID found - stop the firmware scan and connect.
                self.sched_scan_rotate = false;
                self.stop_sched_scan().await?;
                self.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
                self.send_out_auth_request().await?;
                self.state = WifiState::Authenticating;
                Ok(())
            }
            Err(e) if e.kind == ErrorKind::SsidNotFound => {
                // No match in this round; the firmware keeps scanning and
                // wakes us again with the next results event.
                log::debug!("SSID not in scheduled scan results; continuing");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn handle_event(&mut self, event: Nl80211Event) {
        match event {
            Nl80211Event::Frame { frame } => {
                // Registered management frames reach us here: SAE auth
                // frames during authentication, and WNM action frames
                // (BTM Requests) while connected.
                if frame.len() > 24
                    && frame[24] == crate::ieee80211::wnm::WNM_ACTION_CATEGORY
                {
                    self.handle_wnm_frame(&frame).await;
                } else if frame.len() > 24
                    && frame[24] == crate::ieee80211::rrm::RRM_ACTION_CATEGORY
                {
                    self.handle_rrm_frame(&frame).await;
                } else {
                    self.handle_auth_frame(&frame).await;
                }
            }

            Nl80211Event::Authenticated { status, frame } => {
                if self.ft_roam.is_some() {
                    // FT roam: the target AP's FT Authentication response
                    // (transaction 2).
                    self.handle_ft_auth_response(
                        frame.as_deref().unwrap_or(&[]),
                    )
                    .await;
                } else if self.pmksa_in_use.is_some() {
                    // PMKSA caching: the open-system authentication
                    // already succeeded; associate with the cached PMKID in
                    // the RSNE. An AP without the matching PMKSA rejects
                    // the association, which triggers the full-auth
                    // fallback.
                    if status == Ieee80211StatusCode::Success {
                        self.associate_with_pmksa().await;
                    } else {
                        log::warn!(
                            "AUTHENTICATE failed (cached PMKSA): \
                             status={status}"
                        );
                        self.pmksa_fallback().await;
                    }
                } else if !matches!(
                    self.bss_info.security,
                    SecurityType::Sae | SecurityType::FtSae
                ) {
                    // Open-system auth (open + OWE): no frame, just
                    // a status.
                    if status == Ieee80211StatusCode::Success {
                        if self.bss_info.security == SecurityType::Owe {
                            // OWE: associate with DH element.
                            let owe_auth = OweAuth::new();
                            let dh_elem = owe_auth.build_dh_element();
                            self.owe = Some(owe_auth);
                            log::info!(
                                "open-system AUTHENTICATE ok - sending OWE \
                                 ASSOCIATE"
                            );
                            let mut ie_buf = elements::owe_ie_cipher(
                                self.bss_info.group_mgmt_cipher,
                            );
                            ie_buf.extend_from_slice(&dh_elem);
                            log::debug!("associate OWE IE: {ie_buf:02x?}");
                            if let Err(e) = self
                                .associate(
                                    ie_buf,
                                    Some(Nl80211UseMfp::Required),
                                )
                                .await
                            {
                                log::warn!("OWE ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else if self.bss_info.security
                            == SecurityType::Wpa2Psk
                        {
                            // WPA2-PSK: associate with PSK RSNE. PMF is
                            // negotiated as optional (MFPC in the RSNE);
                            // when the AP supports it, request MFP - the
                            // kernel's ASSOCIATE command only takes
                            // REQUIRED or none.
                            log::info!(
                                "open-system AUTHENTICATE ok - sending \
                                 WPA2-PSK ASSOCIATE"
                            );
                            let mfp = self
                                .bss_info
                                .ap_mfp_capable()
                                .then_some(Nl80211UseMfp::Required);
                            if let Err(e) = self
                                .associate(
                                    elements::wpa2_psk_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    mfp,
                                )
                                .await
                            {
                                log::warn!("ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else if self.bss_info.security
                            == SecurityType::Wpa2PskSha256
                        {
                            // WPA2-PSK-SHA256 (AKM 6): same association
                            // shape as WPA2-PSK, different RSNE.
                            log::info!(
                                "open-system AUTHENTICATE ok - sending \
                                 WPA2-PSK-SHA256 ASSOCIATE"
                            );
                            let mfp = self
                                .bss_info
                                .ap_mfp_capable()
                                .then_some(Nl80211UseMfp::Required);
                            if let Err(e) = self
                                .associate(
                                    elements::wpa2_psk_sha256_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    mfp,
                                )
                                .await
                            {
                                log::warn!("ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else if self.bss_info.security
                            == SecurityType::Wpa2Ent
                        {
                            // WPA2-Enterprise (AKM 1): open-system
                            // auth, associate, then run EAP over the
                            // control port.
                            log::info!(
                                "open-system AUTHENTICATE ok - sending \
                                 WPA2-Enterprise ASSOCIATE"
                            );
                            let mfp = self
                                .bss_info
                                .ap_mfp_capable()
                                .then_some(Nl80211UseMfp::Required);
                            if let Err(e) = self
                                .associate(
                                    elements::wpa2_ent_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    mfp,
                                )
                                .await
                            {
                                log::warn!("ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else if self.bss_info.security
                            == SecurityType::Wpa2EntSha256
                        {
                            log::info!(
                                "open-system AUTHENTICATE ok - sending \
                                 WPA3-Enterprise ASSOCIATE"
                            );
                            // WPA3-Enterprise baseline: PMF is
                            // mandatory for the SHA-256 AKM.
                            let mfp = Some(Nl80211UseMfp::Required);
                            if let Err(e) = self
                                .associate(
                                    elements::wpa2_ent_sha256_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    mfp,
                                )
                                .await
                            {
                                log::warn!("ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else if self.bss_info.security == SecurityType::FtPsk
                        {
                            // FT-PSK: open-system auth, then associate
                            // with the FT-PSK RSNE and the MDIE.
                            log::info!(
                                "open-system AUTHENTICATE ok - sending FT-PSK \
                                 ASSOCIATE"
                            );
                            let mut ies = elements::ft_psk_ie_cipher(
                                None,
                                self.bss_info.group_mgmt_cipher,
                            );
                            if let Err(e) = self.append_ft_mdie(&mut ies) {
                                log::warn!("FT-PSK ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                                return;
                            }
                            let mfp = self
                                .bss_info
                                .ap_mfp_capable()
                                .then_some(Nl80211UseMfp::Required);
                            if let Err(e) = self.associate(ies, mfp).await {
                                log::warn!("FT-PSK ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else {
                            // Plain open: associate without DH.
                            log::info!(
                                "open-system AUTHENTICATE ok - sending \
                                 ASSOCIATE"
                            );
                            if let Err(e) =
                                self.associate(Vec::new(), None).await
                            {
                                log::warn!("ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        }
                    } else {
                        log::warn!(
                            "open-system AUTHENTICATE failed: status={status}"
                        );
                        self.state = WifiState::Failed;
                    }
                } else if let Some(frame) = frame {
                    // SAE: the auth frame carries the AP's commit
                    // (transaction 1) or confirm (transaction 2).
                    self.handle_auth_frame(&frame).await;
                } else if status != Ieee80211StatusCode::Success {
                    log::warn!("AUTHENTICATE failed: status={status}");
                    let err = if status == Ieee80211StatusCode::ChallengeFail {
                        WifiError::new(
                            ErrorKind::WrongPassword,
                            "wrong password (SAE confirm rejected by AP)",
                        )
                    } else {
                        WifiError::new(
                            ErrorKind::AuthFailed,
                            format!(
                                "SAE authentication failed: status={status}"
                            ),
                        )
                    };
                    self.fail_auth(err);
                } else {
                    log::debug!("AUTHENTICATE event without frame (status=0)");
                }
            }

            Nl80211Event::Associated { status, ies } => {
                if self.ft_roam.is_some() {
                    // FT roam: (Re)Association Response from the target
                    // AP - validate the FTIE MIC and install the keys.
                    // On failure the old AP is already disconnected
                    // (CMD_AUTHENTICATE did that), so the retry loop
                    // reconnects.
                    if status == Ieee80211StatusCode::Success {
                        if let Err(e) = self
                            .handle_ft_assoc_response(
                                ies.as_deref().unwrap_or(&[]),
                            )
                            .await
                        {
                            log::warn!("FT roam aborted: {e}; reconnecting");
                            self.state = WifiState::Failed;
                        }
                    } else {
                        log::warn!(
                            "FT REASSOCIATE rejected: status={status}; \
                             reconnecting"
                        );
                        self.ft_roam = None;
                        self.state = WifiState::Failed;
                    }
                } else if status == Ieee80211StatusCode::Success {
                    if self.bss_info.security == SecurityType::Open {
                        log::info!(
                            "ASSOCIATED - open network, connection established"
                        );
                        self.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
                        self.state = WifiState::ConnectedWithoutOffloadRekey;
                        self.arm_wowlan_if_enabled().await;
                    } else if self.bss_info.security == SecurityType::Owe {
                        if self.process_owe_assoc_response(ies.as_deref()) {
                            log::info!(
                                "ASSOCIATED - OWE PMK derived, waiting for \
                                 4-way handshake"
                            );
                        } else {
                            self.state = WifiState::Failed;
                        }
                    } else if self.bss_info.security.is_ft() {
                        // Initial association with an FT AKM: record the
                        // mobility domain and R0/R1 key holders from the
                        // response IEs and derive the FT key hierarchy;
                        // the 4-way handshake that follows runs with the
                        // PMK-R1-derived PTK.
                        if let Err(e) = self
                            .setup_ft_context(ies.as_deref().unwrap_or(&[]))
                            .await
                        {
                            log::warn!("FT setup failed: {e}");
                            self.state = WifiState::Failed;
                        } else {
                            log::info!(
                                "ASSOCIATED (FT) - waiting for 4-way handshake"
                            );
                            // A Message 1 may have raced ahead of this
                            // association event; feed it now.
                            if let Some(frame) = self.pending_ft_msg1.take() {
                                self.handle_control_port_frame(&frame).await;
                            }
                        }
                    } else {
                        if self.pmksa_in_use.is_some() {
                            log::info!(
                                "ASSOCIATED with cached PMKID - the AP \
                                 accepted the PMKSA; awaiting 4-way handshake"
                            );
                        } else {
                            log::info!(
                                "ASSOCIATED - waiting for 4-way handshake"
                            );
                        }
                    }
                } else if self.pmksa_in_use.is_some() {
                    // The AP rejected the association with the cached
                    // PMKID (no matching PMKSA on the AP side): fall back
                    // to full authentication right away.
                    log::warn!(
                        "ASSOCIATE with cached PMKID failed: status={status} \
                         - retrying with full authentication"
                    );
                    self.pmksa_fallback().await;
                } else {
                    log::warn!("ASSOCIATE failed: status={status}");
                    self.state = WifiState::Failed;
                }
            }

            Nl80211Event::ConnectResult { status } => {
                if status == Ieee80211StatusCode::Success {
                    log::debug!(
                        "CONNECT event (associated); awaiting 4-way handshake"
                    );
                } else {
                    log::warn!("CONNECT failed: status={status}");
                    self.state = WifiState::Failed;
                }
            }

            Nl80211Event::ControlPortFrame { frame } => {
                self.handle_control_port_frame(&frame).await;
            }

            Nl80211Event::PortAuthorized => {
                log::info!("PORT_AUTHORIZED - connection ready");
                self.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
                self.state = WifiState::ConnectedWithoutOffloadRekey;
                self.arm_wowlan_if_enabled().await;
            }

            Nl80211Event::WowlanWakeup { reasons } => {
                self.handle_wowlan_wakeup(reasons).await;
            }

            Nl80211Event::CqmRssi(cqm) => {
                self.handle_cqm_rssi(cqm).await;
            }

            Nl80211Event::Disconnect { reason } => {
                // During an FT roam this is the expected side effect of
                // CMD_AUTHENTICATE disconnecting the old AP - the roam
                // continues; acting on it would tear the roam down.
                if self.ft_roam.is_some() {
                    log::debug!("DISCONNECT during FT roam ignored (expected)");
                } else if matches!(
                    self.state,
                    WifiState::ConnectedWithoutOffloadRekey
                        | WifiState::ConnectedWithOffloadRekey
                ) || (self.state == WifiState::Authenticating
                    && self.is_psk_4way_in_progress())
                {
                    // cfg80211-style drivers (e.g. brcmfmac) report the
                    // AP-initiated disconnect through CMD_DISCONNECT
                    // with the same IEEE 802.11 reason code; classify
                    // it like the deauth/disassoc events.
                    self.handle_ap_disconnect(Some(reason)).await;
                } else {
                    // The kernel can trail a CMD_DISCONNECT behind the
                    // deauth/disassoc event (or a previous disconnect)
                    // by seconds; acting on a stale one would tear down
                    // the reconnection already in flight - and would
                    // downgrade a fatal backoff back to a short one.
                    log::debug!(
                        "stale DISCONNECT (reason={reason}) in state {:?}; \
                         ignored",
                        self.state
                    );
                }
            }

            // AP-initiated deauth/disassoc with the IEEE 802.11
            // reason code parsed out of the management frame by
            // wl-nl80211. The reason tells a fatal credential problem
            // (retry with the long authentication backoff) apart from a
            // transient disconnect (short backoff).
            Nl80211Event::Deauthenticated { reason }
            | Nl80211Event::Disassociated { reason } => {
                self.handle_ap_disconnect(Some(reason)).await;
            }

            Nl80211Event::ScanStart | Nl80211Event::NewScanResults => {
                if self.roam_scan {
                    log::trace!("scan event: {event:?}");
                } else {
                    log::debug!("scan event: {event:?}");
                }
            }
            Nl80211Event::ExternalAuth => {
                log::debug!("EXTERNAL_AUTH event (unsupported in this mode)");
            }
            Nl80211Event::Unknown { cmd } => {
                if cmd == Nl80211Command::SchedScanStopped
                    && self.sched_scan_stop_pending
                {
                    // Consume the echo of our own stop request when it
                    // lands outside SchedScanWait (e.g. while
                    // authenticating).
                    self.sched_scan_stop_pending = false;
                } else if matches!(
                    cmd,
                    Nl80211Command::Deauthenticate
                        | Nl80211Command::Disassociate
                ) {
                    // Fallback: the kernel did not deliver a parseable
                    // management frame, so no reason code is available.
                    // Treat it like any transient AP disconnect.
                    self.handle_ap_disconnect(None).await;
                } else if matches!(
                    cmd,
                    Nl80211Command::UnprotDeauthenticate
                        | Nl80211Command::UnprotDisassociate
                        | Nl80211Command::DelStation
                ) {
                    // AP-initiated disconnect without a reason: mac80211
                    // reports the un-protected deauth/disassoc (and the
                    // station-entry removal) rather than CMD_DISCONNECT
                    // when userspace drives the MLME.
                    self.handle_ap_disconnect(None).await;
                } else {
                    log::debug!("event: {cmd:?}");
                }
            }
            // `Nl80211Event` is #[non_exhaustive]; keep future variants
            // from silently wedging the state machine.
            _ => {
                log::debug!("unhandled nl80211 event: {event:?}");
            }
        }
    }

    /// An AP-initiated disconnect (deauth/disassoc, protected or not)
    /// during a connection attempt or while connected: clean up the
    /// kernel connection state and schedule a reconnect.
    ///
    /// Reason codes 2 (`PrevAuthNotValid`) and 23 (`Ieee8021xFailed`)
    /// mean the AP no longer accepts the current credentials/PMKSA -
    /// retrying soon is futile, so the client backs off for the long
    /// authentication-retry interval (`FailedAuthentication`). Every
    /// other reason is transient (`Failed`, short backoff). `None`
    /// means no reason was available (missing frame); treat it as
    /// transient.
    async fn handle_ap_disconnect(
        &mut self,
        reason: Option<Ieee80211ReasonCode>,
    ) {
        // During an FT roam these events are the expected consequence of
        // CMD_AUTHENTICATE disconnecting the old AP - let the roam
        // continue. While connected, classify credential failures. An
        // initial WPA2-PSK handshake also counts as a credential
        // failure: the passphrase is only verified by that handshake,
        // so an AP disconnect there means the configured key is wrong.
        // Stale events in every other state are ignored: the kernel
        // delivers the same disconnect as several events with a long
        // delay between them, and acting on a stale one would tear down
        // the reconnection already in flight.
        if self.ft_roam.is_some() {
            log::debug!("AP disconnect during FT roam ignored (expected)");
        } else if matches!(
            self.state,
            WifiState::ConnectedWithoutOffloadRekey
                | WifiState::ConnectedWithOffloadRekey
        ) {
            let fatal = is_fatal_disconnect_reason(reason);
            log::warn!(
                "AP disconnect (reason={reason:?}); retrying{}",
                if fatal {
                    " with long authentication backoff"
                } else {
                    ""
                }
            );
            // For a socket-owned connection the kernel keeps its
            // connection state (wdev->connected) until userspace cleans
            // up, and rejects the next ASSOCIATE with -EALREADY
            // otherwise. wpa_supplicant sends CMD_DEAUTHENTICATE here;
            // CMD_DISCONNECT clears the same state.
            if let Err(e) =
                connect::disconnect(&mut self.conn_handle, self.if_index).await
            {
                log::debug!("disconnect cleanup failed: {e}");
            }
            if fatal {
                self.fail_auth(fatal_disconnect_error(reason));
            } else {
                self.state = WifiState::Failed;
            }
        } else if self.state == WifiState::Authenticating
            && self.is_psk_4way_in_progress()
        {
            // wpa_supplicant's `could_be_psk_mismatch()` treats an AP
            // disconnect during the initial PSK 4-way handshake as a
            // wrong passphrase. Surface it as `WrongPassword` instead of
            // silently retrying on the short backoff.
            log::warn!(
                "AP disconnect during WPA2-PSK/FT-PSK 4-way handshake \
                 (reason={reason:?}); treating as wrong password"
            );
            if let Err(e) =
                connect::disconnect(&mut self.conn_handle, self.if_index).await
            {
                log::debug!("disconnect cleanup failed: {e}");
            }
            self.fail_auth(WifiError::wrong_password(&self.network.ssid));
        } else {
            log::debug!(
                "stale AP disconnect (reason={reason:?}) in state {:?}; \
                 ignored",
                self.state
            );
        }
    }

    /// Whether the current connection attempt is an initial WPA2-PSK /
    /// FT-PSK 4-way handshake (i.e. the passphrase is verified by the
    /// handshake, not by an earlier SAE/PMKSA exchange).
    fn is_psk_4way_in_progress(&self) -> bool {
        self.pmksa_in_use.is_none()
            && matches!(
                self.bss_info.security,
                SecurityType::Wpa2Psk
                    | SecurityType::Wpa2PskSha256
                    | SecurityType::FtPsk
            )
    }

    /// the device woke the host while it was suspended. Clear the
    /// per-suspend triggers, and when the wake means the connection is
    /// no longer trustworthy (GTK rekey failure / disconnect) tear it
    /// down so the retry loop rebuilds it.
    async fn handle_wowlan_wakeup(
        &mut self,
        reasons: Vec<Nl80211WowlanWakeup>,
    ) {
        if reasons.is_empty() {
            log::debug!("WoWLAN wake event without reasons");
        } else {
            log::warn!("WoWLAN wake: {reasons:?}");
        }

        // Triggers stay armed while connected; clear them after a wake
        // so they cannot fire again before the next connection (which
        // re-arms when `wowlan: true`).
        if self.wowlan_armed
            && let Err(e) = self.disarm_wowlan().await
        {
            log::warn!("clear WoWLAN triggers after wake failed: {e}");
        }

        if !matches!(
            self.state,
            WifiState::ConnectedWithoutOffloadRekey
                | WifiState::ConnectedWithOffloadRekey
        ) {
            log::debug!("stale WoWLAN wake in state {:?}; ignored", self.state);
            return;
        }

        if wowlan_wakeup_requires_reconnect(&reasons) {
            log::warn!("WoWLAN wake invalidated the connection; reconnecting");
            // Same kernel-state cleanup as an AP disconnect: clear
            // wdev->connected before the next ASSOCIATE.
            if let Err(e) =
                connect::disconnect(&mut self.conn_handle, self.if_index).await
            {
                log::debug!("disconnect cleanup after WoWLAN wake failed: {e}");
            }
            self.state = WifiState::Failed;
        }
    }

    /// arm WoWLAN when the connected network opted in
    /// (`NetworkConfig::wowlan`). WoWLAN is off by default; this keeps
    /// the feature opt-in per network.
    pub(crate) async fn arm_wowlan_if_enabled(&mut self) {
        if self.network.wowlan {
            let _ = self.arm_wowlan().await;
        }
    }

    /// Feed an 802.11 management frame (or the auth frame embedded in an
    /// AUTHENTICATE event) into the active auth method.
    async fn handle_auth_frame(&mut self, frame: &[u8]) {
        // Only frames from the AP we are authenticating with belong to
        // this exchange. On a shared medium (and in the wild: two STAs
        // of neighbouring APs hear each other) the SAE frames of a
        // parallel exchange would otherwise corrupt ours - e.g. the
        // peer's confirm fails its own send-confirm check and the
        // handshake aborts. wpa_supplicant filters the same way.
        if frame.len() >= 16 && frame[10..16] != self.bss_info.bssid {
            log::debug!(
                "ignoring auth frame from {:02x?} (expecting {:02x?})",
                &frame[10..16],
                self.bss_info.bssid
            );
            return;
        }
        let Some((auth_seq, status_code, payload)) =
            auth::parse_sae_auth_frame(frame)
        else {
            log::debug!("received mgmt frame: {} bytes", frame.len());
            return;
        };
        log::debug!("auth frame: seq={auth_seq}, status={status_code}");

        let action = match self.auth.as_mut() {
            Some(auth) => {
                match auth.process_frame(auth_seq, status_code, &payload) {
                    Ok(action) => action,
                    Err(e) => {
                        // SAE crypto failure (wrong password / confirm
                        // mismatch): use the long retry backoff.
                        log::warn!("{e}");
                        self.fail_auth(e);
                        return;
                    }
                }
            }
            None => {
                log::warn!("auth frame before auth was started");
                return;
            }
        };

        match action {
            AuthAction::Continue => {}
            AuthAction::SendConfirm(confirm) => {
                // auth_data = trans(2 LE=2) || status(2 LE=0)
                //             || send_confirm(2 LE=1) || confirm_hash(32)
                let mut auth_data = Vec::with_capacity(6 + confirm.len());
                auth_data.extend_from_slice(&2u16.to_le_bytes());
                auth_data.extend_from_slice(&0u16.to_le_bytes());
                auth_data.extend_from_slice(&1u16.to_le_bytes());
                auth_data.extend_from_slice(&confirm);

                let attrs = Nl80211Authenticate::new(self.if_index)
                    .ssid(&self.network.ssid)
                    .mac(self.bss_info.bssid)
                    .frequency(self.bss_info.freq_mhz)
                    .auth_type(Nl80211AuthType::Sae)
                    .auth_data(auth_data)
                    .build();
                if let Err(e) = drain_request(
                    self.conn_handle.authenticate(attrs).execute().await,
                )
                .await
                {
                    log::warn!("send SAE confirm failed: {e}");
                    self.state = WifiState::Failed;
                } else {
                    log::info!("SAE confirm sent");
                    // The commit exchange is done; only the confirm wait
                    // remains, which is not retransmitted.
                    self.sae_commit_sent = false;
                }
            }
            AuthAction::SendCommitWithToken(token) => {
                // the AP demanded an anti-clogging token - re-send
                // the commit (fresh scalar/element) with the token.
                let auth_data = match self.auth.as_mut() {
                    Some(auth) => match auth.commit_with_token(&token) {
                        Ok(data) => data,
                        Err(e) => {
                            log::warn!("SAE token commit failed: {e}");
                            self.fail_auth(e);
                            return;
                        }
                    },
                    None => {
                        log::warn!("no SAE auth for token retry");
                        return;
                    }
                };
                self.sae_sync = 0;
                self.send_sae_commit(&auth_data).await;
            }
            AuthAction::RetryWithHnp => {
                // the AP rejected the H2E commit; restart the
                // exchange with hunting-and-pecking.
                self.restart_sae_with_hnp().await;
            }
            AuthAction::RetryTemporarily => {
                // 802.11-2020 §12.4.8.6.4 (Committed state): a nonzero
                // status is silently discarded and the t0
                // (retransmission) timer set - the Authenticating wait
                // loop re-sends the same commit on expiry and
                // increments the Sync counter. Only once Sync is
                // exhausted does the protocol instance give up (Del),
                // which the retry loop turns into a short-backoff
                // reconnect.
                if self.sae_sync < SAE_SYNC_MAX {
                    log::debug!(
                        "SAE commit temporarily rejected; waiting for the \
                         retransmission timer"
                    );
                } else {
                    log::warn!(
                        "SAE commit temporarily rejected {} times; giving up, \
                         will reconnect",
                        self.sae_sync
                    );
                    self.state = WifiState::Failed;
                }
            }
            AuthAction::Complete => {
                log::info!("SAE completed - sending ASSOCIATE");
                let rsne = match self.bss_info.security {
                    SecurityType::FtSae => elements::ft_sae_ie_cipher(
                        None,
                        self.bss_info.group_mgmt_cipher,
                    ),
                    SecurityType::FtSaeExtKey => {
                        elements::ft_sae_ext_key_ie_cipher(
                            None,
                            self.bss_info.group_mgmt_cipher,
                        )
                    }
                    SecurityType::SaeExtKey => elements::sae_ext_key_ie_cipher(
                        self.bss_info.group_mgmt_cipher,
                    ),
                    _ => {
                        elements::sae_ie_cipher(self.bss_info.group_mgmt_cipher)
                    }
                };
                let mut ies = rsne;
                // FT initial mobility domain association: the request
                // carries the MDIE, which prompts the AP to answer with
                // MDIE + FTIE (R0KH-ID / R1KH-ID).
                if matches!(
                    self.bss_info.security,
                    SecurityType::FtSae | SecurityType::FtSaeExtKey
                ) && let Err(e) = self.append_ft_mdie(&mut ies)
                {
                    log::warn!("FT ASSOCIATE failed: {e}");
                    self.state = WifiState::Failed;
                    return;
                }
                if let Err(e) =
                    self.associate(ies, Some(Nl80211UseMfp::Required)).await
                {
                    log::warn!("ASSOCIATE failed: {e}");
                    self.state = WifiState::Failed;
                }
            }
        }
    }

    /// Send an SAE commit auth_data via `NL80211_CMD_AUTHENTICATE` and
    /// record it for retransmission (SAE Sync). The commit being
    /// (re)sent stays in flight until the AP's commit arrives.
    async fn send_sae_commit(&mut self, auth_data: &[u8]) {
        let attrs = Nl80211Authenticate::new(self.if_index)
            .ssid(&self.network.ssid)
            .mac(self.bss_info.bssid)
            .frequency(self.bss_info.freq_mhz)
            .auth_type(Nl80211AuthType::Sae)
            .auth_data(auth_data.to_vec())
            .build();
        if let Err(e) =
            drain_request(self.conn_handle.authenticate(attrs).execute().await)
                .await
        {
            log::warn!("send SAE commit failed: {e}");
            self.state = WifiState::Failed;
            return;
        }
        self.sae_commit_sent = true;
        self.sae_commit_auth_data = auth_data.to_vec();
        log::info!("SAE commit sent");
    }

    /// the AP rejected the H2E commit (an HnP-only AP); restart the
    /// SAE exchange with a hunting-and-pecking commit. Only attempted
    /// once per connection attempt (`sae_hnp_attempted`).
    async fn restart_sae_with_hnp(&mut self) {
        let Some(password) = self.network.password.as_deref() else {
            log::warn!("no password for HnP SAE restart");
            self.fail_auth(WifiError::new(
                ErrorKind::InvalidConfig,
                "no password for HnP SAE restart",
            ));
            return;
        };
        let auth = match AuthMethod::new_sae(
            password,
            &self.network.ssid,
            self.mac,
            self.bss_info.bssid,
            false, // h2e
            false, // no further fallback
            None,  // HnP restart never carries a password identifier
        ) {
            Ok(auth) => auth,
            Err(e) => {
                log::warn!("HnP SAE restart failed: {e}");
                self.fail_auth(e);
                return;
            }
        };
        self.auth = Some(auth);
        self.sae_hnp_attempted = true;
        let auth_data = match self.auth.as_mut().unwrap().initial_frame() {
            Ok(data) => data,
            Err(e) => {
                log::warn!("HnP SAE commit failed: {e}");
                self.fail_auth(e);
                return;
            }
        };
        log::info!("SAE restarted with hunting-and-pecking");
        self.sae_sync = 0;
        self.send_sae_commit(&auth_data).await;
    }

    /// Handle an EAPOL-Key frame (4-way handshake / group rekey).
    async fn handle_control_port_frame(&mut self, frame: &[u8]) {
        // 802.1X EAP frames (EAPOL type 0) arrive on the
        // same control port as EAPOL-Key frames.
        if let Some(eap_pdu) = eapol::parse_eapol_eap_frame(frame) {
            self.handle_eap_frame(eap_pdu).await;
            return;
        }

        let Some(parsed) = eapol::parse_eapol_key_frame(frame) else {
            log::debug!("unparseable control port frame");
            return;
        };

        log::debug!(
            "EAPOL-Key: info={} replay={}",
            eapol::fmt_key_info(parsed.key_info),
            parsed.replay_counter
        );

        // EAPOL-Key with the Request bit asks the supplicant to start a
        // handshake; both reference supplicants drop it, and so does
        // shuli (handshakes here are AP-driven only).
        if parsed.is_request() {
            log::debug!("EAPOL-Key with Request bit - dropped");
            return;
        }

        if !parsed.has_mic() && parsed.has_ack() {
            // 4-way handshake Message 1 (ANonce).
            log::info!("4-way handshake: Message 1 (ANonce)");

            // With an FT AKM the PTK comes from the FT key hierarchy,
            // whose parameters (R0KH-ID / R1KH-ID) only become known
            // through the association response event - which can race
            // behind this first EAPOL frame. Buffer the frame until the
            // FT context exists.
            if self.bss_info.security.is_ft() && self.ft.is_none() {
                log::debug!(
                    "buffered 4-way Message 1 until the FT context exists"
                );
                self.pending_ft_msg1 = Some(frame.to_vec());
                return;
            }

            if self.fourway.is_none() {
                if self.bss_info.security.is_ft() {
                    // Initial association with an FT AKM: the 4-way
                    // handshake runs with the PTK derived from PMK-R1
                    // (802.11-2020 §12.8); Message 2's RSNE must carry
                    // PMKR1Name as its PMKID (the AP verifies that for
                    // FT AKMs), matching the association's FT context.
                    let Some(ft) = self.ft.as_ref() else {
                        log::warn!("no FT context for 4-way handshake");
                        self.state = WifiState::Failed;
                        return;
                    };
                    let mut rsne = match self.bss_info.security {
                        SecurityType::FtSae => elements::ft_sae_ie_cipher(
                            Some(ft.pmk_r1.name),
                            self.bss_info.group_mgmt_cipher,
                        ),
                        SecurityType::FtSaeExtKey => {
                            elements::ft_sae_ext_key_ie_cipher(
                                Some(ft.pmk_r1.name),
                                self.bss_info.group_mgmt_cipher,
                            )
                        }
                        _ => elements::ft_psk_ie_cipher(
                            Some(ft.pmk_r1.name),
                            self.bss_info.group_mgmt_cipher,
                        ),
                    };
                    // MDIE + FTIE from the association response join the
                    // RSNE in the Message 2 key data.
                    rsne.extend_from_slice(&ft.assoc_resp_ft_ies);
                    if self.network.ocv {
                        elements::rsne_set_ocvc(&mut rsne, true);
                    }
                    if self.network.ext_key_id {
                        elements::rsne_set_ext_key_id(&mut rsne, true);
                    }
                    let mut fw = FourWayState::new_ft(
                        ft.pmk_r1.clone(),
                        self.mac,
                        self.bss_info.bssid,
                        rsne,
                        self.bss_info.ap_rsne.clone(),
                        self.bss_info.ap_rsnxe.clone(),
                    );
                    if !self.enable_ocv(&mut fw) {
                        self.state = WifiState::Failed;
                        return;
                    }
                    fw.set_ext_key_id(self.ext_key_id_enabled());
                    self.fourway = Some(fw);
                } else {
                    let (pmk, mut rsne, mic_alg) = if let Some(entry) =
                        self.pmksa_in_use.as_ref()
                    {
                        // 4-way over a cached PMK. The RSNE must be
                        // the same one the association request carried
                        // (with the PMKID) - the AP verifies that.
                        let rsne = self.rsne_with_pmkid(Some(entry.pmkid));
                        (entry.pmk, rsne, entry.mic_alg)
                    } else {
                        match self.bss_info.security {
                            SecurityType::Owe => {
                                let Some(ref owe_auth) = self.owe else {
                                    log::warn!(
                                        "no OWE state for 4-way handshake"
                                    );
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                let Some(pmk) = owe_auth.pmk() else {
                                    log::warn!("OWE PMK not derived");
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::owe_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::HmacSha256,
                                )
                            }
                            SecurityType::Wpa2Psk => {
                                let Some(pmk) = self.psk_pmk else {
                                    log::warn!(
                                        "no PSK PMK for 4-way handshake"
                                    );
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::wpa2_psk_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::HmacSha1,
                                )
                            }
                            SecurityType::Wpa2PskSha256 => {
                                let Some(pmk) = self.psk_pmk else {
                                    log::warn!(
                                        "no PSK PMK for 4-way handshake"
                                    );
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::wpa2_psk_sha256_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::AesCmac,
                                )
                            }
                            SecurityType::Wpa2Ent => {
                                let Some(pmk) = self.eap_pmk else {
                                    log::warn!(
                                        "no EAP PMK for 4-way handshake"
                                    );
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::wpa2_ent_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::HmacSha1,
                                )
                            }
                            SecurityType::Wpa2EntSha256 => {
                                let Some(pmk) = self.eap_pmk else {
                                    log::warn!(
                                        "no EAP PMK for 4-way handshake"
                                    );
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::wpa2_ent_sha256_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::AesCmac,
                                )
                            }
                            SecurityType::SaeExtKey => {
                                let Some(pmk) =
                                    self.auth.as_ref().and_then(|a| a.pmk())
                                else {
                                    log::warn!(
                                        "no SAE-EXT-KEY PMK for 4-way \
                                         handshake"
                                    );
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::sae_ext_key_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::HmacSha256,
                                )
                            }
                            _ => {
                                // SAE
                                let Some(pmk) =
                                    self.auth.as_ref().and_then(|a| a.pmk())
                                else {
                                    log::warn!("no PMK for 4-way handshake");
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::sae_ie_cipher(
                                        self.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::AesCmac,
                                )
                            }
                        }
                    };
                    if self.network.ocv {
                        elements::rsne_set_ocvc(&mut rsne, true);
                    }
                    if self.network.ext_key_id {
                        elements::rsne_set_ext_key_id(&mut rsne, true);
                    }
                    let mut fw = FourWayState::new_with_ap_ies(
                        &pmk,
                        mic_alg,
                        self.mac,
                        self.bss_info.bssid,
                        rsne,
                        self.bss_info.ap_rsne.clone(),
                        self.bss_info.ap_rsnxe.clone(),
                    );
                    if !self.enable_ocv(&mut fw) {
                        self.state = WifiState::Failed;
                        return;
                    }
                    fw.set_ext_key_id(self.ext_key_id_enabled());
                    self.fourway = Some(fw);
                }
            }

            let msg2 = {
                let fw = self.fourway.as_mut().unwrap();
                match fw.process_message_1(
                    &parsed.key_nonce,
                    parsed.replay_counter,
                    parsed.key_info,
                ) {
                    Ok(msg2) => msg2,
                    Err(e) => {
                        log::warn!("process_message_1 failed: {e}");
                        self.state = WifiState::Failed;
                        return;
                    }
                }
            };
            if let Err(e) = send_ctrl_port_frame(
                &mut self.conn_handle,
                self.if_index,
                self.bss_info.bssid,
                &msg2,
            )
            .await
            {
                log::warn!("send msg2 failed: {e}");
                self.state = WifiState::Failed;
                return;
            }
            log::info!("4-way: Message 2 sent");
        } else if parsed.has_mic() && parsed.is_secure() && parsed.is_pairwise()
        {
            // 4-way handshake Message 3 (GTK + MIC).
            log::info!("4-way handshake: Message 3");

            let (msg4, kdes) = {
                let fw = match self.fourway.as_mut() {
                    Some(fw) => fw,
                    None => {
                        log::warn!("no 4-way state for Message 3");
                        self.state = WifiState::Failed;
                        return;
                    }
                };
                match fw.process_message_3(&parsed) {
                    Ok(result) => result,
                    Err(e) => {
                        // SAE already proved the passphrase, so a Message 3
                        // MIC mismatch here is a transient frame/AP issue:
                        // retry on the short backoff. With a cached PMK it
                        // means the cache entry is stale: drop it and fall
                        // back to full authentication right away.
                        log::warn!("process_message_3 failed: {e}");
                        if self.pmksa_in_use.is_some() {
                            self.pmksa_fallback().await;
                        } else if matches!(
                            self.bss_info.security,
                            SecurityType::Wpa2Psk
                                | SecurityType::Wpa2PskSha256
                                | SecurityType::FtPsk
                        ) && e.msg == "MIC mismatch"
                        {
                            // WPA2-PSK/FT-PSK verifies the passphrase
                            // only in the 4-way handshake; a Message 3
                            // MIC mismatch is the wrong-password signal.
                            let err =
                                WifiError::wrong_password(&self.network.ssid);
                            log::warn!("{err}");
                            self.fail_auth(err);
                        } else {
                            self.state = WifiState::Failed;
                        }
                        return;
                    }
                }
            };

            // the AP can tell the STA to stop using legacy
            // AKMs via the Transition Disable KDE.  shuli's config is
            // file-driven (no runtime profile update), so record it in
            // the log; future reconnects pick up a config change.
            if let Some(bitmap) = kdes.transition_disable {
                log::info!(
                    "AP Transition Disable KDE: 0x{bitmap:02x} ({})",
                    fmt_transition_disable(bitmap)
                );
            }

            // with Extended Key ID the pairwise key is
            // installed in two phases - RX-only before Message 4 (so
            // frames protected with the new key id decrypt), then
            // activated (TX) after Message 4.
            let ext_key_id = self.fourway.as_ref().and_then(|fw| fw.key_id());
            if let Some(key_id) = ext_key_id
                && let Some(tk) = self.fourway.as_ref().and_then(|fw| fw.tk())
            {
                let attrs = Nl80211Key::new_ptk(
                    self.if_index,
                    self.bss_info.bssid,
                    tk.to_vec(),
                )
                .key_index(key_id)
                .build();
                if let Err(e) = drain_request(
                    self.conn_handle.new_key(attrs).execute().await,
                )
                .await
                {
                    log::warn!("install PTK (RX) failed: {e}");
                    self.state = WifiState::Failed;
                    return;
                }
                log::info!("PTK installed for RX (key id {key_id})");
            }

            if let Err(e) = send_ctrl_port_frame(
                &mut self.conn_handle,
                self.if_index,
                self.bss_info.bssid,
                &msg4,
            )
            .await
            {
                log::warn!("send msg4 failed: {e}");
                self.state = WifiState::Failed;
                return;
            }
            log::info!("4-way: Message 4 sent");

            if let Some(tk) = self.fourway.as_ref().and_then(|fw| fw.tk()) {
                let mut builder = Nl80211Key::new_ptk(
                    self.if_index,
                    self.bss_info.bssid,
                    tk.to_vec(),
                );
                if let Some(key_id) = ext_key_id {
                    // Activate the RX-installed key as the default
                    // unicast TX key.
                    builder = builder
                        .key_index(key_id)
                        .default_types(vec![Nl80211KeyDefaultType::Unicast]);
                }
                if let Err(e) = drain_request(
                    self.conn_handle.new_key(builder.build()).execute().await,
                )
                .await
                {
                    log::warn!("install PTK failed: {e}");
                    self.state = WifiState::Failed;
                    return;
                }
                if let Some(key_id) = ext_key_id {
                    log::info!("PTK activated (key id {key_id})");
                } else {
                    log::info!("PTK installed");
                }
            }

            if let Some((gtk_idx, gtk_data)) = &kdes.gtk {
                if let Err(e) = drain_request(
                    self.conn_handle
                        .new_key(
                            Nl80211Key::new_gtk(
                                self.if_index,
                                gtk_data.to_vec(),
                                *gtk_idx,
                            )
                            .build(),
                        )
                        .execute()
                        .await,
                )
                .await
                {
                    log::warn!("install GTK failed: {e}");
                    self.state = WifiState::Failed;
                    return;
                }
                log::info!("GTK[{gtk_idx}] installed");
            }

            // install the IGTK (and BIGTK when the AP delivers one)
            // from the Message 3 KDEs. Without the IGTK, mac80211 drops
            // every protected management frame (SA Query, BTM, channel
            // switch announcements) the AP sends. Failures are logged but
            // not fatal: the data path works without them.
            if let Some(ref igtk) = kdes.igtk {
                match drain_request(
                    self.conn_handle
                        .new_key(
                            Nl80211Key::new_igtk(
                                self.if_index,
                                igtk.key.clone(),
                                igtk.key_index,
                                igtk.ipn.to_vec(),
                            )
                            .cipher(self.bss_info.group_mgmt_cipher)
                            .build(),
                        )
                        .execute()
                        .await,
                )
                .await
                {
                    Ok(()) => {
                        log::info!("IGTK[{}] installed", igtk.key_index)
                    }
                    Err(e) => log::warn!("install IGTK failed: {e}"),
                }
            }
            if let Some(ref bigtk) = kdes.bigtk {
                match drain_request(
                    self.conn_handle
                        .new_key(
                            Nl80211Key::new_bigtk(
                                self.if_index,
                                bigtk.key.clone(),
                                bigtk.key_index,
                                bigtk.ipn.to_vec(),
                            )
                            .cipher(self.bss_info.group_mgmt_cipher)
                            .build(),
                        )
                        .execute()
                        .await,
                )
                .await
                {
                    Ok(()) => {
                        log::info!("BIGTK[{}] installed", bigtk.key_index)
                    }
                    Err(e) => log::warn!("install BIGTK failed: {e}"),
                }
            }

            // the handshake proved the PMK - cache the PMKSA for the
            // next reconnect/roam (and hand it to the driver's cache).
            self.cache_pmksa().await;

            // Try to offload GTK rekey to the driver/firmware.
            // Falls back to userspace rekey when unsupported
            // (e.g. mac80211_hwsim returns -EOPNOTSUPP).
            let offloaded = if let (Some(kck), Some(kek), Some(fw)) = (
                self.fourway.as_ref().and_then(|f| f.kck()),
                self.fourway.as_ref().and_then(|f| f.kek()),
                &self.fourway,
            ) {
                let rc = fw.replay_counter_bytes();
                let attrs = Nl80211RekeyOffload::new(self.if_index)
                    .kek(kek.to_vec())
                    .kck(kck.to_vec())
                    .replay_ctr(rc)
                    .build();
                match drain_request(
                    self.conn_handle.set_rekey_offload(attrs).execute().await,
                )
                .await
                {
                    Ok(()) => {
                        log::info!("GTK rekey offloaded to driver");
                        true
                    }
                    Err(e) => {
                        log::debug!("rekey offload not available: {e}");
                        false
                    }
                }
            } else {
                false
            };

            if offloaded {
                log::info!("keys installed - connection established");
                self.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
                self.state = WifiState::ConnectedWithOffloadRekey;
            } else {
                log::info!(
                    "keys installed - connection established (userspace rekey)"
                );
                self.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
                self.state = WifiState::ConnectedWithoutOffloadRekey;
            }
            // (wpa_supplicant model): arm WoWLAN triggers when the
            // connection lands and leave them armed. The kernel only
            // uses them while the host is suspended; the wake handler
            // clears them after a WoWLAN wake and this arms again on
            // the next reconnect.
            self.arm_wowlan_if_enabled().await;
        } else if parsed.has_mic()
            && parsed.is_secure()
            && parsed.has_ack()
            && !parsed.is_pairwise()
        {
            // Group key handshake: GTK rekey while connected.
            log::info!("group key handshake: rekey (Message 1)");

            let msg2 = {
                let fw = match self.fourway.as_mut() {
                    Some(fw) => fw,
                    None => {
                        log::warn!(
                            "group rekey before 4-way handshake; ignoring"
                        );
                        return;
                    }
                };
                match fw.process_group_rekey(&parsed) {
                    Ok(msg2) => msg2,
                    Err(e) => {
                        log::warn!("process_group_rekey failed: {e}");
                        return;
                    }
                }
            };

            if let Err(e) = send_ctrl_port_frame(
                &mut self.conn_handle,
                self.if_index,
                self.bss_info.bssid,
                &msg2,
            )
            .await
            {
                log::warn!("send group rekey reply failed: {e}");
                return;
            }
            log::info!("group key handshake: Message 2 sent");

            let (gtk_data, gtk_idx) = match self.fourway.as_ref() {
                Some(fw) => (fw.gtk().map(|g| g.to_vec()), fw.gtk_index()),
                None => (None, 0),
            };
            if let Some(gtk_data) = gtk_data {
                if let Err(e) = drain_request(
                    self.conn_handle
                        .new_key(
                            Nl80211Key::new_gtk(
                                self.if_index,
                                gtk_data,
                                gtk_idx,
                            )
                            .build(),
                        )
                        .execute()
                        .await,
                )
                .await
                {
                    log::warn!("install rekeyed GTK failed: {e}");
                } else {
                    log::info!("GTK[{gtk_idx}] rekeyed");
                }
            }
        } else {
            log::debug!("unhandled EAPOL-Key frame type");
        }
    }

    /// feed an EAP packet into the 802.1X peer state
    /// machine and act on its output (response / Success / Failure).
    async fn handle_eap_frame(&mut self, eap_pdu: &[u8]) {
        let Some(packet) = EapPacket::parse(eap_pdu) else {
            log::warn!("unparseable EAP packet ({} bytes)", eap_pdu.len());
            return;
        };
        let Some(peer) = self.eap_peer.as_mut() else {
            log::warn!("EAP frame without an active EAP peer");
            return;
        };
        match peer.handle_packet(&packet) {
            Ok(EapAction::Respond(response)) => {
                let frame = eapol::build_eapol_eap_frame(&response);
                if let Err(e) = send_ctrl_port_frame(
                    &mut self.conn_handle,
                    self.if_index,
                    self.bss_info.bssid,
                    &frame,
                )
                .await
                {
                    log::warn!("send EAP response failed: {e}");
                    self.state = WifiState::Failed;
                }
            }
            Ok(EapAction::Success) => {
                let Some(msk) = peer.msk() else {
                    log::warn!("EAP-Success without an MSK");
                    self.fail_auth(WifiError::new(
                        ErrorKind::AuthFailed,
                        "EAP-Success without an MSK",
                    ));
                    return;
                };
                let mut pmk = [0u8; 32];
                pmk.copy_from_slice(&msk[..32]);
                self.eap_pmk = Some(pmk);
                log::info!(
                    "EAP success - PMK derived from MSK; awaiting 4-way \
                     handshake"
                );
            }
            Ok(EapAction::Failure) => {
                log::warn!("EAP failure");
                self.fail_auth(WifiError::new(
                    ErrorKind::AuthFailed,
                    "EAP authentication failed: check the configured EAP \
                     credentials",
                ));
            }
            Ok(EapAction::Wait) => {}
            Err(e) => {
                log::warn!("EAP error: {e}");
                self.fail_auth(WifiError::new(
                    ErrorKind::AuthFailed,
                    format!("EAP authentication failed: {e}"),
                ));
            }
        }
    }
}

impl WifiIface {
    /// Process the Association Response IEs for OWE: find the AP's
    /// DH Parameter Element and derive PMK/PMKID (RFC 8110 §4.4).
    /// Returns true on success.
    fn process_owe_assoc_response(&mut self, ies: Option<&[u8]>) -> bool {
        let Some(ies) = ies else {
            log::warn!("OWE: no IEs in association response");
            return false;
        };
        let Some(dh_data) = owe::find_owe_dh_element(ies) else {
            log::warn!("OWE: no DH Parameter Element in assoc response");
            return false;
        };
        let Some(ref mut owe_auth) = self.owe else {
            log::warn!("OWE: no OWE state for assoc response");
            return false;
        };
        if let Err(e) = owe_auth.process_ap_dh_element(dh_data) {
            log::warn!("OWE DH processing failed: {e}");
            return false;
        }
        true
    }
}

impl WifiIface {
    /// SSID of the network the client is currently working toward.
    /// Before the first scan selects a BSS this is the first configured
    /// network; after a successful scan it is the network whose BSS was
    /// selected (and whose passphrase is used for authentication).
    pub fn current_ssid(&self) -> &str {
        &self.network.ssid
    }

    /// BSSID of the BSS the client is currently working toward.
    /// Before the first scan selects a BSS this is all-zero; after a
    /// successful scan it is the selected BSS's BSSID.
    pub fn current_bssid(&self) -> [u8; ETH_ALEN] {
        self.bss_info.bssid
    }

    /// Replace the configured network list at runtime, reusing the same
    /// client (nl80211 socket, wiphy capability probes and PMKSA cache).
    ///
    /// * An unchanged list is a no-op: idempotent re-apply keeps the current
    ///   connection.
    /// * If the currently connected network is dropped from the list (or the
    ///   list becomes empty), the client disconnects cleanly, stops any
    ///   scheduled scan and resets to `Init` so the next `run()` starts a fresh
    ///   scan for the new SSIDs.
    /// * If the list changes while not connected, the same reset makes the next
    ///   `run()` probe the new SSIDs immediately.
    /// * If the connected network is still in the new list, the connection is
    ///   kept; only the scan/match list changes.
    pub async fn update_networks(
        &mut self,
        networks: Vec<NetworkConfig>,
    ) -> Result<(), WifiError> {
        if networks == self.config.networks {
            log::debug!("network list unchanged");
            return Ok(());
        }

        let old_ssid = self.network.ssid.clone();
        let connected = matches!(
            self.state,
            WifiState::ConnectedWithoutOffloadRekey
                | WifiState::ConnectedWithOffloadRekey
        );
        let connected_network_kept = connected
            && networks.iter().any(|network| network.ssid == old_ssid);

        if connected && connected_network_kept {
            self.config.networks = networks;
            self.scan_ssid_cursor = 0;
            self.scan_wildcard_next = true;
            self.sched_scan_cursor = 0;
            self.sched_scan_more = false;
            self.sched_scan_rotate = false;
            self.sched_scan_first = true;
            self.sched_scan_interval_sec = SCHED_SCAN_INTERVAL_SEC;
            self.sched_scan_timeout_secs = SCHED_SCAN_WATCHDOG_SECS;
            log::info!(
                "network list updated, keeping connection to {old_ssid}: [{}]",
                self.config.ssids().collect::<Vec<_>>().join(", ")
            );
            return Ok(());
        }

        self.config.networks = networks;
        self.scan_ssid_cursor = 0;
        self.scan_wildcard_next = true;
        self.sched_scan_cursor = 0;
        self.sched_scan_more = false;
        self.sched_scan_rotate = false;
        self.sched_scan_first = true;
        self.sched_scan_interval_sec = SCHED_SCAN_INTERVAL_SEC;
        self.sched_scan_timeout_secs = SCHED_SCAN_WATCHDOG_SECS;

        if connected {
            log::info!(
                "network list update drops current SSID {old_ssid}; \
                 disconnecting"
            );
            self.stop_sched_scan().await?;
            if self.wowlan_armed {
                self.disarm_wowlan().await?;
            }
            if let Err(e) =
                connect::disconnect(&mut self.conn_handle, self.if_index).await
            {
                log::debug!("disconnect on network update: {e}");
            }
        } else {
            // A scheduled scan's match set can only be changed by
            // restarting it; stop it so the next host scan probes the
            // new list.
            self.stop_sched_scan().await?;
        }

        // Reset every per-attempt field; keep the PMKSA cache so a later
        // return to a known network can skip full authentication.
        self.network = self
            .config
            .networks
            .first()
            .cloned()
            .unwrap_or_else(|| NetworkConfig::new(""));
        self.bss_info = BssInfo::default();
        self.auth = None;
        self.owe = None;
        self.psk_pmk = None;
        self.eap_peer = None;
        self.eap_pmk = None;
        self.fourway = None;
        self.pmksa_in_use = None;
        self.ft = None;
        self.ft_roam = None;
        self.roam_scan = false;
        self.pre_roam_state = None;
        self.roam_target = None;
        self.last_scan_candidates.clear();
        self.roam_freqs.clear();
        self.roam_scan_full = false;
        self.pending_nr_dialog = None;
        self.neighbor_report_responses = 0;
        self.pending_ft_msg1 = None;
        self.last_roam = None;
        self.sae_commit_sent = false;
        self.sae_sync = 0;
        self.sae_commit_auth_data.clear();
        self.sae_hnp_attempted = false;
        self.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
        self.state = WifiState::Init;
        log::info!(
            "network list updated: [{}]",
            self.config.ssids().collect::<Vec<_>>().join(", ")
        );
        Ok(())
    }

    /// Whether the wiphy advertises WoWLAN triggers shuli can arm
    /// (disconnect and/or GTK rekey failure).
    pub fn wowlan_supported(&self) -> bool {
        !desired_wowlan_triggers(&self.wowlan_supported_triggers).is_empty()
    }

    /// arm WoWLAN triggers (`NL80211_CMD_SET_WOWLAN`) so the device
    /// can wake the host while it is suspended. Arms `Disconnect` and
    /// `GtkRekeyFailure` when the wiphy advertises them; returns `true`
    /// when triggers were armed and `false` when the wiphy has no
    /// usable WoWLAN support. Best-effort: failures are logged, not
    /// fatal (a suspend must not be blocked on WoWLAN).
    pub async fn arm_wowlan(&mut self) -> Result<bool, WifiError> {
        if self.wowlan_armed {
            return Ok(true);
        }
        let triggers = desired_wowlan_triggers(&self.wowlan_supported_triggers);
        if triggers.is_empty() {
            log::debug!("WoWLAN unsupported; not arming triggers");
            return Ok(false);
        }
        let attrs =
            Nl80211Wowlan::new(self.if_index).triggers(triggers).build();
        match drain_request(self.conn_handle.set_wowlan(attrs).execute().await)
            .await
        {
            Ok(()) => {
                self.wowlan_armed = true;
                log::info!(
                    "WoWLAN triggers armed (disconnect, GTK rekey failure)"
                );
                Ok(true)
            }
            Err(e) => {
                log::warn!("arm WoWLAN failed: {e}");
                Ok(false)
            }
        }
    }

    /// clear WoWLAN triggers (`NL80211_CMD_SET_WOWLAN` with an
    /// empty trigger set), e.g. after a WoWLAN wake or before
    /// shutdown. Best-effort.
    pub async fn disarm_wowlan(&mut self) -> Result<(), WifiError> {
        if !self.wowlan_armed {
            return Ok(());
        }
        let attrs = Nl80211Wowlan::new(self.if_index)
            .triggers(Vec::new())
            .build();
        match drain_request(self.conn_handle.set_wowlan(attrs).execute().await)
            .await
        {
            Ok(()) => {
                self.wowlan_armed = false;
                log::info!("WoWLAN triggers cleared");
                Ok(())
            }
            Err(e) => {
                self.wowlan_armed = false;
                log::warn!("disarm WoWLAN failed: {e}");
                Ok(())
            }
        }
    }

    /// Cleanly disconnect from the AP.  Call this before dropping the
    /// client so the AP receives a proper deauthentication.
    pub async fn shutdown(&mut self) {
        // Stop any running firmware scheduled scan before disconnecting.
        let _ = self.stop_sched_scan().await;
        if self.wowlan_armed
            && let Err(e) = self.disarm_wowlan().await
        {
            log::debug!("disarm WoWLAN on shutdown failed: {e}");
        }
        if let Err(e) =
            connect::disconnect(&mut self.conn_handle, self.if_index).await
        {
            log::debug!("disconnect on shutdown: {e}");
        }
    }
}

impl Drop for WifiIface {
    fn drop(&mut self) {
        let mut conn_handle = self.conn_handle.clone();
        let handle = self.handle.clone();
        let if_index = self.if_index;
        let sched_scan_active = self.sched_scan_active;
        let wowlan_armed = self.wowlan_armed;
        // Best-effort: run the cleanup on a dedicated thread with its own
        // runtime so we never panic outside a tokio context.  The thread
        // is detached; if the process exits first the cleanup is simply
        // lost (same as the old tokio::spawn approach, but without the
        // panic risk).  When the process does exit, the kernel also stops
        // a socket-owned scheduled scan by itself (nl80211_netlink_notify).
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            if let Ok(rt) = rt {
                rt.block_on(async {
                    if sched_scan_active {
                        let _ = drain_request(
                            handle
                                .scan()
                                .schedule_stop_all(if_index)
                                .execute()
                                .await,
                        )
                        .await;
                    }
                    if wowlan_armed {
                        let _ = drain_request(
                            conn_handle
                                .set_wowlan(
                                    Nl80211Wowlan::new(if_index)
                                        .triggers(Vec::new())
                                        .build(),
                                )
                                .execute()
                                .await,
                        )
                        .await;
                    }
                    let _ =
                        connect::disconnect(&mut conn_handle, if_index).await;
                });
            }
        });
    }
}

/// the WoWLAN triggers shuli wants to arm, filtered down to what
/// the wiphy advertises. GTK-rekey-failure is the motivating trigger:
/// while the host is suspended the device must wake it when the AP
/// rekeys the group key (otherwise the association silently loses the
/// new GTK). Disconnect wakes on link loss.
fn desired_wowlan_triggers(
    supported: &[Nl80211WowlanTriggersSupport],
) -> Vec<Nl80211WowlanTriggersSupport> {
    let mut triggers = Vec::new();
    for trigger in [
        Nl80211WowlanTriggersSupport::Disconnect,
        Nl80211WowlanTriggersSupport::GtkRekeyFailure,
    ] {
        if supported.contains(&trigger) {
            triggers.push(trigger);
        }
    }
    triggers
}

/// a WoWLAN wake that invalidates the current connection: the GTK
/// rekey failed while the host was suspended (the group key is unknown,
/// so the old association must be rebuilt) or the device woke on a
/// disconnect.
fn wowlan_wakeup_requires_reconnect(reasons: &[Nl80211WowlanWakeup]) -> bool {
    reasons.iter().any(|reason| {
        matches!(
            reason,
            Nl80211WowlanWakeup::GtkRekeyFailure
                | Nl80211WowlanWakeup::Disconnect
        )
    })
}

/// The error reported to callers when the AP rejects the current
/// credentials/PMKSA with a fatal disconnect reason.
fn fatal_disconnect_error(reason: Option<Ieee80211ReasonCode>) -> WifiError {
    match reason {
        Some(Ieee80211ReasonCode::PrevAuthNotValid) => WifiError::new(
            ErrorKind::WrongPassword,
            "AP rejected authentication (prev_auth_not_valid): the configured \
             password is wrong or the PMKSA is stale",
        ),
        Some(Ieee80211ReasonCode::Ieee8021xFailed) => WifiError::new(
            ErrorKind::AuthFailed,
            "AP rejected 802.1X authentication (ieee8021x_failed): check the \
             configured EAP credentials",
        ),
        _ => WifiError::new(
            ErrorKind::AuthFailed,
            "AP rejected authentication; check the configured credentials",
        ),
    }
}

/// Whether an AP-initiated disconnect reason means a fatal
/// credential/PMKSA problem (retry with the long authentication
/// backoff) instead of a transient failure (short backoff). `None`
/// (no reason was available) is transient.
fn is_fatal_disconnect_reason(reason: Option<Ieee80211ReasonCode>) -> bool {
    matches!(
        reason,
        Some(Ieee80211ReasonCode::PrevAuthNotValid)
            | Some(Ieee80211ReasonCode::Ieee8021xFailed)
    )
}

/// human-readable names for the Transition Disable KDE
/// bitmap bits (bit 0 = WPA3-Personal, 1 = SAE-PK, 2 = WPA3-Enterprise,
/// 3 = Enhanced Open).
fn fmt_transition_disable(bitmap: u8) -> String {
    let mut flags = Vec::new();
    if bitmap & 0x01 != 0 {
        flags.push("WPA3-Personal");
    }
    if bitmap & 0x02 != 0 {
        flags.push("SAE-PK");
    }
    if bitmap & 0x04 != 0 {
        flags.push("WPA3-Enterprise");
    }
    if bitmap & 0x08 != 0 {
        flags.push("Enhanced Open");
    }
    if flags.is_empty() {
        "none".to_string()
    } else {
        flags.join(", ")
    }
}

async fn send_ctrl_port_frame(
    conn_handle: &mut Nl80211ConnectionHandle,
    if_index: u32,
    bssid: [u8; 6],
    frame: &[u8],
) -> Result<(), WifiError> {
    let attrs = Nl80211ControlPortFrame::new(if_index)
        .mac(bssid)
        .frame(frame.to_vec())
        .control_port_ethertype(netlink_packet_core::EthernetProtocol::Pae)
        .build();
    drain_request(conn_handle.control_port_frame(attrs).execute().await).await
}

impl WifiIface {
    /// enable OCV on the 4-way state with our OCI derived
    /// from the BSS frequency, but only when the AP's RSNE actually
    /// advertises OCVC support. Otherwise Message 3 will never carry an
    /// OCI KDE and `verify_oci()` would unconditionally fail the
    /// handshake, so proceed without OCV instead (matches
    /// wpa_supplicant's `wpa_sm_ocv_enabled()`, which requires both the
    /// local config and the AP's OCVC bit). Returns false (and logs)
    /// only when OCV is otherwise usable but the frequency cannot be
    /// mapped to an OCI.
    fn enable_ocv(&self, fw: &mut FourWayState) -> bool {
        if !self.network.ocv {
            return true;
        }
        if !self.bss_info.ap_ocv_capable() {
            log::warn!(
                "OCV requested but AP does not advertise OCVC support; \
                 proceeding without OCV"
            );
            return true;
        }
        match crate::crypto::ocv::oci_from_freq(self.bss_info.freq_mhz) {
            Some(oci) => {
                fw.set_ocv(true, oci, self.bss_info.freq_mhz);
                true
            }
            None => {
                log::warn!(
                    "OCV: cannot map BSS freq {} MHz to an OCI",
                    self.bss_info.freq_mhz
                );
                false
            }
        }
    }

    /// whether Extended Key ID should be requested for
    /// this 4-way handshake - both the network config and the AP's
    /// advertised RSN capability (bit 13) must agree, otherwise Message
    /// 3 will never carry a Key ID KDE and the handshake would
    /// unconditionally fail. Proceed without it (with a warning)
    /// instead, matching the same opportunistic gating as OCV.
    fn ext_key_id_enabled(&self) -> bool {
        if !self.network.ext_key_id {
            return false;
        }
        if !self.bss_info.ap_ext_key_id_capable() {
            log::warn!(
                "Extended Key ID requested but AP does not advertise support \
                 for it; proceeding without it"
            );
            return false;
        }
        true
    }

    /// Send `NL80211_CMD_ASSOCIATE` for the selected BSS.
    ///
    /// `ie` carries the RSN element built for the network's security mode
    /// (plus e.g. the OWE DH Parameter Element); empty for open networks.
    /// `mfp` requests management frame protection (IEEE 802.11w): required
    /// for SAE and OWE, optional for WPA2-PSK (MFPC), absent for open.
    async fn associate(
        &mut self,
        mut ie: Vec<u8>,
        mfp: Option<Nl80211UseMfp>,
    ) -> Result<(), WifiError> {
        // advertise the OCVC RSN capability when OCV is
        // enabled for this network.
        if self.network.ocv {
            elements::rsne_set_ocvc(&mut ie, true);
        }
        if self.network.ext_key_id {
            elements::rsne_set_ext_key_id(&mut ie, true);
        }
        let mut builder = Nl80211Associate::new(self.if_index)
            .ssid(&self.network.ssid)
            .mac(self.bss_info.bssid)
            .frequency(self.bss_info.freq_mhz);
        if !ie.is_empty() {
            builder = builder.ie(ie);
        }
        if let Some(mfp) = mfp {
            builder = builder.use_mfp(mfp);
        }
        // Encrypted networks carry EAPOL over nl80211 and tie the
        // connection's lifetime to this socket; open networks don't.
        if self.bss_info.security != SecurityType::Open {
            builder =
                builder.control_port_over_nl80211(true).socket_owner(true);
        }
        let attrs = builder.build();
        drain_request(self.conn_handle.associate(attrs).execute().await).await
    }
}

impl WifiIface {
    /// The RSNE sent in the association request / 4-way Message 2 for the
    /// current security type, optionally carrying a PMKID (PMKSA caching).
    /// Both sites must stay byte-identical - the AP verifies that.
    fn rsne_with_pmkid(&self, pmkid: Option<[u8; 16]>) -> Vec<u8> {
        match self.bss_info.security {
            SecurityType::Sae => elements::sae_ie_with_pmkid_cipher(
                pmkid,
                self.bss_info.group_mgmt_cipher,
            ),
            SecurityType::SaeExtKey => {
                elements::sae_ext_key_ie_with_pmkid_cipher(
                    pmkid,
                    self.bss_info.group_mgmt_cipher,
                )
            }
            SecurityType::FtSae => elements::ft_sae_ie_cipher(
                pmkid,
                self.bss_info.group_mgmt_cipher,
            ),
            SecurityType::FtSaeExtKey => elements::ft_sae_ext_key_ie_cipher(
                pmkid,
                self.bss_info.group_mgmt_cipher,
            ),
            SecurityType::Wpa2Psk => elements::wpa2_psk_ie_with_pmkid_cipher(
                pmkid,
                self.bss_info.group_mgmt_cipher,
            ),
            SecurityType::Wpa2PskSha256 => {
                elements::wpa2_psk_sha256_ie_with_pmkid_cipher(
                    pmkid,
                    self.bss_info.group_mgmt_cipher,
                )
            }
            SecurityType::Wpa2Ent => {
                elements::wpa2_ent_ie_cipher(self.bss_info.group_mgmt_cipher)
            }
            SecurityType::Wpa2EntSha256 => elements::wpa2_ent_sha256_ie_cipher(
                self.bss_info.group_mgmt_cipher,
            ),
            SecurityType::FtPsk => elements::ft_psk_ie_cipher(
                pmkid,
                self.bss_info.group_mgmt_cipher,
            ),
            SecurityType::Owe => {
                elements::owe_ie_cipher(self.bss_info.group_mgmt_cipher)
            }
            SecurityType::Open | SecurityType::Unsupported => Vec::new(),
        }
    }

    /// associate with the cached PMKID in the RSNE so the AP can
    /// skip the full authentication. MFP stays required for SAE and is
    /// requested on MFP-capable WPA2-PSK APs, matching the full-auth
    /// association.
    async fn associate_with_pmksa(&mut self) {
        let Some(entry) = self.pmksa_in_use.clone() else {
            return;
        };
        log::info!(
            "open-system AUTHENTICATE ok - sending ASSOCIATE with cached PMKID"
        );
        let ie = self.rsne_with_pmkid(Some(entry.pmkid));
        let mfp = match self.bss_info.security {
            SecurityType::Sae
            | SecurityType::SaeExtKey
            | SecurityType::FtSaeExtKey => Some(Nl80211UseMfp::Required),
            _ => self
                .bss_info
                .ap_mfp_capable()
                .then_some(Nl80211UseMfp::Required),
        };
        if let Err(e) = self.associate(ie, mfp).await {
            log::warn!("ASSOCIATE with cached PMKID failed: {e}");
            self.pmksa_fallback().await;
        }
    }

    /// fallback: the AP rejected the cached PMKID (association
    /// rejected) or the handshake over the cached PMK failed (stale
    /// entry). Drop the entry from both caches and retry immediately
    /// with full authentication.
    async fn pmksa_fallback(&mut self) {
        if let Some(entry) = self.pmksa_in_use.take() {
            self.pmksa_cache.invalidate(&entry.ssid, entry.bssid);
            self.driver_del_pmksa(&entry).await;
        }
        if let Err(e) = self.send_out_auth_request().await {
            log::warn!("PMKSA fallback authentication failed: {e}");
            self.state = WifiState::Failed;
        } else {
            self.state = WifiState::Authenticating;
        }
    }

    /// the 4-way handshake proved the PMK - remember the PMKSA for
    /// the next reconnect/roam and hand it to the driver's PMKSA cache.
    /// A reused entry simply gets a fresh lifetime.
    async fn cache_pmksa(&mut self) {
        let entry = match self.pmksa_in_use.take() {
            Some(entry) => entry_with_fresh_lifetime(entry),
            None => {
                let (pmk, pmkid, mic_alg) = match self.bss_info.security {
                    // SAE: the PMKID is derived by the SAE exchange
                    // itself (L(val, 0, 128)); the AP caches that one.
                    SecurityType::Sae => {
                        let Some((pmk, pmkid)) = self
                            .auth
                            .as_ref()
                            .and_then(|a| a.pmk().zip(a.pmkid()))
                        else {
                            return;
                        };
                        (pmk, pmkid, MicAlg::AesCmac)
                    }
                    // SAE-EXT-KEY: same SAE PMK/PMKID derivation; the
                    // 4-way MIC is HMAC-SHA256 (AKM-defined).
                    SecurityType::SaeExtKey => {
                        let Some((pmk, pmkid)) = self
                            .auth
                            .as_ref()
                            .and_then(|a| a.pmk().zip(a.pmkid()))
                        else {
                            return;
                        };
                        (pmk, pmkid, MicAlg::HmacSha256)
                    }
                    // WPA2-PSK: PMKID = Truncate-128(HMAC-SHA1(PMK,
                    // "PMK Name" || AA || SPA)), 802.11-2020 §9.4.2.25.3.
                    SecurityType::Wpa2Psk => {
                        let Some(pmk) = self.psk_pmk else {
                            return;
                        };
                        (
                            pmk,
                            kdf::pmkid_sha1(
                                &pmk,
                                &self.bss_info.bssid,
                                &self.mac,
                            ),
                            MicAlg::HmacSha1,
                        )
                    }
                    // PSK-SHA256: PMKID = Truncate-128(HMAC-SHA256(PMK,
                    // "PMK Name" || AA || SPA)).
                    SecurityType::Wpa2PskSha256 => {
                        let Some(pmk) = self.psk_pmk else {
                            return;
                        };
                        (
                            pmk,
                            kdf::pmkid_sha256(
                                &pmk,
                                &self.bss_info.bssid,
                                &self.mac,
                            ),
                            MicAlg::AesCmac,
                        )
                    }
                    _ => return,
                };
                PmksaEntry {
                    ssid: self.network.ssid.clone(),
                    bssid: self.bss_info.bssid,
                    pmkid,
                    pmk,
                    mic_alg,
                    expires: std::time::Instant::now()
                        + std::time::Duration::from_secs(PMK_LIFETIME_SECS),
                }
            }
        };
        self.driver_set_pmksa(&entry).await;
        log::info!(
            "PMKSA cached: ssid={}, bssid={:02x?}",
            entry.ssid,
            entry.bssid
        );
        self.pmksa_cache.insert(entry);
    }

    /// Hand a PMKSA entry to the driver/firmware cache
    /// (`NL80211_CMD_SET_PMKSA`). Best effort: mac80211-based drivers
    /// (including mac80211_hwsim) return `-EOPNOTSUPP`, and the
    /// userspace cache works without them.
    async fn driver_set_pmksa(&mut self, entry: &PmksaEntry) {
        let attrs = Nl80211Pmksa::new(self.if_index)
            .pmkid(entry.pmkid.to_vec())
            .mac(entry.bssid)
            .pmk(entry.pmk.to_vec())
            .pmk_lifetime(PMK_LIFETIME_SECS as u32)
            .pmk_reauth_threshold(PMK_REAUTH_THRESHOLD_PERCENT)
            .build();
        match drain_request(self.conn_handle.set_pmksa(attrs).execute().await)
            .await
        {
            Ok(()) => log::info!("PMKSA offloaded to driver"),
            Err(e) => log::debug!("driver PMKSA cache not available: {e}"),
        }
    }

    /// Drop a PMKSA entry from the driver/firmware cache
    /// (`NL80211_CMD_DEL_PMKSA`), best effort.
    async fn driver_del_pmksa(&mut self, entry: &PmksaEntry) {
        let attrs = Nl80211Pmksa::new(self.if_index)
            .pmkid(entry.pmkid.to_vec())
            .mac(entry.bssid)
            .build();
        if let Err(e) =
            drain_request(self.conn_handle.del_pmksa(attrs).execute().await)
                .await
        {
            log::debug!("driver del_pmksa not available: {e}");
        }
    }
}

/// Drain the reply stream of a high-level nl80211 request until it closes.
/// Netlink errors surface as stream errors and are converted to
/// [`WifiError`] via the `From<Nl80211Error>` impl.
pub(crate) async fn drain_request<S>(stream: S) -> Result<(), WifiError>
where
    S: futures::TryStream<
            Ok = netlink_packet_generic::GenlMessage<
                wl_nl80211::Nl80211Message,
            >,
            Error = wl_nl80211::Nl80211Error,
        > + Unpin,
{
    let mut stream = stream;
    while let Some(_msg) = stream.try_next().await? {}
    Ok(())
}

pub(crate) async fn get_if_index_and_mac(
    handle: &Nl80211Handle,
    ifname: &str,
) -> Result<(u32, [u8; ETH_ALEN], u32), WifiError> {
    let mut dump = handle.interface().get(vec![]).execute().await;
    while let Some(msg) = dump.try_next().await? {
        if msg.payload.attributes.iter().any(
            |attr| matches!(attr, Nl80211Attr::IfName(name) if name == ifname),
        ) {
            let mut index = 0;
            let mut mac = [0u8; ETH_ALEN];
            let mut wiphy = None;
            for attr in &msg.payload.attributes {
                if let Nl80211Attr::IfIndex(idx) = attr {
                    index = *idx;
                } else if let Nl80211Attr::Mac(mac_addr) = attr {
                    mac.copy_from_slice(mac_addr);
                } else if let Nl80211Attr::Wiphy(w) = attr {
                    wiphy = Some(*w);
                }
            }
            if index != 0 && mac != [0u8; ETH_ALEN] {
                return match wiphy {
                    Some(w) => Ok((index, mac, w)),
                    None => Err(WifiError::new(
                        ErrorKind::Nl80211,
                        format!(
                            "interface {ifname}: wiphy index missing from \
                             netlink message: {msg:?}",
                        ),
                    )),
                };
            } else {
                return Err(WifiError::new(
                    ErrorKind::InterfaceNotFound,
                    format!(
                        "interface {ifname}: index or mac not found in \
                         netlink message: {msg:?}",
                    ),
                ));
            }
        }
    }
    Err(WifiError::new(
        ErrorKind::InterfaceNotFound,
        format!("interface {ifname} not found"),
    ))
}

/// Whether the netlink error is `-EOPNOTSUPP`, i.e. the driver has no
/// `sched_scan_start` op. Netlink NACK codes carry the negated errno.
fn is_eopnotsupp(e: &wl_nl80211::Nl80211Error) -> bool {
    matches!(
        e,
        wl_nl80211::Nl80211Error::NetlinkError(err)
            if err.code == std::num::NonZeroI32::new(-95)
    )
}

/// Build one PNO chunk the way wpa_supplicant does: reserve one slot
/// for the wildcard probe when visible networks are configured, then
/// take a contiguous slice of the rotating hidden SSID list within
/// `cap`. Returns `(ssids, more)` where `more` is true when hidden
/// SSIDs remain for a later chunk.
fn next_sched_scan_ssids(
    hidden_ssids: &[String],
    wildcard: bool,
    cursor: &mut usize,
    cap: usize,
) -> (Vec<String>, bool) {
    let cap = cap.clamp(1, MAX_SCHED_SCAN_SSIDS);
    let specific_cap = cap - if wildcard { 1 } else { 0 };
    let mut ssids = Vec::new();
    if wildcard {
        ssids.push(String::new());
    }
    let mut idx = (*cursor).min(hidden_ssids.len());
    let mut added = 0usize;
    while idx < hidden_ssids.len() && added < specific_cap {
        ssids.push(hidden_ssids[idx].clone());
        idx += 1;
        added += 1;
    }
    let more = idx < hidden_ssids.len();
    *cursor = if more { idx } else { 0 };
    (ssids, more)
}

/// Hardware scheduled scan (PNO) capabilities of the wiphy owning
/// `wiphy_idx`. The kernel omits
/// `NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS` for drivers without a
/// `sched_scan_start` op, so its presence means the feature is
/// available.
pub(crate) struct WiphySchedScanCaps {
    pub(crate) supported: bool,
    pub(crate) max_ssids: usize,
    pub(crate) max_match_sets: usize,
}

pub(crate) async fn wiphy_sched_scan_caps(
    handle: &Nl80211Handle,
    wiphy_idx: u32,
) -> Result<WiphySchedScanCaps, WifiError> {
    let mut dump = handle.wireless_physic().get().execute().await;
    while let Some(msg) = dump.try_next().await? {
        let mut idx = None;
        let mut max_ssids = 0u8;
        let mut max_match_sets = 0u8;
        for attr in &msg.payload.attributes {
            match attr {
                Nl80211Attr::Wiphy(i) => idx = Some(*i),
                Nl80211Attr::MaxNumSchedScanSsids(n) => max_ssids = *n,
                Nl80211Attr::MaxMatchSets(n) => max_match_sets = *n,
                _ => {}
            }
        }
        if idx == Some(wiphy_idx) {
            return Ok(WiphySchedScanCaps {
                supported: max_ssids > 0,
                max_ssids: max_ssids as usize,
                max_match_sets: max_match_sets as usize,
            });
        }
    }
    Ok(WiphySchedScanCaps {
        supported: false,
        max_ssids: 0,
        max_match_sets: 0,
    })
}

/// The maximum number of SSIDs the wiphy accepts in one scan request
/// (`NL80211_ATTR_MAX_NUM_SCAN_SSIDS`). Returns 0 when the kernel did
/// not advertise the attribute.
pub(crate) async fn wiphy_max_scan_ssids(
    handle: &Nl80211Handle,
    wiphy_idx: u32,
) -> Result<u8, WifiError> {
    let mut dump = handle.wireless_physic().get().execute().await;
    while let Some(msg) = dump.try_next().await? {
        let mut idx = None;
        let mut max_ssids = 0u8;
        for attr in &msg.payload.attributes {
            match attr {
                Nl80211Attr::Wiphy(i) => idx = Some(*i),
                Nl80211Attr::MaxNumScanSsids(n) => max_ssids = *n,
                _ => {}
            }
        }
        if idx == Some(wiphy_idx) {
            return Ok(max_ssids);
        }
    }
    Ok(0)
}

/// the WoWLAN triggers the wiphy owning `wiphy_idx` advertises via
/// `NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED` (empty when the driver has
/// no WoWLAN support).
async fn wiphy_wowlan_support(
    handle: &Nl80211Handle,
    wiphy_idx: u32,
) -> Result<Vec<Nl80211WowlanTriggersSupport>, WifiError> {
    let mut dump = handle.wireless_physic().get().execute().await;
    while let Some(msg) = dump.try_next().await? {
        let mut idx = None;
        let mut triggers = Vec::new();
        for attr in &msg.payload.attributes {
            match attr {
                Nl80211Attr::Wiphy(i) => idx = Some(*i),
                Nl80211Attr::WowlanTriggersSupport(supported) => {
                    triggers.clone_from(supported)
                }
                _ => {}
            }
        }
        if idx == Some(wiphy_idx) {
            return Ok(triggers);
        }
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use wl_nl80211::{
        Ieee80211ReasonCode, Nl80211WowlanTriggersSupport, Nl80211WowlanWakeup,
    };

    use super::{
        MAX_SCHED_SCAN_SSIDS, desired_wowlan_triggers, fatal_disconnect_error,
        fmt_transition_disable, is_fatal_disconnect_reason,
        next_sched_scan_ssids, wowlan_wakeup_requires_reconnect,
    };

    /// reasons 2 (PREV_AUTH_NOT_VALID) and 23
    /// (IEEE_802_1X_AUTH_FAILED) mean a fatal credential/PMKSA problem
    /// and must use the long authentication backoff; every other
    /// reason (and a missing one) is transient.
    #[test]
    fn fatal_disconnect_reasons_are_2_and_23() {
        assert!(is_fatal_disconnect_reason(Some(
            Ieee80211ReasonCode::PrevAuthNotValid
        )));
        assert!(is_fatal_disconnect_reason(Some(
            Ieee80211ReasonCode::Ieee8021xFailed
        )));
    }

    #[test]
    fn fatal_disconnect_error_reports_wrong_password() {
        let err =
            fatal_disconnect_error(Some(Ieee80211ReasonCode::PrevAuthNotValid));
        assert_eq!(err.kind, crate::ErrorKind::WrongPassword);
        assert!(
            err.to_string().contains("password is wrong"),
            "unexpected error: {err}"
        );

        let err =
            fatal_disconnect_error(Some(Ieee80211ReasonCode::Ieee8021xFailed));
        assert_eq!(err.kind, crate::ErrorKind::AuthFailed);
    }

    #[test]
    fn transient_disconnect_reasons() {
        for reason in [
            Ieee80211ReasonCode::Unspecified,
            Ieee80211ReasonCode::DeauthLeaving,
            Ieee80211ReasonCode::DisassocDueToInactivity,
            Ieee80211ReasonCode::MicFailure,
            Ieee80211ReasonCode::GroupKeyHandshakeTimeout,
        ] {
            assert!(
                !is_fatal_disconnect_reason(Some(reason)),
                "{reason:?} must be transient"
            );
        }
        // A disconnect without a parseable reason is transient.
        assert!(!is_fatal_disconnect_reason(None));
    }

    /// only triggers the wiphy actually advertises are armed, and
    /// GTK-rekey-failure alone is enough to enable WoWLAN.
    #[test]
    fn wowlan_desired_triggers_filtered_by_support() {
        let all = vec![
            Nl80211WowlanTriggersSupport::Disconnect,
            Nl80211WowlanTriggersSupport::GtkRekeyFailure,
        ];
        assert_eq!(desired_wowlan_triggers(&all), all);

        let rekey_only = vec![Nl80211WowlanTriggersSupport::GtkRekeyFailure];
        assert_eq!(
            desired_wowlan_triggers(&rekey_only),
            vec![Nl80211WowlanTriggersSupport::GtkRekeyFailure]
        );

        let none = vec![Nl80211WowlanTriggersSupport::MagicPkt];
        assert!(desired_wowlan_triggers(&none).is_empty());
    }

    /// a GTK-rekey-failure or disconnect wake must rebuild the
    /// connection; any other wake (magic packet, rfkill, ...) does not
    /// invalidate it.
    #[test]
    fn wowlan_wakeup_reconnect_reasons() {
        assert!(wowlan_wakeup_requires_reconnect(&[
            Nl80211WowlanWakeup::GtkRekeyFailure
        ]));
        assert!(wowlan_wakeup_requires_reconnect(&[
            Nl80211WowlanWakeup::Disconnect
        ]));
        assert!(!wowlan_wakeup_requires_reconnect(&[
            Nl80211WowlanWakeup::MagicPkt
        ]));
        assert!(!wowlan_wakeup_requires_reconnect(&[
            Nl80211WowlanWakeup::Any
        ]));
        assert!(!wowlan_wakeup_requires_reconnect(&[]));
    }

    /// the Transition Disable bitmap maps to the AKM group
    /// names (bit 0 = WPA3-Personal, 1 = SAE-PK, 2 = WPA3-Enterprise,
    /// 3 = Enhanced Open).
    #[test]
    fn transition_disable_bitmap_names() {
        let s = fmt_transition_disable(0x01);
        assert!(s.contains("WPA3-Personal"));
        assert!(!s.contains("Enhanced Open"));
        let s = fmt_transition_disable(0x08);
        assert!(s.contains("Enhanced Open"));
        assert!(!s.contains("WPA3-Personal"));
        let s = fmt_transition_disable(0x0F);
        assert_eq!(s, "WPA3-Personal, SAE-PK, WPA3-Enterprise, Enhanced Open");
        assert_eq!(fmt_transition_disable(0), "none");
    }

    #[test]
    fn sched_scan_chunk_reserves_wildcard_and_rotates() {
        let hidden: Vec<String> =
            ["A", "B", "C", "D"].iter().map(|s| s.to_string()).collect();
        let mut cursor = 0;
        let (round, more) =
            next_sched_scan_ssids(&hidden, true, &mut cursor, 4);
        assert_eq!(round, vec!["", "A", "B", "C"]);
        assert!(more);
        assert_eq!(cursor, 3);

        let (round, more) =
            next_sched_scan_ssids(&hidden, true, &mut cursor, 4);
        assert_eq!(round, vec!["", "D"]);
        assert!(!more);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn sched_scan_chunk_fits_all_hidden_ssids() {
        let hidden: Vec<String> =
            ["A", "B"].iter().map(|s| s.to_string()).collect();
        let mut cursor = 0;
        let (round, more) =
            next_sched_scan_ssids(&hidden, false, &mut cursor, 4);
        assert_eq!(round, vec!["A", "B"]);
        assert!(!more);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn sched_scan_chunk_caps_at_wpa_supplicant_max() {
        let hidden: Vec<String> = (0..20).map(|i| format!("S{i:02}")).collect();
        let mut cursor = 0;
        let (round, more) =
            next_sched_scan_ssids(&hidden, true, &mut cursor, 255);
        assert_eq!(round.len(), MAX_SCHED_SCAN_SSIDS);
        assert_eq!(round[0], "");
        assert_eq!(round[1], "S00");
        assert_eq!(round[15], "S14");
        assert!(more);
        assert_eq!(cursor, 15);

        let (round, more) =
            next_sched_scan_ssids(&hidden, true, &mut cursor, 255);
        assert_eq!(round, vec!["", "S15", "S16", "S17", "S18", "S19"]);
        assert!(!more);
        assert_eq!(cursor, 0);
    }
}
