// SPDX-License-Identifier: Apache-2.0

use wl_nl80211::Nl80211WowlanTriggersSupport;

use super::{
    AuthMethod, EapPeer, FourWayState, Nl80211EventReceiver, OweAuth,
    PmksaCache, PmksaEntry, SCHED_SCAN_INTERVAL_SEC, SCHED_SCAN_WATCHDOG_SECS,
};
use crate::{
    BssInfo, ETH_ALEN, NetworkConfig, ShuliNl80211Connection, WifiConfig,
    WifiError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
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

pub(crate) struct IfaceCore {
    pub(crate) nl: ShuliNl80211Connection,
    pub(crate) event_receiver: Nl80211EventReceiver,
    pub(crate) config: WifiConfig,
}

/// Capabilities probed once from the wiphy and shared by every scan,
/// PNO and WoWLAN operation on this interface.
pub(crate) struct WiphyCaps {
    /// Whether the driver advertises hardware scheduled scan (PNO)
    /// support.
    pub(crate) sched_scan_supported: bool,
    /// Maximum number of SSIDs the wiphy accepts in one scheduled-scan
    /// request (`NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS`).
    pub(crate) max_sched_scan_ssids: usize,
    /// Maximum number of match sets the wiphy accepts in one scheduled
    /// scan (`NL80211_ATTR_MAX_MATCH_SETS`); 0 means no filtering.
    pub(crate) max_match_sets: usize,
    /// Maximum number of SSIDs the wiphy accepts in one scan request
    /// (`NL80211_ATTR_MAX_NUM_SCAN_SSIDS`). Hidden SSIDs are rotated
    /// through this cap with a wildcard entry reserved, exactly like
    /// wpa_supplicant.
    pub(crate) max_scan_ssids: usize,
    /// The WoWLAN triggers the wiphy advertises (e.g.
    /// `GtkRekeyFailure`), as reported by
    /// `NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED`. Empty when the driver
    /// has no WoWLAN support.
    pub(crate) wowlan_supported_triggers: Vec<Nl80211WowlanTriggersSupport>,
}

/// Host scan and hardware scheduled-scan (PNO) state, including the
/// per-cycle backoff and SSID rotation cursors.
pub(crate) struct ScanEngine {
    /// Current scan-retry backoff in seconds; doubles after each scan
    /// that fails to find the SSID (capped at `RETRY_BACKOFF_MAX_SEC`)
    /// and resets to `RETRY_BACKOFF_INIT_SEC` once the SSID is found or
    /// a connection is established.
    pub(crate) scan_retry_interval: u64,
    /// Whether a scheduled scan is currently running in the firmware.
    pub(crate) sched_scan_active: bool,
    /// A stop was requested and the kernel's `SCHED_SCAN_STOPPED` echo
    /// has not been consumed yet. The kernel multicasts that event for
    /// every stop - including our own - so this flag lets
    /// [`WifiState::SchedScanWait`] tell our own echo from a genuine
    /// firmware abort.
    pub(crate) sched_scan_stop_pending: bool,
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
    /// Index of the next hidden SSID to probe (wpa_supplicant-style
    /// rotation across scans).
    pub(crate) scan_ssid_cursor: usize,
    /// Drivers accepting only one SSID per scan get wildcard and
    /// specific-SSID scans interleaved (wpa_supplicant's
    /// `prev_scan_wildcard`); true when the next round should be the
    /// wildcard probe.
    pub(crate) scan_wildcard_next: bool,
    /// Whether the next connection attempt may use the configured
    /// network hints: a complete hint set is tried scan-free, otherwise
    /// the first host scan is restricted to hinted frequencies. Cleared
    /// once either path has been tried.
    pub(crate) hint_scan: bool,
}

/// State that lives with the current target/association: the selected
/// network and BSS, plus the 4-way/FT state that survives until the
/// next disconnect.
pub(crate) struct Link {
    /// The configured network whose BSS the scan phase selected; carries
    /// the passphrase used for authentication.
    pub(crate) network: NetworkConfig,
    /// Best BSS found by the scan phase.
    pub(crate) bss_info: BssInfo,
    /// 4-way handshake state (shared by all auth methods).
    pub(crate) fourway: Option<FourWayState>,
    /// The PMKSA entry of the connection attempt in flight, when the
    /// association is (to be) done with a cached PMKID.
    pub(crate) pmksa_in_use: Option<PmksaEntry>,
    /// FT key context of the current connection (802.11r roaming).
    pub(crate) ft: Option<crate::roam::FtContext>,
    /// A 4-way Message 1 that arrived before the FT context could be
    /// built from the association response event (the two can race).
    pub(crate) pending_ft_msg1: Option<Vec<u8>>,
}

/// Per-attempt pre-association and key-derivation state. Reset at the
/// start of every new connection attempt.
#[derive(Default)]
pub(crate) struct AuthSession {
    /// Active pre-association authentication method.
    pub(crate) method: Option<AuthMethod>,
    /// OWE DH exchange state (only for OWE networks).
    pub(crate) owe: Option<OweAuth>,
    /// WPA2-PSK PMK derived via PBKDF2 (only for WPA2-PSK networks).
    pub(crate) psk_pmk: Option<[u8; 32]>,
    /// EAP peer state machine for 802.1X networks
    /// (WPA2-Enterprise / later wired 802.1X).
    pub(crate) eap_peer: Option<EapPeer>,
    /// PMK derived from the EAP MSK after EAP-Success (enterprise).
    pub(crate) eap_pmk: Option<[u8; 32]>,
    /// SAE commit retransmission state. `sae_commit_sent` is true
    /// while we await the AP's commit; on a timeout the same commit is
    /// re-sent (the 802.11 SAE Sync counter, max 3) instead of paying a
    /// full rescan cycle for one lost frame.
    pub(crate) sae_commit_sent: bool,
    /// SAE Sync counter: number of commit retransmissions so far.
    pub(crate) sae_sync: u8,
    /// The last SAE commit auth_data, re-sent verbatim on a timeout.
    pub(crate) sae_commit_auth_data: Vec<u8>,
    /// An H2E commit was rejected and the exchange restarted with
    /// hunting-and-pecking (never retried a second time).
    pub(crate) sae_hnp_attempted: bool,
}

/// Roaming state: in-flight FT roams, roam scans, BTM/RRM bookkeeping
/// and the CQM/background-scan triggers.
#[derive(Default)]
pub(crate) struct RoamEngine {
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
}

/// WoWLAN state that changes at runtime. The supported trigger set is
/// part of [`WiphyCaps`].
#[derive(Default)]
pub(crate) struct WowlanState {
    /// Whether WoWLAN triggers are currently armed on the device.
    pub(crate) armed: bool,
}

impl ScanEngine {
    /// Start a fresh SSID rotation cycle for both host scans and PNO.
    pub(crate) fn reset_rotation(&mut self) {
        self.scan_ssid_cursor = 0;
        self.scan_wildcard_next = true;
        self.sched_scan_cursor = 0;
        self.sched_scan_more = false;
        self.sched_scan_rotate = false;
        self.sched_scan_first = true;
        self.sched_scan_interval_sec = SCHED_SCAN_INTERVAL_SEC;
        self.sched_scan_timeout_secs = SCHED_SCAN_WATCHDOG_SECS;
        self.hint_scan = true;
    }
}

impl Link {
    /// Reset every per-association field, keeping the interface core and
    /// PMKSA cache intact.
    pub(crate) fn reset_for_update(&mut self, network: NetworkConfig) {
        self.network = network;
        self.bss_info = BssInfo::default();
        self.fourway = None;
        self.pmksa_in_use = None;
        self.ft = None;
        self.pending_ft_msg1 = None;
    }
}

impl AuthSession {
    /// Drop all per-attempt key and EAP/SAE state.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}

impl RoamEngine {
    /// Drop the per-attempt roam, BTM/RRM and cooldown bookkeeping that
    /// must not survive a network-list update. Runtime CQM and
    /// background-scan flags keep their previous reset scope.
    pub(crate) fn reset(&mut self) {
        self.ft_roam = None;
        self.roam_scan = false;
        self.pre_roam_state = None;
        self.roam_target = None;
        self.last_scan_candidates.clear();
        self.roam_freqs.clear();
        self.roam_scan_full = false;
        self.pending_nr_dialog = None;
        self.neighbor_report_responses = 0;
        self.last_roam = None;
    }
}

pub(crate) struct WifiIface {
    pub(crate) core: IfaceCore,
    pub(crate) caps: WiphyCaps,
    pub(crate) scan: ScanEngine,
    pub(crate) link: Link,
    pub(crate) auth: AuthSession,
    pub(crate) roam: RoamEngine,
    pub(crate) wowlan: WowlanState,
    pub(crate) state: WifiState,
    /// PMKSA cache: reconnects and roams to a cached BSS
    /// skip the full authentication.
    pub(crate) pmksa_cache: PmksaCache,
    /// The most recent connection/auth error attached to a state
    /// change, surfaced once to the caller by `run()` (e.g. a
    /// wrong-password rejection). Cleared when reported.
    pub(crate) last_error: Option<WifiError>,
}
