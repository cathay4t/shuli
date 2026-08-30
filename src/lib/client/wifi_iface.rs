// SPDX-License-Identifier: Apache-2.0

use futures::StreamExt;
use wl_nl80211::{Ieee80211ReasonCode, Nl80211Command, Nl80211WowlanWakeup};

use super::{
    AUTH_EVENT_TIMEOUT_SECS, AuthMethod, AuthSession, ErrorKind, IfaceCore,
    Link, MAX_SCHED_SCAN_SSIDS, NetworkConfig, Nl80211Attr, Nl80211Disconnect,
    Nl80211Event, Nl80211EventReceiver, Nl80211SchedScanMatch,
    Nl80211SchedScanMatchAttr, Nl80211SchedScanPlan, Nl80211SchedScanPlanAttr,
    Nl80211Wowlan, Nl80211WowlanTriggersSupport, PmksaCache, RETRY_AUTH_SEC,
    RETRY_BACKOFF_INIT_SEC, RETRY_BACKOFF_MAX_SEC, ROAM_SIGNAL_CHECK_SECS,
    RoamEngine, SAE_COMMIT_RETRANSMIT_TIMEOUT_SECS, SAE_SYNC_MAX,
    SCHED_SCAN_INTERVAL_SEC, SCHED_SCAN_STOP_ECHO_TIMEOUT_SECS,
    SCHED_SCAN_WATCHDOG_SECS, ScanEngine, ShuliNl80211Connection, WifiConfig,
    WifiError, WifiIface, WifiState, WiphyCaps, WowlanState, drain_request,
    format_ssids, is_eopnotsupp, next_sched_scan_ssids, wiphy_sched_scan_caps,
    wiphy_wowlan_support,
};
use crate::{
    BssInfo, ETH_ALEN,
    nl80211::{ClientEvent, parse_client_event},
};

impl WifiIface {
    /// Pick the first configured network whose hints are complete
    /// enough for a scan-free connection attempt.
    fn scan_free_target(&self) -> Option<(NetworkConfig, BssInfo)> {
        self.core.config.networks.iter().find_map(|network| {
            let bss_info = network.hints.bss_info()?;
            Some((network.clone(), bss_info))
        })
    }

    /// Validate the configuration and prepare one interface state machine.
    /// The nl80211 connection is shared with every other interface in the
    /// parent [`WifiClient`].
    pub(crate) async fn init(
        mut nl: ShuliNl80211Connection,
        event_receiver: Nl80211EventReceiver,
        config: WifiConfig,
    ) -> Result<Self, WifiError> {
        let if_index = nl.if_index;
        let mac = nl.mac;
        let wiphy_idx = nl.wiphy_index;

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
            match wiphy_sched_scan_caps(&nl.handle, wiphy_idx).await {
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
        let max_scan_ssids = if nl.wiphy_max_scan_count > 0 {
            nl.wiphy_max_scan_count as usize
        } else {
            log::debug!(
                "wiphy {wiphy_idx} advertises no per-scan SSID cap; using \
                 wildcard-only scans"
            );
            1
        };

        // detect WoWLAN trigger support once, so arming a
        // `wowlan: true` network is a no-op (and clearly logged) on
        // drivers without it.
        let wowlan_supported_triggers =
            match wiphy_wowlan_support(&nl.handle, wiphy_idx).await {
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
            match nl.set_wowlan(attrs).await {
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

        let core = IfaceCore {
            nl,
            event_receiver,
            config,
        };
        let caps = WiphyCaps {
            sched_scan_supported,
            max_sched_scan_ssids,
            max_match_sets,
            max_scan_ssids,
            wowlan_supported_triggers,
        };
        let scan = ScanEngine {
            scan_retry_interval: RETRY_BACKOFF_INIT_SEC,
            sched_scan_active: false,
            sched_scan_stop_pending: false,
            sched_scan_cursor: 0,
            sched_scan_more: false,
            sched_scan_rotate: false,
            sched_scan_interval_sec: SCHED_SCAN_INTERVAL_SEC,
            sched_scan_timeout_secs: SCHED_SCAN_WATCHDOG_SECS,
            sched_scan_first: true,
            scan_ssid_cursor: 0,
            scan_wildcard_next: true,
            hint_scan: true,
        };
        let link = Link {
            network,
            bss_info: BssInfo::default(),
            fourway: None,
            pmksa_in_use: None,
            ft: None,
            pending_ft_msg1: None,
        };

        let mut client = WifiIface {
            core,
            caps,
            scan,
            link,
            auth: AuthSession::default(),
            roam: RoamEngine::default(),
            wowlan: WowlanState::default(),
            state: WifiState::Init,
            pmksa_cache: PmksaCache::default(),
            last_error: None,
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
            self.roam.pre_roam_state.unwrap_or(self.state)
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
                && self.roam.pre_roam_state.is_some();
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
    pub(crate) fn fail_auth(&mut self, error: WifiError) {
        self.last_error = Some(error);
        self.state = WifiState::FailedAuthentication;
    }

    pub(crate) async fn _run(&mut self) -> Result<(), WifiError> {
        // With no configured networks the client idles: never start a
        // scan with an empty SSID list. Sleep instead of busy-looping so
        // a multi-interface `WifiClient` can keep an empty interface
        // without spinning the runtime.
        if self.core.config.networks.is_empty() {
            self.state = WifiState::Init;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            return Ok(());
        }
        match self.state {
            WifiState::Init => {
                if self.scan.hint_scan
                    && let Some((network, bss_info)) = self.scan_free_target()
                {
                    self.scan.hint_scan = false;
                    self.link.network = network;
                    self.link.bss_info = bss_info;
                    log::info!(
                        "scan-free connect: ssid={}, bssid={:02x?}, freq={} \
                         MHz",
                        self.link.network.ssid,
                        self.link.bss_info.bssid,
                        self.link.bss_info.freq_mhz
                    );
                    self.send_out_auth_request().await?;
                    self.state = WifiState::Authenticating;
                } else {
                    self.send_out_scan_request().await?;
                    self.state = WifiState::Scanning;
                }
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
                if self.roam.roam_scan {
                    // Roam scan: evaluate candidates while staying on the
                    // current BSS.
                    self.roam.roam_scan = false;
                    self.process_roam_scan_results().await;
                    // The roam scan fell back to a full scan and it is
                    // already in flight: keep Scanning (and the recorded
                    // pre-roam state) for the next iteration.
                    if self.roam.roam_scan {
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
                        && let Some(prev) = self.roam.pre_roam_state.take()
                    {
                        self.state = prev;
                    }
                    self.roam.pre_roam_state = None;
                    return Ok(());
                }
                if let Err(e) = self.process_scan_results().await {
                    // A hinted-frequency scan missed: retry once with a
                    // full scan before handing the periodic search over
                    // to PNO / host-side backoff.
                    if e.kind == ErrorKind::SsidNotFound && self.scan.hint_scan
                    {
                        self.scan.hint_scan = false;
                        log::debug!(
                            "no configured SSID found on hinted frequencies; \
                             falling back to full scan"
                        );
                        self.send_out_scan_request().await?;
                        return Ok(());
                    }
                    // SSID not found: hand the periodic scanning over to
                    // the firmware (PNO) when supported, otherwise fall
                    // back to host-side scans with exponential backoff.
                    if e.kind == ErrorKind::SsidNotFound {
                        // A fresh PNO session starts from the first
                        // hidden SSID with reset rotation timing
                        // (wpa_supplicant resets `prev_sched_ssid`).
                        self.scan.sched_scan_cursor = 0;
                        self.scan.sched_scan_more = false;
                        self.scan.sched_scan_rotate = false;
                        self.scan.sched_scan_first = true;
                        if self.start_sched_scan().await? {
                            log::info!(
                                "no configured SSID ([{}]) found; entering \
                                 scheduled scan mode",
                                self.core
                                    .config
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
                self.scan.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
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
                let wait_secs = if self.scan.sched_scan_stop_pending {
                    SCHED_SCAN_STOP_ECHO_TIMEOUT_SECS
                } else if self.scan.sched_scan_more {
                    self.scan.sched_scan_timeout_secs
                } else {
                    SCHED_SCAN_WATCHDOG_SECS
                };
                let timed = tokio::time::timeout(
                    std::time::Duration::from_secs(wait_secs),
                    self.core.event_receiver.next(),
                )
                .await;
                match timed {
                    Ok(Some(raw_msg)) => {
                        if let Some(event) = parse_client_event(raw_msg) {
                            match event {
                                ClientEvent::Nl80211(
                                    Nl80211Event::Unknown {
                                        cmd: Nl80211Command::SchedScanResults,
                                    },
                                ) => {
                                    self.handle_sched_scan_results().await?;
                                }
                                ClientEvent::Nl80211(
                                    Nl80211Event::Unknown {
                                        cmd: Nl80211Command::SchedScanStopped,
                                    },
                                ) => {
                                    if self.scan.sched_scan_stop_pending {
                                        // Echo of our own stop request
                                        // (rotation or watchdog fallback);
                                        // the firmware scan is gone.
                                        self.scan.sched_scan_stop_pending =
                                            false;
                                        if self.scan.sched_scan_rotate {
                                            self.scan.sched_scan_rotate = false;
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
                                        self.scan.sched_scan_active = false;
                                        if !self.start_sched_scan().await? {
                                            self.state = WifiState::Failed;
                                        }
                                    }
                                }
                                other => self.handle_client_event(other).await,
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
                        if self.scan.sched_scan_stop_pending {
                            // The stop echo was lost; force the rotation
                            // (or restart) that was in flight.
                            self.scan.sched_scan_stop_pending = false;
                            if self.scan.sched_scan_rotate {
                                self.scan.sched_scan_rotate = false;
                                log::info!(
                                    "scheduled scan stop echo lost; rotating \
                                     to the next SSID chunk"
                                );
                                if !self.start_sched_scan().await? {
                                    self.state = WifiState::Failed;
                                }
                            }
                        } else if self.scan.sched_scan_more {
                            // This chunk ran long enough: stop it and let
                            // the STOPPED echo start the next chunk.
                            log::info!(
                                "scheduled scan chunk timed out after {}s; \
                                 rotating to the next SSID chunk",
                                self.scan.sched_scan_timeout_secs
                            );
                            self.scan.sched_scan_rotate = true;
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
                    let wait_secs = if self.auth.sae_commit_sent
                        && self.auth.sae_sync < SAE_SYNC_MAX
                    {
                        SAE_COMMIT_RETRANSMIT_TIMEOUT_SECS
                    } else {
                        AUTH_EVENT_TIMEOUT_SECS
                    };
                    let timed = tokio::time::timeout(
                        std::time::Duration::from_secs(wait_secs),
                        self.core.event_receiver.next(),
                    )
                    .await;
                    match timed {
                        Ok(Some(raw_msg)) => {
                            if let Some(event) = parse_client_event(raw_msg) {
                                self.handle_client_event(event).await;
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
                            if self.auth.sae_commit_sent
                                && self.auth.sae_sync < SAE_SYNC_MAX
                            {
                                // retransmit the pending SAE commit.
                                self.auth.sae_sync += 1;
                                log::info!(
                                    "SAE commit timed out - retransmitting \
                                     (sync {}/{})",
                                    self.auth.sae_sync,
                                    SAE_SYNC_MAX
                                );
                                self.send_sae_commit(
                                    &self.auth.sae_commit_auth_data.clone(),
                                )
                                .await;
                                continue;
                            }
                            // Some APs silently drop the H2E commit
                            // instead of answering with a rejection
                            // status.  Retry once with
                            // hunting-and-pecking before giving up.
                            if let Some(AuthMethod::Sae(sae)) =
                                self.auth.method.as_ref()
                                && sae.is_h2e()
                                && sae.hnp_fallback_allowed()
                                && !self.auth.sae_hnp_attempted
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
                                && self.link.fourway.is_some()
                            {
                                let err = WifiError::wrong_password(
                                    &self.link.network.ssid,
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
                let ap_roams = self.link.network.roaming
                    && self.link.bss_info.ap_supports_signal_roam();
                if !self.roam.cqm_armed && ap_roams {
                    self.roam.cqm_armed = self.arm_cqm().await;
                }
                let wait_secs = if ap_roams {
                    if self.roam.cqm_armed {
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
                        self.core.event_receiver.next(),
                    )
                    .await
                } else {
                    Ok(self.core.event_receiver.next().await)
                };
                match next {
                    Ok(Some(raw_msg)) => {
                        if let Some(event) = parse_client_event(raw_msg) {
                            self.handle_client_event(event).await;
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
                        if self.roam.cqm_armed {
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
                if self.scan.sched_scan_active {
                    let _ = self.stop_sched_scan().await;
                }
                let secs = if self.state == WifiState::FailedAuthentication {
                    RETRY_AUTH_SEC
                } else {
                    self.scan.scan_retry_interval
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
                        self.core.event_receiver.next(),
                    )
                    .await
                    {
                        Ok(Some(raw_msg)) => {
                            if let Some(event) = parse_client_event(raw_msg) {
                                self.handle_client_event(event).await;
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
                    self.scan.scan_retry_interval =
                        (self.scan.scan_retry_interval * 2)
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
    pub(crate) async fn start_sched_scan(&mut self) -> Result<bool, WifiError> {
        if !self.caps.sched_scan_supported {
            return Ok(false);
        }
        let cap = self.caps.max_sched_scan_ssids.min(MAX_SCHED_SCAN_SSIDS);
        if cap == 0 {
            return Ok(false);
        }

        let hidden_ssids: Vec<String> = self
            .core
            .config
            .hidden_ssids()
            .map(str::to_string)
            .collect();
        let wildcard = self.core.config.networks.iter().any(|n| !n.hidden);
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
        if self.scan.sched_scan_first {
            self.scan.sched_scan_interval_sec = SCHED_SCAN_INTERVAL_SEC;
            self.scan.sched_scan_timeout_secs = (cap as u64) * 2;
            self.scan.sched_scan_first = false;
        }

        let (ssids, more) = next_sched_scan_ssids(
            &hidden_ssids,
            wildcard,
            &mut self.scan.sched_scan_cursor,
            cap,
        );
        self.scan.sched_scan_more = more;

        // Match sets wake the host only for configured SSIDs; when more
        // are configured than the driver can filter, drop the filter
        // entirely (wpa_supplicant does the same) so every scan result
        // is reported instead of silently missing networks.
        let match_sets = if self.caps.max_match_sets > 0
            && self.core.config.networks.len() <= self.caps.max_match_sets
        {
            Some(
                self.core
                    .config
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
            Nl80211Attr::IfIndex(self.core.nl.if_index),
            // Active probe for this chunk's hidden SSIDs plus the
            // wildcard entry for visible networks...
            Nl80211Attr::ScanSsids(ssids.clone()),
            Nl80211Attr::SchedScanPlans(vec![Nl80211SchedScanPlan(vec![
                Nl80211SchedScanPlanAttr::Interval(
                    self.scan.sched_scan_interval_sec,
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
        let result = self.core.nl.start_sched_scan(attrs).await;
        match result {
            Ok(()) => {
                self.scan.sched_scan_active = true;
                log::info!(
                    "scheduled scan started: ssids=[{}], interval={}s, \
                     chunk_timeout={}s{}",
                    format_ssids(&ssids),
                    self.scan.sched_scan_interval_sec,
                    self.scan.sched_scan_timeout_secs,
                    if more { ", more SSIDs pending" } else { "" }
                );
                if more {
                    // Throttle the rotation like wpa_supplicant: each
                    // subsequent chunk runs for a shorter timeout with a
                    // longer scan interval, resetting when the interval
                    // grows too large.
                    self.scan.sched_scan_timeout_secs =
                        (self.scan.sched_scan_timeout_secs / 2).max(2);
                    self.scan.sched_scan_interval_sec =
                        (self.scan.sched_scan_interval_sec * 2)
                            .min(RETRY_BACKOFF_MAX_SEC as u32);
                    if self.scan.sched_scan_timeout_secs
                        < self.scan.sched_scan_interval_sec as u64
                    {
                        self.scan.sched_scan_interval_sec =
                            SCHED_SCAN_INTERVAL_SEC;
                        self.scan.sched_scan_timeout_secs = (cap as u64) * 2;
                    }
                } else {
                    // Full coverage in one chunk: the next start begins a
                    // fresh cycle with reset timing.
                    self.scan.sched_scan_first = true;
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
                    self.caps.sched_scan_supported = false;
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
    pub(crate) async fn stop_sched_scan(&mut self) -> Result<(), WifiError> {
        if !self.scan.sched_scan_active {
            return Ok(());
        }
        self.scan.sched_scan_active = false;
        self.scan.sched_scan_stop_pending = true;
        match self.core.nl.stop_sched_scan().await {
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
    pub(crate) async fn handle_sched_scan_results(
        &mut self,
    ) -> Result<(), WifiError> {
        log::debug!("scheduled scan results event");
        match self.process_scan_results().await {
            Ok(()) => {
                // SSID found - stop the firmware scan and connect.
                self.scan.sched_scan_rotate = false;
                self.stop_sched_scan().await?;
                self.scan.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
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
}

impl WifiIface {
    /// SSID of the network the client is currently working toward.
    /// Before the first scan selects a BSS this is the first configured
    /// network; after a successful scan it is the network whose BSS was
    /// selected (and whose passphrase is used for authentication).
    pub fn current_ssid(&self) -> &str {
        &self.link.network.ssid
    }

    /// BSSID of the BSS the client is currently working toward.
    /// Before the first scan selects a BSS this is all-zero; after a
    /// successful scan it is the selected BSS's BSSID.
    pub fn current_bssid(&self) -> [u8; ETH_ALEN] {
        self.link.bss_info.bssid
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
        if networks == self.core.config.networks {
            log::debug!("network list unchanged");
            return Ok(());
        }

        let old_ssid = self.link.network.ssid.clone();
        let connected = matches!(
            self.state,
            WifiState::ConnectedWithoutOffloadRekey
                | WifiState::ConnectedWithOffloadRekey
        );
        let connected_network_kept = connected
            && networks.iter().any(|network| network.ssid == old_ssid);

        if connected && connected_network_kept {
            self.core.config.networks = networks;
            self.scan.reset_rotation();
            log::info!(
                "network list updated, keeping connection to {old_ssid}: [{}]",
                self.core.config.ssids().collect::<Vec<_>>().join(", ")
            );
            return Ok(());
        }

        self.core.config.networks = networks;
        self.scan.reset_rotation();

        if connected {
            log::info!(
                "network list update drops current SSID {old_ssid}; \
                 disconnecting"
            );
            self.stop_sched_scan().await?;
            if self.wowlan.armed {
                self.disarm_wowlan().await?;
            }
            if let Err(e) = self.core.nl.disconnect().await {
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
        self.link.reset_for_update(
            self.core
                .config
                .networks
                .first()
                .cloned()
                .unwrap_or_else(|| NetworkConfig::new("")),
        );
        self.auth.reset();
        self.roam.reset();
        self.scan.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
        self.state = WifiState::Init;
        log::info!(
            "network list updated: [{}]",
            self.core.config.ssids().collect::<Vec<_>>().join(", ")
        );
        Ok(())
    }

    /// Whether the wiphy advertises WoWLAN triggers shuli can arm
    /// (disconnect and/or GTK rekey failure).
    pub fn wowlan_supported(&self) -> bool {
        !desired_wowlan_triggers(&self.caps.wowlan_supported_triggers)
            .is_empty()
    }

    /// arm WoWLAN triggers (`NL80211_CMD_SET_WOWLAN`) so the device
    /// can wake the host while it is suspended. Arms `Disconnect` and
    /// `GtkRekeyFailure` when the wiphy advertises them; returns `true`
    /// when triggers were armed and `false` when the wiphy has no
    /// usable WoWLAN support. Best-effort: failures are logged, not
    /// fatal (a suspend must not be blocked on WoWLAN).
    pub async fn arm_wowlan(&mut self) -> Result<bool, WifiError> {
        if self.wowlan.armed {
            return Ok(true);
        }
        let triggers =
            desired_wowlan_triggers(&self.caps.wowlan_supported_triggers);
        if triggers.is_empty() {
            log::debug!("WoWLAN unsupported; not arming triggers");
            return Ok(false);
        }
        let attrs = Nl80211Wowlan::new(self.core.nl.if_index)
            .triggers(triggers)
            .build();
        match self.core.nl.set_wowlan(attrs).await {
            Ok(()) => {
                self.wowlan.armed = true;
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
        if !self.wowlan.armed {
            return Ok(());
        }
        let attrs = Nl80211Wowlan::new(self.core.nl.if_index)
            .triggers(Vec::new())
            .build();
        match self.core.nl.set_wowlan(attrs).await {
            Ok(()) => {
                self.wowlan.armed = false;
                log::info!("WoWLAN triggers cleared");
                Ok(())
            }
            Err(e) => {
                self.wowlan.armed = false;
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
        if self.wowlan.armed
            && let Err(e) = self.disarm_wowlan().await
        {
            log::debug!("disarm WoWLAN on shutdown failed: {e}");
        }
        if let Err(e) = self.core.nl.disconnect().await {
            log::debug!("disconnect on shutdown: {e}");
        }
    }
}

impl Drop for WifiIface {
    fn drop(&mut self) {
        let mut conn_handle = self.core.nl.conn_handle.clone();
        let handle = self.core.nl.handle.clone();
        let if_index = self.core.nl.if_index;
        let sched_scan_active = self.scan.sched_scan_active;
        let wowlan_armed = self.wowlan.armed;
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
                    let _ = drain_request(
                        conn_handle
                            .disconnect(
                                Nl80211Disconnect::new(if_index).build(),
                            )
                            .execute()
                            .await,
                    )
                    .await;
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
pub(crate) fn desired_wowlan_triggers(
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
pub(crate) fn wowlan_wakeup_requires_reconnect(
    reasons: &[Nl80211WowlanWakeup],
) -> bool {
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
pub(crate) fn fatal_disconnect_error(
    reason: Option<Ieee80211ReasonCode>,
) -> WifiError {
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
pub(crate) fn is_fatal_disconnect_reason(
    reason: Option<Ieee80211ReasonCode>,
) -> bool {
    matches!(
        reason,
        Some(Ieee80211ReasonCode::PrevAuthNotValid)
            | Some(Ieee80211ReasonCode::Ieee8021xFailed)
    )
}

/// human-readable names for the Transition Disable KDE
/// bitmap bits (bit 0 = WPA3-Personal, 1 = SAE-PK, 2 = WPA3-Enterprise,
/// 3 = Enhanced Open).
pub(crate) fn fmt_transition_disable(bitmap: u8) -> String {
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
