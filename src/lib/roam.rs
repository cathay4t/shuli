// SPDX-License-Identifier: Apache-2.0

//! Roaming (Stage 2 G8): IEEE 802.11r Fast BSS Transition (over the
//! air), IEEE 802.11v BSS Transition Management and the roam decision
//! engine (signal-threshold triggered scans + candidate selection).
//!
//! Flow of an FT roam:
//!  1. pick a target BSS (BTM candidate list or scan results),
//!  2. FT Authentication: send MDIE + FTIE{SNonce, R0KH-ID} with
//!     `NL80211_AUTHTYPE_FT`,
//!  3. validate the response (MDID / SNonce / R0KH-ID / PMKR0Name, get ANonce +
//!     R1KH-ID), derive PMK-R1 and the PTK,
//!  4. reassociate to the target with RSNE(PMKID=PMKR1Name) + MDIE + FTIE(MIC)
//!     and `NL80211_ATTR_PREV_BSSID`,
//!  5. validate the response FTIE MIC and install PTK/GTK/IGTK/BIGTK from the
//!     FTIE subelements - no 4-way handshake follows.

use aws_lc_rs::rand::SecureRandom;
use wl_nl80211::{
    Nl80211Associate, Nl80211AuthType, Nl80211Authenticate, Nl80211Cqm,
    Nl80211CqmAttr, Nl80211CqmRssiEvent, Nl80211CqmRssiThresholdEvent,
    Nl80211UseMfp,
};

use crate::{
    ETH_ALEN, ErrorKind, NetworkConfig, WifiClient, WifiError, WifiState,
    client::drain_request,
    config::SaePwe,
    crypto::ft::{
        FT_PTK_LEN, PmkR0, PmkR1, derive_ft_ptk, derive_pmk_r0, derive_pmk_r1,
    },
    ieee80211::{
        elements,
        wnm::{
            BTM_REQUEST_ACTION, BTM_STATUS_ACCEPT,
            BTM_STATUS_REJECT_UNSPECIFIED, BtmRequest, WNM_ACTION_CATEGORY,
            build_btm_response, parse_btm_request,
        },
    },
    scan::{BssInfo, SecurityType},
};

/// IEEE 802.11 management frame type for Action frames:
/// type 0 (management) | subtype 13 (action) << 4.
const FRAME_TYPE_ACTION: u16 = 0x00d0;

/// Pause signal-triggered roaming for this long after a completed roam.
const ROAM_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

/// Hysteresis (dBm) for the kernel connection quality monitor (CQM):
/// after a LOW RSSI event the kernel only re-arms the HIGH event once
/// the signal moved this far above the roam threshold, and vice versa.
/// Matches iwd's `CQM_RSSI_HYST`.
const CQM_RSSI_HYST_DBM: u32 = 5;

/// Interval (seconds) between proactive background roam scans in the
/// connected state: the scan evaluates whether a better BSS (same
/// network with a stronger signal, or - on a critical link - a
/// well-signalled BSS of another configured SSID) warrants a roam.
/// Only created for APs that advertise a managed-roaming capability
/// (802.11v BSS Transition / 802.11k Neighbor Report).
pub(crate) const BACKGROUND_SCAN_SECS: u64 = 30;

/// FT key material of the current connection (802.11-2020 §12.8.2).
#[derive(Debug)]
pub(crate) struct FtContext {
    pub mdid: [u8; 2],
    pub ft_capab: u8,
    pub r0kh_id: Vec<u8>,
    pub pmk_r0: PmkR0,
    /// PMK-R1 shared with the AP of the current association (its R1KH);
    /// kept for the 4-way handshake of the initial FT association.
    pub pmk_r1: PmkR1,
    /// MDIE + FTIE of the (Re)Association Response, echoed in the
    /// 4-way Message 2 key data for FT AKMs.
    pub assoc_resp_ft_ies: Vec<u8>,
}

/// State of an FT roam in flight.
#[derive(Debug)]
pub(crate) struct FtRoam {
    pub target: BssInfo,
    pub snonce: [u8; 32],
    pub pmk_r1: Option<PmkR1>,
    pub r1kh_id: Option<[u8; 6]>,
    pub ptk: Option<[u8; FT_PTK_LEN]>,
}

/// Whether the FT Reassociation Request must carry the SAE-H2E RSNXE
/// (and mark it in the FTIE MIC control). The RSNXE is only meaningful
/// when the SAE exchange actually used hash-to-element: an explicit
/// `H2E` setting, an H2E-advertising AP under `Auto`, or an SAE password
/// identifier (which forces H2E). Sending it on an HnP exchange makes
/// strict APs reject the FT reassociation; wpa_supplicant omits it when
/// the AP has no RSNXE (`wpa_ft_gen_req_ies(..., !sm->ap_rsnxe)`).
fn ft_reassoc_uses_rsnxe(
    security: SecurityType,
    sae_pwe: SaePwe,
    ap_supports_h2e: bool,
    sae_password_id: Option<&str>,
) -> bool {
    matches!(security, SecurityType::FtSae | SecurityType::FtSaeExtKey)
        && (sae_password_id.is_some() || sae_pwe.starts_h2e(ap_supports_h2e))
}

impl WifiClient {
    /// Register for WNM action frames so BTM Requests reach us
    /// (802.11-2020 §11.11.9; requires PMF for protected delivery).
    pub(crate) async fn register_roam_frames(&mut self) {
        let attrs = wl_nl80211::Nl80211RegisterFrame::new(self.if_index)
            .frame_type(FRAME_TYPE_ACTION)
            .frame_match(vec![WNM_ACTION_CATEGORY])
            .build();
        if let Err(e) = drain_request(
            self.conn_handle.register_frame(attrs).execute().await,
        )
        .await
        {
            log::debug!("register WNM action frames failed: {e}");
        }
    }

    /// The roam threshold, or `None` when signal-triggered roaming is
    /// disabled for the connected network.
    pub(crate) fn roam_threshold(&self) -> Option<i32> {
        self.network
            .roaming
            .then_some(self.network.roaming_threshold)
    }

    /// Append the Mobility Domain element to the association request IEs
    /// of an initial FT association; the AP answers with MDIE + FTIE
    /// only when the request carries the MDIE (802.11-2020 §12.8.1).
    pub(crate) fn append_ft_mdie(
        &self,
        ies: &mut Vec<u8>,
    ) -> Result<(), WifiError> {
        let Some(mdie) = self.bss_info.mdie else {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "FT BSS without MDIE in scan results",
            ));
        };
        ies.extend_from_slice(&elements::mdie(mdie.mdid, mdie.ft_capab));
        Ok(())
    }

    /// Initial association with an FT AKM completed: parse MDIE/FTIE
    /// from the (Re)Association Response IEs and derive PMK-R0/PMK-R1
    /// (802.11-2020 §12.8.2). The PMK (XXKey) comes from the just
    /// completed authentication: SAE PMK for FT-SAE, PBKDF2 PMK for
    /// FT-PSK.
    pub(crate) async fn setup_ft_context(
        &mut self,
        ies: &[u8],
    ) -> Result<(), WifiError> {
        let (mdid, ft_capab) = elements::find_ie(ies, elements::IE_ID_MDIE)
            .and_then(elements::parse_mdie)
            .ok_or_else(|| {
                WifiError::new(
                    ErrorKind::Roaming,
                    "no MDIE in FT association response",
                )
            })?;
        let ftie_body = elements::find_ie(ies, elements::IE_ID_FTIE)
            .ok_or_else(|| {
                WifiError::new(
                    ErrorKind::Roaming,
                    "no FTIE in FT association response",
                )
            })?;
        let ftie = elements::parse_ftie(ftie_body).ok_or_else(|| {
            WifiError::new(
                ErrorKind::Roaming,
                "malformed FTIE in FT association response",
            )
        })?;
        let r0kh_id = ftie.r0kh_id.ok_or_else(|| {
            WifiError::new(
                ErrorKind::Roaming,
                "no R0KH-ID in FT association response FTIE",
            )
        })?;
        let r1kh_id = ftie.r1kh_id.ok_or_else(|| {
            WifiError::new(
                ErrorKind::Roaming,
                "no R1KH-ID in FT association response FTIE",
            )
        })?;

        let xxkey = match self.bss_info.security {
            SecurityType::FtSae | SecurityType::FtSaeExtKey => {
                self.auth.as_ref().and_then(|a| a.pmk()).ok_or_else(|| {
                    WifiError::new(ErrorKind::Roaming, "no SAE PMK for FT")
                })?
            }
            SecurityType::FtPsk => self.psk_pmk.ok_or_else(|| {
                WifiError::new(ErrorKind::Roaming, "no PSK PMK for FT")
            })?,
            other => {
                return Err(WifiError::new(
                    ErrorKind::Roaming,
                    format!("FT context for non-FT security {other:?}"),
                ));
            }
        };

        let pmk_r0 =
            derive_pmk_r0(&xxkey, &self.network.ssid, mdid, &r0kh_id, self.mac);
        let pmk_r1 = derive_pmk_r1(&pmk_r0, r1kh_id, self.mac);

        // MDIE + FTIE of the response are echoed in the 4-way Message 2
        // key data for FT AKMs.
        let mut assoc_resp_ft_ies = Vec::new();
        if let Some(pos) = elements::find_ie_pos(ies, elements::IE_ID_MDIE) {
            assoc_resp_ft_ies.extend_from_slice(elements::ie_at(ies, pos));
        }
        if let Some(pos) = elements::find_ie_pos(ies, elements::IE_ID_FTIE) {
            assoc_resp_ft_ies.extend_from_slice(elements::ie_at(ies, pos));
        }

        log::debug!(
            "FT context: mdid={mdid:02x?} r0kh-id={r0kh_id:?} \
             r1kh-id={r1kh_id:02x?} pmkr0name={:02x?}",
            pmk_r0.name
        );
        self.ft = Some(FtContext {
            mdid,
            ft_capab,
            r0kh_id,
            pmk_r0,
            pmk_r1,
            assoc_resp_ft_ies,
        });
        Ok(())
    }

    /// Connected-state tick: poll the current AP's signal level and
    /// start a roam scan when it drops below the threshold. This is the
    /// fallback used when the driver has no kernel connection quality
    /// monitor (see [`Self::arm_cqm`]).
    pub(crate) async fn check_roam_conditions(&mut self) {
        let Some(threshold) = self.roam_threshold() else {
            return;
        };
        if !self.bss_info.ap_supports_signal_roam() {
            return;
        }
        if self.ft_roam.is_some() || self.roam_scan {
            return;
        }
        // Cooldown after the previous roam: with equal-signal BSSes the
        // threshold check alone would ping-pong the client forever.
        if let Some(last) = self.last_roam
            && last.elapsed() < ROAM_COOLDOWN
        {
            return;
        }
        let signal = match self.current_signal_dbm().await {
            Ok(Some(signal)) => signal,
            Ok(None) => return,
            Err(e) => {
                log::debug!("station signal query failed: {e}");
                return;
            }
        };
        if signal >= threshold {
            return;
        }
        log::trace!(
            "signal {signal} dBm below roam threshold {threshold} dBm; \
             scanning for roam candidates"
        );
        self.roam_scan_background = false;
        self.trigger_roam_scan().await;
    }

    /// Proactive background roam check (Connected state): start a roam
    /// scan to look for a better BSS - the same network with a stronger
    /// signal, or (when the current link is critical) a well-signalled
    /// BSS of another configured SSID. The caller only invokes this on a
    /// managed-roaming AP, so no additional capability gate is needed;
    /// the same in-flight / cooldown gates as the CQM path apply.
    pub(crate) async fn check_background_roam(&mut self) {
        if self.roam_threshold().is_none() {
            return;
        }
        if !self.bss_info.ap_supports_signal_roam() {
            return;
        }
        if self.ft_roam.is_some() || self.roam_scan {
            return;
        }
        if let Some(last) = self.last_roam
            && last.elapsed() < ROAM_COOLDOWN
        {
            return;
        }
        self.roam_scan_background = true;
        log::trace!("background roam scan: looking for a better BSS");
        self.trigger_roam_scan().await;
    }

    /// A `NL80211_CMD_NOTIFY_CQM` event from the kernel. On a LOW
    /// crossing (the connected AP's signal dropped below the armed roam
    /// threshold) start a roam scan, honoring the same gates as the
    /// polling path: only on a managed-roaming AP, and never while
    /// another roam / scan is already in flight. A HIGH crossing just
    /// means the signal recovered.
    pub(crate) async fn handle_cqm_rssi(&mut self, cqm: Nl80211CqmRssiEvent) {
        if !matches!(
            self.state,
            WifiState::ConnectedWithoutOffloadRekey
                | WifiState::ConnectedWithOffloadRekey
        ) {
            return;
        }
        let mut threshold_event = None;
        let mut rssi = 0;
        for attr in &cqm.events {
            match attr {
                Nl80211CqmAttr::RssiThresholdEvent(ev) => {
                    threshold_event = Some(*ev);
                }
                Nl80211CqmAttr::RssiLevel(level) => rssi = *level,
                _ => {}
            }
        }
        match threshold_event.unwrap_or(Nl80211CqmRssiThresholdEvent::Other(0))
        {
            Nl80211CqmRssiThresholdEvent::Low => {
                if self.roam_threshold().is_none() {
                    return;
                }
                if !self.bss_info.ap_supports_signal_roam() {
                    log::debug!(
                        "CQM LOW but AP {:02x?} advertises no BSS Transition \
                         / Neighbor Report capability; staying",
                        self.bss_info.bssid
                    );
                    return;
                }
                if self.ft_roam.is_some() || self.roam_scan {
                    return;
                }
                if let Some(last) = self.last_roam
                    && last.elapsed() < ROAM_COOLDOWN
                {
                    return;
                }
                log::trace!(
                    "kernel CQM: signal {rssi} dBm below the roam threshold; \
                     scanning for roam candidates"
                );
                self.roam_scan_background = false;
                self.trigger_roam_scan().await;
            }
            Nl80211CqmRssiThresholdEvent::High => {
                log::debug!("kernel CQM: signal {rssi} dBm recovered");
            }
            Nl80211CqmRssiThresholdEvent::Other(_) => {}
        }
    }

    /// Arm the kernel connection quality monitor (`NL80211_CMD_SET_CQM`)
    /// with the connected network's roam threshold, so the kernel
    /// reports a `NL80211_CMD_NOTIFY_CQM` event when the AP's signal
    /// drops. Returns true when armed; false when the driver has no CQM
    /// support (mac80211 with beacon filtering and no hardware CQM), in
    /// which case the caller keeps polling the signal instead.
    pub(crate) async fn arm_cqm(&mut self) -> bool {
        let Some(threshold) = self.roam_threshold() else {
            return false;
        };
        let attrs = Nl80211Cqm::new(self.if_index)
            .rssi_thold(threshold)
            .rssi_hyst(CQM_RSSI_HYST_DBM)
            .build();
        match drain_request(self.conn_handle.set_cqm(attrs).execute().await)
            .await
        {
            Ok(()) => {
                log::info!(
                    "kernel CQM armed: roam below {threshold} dBm (hysteresis \
                     {CQM_RSSI_HYST_DBM} dBm)"
                );
                true
            }
            Err(e) => {
                log::debug!(
                    "kernel CQM not supported ({e}); polling the signal every \
                     {}s instead",
                    crate::client::ROAM_SIGNAL_CHECK_SECS
                );
                false
            }
        }
    }

    /// Start a roam scan (active scan for the configured SSIDs) from the
    /// connected state. The caller has already decided the signal is
    /// below the roam threshold; this records the pre-scan state so a
    /// scan that decides to stay put can restore the connection.
    async fn trigger_roam_scan(&mut self) {
        self.roam_scan = true;
        // Remember the connected state so a roam scan that decides to
        // stay can restore it instead of leaving the state machine in
        // Scanning (which would re-authenticate the already-connected
        // AP and fail with -EALREADY).
        self.pre_roam_state = Some(self.state);
        if let Err(e) = self.send_out_scan_request().await {
            log::warn!("roam scan trigger failed: {e}");
            self.roam_scan = false;
            self.pre_roam_state = None;
            return;
        }
        self.state = WifiState::Scanning;
    }

    /// Signal level (dBm) of the station entry for the current BSSID via
    /// `NL80211_CMD_GET_STATION`.
    async fn current_signal_dbm(&mut self) -> Result<Option<i32>, WifiError> {
        use futures::TryStreamExt;
        use wl_nl80211::{
            Nl80211Attr, Nl80211StationHandle, Nl80211StationInfo,
        };

        let mut station_handle = Nl80211StationHandle::new(self.handle.clone());
        let mut stream = station_handle.dump(self.if_index).execute().await;
        while let Some(msg) = stream
            .try_next()
            .await
            .map_err(|e| WifiError::new(ErrorKind::Nl80211, e.to_string()))?
        {
            let mut mac = None;
            let mut signal = None;
            for attr in &msg.payload.attributes {
                match attr {
                    Nl80211Attr::Mac(m) => mac = Some(*m),
                    Nl80211Attr::StationInfo(infos) => {
                        for info in infos {
                            if let Nl80211StationInfo::Signal(dbm) = info {
                                signal = Some(*dbm as i32);
                            }
                        }
                    }
                    _ => {}
                }
            }
            if mac == Some(self.bss_info.bssid) && signal.is_some() {
                return Ok(signal);
            }
        }
        Ok(None)
    }

    /// Handle a received WNM action frame (registered via
    /// [`register_roam_frames`]).
    pub(crate) async fn handle_wnm_frame(&mut self, frame: &[u8]) {
        // 24-byte 802.11 header, then category / action / body.
        if frame.len() < 27 || frame[24] != WNM_ACTION_CATEGORY {
            return;
        }
        if frame[25] != BTM_REQUEST_ACTION {
            log::debug!("WNM action {} ignored", frame[25]);
            return;
        }
        if !matches!(
            self.state,
            WifiState::ConnectedWithoutOffloadRekey
                | WifiState::ConnectedWithOffloadRekey
        ) {
            return;
        }
        let Some(btm) = parse_btm_request(&frame[26..]) else {
            log::warn!("malformed BTM Request; ignored");
            return;
        };
        log::info!(
            "BTM Request: dialog={} candidates={} preferred={}",
            btm.dialog_token,
            btm.candidates.len(),
            btm.preferred_candidates
        );

        let target = self.pick_btm_target(&btm);
        match target {
            Some(target) => {
                self.send_btm_response(
                    btm.dialog_token,
                    BTM_STATUS_ACCEPT,
                    target.bssid,
                )
                .await;
                self.start_roam(target, self.network.clone()).await;
            }
            None => {
                log::info!("no usable BTM candidate; rejecting");
                self.send_btm_response(
                    btm.dialog_token,
                    BTM_STATUS_REJECT_UNSPECIFIED,
                    [0u8; ETH_ALEN],
                )
                .await;
            }
        }
    }

    /// Choose a roam target from a BTM candidate list: candidates are in
    /// preference order; each must match the last scan results and the
    /// network's security family, and differ from the current BSS.
    fn pick_btm_target(&mut self, btm: &BtmRequest) -> Option<BssInfo> {
        for candidate in &btm.candidates {
            if candidate.bssid == self.bss_info.bssid {
                continue;
            }
            let Some((bss, _)) = self
                .last_scan_candidates
                .iter()
                .find(|(b, _)| b.bssid == candidate.bssid)
            else {
                log::debug!(
                    "BTM candidate {:02x?} not in scan results",
                    candidate.bssid
                );
                continue;
            };
            if bss.security.base() != self.bss_info.security.base() {
                log::debug!(
                    "BTM candidate {:02x?} security {:?} incompatible with \
                     current {:?}",
                    candidate.bssid,
                    bss.security,
                    self.bss_info.security
                );
                continue;
            }
            return Some(bss.clone());
        }
        None
    }

    /// Transmit a BTM Response action frame to the current AP.
    async fn send_btm_response(
        &mut self,
        dialog_token: u8,
        status: u8,
        target_bssid: [u8; ETH_ALEN],
    ) {
        let mut frame = Vec::with_capacity(24 + 11);
        frame.extend_from_slice(&FRAME_TYPE_ACTION.to_le_bytes());
        frame.extend_from_slice(&[0, 0]); // duration
        frame.extend_from_slice(&self.bss_info.bssid); // DA = AP
        frame.extend_from_slice(&self.mac); // SA
        frame.extend_from_slice(&self.bss_info.bssid); // BSSID
        frame.extend_from_slice(&[0, 0]); // sequence control
        frame.extend_from_slice(&build_btm_response(
            dialog_token,
            status,
            target_bssid,
        ));

        let attrs = wl_nl80211::Nl80211Frame::new(self.if_index)
            .frame(frame)
            .frequency(self.bss_info.freq_mhz)
            .build();
        if let Err(e) =
            drain_request(self.conn_handle.frame(attrs).execute().await).await
        {
            log::warn!("send BTM Response failed: {e}");
        }
    }

    /// Start roaming to `target`: FT within the mobility domain when
    /// possible, otherwise disconnect and reconnect through the normal
    /// flow (PMKSA cache first, full authentication otherwise), steered
    /// to the target BSSID. `target_network` is the configuration of the
    /// target's SSID; when it differs from the connected network the
    /// client switches SSID, terminating the current session.
    pub(crate) async fn start_roam(
        &mut self,
        target: BssInfo,
        target_network: NetworkConfig,
    ) {
        // An FT roam only applies within the connected network (the FT
        // context is bound to the current SSID); a different configured
        // SSID always goes through a full reconnection.
        let switching_network = target_network.ssid != self.network.ssid;
        if !switching_network
            && self.ft.is_some()
            && target.security.is_ft()
            && target.mdie.map(|m| m.mdid) == self.ft.as_ref().map(|ft| ft.mdid)
        {
            if let Err(e) = self.start_ft_roam(target.clone()).await {
                log::warn!("FT roam start failed: {e}");
            }
            return;
        }

        if switching_network {
            log::info!(
                "switching to configured SSID {} (bssid {:02x?}) - the \
                 current session is terminated",
                target_network.ssid,
                target.bssid
            );
            self.network = target_network;
        }
        // No FT path: leave the current BSS and let the retry loop
        // reconnect to the target. An exact PMKSA cache hit skips the
        // full authentication; without one, OKC clones the current PMK's
        // PMKID onto the target BSSID and tries that first (the
        // association is rejected when the AP has no matching PMKSA, and
        // the existing fallback then runs the full authentication). OKC
        // is meaningless across an SSID switch (different PMK), so it is
        // skipped there.
        if !switching_network
            && self
                .pmksa_cache
                .lookup(&self.network.ssid, target.bssid)
                .is_none()
        {
            self.synthesize_okc_entry(&target);
        }
        log::info!("roam to {:02x?} via full reconnection", target.bssid);
        self.roam_target = Some(target.bssid);
        // Cooldown from the roam decision so equal-signal BSSes do not
        // ping-pong through repeated full reconnections.
        self.last_roam = Some(std::time::Instant::now());
        if let Err(e) = crate::nl80211::connect::disconnect(
            &mut self.conn_handle,
            self.if_index,
        )
        .await
        {
            log::debug!("disconnect for roam failed: {e}");
        }
        self.state = WifiState::Failed;
    }

    /// Opportunistic Key Caching for a roam target: derive the PMKID the
    /// target BSS *would* use for the current PMK and cache it, so the
    /// reconnecting state machine offers it in the (Re)Association RSNE.
    /// Only meaningful for PSK-family PMKIDs (WPA2-PSK / PSK-SHA256);
    /// SAE PMKIDs come from the SAE exchange itself and cannot be
    /// cloned.
    fn synthesize_okc_entry(&mut self, target: &BssInfo) {
        let Some(pmk) = self.psk_pmk else {
            return;
        };
        let (pmkid, mic_alg) = match self.bss_info.security {
            SecurityType::Wpa2Psk => (
                crate::crypto::kdf::pmkid_sha1(&pmk, &target.bssid, &self.mac),
                crate::crypto::handshake4::MicAlg::HmacSha1,
            ),
            SecurityType::Wpa2PskSha256 => (
                crate::crypto::kdf::pmkid_sha256(
                    &pmk,
                    &target.bssid,
                    &self.mac,
                ),
                crate::crypto::handshake4::MicAlg::AesCmac,
            ),
            _ => return,
        };
        log::debug!(
            "OKC: offering cloned PMKID {pmkid:02x?} to {:02x?}",
            target.bssid
        );
        self.pmksa_cache.insert(crate::pmksa::PmksaEntry {
            ssid: self.network.ssid.clone(),
            bssid: target.bssid,
            pmkid,
            pmk,
            mic_alg,
            expires: std::time::Instant::now()
                + std::time::Duration::from_secs(
                    crate::pmksa::PMK_LIFETIME_SECS,
                ),
        });
    }

    /// FT roam step 1: FT Authentication request to the target AP.
    async fn start_ft_roam(
        &mut self,
        target: BssInfo,
    ) -> Result<(), WifiError> {
        let ft = self.ft.as_ref().ok_or_else(|| {
            WifiError::new(ErrorKind::Roaming, "no FT context")
        })?;
        let Some(target_mdie) = target.mdie else {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "roam target has no MDIE",
            ));
        };

        let mut snonce = [0u8; 32];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut snonce)
            .expect("RNG");

        // FT Authentication request IEs: RSNE with PMKR0Name as PMKID,
        // then MDIE and FTIE (SNonce + R0KH-ID). hostapd rejects the
        // request with INVALID_PMKID when the RSNE / PMKR0Name is
        // missing.
        let rsne = match self.bss_info.security {
            SecurityType::FtSae => elements::ft_sae_rsne_cipher(
                Some(ft.pmk_r0.name),
                self.bss_info.group_mgmt_cipher,
            ),
            SecurityType::FtSaeExtKey => elements::ft_sae_ext_key_rsne_cipher(
                Some(ft.pmk_r0.name),
                self.bss_info.group_mgmt_cipher,
            ),
            _ => elements::ft_psk_rsne_cipher(
                Some(ft.pmk_r0.name),
                self.bss_info.group_mgmt_cipher,
            ),
        };
        let mut ft_ies = rsne;
        ft_ies.extend_from_slice(&elements::mdie(
            target_mdie.mdid,
            target_mdie.ft_capab,
        ));
        ft_ies.extend_from_slice(&elements::ftie_auth_request(
            &snonce,
            &ft.r0kh_id,
        ));

        log::info!(
            "FT roam to {:02x?} (freq {} MHz): sending FT AUTHENTICATE",
            target.bssid,
            target.freq_mhz
        );
        // FT authentication carries the MDIE + FTIE in NL80211_ATTR_IE;
        // NL80211_ATTR_AUTH_DATA is rejected for AUTHTYPE_FT.
        let attrs = Nl80211Authenticate::new(self.if_index)
            .ssid(&self.network.ssid)
            .mac(target.bssid)
            .frequency(target.freq_mhz)
            .auth_type(Nl80211AuthType::Ft)
            .ie(ft_ies)
            .build();
        if let Err(e) =
            drain_request(self.conn_handle.authenticate(attrs).execute().await)
                .await
        {
            // CMD_AUTHENTICATE disconnects the old AP even when it
            // fails, so the connection is gone either way; the retry
            // loop reconnects.
            log::warn!("FT AUTHENTICATE failed: {e}");
            self.state = WifiState::Failed;
            return Err(WifiError::new(
                ErrorKind::Roaming,
                format!("FT AUTHENTICATE failed: {e}"),
            ));
        }

        // The FT Authentication response arrives as a regular
        // Authenticated event; handle_ft_auth_response continues the
        // roam. Moving out of Scanning/Connected keeps the state
        // machine from restarting the normal connection flow.
        self.state = WifiState::Authenticating;
        self.ft_roam = Some(FtRoam {
            target,
            snonce,
            pmk_r1: None,
            r1kh_id: None,
            ptk: None,
        });
        Ok(())
    }

    /// FT roam step 2: the target AP answered the FT Authentication
    /// (transaction 2). Validate MDID / SNonce / R0KH-ID / PMKR0Name,
    /// derive PMK-R1 + PTK, then send the FT Reassociation Request.
    pub(crate) async fn handle_ft_auth_response(&mut self, frame: &[u8]) {
        let result = self.handle_ft_auth_response_inner(frame).await;
        if let Err(e) = result {
            // CMD_AUTHENTICATE already disconnected the old AP, so the
            // roam cannot fall back to it; the retry loop reconnects.
            log::warn!("FT roam authentication failed: {e}; reconnecting");
            self.ft_roam = None;
            self.state = WifiState::Failed;
        }
    }

    async fn handle_ft_auth_response_inner(
        &mut self,
        frame: &[u8],
    ) -> Result<(), WifiError> {
        let roam = self.ft_roam.as_mut().ok_or_else(|| {
            WifiError::new(ErrorKind::Roaming, "no FT roam in progress")
        })?;
        let ft = self.ft.as_ref().ok_or_else(|| {
            WifiError::new(ErrorKind::Roaming, "no FT context")
        })?;

        // 24-byte header, alg(2) seq(2) status(2), then IEs.
        if frame.len() < 30 {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "short FT authentication frame",
            ));
        }
        let alg = u16::from_le_bytes([frame[24], frame[25]]);
        let seq = u16::from_le_bytes([frame[26], frame[27]]);
        let status = u16::from_le_bytes([frame[28], frame[29]]);
        if alg != 2 || seq != 2 {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                format!("unexpected FT auth frame alg={alg} seq={seq}"),
            ));
        }
        if status != 0 {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                format!("FT authentication rejected: status={status}"),
            ));
        }
        let ies = &frame[30..];

        let mdie = elements::find_ie(ies, elements::IE_ID_MDIE)
            .and_then(elements::parse_mdie)
            .ok_or_else(|| {
                WifiError::new(
                    ErrorKind::Roaming,
                    "no MDIE in FT auth response",
                )
            })?;
        if mdie.0 != ft.mdid {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "MDID mismatch in FT auth response",
            ));
        }

        let ftie_body = elements::find_ie(ies, elements::IE_ID_FTIE)
            .ok_or_else(|| {
                WifiError::new(
                    ErrorKind::Roaming,
                    "no FTIE in FT auth response",
                )
            })?;
        let ftie = elements::parse_ftie(ftie_body).ok_or_else(|| {
            WifiError::new(
                ErrorKind::Roaming,
                "malformed FTIE in FT auth response",
            )
        })?;
        if ftie.snonce != roam.snonce {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "SNonce mismatch in FT auth response",
            ));
        }
        match &ftie.r0kh_id {
            Some(r0kh_id) if *r0kh_id == ft.r0kh_id => {}
            _ => {
                return Err(WifiError::new(
                    ErrorKind::Roaming,
                    "R0KH-ID mismatch in FT auth response",
                ));
            }
        }
        let Some(r1kh_id) = ftie.r1kh_id else {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "no R1KH-ID in FT auth response FTIE",
            ));
        };

        // The response RSNE carries PMKR0Name as its PMKID.
        if let Some(rsne_body) = elements::find_ie(ies, elements::IE_ID_RSNE)
            && let Some(pmkid) = elements::rsne_first_pmkid(rsne_body)
            && pmkid != ft.pmk_r0.name
        {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "PMKR0Name mismatch in FT auth response RSNE",
            ));
        }

        let pmk_r1 = derive_pmk_r1(&ft.pmk_r0, r1kh_id, self.mac);
        let ptk = derive_ft_ptk(
            &pmk_r1,
            &roam.snonce,
            &ftie.anonce,
            roam.target.bssid,
            self.mac,
        );
        log::debug!(
            "FT roam: PMK-R1/PTK derived for {:02x?}",
            roam.target.bssid
        );

        let target = roam.target.clone();
        let snonce = roam.snonce;
        roam.pmk_r1 = Some(pmk_r1.clone());
        roam.r1kh_id = Some(r1kh_id);
        roam.ptk = Some(ptk);

        self.send_ft_reassoc(
            &target,
            &ptk,
            &pmk_r1,
            r1kh_id,
            &snonce,
            &ftie.anonce,
        )
        .await
    }

    /// FT roam step 2b: the Reassociation Request - RSNE(PMKR1Name) +
    /// MDIE + FTIE(MIC), with `PREV_BSSID` pointing at the current AP.
    async fn send_ft_reassoc(
        &mut self,
        target: &BssInfo,
        ptk: &[u8; FT_PTK_LEN],
        pmk_r1: &PmkR1,
        r1kh_id: [u8; 6],
        snonce: &[u8; 32],
        anonce: &[u8; 32],
    ) -> Result<(), WifiError> {
        let ft = self.ft.as_ref().ok_or_else(|| {
            WifiError::new(ErrorKind::Roaming, "no FT context")
        })?;
        let target_mdie = target.mdie.ok_or_else(|| {
            WifiError::new(ErrorKind::Roaming, "roam target has no MDIE")
        })?;

        let rsne = match target.security {
            SecurityType::FtSae => elements::ft_sae_rsne_cipher(
                Some(pmk_r1.name),
                self.bss_info.group_mgmt_cipher,
            ),
            SecurityType::FtSaeExtKey => elements::ft_sae_ext_key_rsne_cipher(
                Some(pmk_r1.name),
                self.bss_info.group_mgmt_cipher,
            ),
            _ => elements::ft_psk_rsne_cipher(
                Some(pmk_r1.name),
                self.bss_info.group_mgmt_cipher,
            ),
        };
        let mdie = elements::mdie(target_mdie.mdid, target_mdie.ft_capab);
        // The RSNXE participates in the FTIE MIC (after the FTIE,
        // 802.11-2020 §12.8.4) and is included only when SAE H2E was
        // actually used for the exchange.
        let rsnxe = ft_reassoc_uses_rsnxe(
            target.security,
            self.network.sae_pwe,
            target.ap_supports_sae_h2e(),
            self.network.sae_password_id.as_deref(),
        )
        .then(elements::sae_rsnxe);

        let kck: [u8; 16] = ptk[..16].try_into().unwrap();
        let ftie = elements::ftie_reassoc_request(
            &kck,
            self.mac,
            target.bssid,
            anonce,
            snonce,
            &ft.r0kh_id,
            &r1kh_id,
            &rsne,
            &mdie,
            rsnxe.as_deref(),
        )?;

        let mut ies =
            Vec::with_capacity(rsne.len() + mdie.len() + ftie.len() + 8);
        ies.extend_from_slice(&rsne);
        ies.extend_from_slice(&mdie);
        ies.extend_from_slice(&ftie);
        if let Some(rsnxe) = rsnxe {
            ies.extend_from_slice(&rsnxe);
        }

        let mfp = match target.security {
            SecurityType::FtSae | SecurityType::FtSaeExtKey => {
                Some(Nl80211UseMfp::Required)
            }
            _ => target.ap_mfp_capable().then_some(Nl80211UseMfp::Required),
        };
        let mut builder = Nl80211Associate::new(self.if_index)
            .ssid(&self.network.ssid)
            .mac(target.bssid)
            .prev_bssid(self.bss_info.bssid)
            .frequency(target.freq_mhz)
            .ie(ies)
            .control_port_over_nl80211(true)
            .socket_owner(true);
        if let Some(mfp) = mfp {
            builder = builder.use_mfp(mfp);
        }

        log::info!("FT roam: sending REASSOCIATE to {:02x?}", target.bssid);
        drain_request(
            self.conn_handle.associate(builder.build()).execute().await,
        )
        .await
    }

    /// FT roam step 3: the target AP accepted the reassociation. Validate
    /// the response (R1KH-ID, PMKR1Name, FTIE MIC with sequence number
    /// 6, RSNE against the target's beacon copy), then install the keys
    /// from the FTIE subelements - the 4-way handshake does not run for
    /// FT.
    pub(crate) async fn handle_ft_assoc_response(
        &mut self,
        ies: &[u8],
    ) -> Result<(), WifiError> {
        let result = self.handle_ft_assoc_response_inner(ies).await;
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                log::warn!("FT roam reassociation failed: {e}");
                self.ft_roam = None;
                Err(e)
            }
        }
    }

    async fn handle_ft_assoc_response_inner(
        &mut self,
        ies: &[u8],
    ) -> Result<(), WifiError> {
        let roam = self.ft_roam.as_ref().ok_or_else(|| {
            WifiError::new(ErrorKind::Roaming, "no FT roam in progress")
        })?;
        let ft = self.ft.as_ref().ok_or_else(|| {
            WifiError::new(ErrorKind::Roaming, "no FT context")
        })?;
        let ptk = roam.ptk.ok_or_else(|| {
            WifiError::new(ErrorKind::Roaming, "FT roam PTK missing")
        })?;
        let r1kh_id = roam.r1kh_id.ok_or_else(|| {
            WifiError::new(ErrorKind::Roaming, "FT roam R1KH-ID missing")
        })?;
        let pmk_r1 = roam.pmk_r1.clone().ok_or_else(|| {
            WifiError::new(ErrorKind::Roaming, "FT roam PMK-R1 missing")
        })?;
        let target = roam.target.clone();
        // Clone what the final FtContext update needs before any &mut
        // self calls below.
        let ft_mdid = ft.mdid;
        let ft_capab = ft.ft_capab;
        let ft_r0kh_id = ft.r0kh_id.clone();
        let ft_pmk_r0 = ft.pmk_r0.clone();

        let ftie_body = elements::find_ie(ies, elements::IE_ID_FTIE)
            .ok_or_else(|| {
                WifiError::new(
                    ErrorKind::Roaming,
                    "no FTIE in reassoc response",
                )
            })?;
        let ftie = elements::parse_ftie(ftie_body).ok_or_else(|| {
            WifiError::new(
                ErrorKind::Roaming,
                "malformed reassoc response FTIE",
            )
        })?;
        if ftie.r1kh_id != Some(r1kh_id) {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "R1KH-ID mismatch in reassoc response",
            ));
        }

        // RSNE: PMKID must be PMKR1Name and the body must match the
        // target's beacon RSNE (ignoring the PMKID).
        let rsne_elem = elements::find_ie_pos(ies, elements::IE_ID_RSNE)
            .map(|pos| elements::ie_at(ies, pos))
            .ok_or_else(|| {
                WifiError::new(
                    ErrorKind::Roaming,
                    "no RSNE in reassoc response",
                )
            })?;
        if let Some(pmkid) = elements::rsne_first_pmkid(&rsne_elem[2..])
            && let Some(ref pmk_r1) = roam.pmk_r1
            && pmkid != pmk_r1.name
        {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "PMKR1Name mismatch in reassoc response RSNE",
            ));
        }
        if !target.ap_rsne.is_empty()
            && !elements::rsne_match_ignore_pmkid(rsne_elem, &target.ap_rsne)
        {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "RSNE downgrade detected in reassoc response",
            ));
        }

        // FTIE MIC: STA || target AP || 6 || RSNE || MDIE ||
        // FTIE(MIC=0) || [RSNXE].
        let mdie_elem = elements::find_ie_pos(ies, elements::IE_ID_MDIE)
            .map(|pos| elements::ie_at(ies, pos));
        let rsnxe_elem = elements::find_ie_pos(ies, elements::IE_ID_RSNXE)
            .map(|pos| elements::ie_at(ies, pos));
        let mut ftie_zmic = Vec::with_capacity(2 + ftie_body.len());
        ftie_zmic.push(elements::IE_ID_FTIE);
        ftie_zmic.push(ftie_body.len() as u8);
        ftie_zmic.extend_from_slice(&ftie_body[..2]); // mic_control
        ftie_zmic.extend_from_slice(&[0u8; 16]); // zeroed MIC
        ftie_zmic.extend_from_slice(&ftie_body[18..]);

        let mut mic_data = Vec::new();
        mic_data.extend_from_slice(rsne_elem);
        if let Some(mdie_elem) = mdie_elem {
            mic_data.extend_from_slice(mdie_elem);
        }
        mic_data.extend_from_slice(&ftie_zmic);
        if let Some(rsnxe_elem) = rsnxe_elem {
            mic_data.extend_from_slice(rsnxe_elem);
        }
        let kck: [u8; 16] = ptk[..16].try_into().unwrap();
        let expected_mic = crate::crypto::ft::ft_mic(
            &kck,
            self.mac,
            target.bssid,
            6,
            &mic_data,
        )?;
        if expected_mic != ftie.mic {
            return Err(WifiError::new(
                ErrorKind::Roaming,
                "FTIE MIC mismatch in reassoc response",
            ));
        }

        // Install the PTK, then GTK / IGTK / BIGTK from the FTIE
        // subelements (unwrapped with the KEK).
        self.install_ft_ptk(&target, &ptk).await?;
        let kek: [u8; 16] = ptk[16..32].try_into().unwrap();
        if let Some(ref gtk) = ftie.gtk {
            let key = elements::unwrap_ft_key(&kek, gtk)?;
            let attrs = wl_nl80211::Nl80211Key::new_gtk(
                self.if_index,
                key,
                gtk.key_index,
            )
            .seq(gtk.rsc.clone())
            .build();
            drain_request(self.conn_handle.new_key(attrs).execute().await)
                .await
                .map_err(|e| {
                    WifiError::new(
                        ErrorKind::Roaming,
                        format!("FT GTK install failed: {e}"),
                    )
                })?;
            log::info!("FT roam: GTK[{}] installed", gtk.key_index);
        }
        if let Some(ref igtk) = ftie.igtk {
            let key = elements::unwrap_ft_key(&kek, igtk)?;
            let attrs = wl_nl80211::Nl80211Key::new_igtk(
                self.if_index,
                key,
                igtk.key_index,
                igtk.rsc.clone(),
            )
            .build();
            if let Err(e) =
                drain_request(self.conn_handle.new_key(attrs).execute().await)
                    .await
            {
                log::warn!("FT roam: IGTK install failed: {e}");
            } else {
                log::info!("FT roam: IGTK[{}] installed", igtk.key_index);
            }
        }
        if let Some(ref bigtk) = ftie.bigtk {
            let key = elements::unwrap_ft_key(&kek, bigtk)?;
            let attrs = wl_nl80211::Nl80211Key::new_bigtk(
                self.if_index,
                key,
                bigtk.key_index,
                bigtk.rsc.clone(),
            )
            .build();
            if let Err(e) =
                drain_request(self.conn_handle.new_key(attrs).execute().await)
                    .await
            {
                log::warn!("FT roam: BIGTK install failed: {e}");
            } else {
                log::info!("FT roam: BIGTK[{}] installed", bigtk.key_index);
            }
        }

        // Roam complete: the connection now lives on the target BSS.
        // Echo MDIE + FTIE of this response in a later 4-way Message 2
        // (group rekeys use the FT AKM too).
        let mut assoc_resp_ft_ies = Vec::new();
        if let Some(pos) = elements::find_ie_pos(ies, elements::IE_ID_MDIE) {
            assoc_resp_ft_ies.extend_from_slice(elements::ie_at(ies, pos));
        }
        if let Some(pos) = elements::find_ie_pos(ies, elements::IE_ID_FTIE) {
            assoc_resp_ft_ies.extend_from_slice(elements::ie_at(ies, pos));
        }
        self.ft = Some(FtContext {
            mdid: ft_mdid,
            ft_capab,
            r0kh_id: ft_r0kh_id,
            pmk_r0: ft_pmk_r0,
            pmk_r1,
            assoc_resp_ft_ies,
        });
        self.bss_info = target.clone();
        self.ft_roam = None;
        self.last_roam = Some(std::time::Instant::now());
        self.fourway = None;
        self.auth = None;
        self.scan_retry_interval = crate::client::RETRY_BACKOFF_INIT_SEC;
        self.state = WifiState::ConnectedWithoutOffloadRekey;
        log::info!(
            "FT roam complete: connected to {:02x?} (freq {} MHz)",
            target.bssid,
            target.freq_mhz
        );
        // G9: a roam is still a connected state - keep WoWLAN armed
        // (wpa_supplicant model: triggers stay set for the interface).
        self.arm_wowlan_if_enabled().await;
        Ok(())
    }

    async fn install_ft_ptk(
        &mut self,
        target: &BssInfo,
        ptk: &[u8; FT_PTK_LEN],
    ) -> Result<(), WifiError> {
        use crate::crypto::ft::{FT_KCK_LEN, FT_KEK_LEN, FT_TK_LEN};
        let tk = ptk[FT_KCK_LEN + FT_KEK_LEN..][..FT_TK_LEN].to_vec();
        let attrs = wl_nl80211::Nl80211Key::new(self.if_index)
            .mac(target.bssid)
            .key_data(tk)
            .key_index(0)
            .key_type(wl_nl80211::Nl80211KeyType::Pairwise)
            .build();
        drain_request(self.conn_handle.new_key(attrs).execute().await)
            .await
            .map_err(|e| {
                WifiError::new(
                    ErrorKind::Roaming,
                    format!("FT PTK install failed: {e}"),
                )
            })?;
        log::info!("FT roam: PTK installed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaePwe;

    #[test]
    fn ft_reassoc_rsnxe_follows_sae_pwe_mode() {
        let cases = [
            (SecurityType::FtSae, SaePwe::Auto, false, None, false),
            (SecurityType::FtSae, SaePwe::Auto, true, None, true),
            (SecurityType::FtSae, SaePwe::H2E, false, None, true),
            (SecurityType::FtSae, SaePwe::HnP, true, None, false),
            (SecurityType::FtSaeExtKey, SaePwe::Auto, true, None, true),
            (SecurityType::FtSae, SaePwe::Auto, false, Some("corp"), true),
            (SecurityType::FtPsk, SaePwe::Auto, true, None, false),
        ];
        for (security, sae_pwe, ap_h2e, password_id, expected) in cases {
            assert_eq!(
                ft_reassoc_uses_rsnxe(security, sae_pwe, ap_h2e, password_id),
                expected,
                "security={security:?} sae_pwe={sae_pwe:?} ap_h2e={ap_h2e} \
                 password_id={password_id:?}"
            );
        }
    }
}
