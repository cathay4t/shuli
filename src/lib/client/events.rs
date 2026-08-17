// SPDX-License-Identifier: Apache-2.0

use super::*;

impl WifiIface {
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
                if self.roam.ft_roam.is_some() {
                    // FT roam: the target AP's FT Authentication response
                    // (transaction 2).
                    self.handle_ft_auth_response(
                        frame.as_deref().unwrap_or(&[]),
                    )
                    .await;
                } else if self.link.pmksa_in_use.is_some() {
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
                    self.link.bss_info.security,
                    SecurityType::Sae | SecurityType::FtSae
                ) {
                    // Open-system auth (open + OWE): no frame, just
                    // a status.
                    if status == Ieee80211StatusCode::Success {
                        if self.link.bss_info.security == SecurityType::Owe {
                            // OWE: associate with DH element.
                            let owe_auth = OweAuth::new();
                            let dh_elem = owe_auth.build_dh_element();
                            self.auth.owe = Some(owe_auth);
                            log::info!(
                                "open-system AUTHENTICATE ok - sending OWE \
                                 ASSOCIATE"
                            );
                            let mut ie_buf = elements::owe_ie_cipher(
                                self.link.bss_info.group_mgmt_cipher,
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
                        } else if self.link.bss_info.security
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
                                .link
                                .bss_info
                                .ap_mfp_capable()
                                .then_some(Nl80211UseMfp::Required);
                            if let Err(e) = self
                                .associate(
                                    elements::wpa2_psk_ie_cipher(
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    mfp,
                                )
                                .await
                            {
                                log::warn!("ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else if self.link.bss_info.security
                            == SecurityType::Wpa2PskSha256
                        {
                            // WPA2-PSK-SHA256 (AKM 6): same association
                            // shape as WPA2-PSK, different RSNE.
                            log::info!(
                                "open-system AUTHENTICATE ok - sending \
                                 WPA2-PSK-SHA256 ASSOCIATE"
                            );
                            let mfp = self
                                .link
                                .bss_info
                                .ap_mfp_capable()
                                .then_some(Nl80211UseMfp::Required);
                            if let Err(e) = self
                                .associate(
                                    elements::wpa2_psk_sha256_ie_cipher(
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    mfp,
                                )
                                .await
                            {
                                log::warn!("ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else if self.link.bss_info.security
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
                                .link
                                .bss_info
                                .ap_mfp_capable()
                                .then_some(Nl80211UseMfp::Required);
                            if let Err(e) = self
                                .associate(
                                    elements::wpa2_ent_ie_cipher(
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    mfp,
                                )
                                .await
                            {
                                log::warn!("ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else if self.link.bss_info.security
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
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    mfp,
                                )
                                .await
                            {
                                log::warn!("ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else if self.link.bss_info.security
                            == SecurityType::FtPsk
                        {
                            // FT-PSK: open-system auth, then associate
                            // with the FT-PSK RSNE and the MDIE.
                            log::info!(
                                "open-system AUTHENTICATE ok - sending FT-PSK \
                                 ASSOCIATE"
                            );
                            let mut ies = elements::ft_psk_ie_cipher(
                                None,
                                self.link.bss_info.group_mgmt_cipher,
                            );
                            if let Err(e) = self.append_ft_mdie(&mut ies) {
                                log::warn!("FT-PSK ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                                return;
                            }
                            let mfp = self
                                .link
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
                if self.roam.ft_roam.is_some() {
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
                        self.roam.ft_roam = None;
                        self.state = WifiState::Failed;
                    }
                } else if status == Ieee80211StatusCode::Success {
                    if self.link.bss_info.security == SecurityType::Open {
                        log::info!(
                            "ASSOCIATED - open network, connection established"
                        );
                        self.scan.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
                        self.state = WifiState::ConnectedWithoutOffloadRekey;
                        self.arm_wowlan_if_enabled().await;
                    } else if self.link.bss_info.security == SecurityType::Owe {
                        if self.process_owe_assoc_response(ies.as_deref()) {
                            log::info!(
                                "ASSOCIATED - OWE PMK derived, waiting for \
                                 4-way handshake"
                            );
                        } else {
                            self.state = WifiState::Failed;
                        }
                    } else if self.link.bss_info.security.is_ft() {
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
                            if let Some(frame) =
                                self.link.pending_ft_msg1.take()
                            {
                                self.handle_control_port_frame(&frame).await;
                            }
                        }
                    } else {
                        if self.link.pmksa_in_use.is_some() {
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
                } else if self.link.pmksa_in_use.is_some() {
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
                self.scan.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
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
                if self.roam.ft_roam.is_some() {
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
                if self.roam.roam_scan {
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
                    && self.scan.sched_scan_stop_pending
                {
                    // Consume the echo of our own stop request when it
                    // lands outside SchedScanWait (e.g. while
                    // authenticating).
                    self.scan.sched_scan_stop_pending = false;
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
    pub(crate) async fn handle_ap_disconnect(
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
        if self.roam.ft_roam.is_some() {
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
            if let Err(e) = connect::disconnect(
                &mut self.core.conn_handle,
                self.core.if_index,
            )
            .await
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
            if let Err(e) = connect::disconnect(
                &mut self.core.conn_handle,
                self.core.if_index,
            )
            .await
            {
                log::debug!("disconnect cleanup failed: {e}");
            }
            self.fail_auth(WifiError::wrong_password(&self.link.network.ssid));
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
    pub(crate) fn is_psk_4way_in_progress(&self) -> bool {
        self.link.pmksa_in_use.is_none()
            && matches!(
                self.link.bss_info.security,
                SecurityType::Wpa2Psk
                    | SecurityType::Wpa2PskSha256
                    | SecurityType::FtPsk
            )
    }

    /// the device woke the host while it was suspended. Clear the
    /// per-suspend triggers, and when the wake means the connection is
    /// no longer trustworthy (GTK rekey failure / disconnect) tear it
    /// down so the retry loop rebuilds it.
    pub(crate) async fn handle_wowlan_wakeup(
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
        if self.wowlan.armed
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
            if let Err(e) = connect::disconnect(
                &mut self.core.conn_handle,
                self.core.if_index,
            )
            .await
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
        if self.link.network.wowlan {
            let _ = self.arm_wowlan().await;
        }
    }

    /// Feed an 802.11 management frame (or the auth frame embedded in an
    /// AUTHENTICATE event) into the active auth method.
    pub(crate) async fn handle_auth_frame(&mut self, frame: &[u8]) {
        // Only frames from the AP we are authenticating with belong to
        // this exchange. On a shared medium (and in the wild: two STAs
        // of neighbouring APs hear each other) the SAE frames of a
        // parallel exchange would otherwise corrupt ours - e.g. the
        // peer's confirm fails its own send-confirm check and the
        // handshake aborts. wpa_supplicant filters the same way.
        if frame.len() >= 16 && frame[10..16] != self.link.bss_info.bssid {
            log::debug!(
                "ignoring auth frame from {:02x?} (expecting {:02x?})",
                &frame[10..16],
                self.link.bss_info.bssid
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

        let action = match self.auth.method.as_mut() {
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

                let attrs = Nl80211Authenticate::new(self.core.if_index)
                    .ssid(&self.link.network.ssid)
                    .mac(self.link.bss_info.bssid)
                    .frequency(self.link.bss_info.freq_mhz)
                    .auth_type(Nl80211AuthType::Sae)
                    .auth_data(auth_data)
                    .build();
                if let Err(e) = drain_request(
                    self.core.conn_handle.authenticate(attrs).execute().await,
                )
                .await
                {
                    log::warn!("send SAE confirm failed: {e}");
                    self.state = WifiState::Failed;
                } else {
                    log::info!("SAE confirm sent");
                    // The commit exchange is done; only the confirm wait
                    // remains, which is not retransmitted.
                    self.auth.sae_commit_sent = false;
                }
            }
            AuthAction::SendCommitWithToken(token) => {
                // the AP demanded an anti-clogging token - re-send
                // the commit (fresh scalar/element) with the token.
                let auth_data = match self.auth.method.as_mut() {
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
                self.auth.sae_sync = 0;
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
                if self.auth.sae_sync < SAE_SYNC_MAX {
                    log::debug!(
                        "SAE commit temporarily rejected; waiting for the \
                         retransmission timer"
                    );
                } else {
                    log::warn!(
                        "SAE commit temporarily rejected {} times; giving up, \
                         will reconnect",
                        self.auth.sae_sync
                    );
                    self.state = WifiState::Failed;
                }
            }
            AuthAction::Complete => {
                log::info!("SAE completed - sending ASSOCIATE");
                let rsne = match self.link.bss_info.security {
                    SecurityType::FtSae => elements::ft_sae_ie_cipher(
                        None,
                        self.link.bss_info.group_mgmt_cipher,
                    ),
                    SecurityType::FtSaeExtKey => {
                        elements::ft_sae_ext_key_ie_cipher(
                            None,
                            self.link.bss_info.group_mgmt_cipher,
                        )
                    }
                    SecurityType::SaeExtKey => elements::sae_ext_key_ie_cipher(
                        self.link.bss_info.group_mgmt_cipher,
                    ),
                    _ => elements::sae_ie_cipher(
                        self.link.bss_info.group_mgmt_cipher,
                    ),
                };
                let mut ies = rsne;
                // FT initial mobility domain association: the request
                // carries the MDIE, which prompts the AP to answer with
                // MDIE + FTIE (R0KH-ID / R1KH-ID).
                if matches!(
                    self.link.bss_info.security,
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
    pub(crate) async fn send_sae_commit(&mut self, auth_data: &[u8]) {
        let attrs = Nl80211Authenticate::new(self.core.if_index)
            .ssid(&self.link.network.ssid)
            .mac(self.link.bss_info.bssid)
            .frequency(self.link.bss_info.freq_mhz)
            .auth_type(Nl80211AuthType::Sae)
            .auth_data(auth_data.to_vec())
            .build();
        if let Err(e) = drain_request(
            self.core.conn_handle.authenticate(attrs).execute().await,
        )
        .await
        {
            log::warn!("send SAE commit failed: {e}");
            self.state = WifiState::Failed;
            return;
        }
        self.auth.sae_commit_sent = true;
        self.auth.sae_commit_auth_data = auth_data.to_vec();
        log::info!("SAE commit sent");
    }

    /// the AP rejected the H2E commit (an HnP-only AP); restart the
    /// SAE exchange with a hunting-and-pecking commit. Only attempted
    /// once per connection attempt (`sae_hnp_attempted`).
    pub(crate) async fn restart_sae_with_hnp(&mut self) {
        let Some(password) = self.link.network.password.as_deref() else {
            log::warn!("no password for HnP SAE restart");
            self.fail_auth(WifiError::new(
                ErrorKind::InvalidConfig,
                "no password for HnP SAE restart",
            ));
            return;
        };
        let auth = match AuthMethod::new_sae(
            password,
            &self.link.network.ssid,
            self.core.mac,
            self.link.bss_info.bssid,
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
        self.auth.method = Some(auth);
        self.auth.sae_hnp_attempted = true;
        let auth_data = match self.auth.method.as_mut().unwrap().initial_frame()
        {
            Ok(data) => data,
            Err(e) => {
                log::warn!("HnP SAE commit failed: {e}");
                self.fail_auth(e);
                return;
            }
        };
        log::info!("SAE restarted with hunting-and-pecking");
        self.auth.sae_sync = 0;
        self.send_sae_commit(&auth_data).await;
    }

    /// Handle an EAPOL-Key frame (4-way handshake / group rekey).
    pub(crate) async fn handle_control_port_frame(&mut self, frame: &[u8]) {
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
            if self.link.bss_info.security.is_ft() && self.link.ft.is_none() {
                log::debug!(
                    "buffered 4-way Message 1 until the FT context exists"
                );
                self.link.pending_ft_msg1 = Some(frame.to_vec());
                return;
            }

            if self.link.fourway.is_none() {
                if self.link.bss_info.security.is_ft() {
                    // Initial association with an FT AKM: the 4-way
                    // handshake runs with the PTK derived from PMK-R1
                    // (802.11-2020 §12.8); Message 2's RSNE must carry
                    // PMKR1Name as its PMKID (the AP verifies that for
                    // FT AKMs), matching the association's FT context.
                    let Some(ft) = self.link.ft.as_ref() else {
                        log::warn!("no FT context for 4-way handshake");
                        self.state = WifiState::Failed;
                        return;
                    };
                    let mut rsne = match self.link.bss_info.security {
                        SecurityType::FtSae => elements::ft_sae_ie_cipher(
                            Some(ft.pmk_r1.name),
                            self.link.bss_info.group_mgmt_cipher,
                        ),
                        SecurityType::FtSaeExtKey => {
                            elements::ft_sae_ext_key_ie_cipher(
                                Some(ft.pmk_r1.name),
                                self.link.bss_info.group_mgmt_cipher,
                            )
                        }
                        _ => elements::ft_psk_ie_cipher(
                            Some(ft.pmk_r1.name),
                            self.link.bss_info.group_mgmt_cipher,
                        ),
                    };
                    // MDIE + FTIE from the association response join the
                    // RSNE in the Message 2 key data.
                    rsne.extend_from_slice(&ft.assoc_resp_ft_ies);
                    if self.link.network.ocv {
                        elements::rsne_set_ocvc(&mut rsne, true);
                    }
                    if self.link.network.ext_key_id {
                        elements::rsne_set_ext_key_id(&mut rsne, true);
                    }
                    let mut fw = FourWayState::new_ft(
                        ft.pmk_r1.clone(),
                        self.core.mac,
                        self.link.bss_info.bssid,
                        rsne,
                        self.link.bss_info.ap_rsne.clone(),
                        self.link.bss_info.ap_rsnxe.clone(),
                    );
                    if !self.enable_ocv(&mut fw) {
                        self.state = WifiState::Failed;
                        return;
                    }
                    fw.set_ext_key_id(self.ext_key_id_enabled());
                    self.link.fourway = Some(fw);
                } else {
                    let (pmk, mut rsne, mic_alg) = if let Some(entry) =
                        self.link.pmksa_in_use.as_ref()
                    {
                        // 4-way over a cached PMK. The RSNE must be
                        // the same one the association request carried
                        // (with the PMKID) - the AP verifies that.
                        let rsne = self.rsne_with_pmkid(Some(entry.pmkid));
                        (entry.pmk, rsne, entry.mic_alg)
                    } else {
                        match self.link.bss_info.security {
                            SecurityType::Owe => {
                                let Some(ref owe_auth) = self.auth.owe else {
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
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::HmacSha256,
                                )
                            }
                            SecurityType::Wpa2Psk => {
                                let Some(pmk) = self.auth.psk_pmk else {
                                    log::warn!(
                                        "no PSK PMK for 4-way handshake"
                                    );
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::wpa2_psk_ie_cipher(
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::HmacSha1,
                                )
                            }
                            SecurityType::Wpa2PskSha256 => {
                                let Some(pmk) = self.auth.psk_pmk else {
                                    log::warn!(
                                        "no PSK PMK for 4-way handshake"
                                    );
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::wpa2_psk_sha256_ie_cipher(
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::AesCmac,
                                )
                            }
                            SecurityType::Wpa2Ent => {
                                let Some(pmk) = self.auth.eap_pmk else {
                                    log::warn!(
                                        "no EAP PMK for 4-way handshake"
                                    );
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::wpa2_ent_ie_cipher(
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::HmacSha1,
                                )
                            }
                            SecurityType::Wpa2EntSha256 => {
                                let Some(pmk) = self.auth.eap_pmk else {
                                    log::warn!(
                                        "no EAP PMK for 4-way handshake"
                                    );
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::wpa2_ent_sha256_ie_cipher(
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::AesCmac,
                                )
                            }
                            SecurityType::SaeExtKey => {
                                let Some(pmk) = self
                                    .auth
                                    .method
                                    .as_ref()
                                    .and_then(|a| a.pmk())
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
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::HmacSha256,
                                )
                            }
                            _ => {
                                // SAE
                                let Some(pmk) = self
                                    .auth
                                    .method
                                    .as_ref()
                                    .and_then(|a| a.pmk())
                                else {
                                    log::warn!("no PMK for 4-way handshake");
                                    self.state = WifiState::Failed;
                                    return;
                                };
                                (
                                    pmk,
                                    elements::sae_ie_cipher(
                                        self.link.bss_info.group_mgmt_cipher,
                                    ),
                                    MicAlg::AesCmac,
                                )
                            }
                        }
                    };
                    if self.link.network.ocv {
                        elements::rsne_set_ocvc(&mut rsne, true);
                    }
                    if self.link.network.ext_key_id {
                        elements::rsne_set_ext_key_id(&mut rsne, true);
                    }
                    let mut fw = FourWayState::new_with_ap_ies(
                        &pmk,
                        mic_alg,
                        self.core.mac,
                        self.link.bss_info.bssid,
                        rsne,
                        self.link.bss_info.ap_rsne.clone(),
                        self.link.bss_info.ap_rsnxe.clone(),
                    );
                    if !self.enable_ocv(&mut fw) {
                        self.state = WifiState::Failed;
                        return;
                    }
                    fw.set_ext_key_id(self.ext_key_id_enabled());
                    self.link.fourway = Some(fw);
                }
            }

            let msg2 = {
                let fw = self.link.fourway.as_mut().unwrap();
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
                &mut self.core.conn_handle,
                self.core.if_index,
                self.link.bss_info.bssid,
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
                let fw = match self.link.fourway.as_mut() {
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
                        if self.link.pmksa_in_use.is_some() {
                            self.pmksa_fallback().await;
                        } else if matches!(
                            self.link.bss_info.security,
                            SecurityType::Wpa2Psk
                                | SecurityType::Wpa2PskSha256
                                | SecurityType::FtPsk
                        ) && e.msg == "MIC mismatch"
                        {
                            // WPA2-PSK/FT-PSK verifies the passphrase
                            // only in the 4-way handshake; a Message 3
                            // MIC mismatch is the wrong-password signal.
                            let err = WifiError::wrong_password(
                                &self.link.network.ssid,
                            );
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
            let ext_key_id =
                self.link.fourway.as_ref().and_then(|fw| fw.key_id());
            if let Some(key_id) = ext_key_id
                && let Some(tk) =
                    self.link.fourway.as_ref().and_then(|fw| fw.tk())
            {
                let attrs = Nl80211Key::new_ptk(
                    self.core.if_index,
                    self.link.bss_info.bssid,
                    tk.to_vec(),
                )
                .key_index(key_id)
                .build();
                if let Err(e) = drain_request(
                    self.core.conn_handle.new_key(attrs).execute().await,
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
                &mut self.core.conn_handle,
                self.core.if_index,
                self.link.bss_info.bssid,
                &msg4,
            )
            .await
            {
                log::warn!("send msg4 failed: {e}");
                self.state = WifiState::Failed;
                return;
            }
            log::info!("4-way: Message 4 sent");

            if let Some(tk) = self.link.fourway.as_ref().and_then(|fw| fw.tk())
            {
                let mut builder = Nl80211Key::new_ptk(
                    self.core.if_index,
                    self.link.bss_info.bssid,
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
                    self.core
                        .conn_handle
                        .new_key(builder.build())
                        .execute()
                        .await,
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
                    self.core
                        .conn_handle
                        .new_key(
                            Nl80211Key::new_gtk(
                                self.core.if_index,
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
                    self.core
                        .conn_handle
                        .new_key(
                            Nl80211Key::new_igtk(
                                self.core.if_index,
                                igtk.key.clone(),
                                igtk.key_index,
                                igtk.ipn.to_vec(),
                            )
                            .cipher(self.link.bss_info.group_mgmt_cipher)
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
                    self.core
                        .conn_handle
                        .new_key(
                            Nl80211Key::new_bigtk(
                                self.core.if_index,
                                bigtk.key.clone(),
                                bigtk.key_index,
                                bigtk.ipn.to_vec(),
                            )
                            .cipher(self.link.bss_info.group_mgmt_cipher)
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
                self.link.fourway.as_ref().and_then(|f| f.kck()),
                self.link.fourway.as_ref().and_then(|f| f.kek()),
                &self.link.fourway,
            ) {
                let rc = fw.replay_counter_bytes();
                let attrs = Nl80211RekeyOffload::new(self.core.if_index)
                    .kek(kek.to_vec())
                    .kck(kck.to_vec())
                    .replay_ctr(rc)
                    .build();
                match drain_request(
                    self.core
                        .conn_handle
                        .set_rekey_offload(attrs)
                        .execute()
                        .await,
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
                self.scan.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
                self.state = WifiState::ConnectedWithOffloadRekey;
            } else {
                log::info!(
                    "keys installed - connection established (userspace rekey)"
                );
                self.scan.scan_retry_interval = RETRY_BACKOFF_INIT_SEC;
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
                let fw = match self.link.fourway.as_mut() {
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
                &mut self.core.conn_handle,
                self.core.if_index,
                self.link.bss_info.bssid,
                &msg2,
            )
            .await
            {
                log::warn!("send group rekey reply failed: {e}");
                return;
            }
            log::info!("group key handshake: Message 2 sent");

            let (gtk_data, gtk_idx) = match self.link.fourway.as_ref() {
                Some(fw) => (fw.gtk().map(|g| g.to_vec()), fw.gtk_index()),
                None => (None, 0),
            };
            if let Some(gtk_data) = gtk_data {
                if let Err(e) = drain_request(
                    self.core
                        .conn_handle
                        .new_key(
                            Nl80211Key::new_gtk(
                                self.core.if_index,
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
    pub(crate) async fn handle_eap_frame(&mut self, eap_pdu: &[u8]) {
        let Some(packet) = EapPacket::parse(eap_pdu) else {
            log::warn!("unparseable EAP packet ({} bytes)", eap_pdu.len());
            return;
        };
        let Some(peer) = self.auth.eap_peer.as_mut() else {
            log::warn!("EAP frame without an active EAP peer");
            return;
        };
        match peer.handle_packet(&packet) {
            Ok(EapAction::Respond(response)) => {
                let frame = eapol::build_eapol_eap_frame(&response);
                if let Err(e) = send_ctrl_port_frame(
                    &mut self.core.conn_handle,
                    self.core.if_index,
                    self.link.bss_info.bssid,
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
                self.auth.eap_pmk = Some(pmk);
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
    pub(crate) fn process_owe_assoc_response(
        &mut self,
        ies: Option<&[u8]>,
    ) -> bool {
        let Some(ies) = ies else {
            log::warn!("OWE: no IEs in association response");
            return false;
        };
        let Some(dh_data) = owe::find_owe_dh_element(ies) else {
            log::warn!("OWE: no DH Parameter Element in assoc response");
            return false;
        };
        let Some(ref mut owe_auth) = self.auth.owe else {
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
