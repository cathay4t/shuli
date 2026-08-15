// SPDX-License-Identifier: Apache-2.0

//! Authentication method abstraction.
//!
//! The connection flow in `client.rs` only knows [`AuthMethod`]: build the
//! initial AUTHENTICATE payload, feed in incoming authentication frames, and
//! collect PMK/PMKID once authenticated. SAE (WPA3-Personal) is implemented
//! today; WPA2-PSK (no pre-association exchange, PMK derived from the
//! passphrase) and EAP/802.1X plug in here without touching the client flow.

use crate::{
    ETH_ALEN, ErrorKind, WifiClient, WifiError, crypto::sae::SaeAuth,
    eap::EapPeer, eap_tls::EapTlsMethod, scan::SecurityType,
};

/// What the client should do after processing an authentication frame.
pub(crate) enum AuthAction {
    /// Keep waiting for more authentication frames.
    Continue,
    /// Send this confirmation frame back to the AP.
    SendConfirm(Vec<u8>),
    /// The AP demanded an anti-clogging token (status 76): re-send the
    /// SAE commit with the carried token bytes.
    SendCommitWithToken(Vec<u8>),
    /// The H2E commit was rejected (e.g. by an HnP-only AP) and the
    /// network allows it: restart the SAE exchange with
    /// hunting-and-pecking.
    RetryWithHnp,
    /// The AP rejected the SAE commit with a transient status (e.g. 30
    /// "refused temporarily"). Per 802.11-2020 §12.4.8.6.4 (Committed
    /// state) the rejection is silently discarded and the commit is
    /// retransmitted on the SAE retransmission timer; only after the
    /// Sync counter is exhausted does the instance give up and the
    /// client restart the connection on the short backoff.
    RetryTemporarily,
    /// Authentication succeeded; proceed to association.
    Complete,
}

/// The pre-association authentication method in use.
/// TODO(WPA2/EAP): add `Psk` (derive PMK from passphrase, skip the SAE
/// exchange) and `Eap` (802.1X) variants here.
pub(crate) enum AuthMethod {
    Sae(SaeAuth),
}

impl AuthMethod {
    pub(crate) fn new_sae(
        password: &str,
        ssid: &str,
        sta_mac: [u8; ETH_ALEN],
        bssid: [u8; ETH_ALEN],
        h2e: bool,
        hnp_fallback: bool,
        password_id: Option<&str>,
    ) -> Result<Self, WifiError> {
        Ok(AuthMethod::Sae(SaeAuth::new_with_password_id(
            password,
            ssid,
            sta_mac,
            bssid,
            h2e,
            hnp_fallback,
            password_id,
        )?))
    }

    /// Build the initial AUTHENTICATE payload (SAE commit for WPA3).
    pub(crate) fn initial_frame(&mut self) -> Result<Vec<u8>, WifiError> {
        match self {
            AuthMethod::Sae(sae) => Ok(sae.build_init_auth_msg()),
        }
    }

    /// Re-run the SAE commit with the AP's anti-clogging token appended
    /// (status 76 retry).
    pub(crate) fn commit_with_token(
        &mut self,
        token: &[u8],
    ) -> Result<Vec<u8>, WifiError> {
        match self {
            AuthMethod::Sae(sae) => sae.build_commit_with_token(token),
        }
    }

    /// Process an authentication frame received from the AP.
    pub(crate) fn process_frame(
        &mut self,
        auth_seq: u16,
        status: u16,
        payload: &[u8],
    ) -> Result<AuthAction, WifiError> {
        match self {
            AuthMethod::Sae(sae) => {
                process_sae_frame(sae, auth_seq, status, payload)
            }
        }
    }

    pub(crate) fn pmk(&self) -> Option<[u8; 32]> {
        match self {
            AuthMethod::Sae(sae) => sae.pmk(),
        }
    }

    /// PMKID of the completed authentication; consumed by the PMKSA
    /// cache (Stage 2 G4).
    #[allow(dead_code)]
    pub(crate) fn pmkid(&self) -> Option<[u8; 16]> {
        match self {
            AuthMethod::Sae(sae) => sae.pmkid(),
        }
    }
}

/// SAE exchange: commit (transaction 1) then confirm (transaction 2).
fn process_sae_frame(
    sae: &mut SaeAuth,
    auth_seq: u16,
    status: u16,
    payload: &[u8],
) -> Result<AuthAction, WifiError> {
    // Once SAE has completed we may already have sent ASSOCIATE; ignore any
    // further (retransmitted) SAE frames instead of re-firing association.
    if sae.confirmed() {
        return Ok(AuthAction::Continue);
    }

    // G2a: anti-clogging token required (status 76): re-send the commit
    // with the token, which sits after the group in the payload (in the
    // Anti-Clogging Token Container element for H2E).
    if auth_seq == 1 && status == crate::crypto::sae::SAE_STATUS_ANTI_CLOGGING {
        let token = crate::crypto::sae::parse_anti_clogging_token(
            sae.is_h2e(),
            payload,
        )?;
        return Ok(AuthAction::SendCommitWithToken(token));
    }

    // Stage 3 M7: status 123 = unknown password identifier (missing or
    // wrong).  Fail cleanly instead of retrying: the identifier is
    // included in every commit when configured, so a 123 here means the
    // AP does not accept our identifier.
    if auth_seq == 1
        && status == crate::crypto::sae::SAE_STATUS_UNKNOWN_PASSWORD_IDENTIFIER
    {
        return Err(WifiError::new(
            ErrorKind::AuthFailed,
            "SAE auth failed: unknown password identifier",
        ));
    }

    // Stage 3 M13: status 127 = SAE-PK required.  shuli does not
    // implement the SAE-PK crypto (PWE + ECDSA confirm signature) yet,
    // so fail cleanly instead of looping with regular SAE.
    if auth_seq == 1 && status == 127 {
        return Err(WifiError::new(
            ErrorKind::AuthFailed,
            "SAE-PK required by AP but shuli does not implement SAE-PK",
        ));
    }

    // Some APs answer the SAE commit with a status that only means
    // "try again shortly" - e.g. 30 (refused temporarily), 17 (no more
    // STAs), or 802.11e channel-condition refusals. 802.11-2020
    // §12.4.8.6.4: "If the Status is some other nonzero value, the
    // frame shall be silently discarded and the t0 (retransmission)
    // timer shall be set" - the SAE layer re-sends the same commit on
    // the retransmission timer (dot11RSNASAERetransPeriod, 2 s) up to
    // `dot11RSNASAESync` times, it does not fail the whole connection
    // on the first rejection. The previous behavior instead backed off
    // for the long `RETRY_AUTH_SEC` interval, which made the client
    // look hung until the daemon was restarted.
    if auth_seq == 1 && is_temporary_reject_status(status) {
        log::info!(
            "SAE commit temporarily rejected (status {status}); \
             retransmitting on the SAE retransmission timer"
        );
        return Ok(AuthAction::RetryTemporarily);
    }

    const SAE_STATUS_H2E: u16 = 126;
    let status_ok = match auth_seq {
        1 => status == 0 || status == SAE_STATUS_H2E,
        _ => status == 0,
    };
    if !status_ok {
        // G2b: an HnP-only AP rejects the H2E commit with a failure
        // status; fall back to hunting-and-pecking when allowed.
        if auth_seq == 1 && sae.is_h2e() && sae.hnp_fallback_allowed() {
            log::info!(
                "SAE H2E commit rejected (status {status}); retrying with \
                 hunting-and-pecking"
            );
            return Ok(AuthAction::RetryWithHnp);
        }
        return Err(WifiError::new(
            ErrorKind::AuthFailed,
            format!("SAE auth failed: seq={auth_seq} status={status}"),
        ));
    }

    match auth_seq {
        // AP commit: body is group(2 LE) || scalar(32) || element(64).
        1 => {
            if payload.len() < 2 + 32 + 64 {
                return Err(WifiError::new(
                    ErrorKind::AuthFailed,
                    format!("SAE commit too short: {} bytes", payload.len()),
                ));
            }
            let group = u16::from_le_bytes([payload[0], payload[1]]);
            if group != sae.group_id() {
                return Err(WifiError::new(
                    ErrorKind::AuthFailed,
                    format!("unsupported SAE group {group}"),
                ));
            }
            let confirm =
                sae.process_commit(&payload[2..34], &payload[34..98])?;
            Ok(AuthAction::SendConfirm(confirm))
        }
        // AP confirm: send_confirm(2 LE) || CN(32). SAE is done.
        2 => {
            sae.process_confirm(payload)?;
            Ok(AuthAction::Complete)
        }
        _ => Ok(AuthAction::Continue),
    }
}

/// Statuses an AP uses to refuse authentication/association
/// temporarily; the client should retry after a short backoff instead
/// of treating them as fatal credential failures.
fn is_temporary_reject_status(status: u16) -> bool {
    matches!(
        status,
        17  // AP unable to handle additional STAs
        | 30 // refused temporarily / association rejected temporarily
        | 32 // unspecified QoS failure
        | 33 // denied due to insufficient bandwidth
        | 34 // denied due to poor channel conditions
        | 35 // denied because QoS is not supported
    )
}

impl WifiClient {
    /// Start authentication with the selected BSS.
    ///
    /// PMKSA cache hit (Stage 2 G4): send open-system AUTHENTICATE and
    /// associate with the cached PMKID, skipping the full SAE exchange.
    ///
    /// Open networks: send open-system AUTHENTICATE (no auth method, no
    /// SAE).  The `Authenticated` event handler proceeds to associate.
    ///
    /// SAE networks: create a fresh SAE auth method and send the commit.
    pub(crate) async fn send_out_auth_request(
        &mut self,
    ) -> Result<(), WifiError> {
        self.auth = None;
        self.fourway = None;
        self.psk_pmk = None;
        self.pmksa_in_use = None;
        self.pending_ft_msg1 = None;
        self.ft_roam = None;
        self.sae_commit_sent = false;
        self.sae_sync = 0;
        self.sae_commit_auth_data.clear();
        self.sae_hnp_attempted = false;
        self.eap_peer = None;
        self.eap_pmk = None;

        // Stage 3 M4: WPA2-Enterprise runs EAP over the control port
        // after association.  Prepare the EAP peer + EAP-TLS method
        // now, so the first EAP-Request/Identity finds it ready.
        if matches!(
            self.bss_info.security,
            SecurityType::Wpa2Ent | SecurityType::Wpa2EntSha256
        ) {
            let eap_cfg = self.network.eap.as_ref().ok_or_else(|| {
                WifiError::new(
                    ErrorKind::InvalidConfig,
                    format!(
                        "{:?} network requires EAP credentials",
                        self.bss_info.security
                    ),
                )
            })?;
            let method = EapTlsMethod::from_config(eap_cfg)?;
            let mut peer = EapPeer::new(eap_cfg.identity.clone());
            peer.set_method(Box::new(method));
            self.eap_peer = Some(peer);
        }

        // G4: a cached PMKSA for the selected BSS replaces the full
        // authentication (SAE) with open-system auth + a PMKID-bearing
        // RSNE at association time.
        if matches!(
            self.bss_info.security,
            SecurityType::Sae
                | SecurityType::SaeExtKey
                | SecurityType::Wpa2Psk
                | SecurityType::Wpa2PskSha256
                | SecurityType::FtSae
                | SecurityType::FtSaeExtKey
                | SecurityType::FtPsk
        ) && let Some(entry) = self
            .pmksa_cache
            .lookup(&self.network.ssid, self.bss_info.bssid)
        {
            log::info!(
                "PMKSA cache hit for BSSID {:02x?} (pmkid {:02x?}); skipping \
                 full authentication",
                self.bss_info.bssid,
                entry.pmkid
            );
            self.pmksa_in_use = Some(entry);
        }

        if self.pmksa_in_use.is_some()
            || !matches!(
                self.bss_info.security,
                SecurityType::Sae
                    | SecurityType::SaeExtKey
                    | SecurityType::FtSae
                    | SecurityType::FtSaeExtKey
            )
        {
            // Open-system authentication: open, OWE, WPA2-PSK, FT-PSK,
            // and cached-PMKSA connections. OWE's DH exchange happens in
            // the association request/response; the PSK AKMs derive the
            // PMK from the passphrase via PBKDF2.
            if self.pmksa_in_use.is_none()
                && matches!(
                    self.bss_info.security,
                    SecurityType::Wpa2Psk
                        | SecurityType::Wpa2PskSha256
                        | SecurityType::FtPsk
                )
            {
                let password =
                    self.network.password.as_deref().ok_or_else(|| {
                        WifiError::new(
                            ErrorKind::InvalidConfig,
                            "password required for WPA2-PSK",
                        )
                    })?;
                self.psk_pmk = Some(crate::crypto::kdf::pbkdf2_pmk(
                    password,
                    &self.network.ssid,
                ));
            }
            log::info!(
                "open-system AUTHENTICATE ({:?} network)",
                self.bss_info.security
            );
            let attrs = wl_nl80211::Nl80211Authenticate::new(self.if_index)
                .ssid(&self.network.ssid)
                .mac(self.bss_info.bssid)
                .frequency(self.bss_info.freq_mhz)
                .auth_type(wl_nl80211::Nl80211AuthType::OpenSystem)
                .build();
            return crate::client::drain_request(
                self.conn_handle.authenticate(attrs).execute().await,
            )
            .await;
        }

        let password = self.network.password.as_deref().ok_or_else(|| {
            WifiError::new(
                ErrorKind::InvalidConfig,
                "password required for encrypted network",
            )
        })?;
        // G2b: `Auto` follows the AP's RSNXE from the scan instead of
        // guessing H2E first - an AP that never advertises H2E support
        // (or advertises none at all) gets hunting-and-pecking on the
        // very first commit, instead of one shuli discovers only after
        // the H2E commit is silently dropped and times out.
        let ap_supports_h2e = self.bss_info.ap_supports_sae_h2e();
        log::debug!(
            "AP RSNXE advertises SAE H2E: {ap_supports_h2e} (sae_pwe={:?})",
            self.network.sae_pwe
        );
        self.auth = Some(AuthMethod::new_sae(
            password,
            &self.network.ssid,
            self.mac,
            self.bss_info.bssid,
            self.network.sae_pwe.starts_h2e(ap_supports_h2e)
                || self.network.sae_password_id.is_some(),
            self.network.sae_pwe.allows_hnp_fallback()
                && self.network.sae_password_id.is_none(),
            self.network.sae_password_id.as_deref(),
        )?);

        let auth_data = self.auth.as_mut().unwrap().initial_frame()?;
        let attrs = wl_nl80211::Nl80211Authenticate::new(self.if_index)
            .ssid(&self.network.ssid)
            .mac(self.bss_info.bssid)
            .frequency(self.bss_info.freq_mhz)
            .auth_type(wl_nl80211::Nl80211AuthType::Sae)
            // NL80211_ATTR_AUTH_DATA: SAE commit (trans||status||body)
            .auth_data(auth_data.clone())
            .build();
        crate::client::drain_request(
            self.conn_handle.authenticate(attrs).execute().await,
        )
        .await?;
        // G2c: remember the commit so a lost frame is answered with a
        // retransmission (SAE Sync) instead of a full rescan cycle.
        self.sae_commit_sent = true;
        self.sae_sync = 0;
        self.sae_commit_auth_data = auth_data;
        Ok(())
    }
}
