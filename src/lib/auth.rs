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
    scan::SecurityType,
};

/// What the client should do after processing an authentication frame.
pub(crate) enum AuthAction {
    /// Keep waiting for more authentication frames.
    Continue,
    /// Send this confirmation frame back to the AP.
    SendConfirm(Vec<u8>),
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
    ) -> Result<Self, WifiError> {
        Ok(AuthMethod::Sae(SaeAuth::new(
            password, ssid, sta_mac, bssid,
        )?))
    }

    /// Build the initial AUTHENTICATE payload (SAE commit for WPA3).
    pub(crate) fn initial_frame(&mut self) -> Result<Vec<u8>, WifiError> {
        match self {
            AuthMethod::Sae(sae) => Ok(sae.build_init_auth_msg()),
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

    const SAE_STATUS_H2E: u16 = 126;
    let status_ok = match auth_seq {
        1 => status == 0 || status == SAE_STATUS_H2E,
        _ => status == 0,
    };
    if !status_ok {
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

impl WifiClient {
    /// Start authentication with the selected BSS.
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

        if self.bss_info.security != SecurityType::Sae {
            // Open, OWE, and WPA2-PSK all use open-system
            // authentication.  OWE's DH exchange happens in the
            // association request/response; WPA2-PSK derives the
            // PMK from the passphrase via PBKDF2.
            if self.bss_info.security == SecurityType::Wpa2Psk {
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
        self.auth = Some(AuthMethod::new_sae(
            password,
            &self.network.ssid,
            self.mac,
            self.bss_info.bssid,
        )?);

        let auth_data = self.auth.as_mut().unwrap().initial_frame()?;
        let attrs = wl_nl80211::Nl80211Authenticate::new(self.if_index)
            .ssid(&self.network.ssid)
            .mac(self.bss_info.bssid)
            .frequency(self.bss_info.freq_mhz)
            .auth_type(wl_nl80211::Nl80211AuthType::Sae)
            // NL80211_ATTR_AUTH_DATA: SAE commit (trans||status||body)
            .auth_data(auth_data)
            .build();
        crate::client::drain_request(
            self.conn_handle.authenticate(attrs).execute().await,
        )
        .await
    }
}
