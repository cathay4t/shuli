// SPDX-License-Identifier: Apache-2.0

//! WPA client core: the per-interface connection flow.
//!
//! The flow is a simple linear walk over [`WifiState`] - Init -> Scanning ->
//! Authenticating -> Connected - driven by repeated calls to
//! [`WifiClient::process`]. There is no internal transition table; events (SAE
//! frames, association results, EAPOL-Key messages) advance the current state
//! directly. Scan specifics live in `scan.rs`, pre-association authentication
//! (SAE today, WPA2/EAP later) in `auth.rs`, and nl80211 details in `nl80211/`.

use futures::{StreamExt, TryStreamExt};
use wl_nl80211::{Nl80211Attr, Nl80211ConnectionHandle, Nl80211Handle};

use crate::{
    ETH_ALEN, ErrorKind, WifiError,
    auth::{AuthAction, AuthMethod},
    config::WifiConfig,
    crypto::{
        handshake4::{FourWayState, MicAlg},
        owe::{self, OweAuth},
    },
    ieee80211::{auth, eapol, elements},
    nl80211::{
        auth_assoc, connect,
        events::{WifiEvent, parse_event},
        keys,
    },
    scan::{BssInfo, SecurityType},
};

const RETRY_WAIT_SEC: u64 = 10;
const RETRY_AUTH_SEC: u64 = 600;
/// Max time to wait for the next authentication event (SAE frame, association
/// result, 4-way handshake message) before giving up and retrying.
const AUTH_EVENT_TIMEOUT_SECS: u64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WifiState {
    /// Initial state; the next `process()` call triggers a scan.
    #[default]
    Init,
    /// Scan in flight / waiting for results.
    Scanning,
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

pub struct WifiClient {
    pub(crate) handle: Nl80211Handle,
    pub(crate) conn_handle: Nl80211ConnectionHandle,
    pub(crate) event_receiver: futures::channel::mpsc::UnboundedReceiver<(
        netlink_packet_core::NetlinkMessage<genetlink::message::RawGenlMessage>,
        netlink_sys::SocketAddr,
    )>,
    pub(crate) state: WifiState,
    pub(crate) if_index: u32,
    pub(crate) mac: [u8; ETH_ALEN],
    pub(crate) config: WifiConfig,
    /// Best BSS found by the scan phase.
    pub(crate) bss_info: BssInfo,
    /// Active pre-association authentication method.
    pub(crate) auth: Option<AuthMethod>,
    /// OWE DH exchange state (only for OWE networks).
    pub(crate) owe: Option<OweAuth>,
    /// WPA2-PSK PMK derived via PBKDF2 (only for WPA2-PSK networks).
    pub(crate) psk_pmk: Option<[u8; 32]>,
    /// 4-way handshake state (shared by all auth methods).
    pub(crate) fourway: Option<FourWayState>,
}

impl WifiClient {
    /// Validate the configuration by checking the WiFi PHY interface exists,
    /// then open the nl80211 connection and join the event multicast groups.
    pub async fn init(config: WifiConfig) -> Result<Self, WifiError> {
        let (mut conn, handle, event_receiver) = wl_nl80211::new_connection()
            .map_err(|e| {
            WifiError::new(ErrorKind::Config, e.to_string())
        })?;

        if let Err(e) = crate::nl80211::mcast::join_multicast_groups(&mut conn)
        {
            log::warn!("multicast join: {e}");
        }
        tokio::spawn(conn);

        let (if_index, mac) =
            get_if_index_and_mac(&handle, &config.iface_name).await?;

        log::info!(
            "interface {} if_index={}, mac={mac:02x?}",
            config.iface_name,
            if_index
        );

        let conn_handle = handle.connection();

        Ok(WifiClient {
            handle,
            conn_handle,
            event_receiver,
            state: WifiState::Init,
            if_index,
            mac,
            config,
            bss_info: BssInfo::default(),
            auth: None,
            owe: None,
            psk_pmk: None,
            fourway: None,
        })
    }

    /// Advance the connection flow by one step and return the current state.
    /// The caller (daemon loop) keeps calling this; on transient errors the
    /// client falls back to a retry state instead of failing hard.
    pub async fn run(&mut self) -> Result<WifiState, WifiError> {
        if let Err(e) = self._run().await {
            log::warn!("WPA process error: {e}");
            self.state = if self.state == WifiState::Authenticating {
                WifiState::FailedAuthentication
            } else {
                WifiState::Failed
            };
            Err(e)
        } else {
            Ok(self.state)
        }
    }

    async fn _run(&mut self) -> Result<(), WifiError> {
        match self.state {
            WifiState::Init => {
                self.send_out_scan_request().await?;
                self.state = WifiState::Scanning;
            }
            WifiState::Scanning => {
                self.wait_scan_finish().await;
                self.process_scan_results().await?;
                self.send_out_auth_request().await?;
                self.state = WifiState::Authenticating;
            }
            WifiState::Authenticating => {
                let timed = tokio::time::timeout(
                    std::time::Duration::from_secs(AUTH_EVENT_TIMEOUT_SECS),
                    self.event_receiver.next(),
                )
                .await;
                match timed {
                    Ok(Some((raw_msg, _addr))) => {
                        if let Some(event) = parse_event(raw_msg) {
                            self.handle_event(event).await;
                        }
                    }
                    Ok(None) => {
                        return Err(WifiError::new(
                            ErrorKind::Nl80211,
                            "event channel closed",
                        ));
                    }
                    Err(_) => {
                        log::warn!("authentication timed out; will retry");
                        self.state = WifiState::Failed;
                    }
                }
            }
            WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey => {
                // Keep draining events so group rekeys and disconnects are
                // handled while the connection stays up.
                match self.event_receiver.next().await {
                    Some((raw_msg, _addr)) => {
                        if let Some(event) = parse_event(raw_msg) {
                            self.handle_event(event).await;
                        }
                    }
                    None => {
                        return Err(WifiError::new(
                            ErrorKind::Nl80211,
                            "event channel closed",
                        ));
                    }
                }
            }
            WifiState::Failed | WifiState::FailedAuthentication => {
                let secs = if self.state == WifiState::FailedAuthentication {
                    RETRY_AUTH_SEC
                } else {
                    RETRY_WAIT_SEC
                };
                log::info!("{:?}; retrying in {} seconds", self.state, secs);
                tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
                self.state = WifiState::Init;
            }
        }
        Ok(())
    }

    async fn handle_event(&mut self, event: WifiEvent) {
        match event {
            WifiEvent::Frame { frame } => {
                self.handle_auth_frame(&frame).await;
            }

            WifiEvent::Authenticated { status, auth_frame } => {
                if self.bss_info.security != SecurityType::Sae {
                    // Open-system auth (open + OWE): no frame, just
                    // a status.
                    if status == 0 {
                        if self.bss_info.security == SecurityType::Owe {
                            // OWE: associate with DH element.
                            let owe_auth = OweAuth::new();
                            let dh_elem = owe_auth.build_dh_element();
                            self.owe = Some(owe_auth);
                            log::info!(
                                "open-system AUTHENTICATE ok - sending OWE \
                                 ASSOCIATE"
                            );
                            if let Err(e) = auth_assoc::associate_owe(
                                &self.handle,
                                self.if_index,
                                &self.config.ssid,
                                self.bss_info.bssid,
                                self.bss_info.freq_mhz,
                                &dh_elem,
                            )
                            .await
                            {
                                log::warn!("OWE ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else if self.bss_info.security
                            == SecurityType::Wpa2Psk
                        {
                            // WPA2-PSK: associate with PSK RSNE.
                            log::info!(
                                "open-system AUTHENTICATE ok - sending \
                                 WPA2-PSK ASSOCIATE"
                            );
                            if let Err(e) = auth_assoc::associate_wpa2_psk(
                                &self.handle,
                                self.if_index,
                                &self.config.ssid,
                                self.bss_info.bssid,
                                self.bss_info.freq_mhz,
                            )
                            .await
                            {
                                log::warn!("ASSOCIATE failed: {e}");
                                self.state = WifiState::Failed;
                            }
                        } else {
                            // Plain open: associate without DH.
                            log::info!(
                                "open-system AUTHENTICATE ok - sending \
                                 ASSOCIATE"
                            );
                            if let Err(e) = auth_assoc::associate_open(
                                &self.handle,
                                self.if_index,
                                &self.config.ssid,
                                self.bss_info.bssid,
                                self.bss_info.freq_mhz,
                            )
                            .await
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
                } else if let Some(frame) = auth_frame {
                    // SAE: the auth frame carries the AP's commit
                    // (transaction 1) or confirm (transaction 2).
                    self.handle_auth_frame(&frame).await;
                } else if status != 0 {
                    log::warn!("AUTHENTICATE failed: status={status}");
                    self.state = WifiState::FailedAuthentication;
                } else {
                    log::debug!("AUTHENTICATE event without frame (status=0)");
                }
            }

            WifiEvent::Associated { status, ies } => {
                if status == 0 {
                    if self.bss_info.security == SecurityType::Open {
                        log::info!(
                            "ASSOCIATED - open network, connection established"
                        );
                        self.state = WifiState::ConnectedWithoutOffloadRekey;
                    } else if self.bss_info.security == SecurityType::Owe {
                        if self.process_owe_assoc_response(ies.as_deref()) {
                            log::info!(
                                "ASSOCIATED - OWE PMK derived, waiting for \
                                 4-way handshake"
                            );
                        } else {
                            self.state = WifiState::Failed;
                        }
                    } else {
                        log::info!("ASSOCIATED - waiting for 4-way handshake");
                    }
                } else {
                    log::warn!("ASSOCIATE failed: status={status}");
                    self.state = WifiState::Failed;
                }
            }

            WifiEvent::ConnectResult { status } => {
                if status == 0 {
                    log::debug!(
                        "CONNECT event (associated); awaiting 4-way handshake"
                    );
                } else {
                    log::warn!("CONNECT failed: status={status}");
                    self.state = WifiState::Failed;
                }
            }

            WifiEvent::ControlPortFrame { frame } => {
                self.handle_control_port_frame(&frame).await;
            }

            WifiEvent::PortAuthorized => {
                log::info!("PORT_AUTHORIZED - connection ready");
                self.state = WifiState::ConnectedWithoutOffloadRekey;
            }

            WifiEvent::Disconnect { reason } => {
                log::warn!("DISCONNECT: reason={reason}");
                self.state = WifiState::Failed;
            }

            WifiEvent::ScanStart | WifiEvent::NewScanResults => {
                log::debug!("scan event: {event:?}");
            }
            WifiEvent::ExternalAuth => {
                log::debug!("EXTERNAL_AUTH event (unsupported in this mode)");
            }
            WifiEvent::Unknown { cmd } => {
                log::debug!("event: {cmd:?}");
            }
        }
    }

    /// Feed an 802.11 management frame (or the auth frame embedded in an
    /// AUTHENTICATE event) into the active auth method.
    async fn handle_auth_frame(&mut self, frame: &[u8]) {
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
                        self.state = WifiState::FailedAuthentication;
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
                if let Err(e) = auth_assoc::authenticate_sae_confirm(
                    &self.handle,
                    self.if_index,
                    &self.config.ssid,
                    self.bss_info.bssid,
                    self.bss_info.freq_mhz,
                    &confirm,
                )
                .await
                {
                    log::warn!("send SAE confirm failed: {e}");
                    self.state = WifiState::Failed;
                } else {
                    log::info!("SAE confirm sent");
                }
            }
            AuthAction::Complete => {
                log::info!("SAE completed - sending ASSOCIATE");
                if let Err(e) = auth_assoc::associate(
                    &self.handle,
                    self.if_index,
                    &self.config.ssid,
                    self.bss_info.bssid,
                    self.bss_info.freq_mhz,
                )
                .await
                {
                    log::warn!("ASSOCIATE failed: {e}");
                    self.state = WifiState::Failed;
                }
            }
        }
    }

    /// Handle an EAPOL-Key frame (4-way handshake / group rekey).
    async fn handle_control_port_frame(&mut self, frame: &[u8]) {
        let Some(parsed) = eapol::parse_eapol_key_frame(frame) else {
            log::debug!("unparseable control port frame");
            return;
        };

        log::debug!(
            "EAPOL-Key: info={} replay={}",
            eapol::fmt_key_info(parsed.key_info),
            parsed.replay_counter
        );

        if !parsed.has_mic() && parsed.has_ack() {
            // 4-way handshake Message 1 (ANonce).
            log::info!("4-way handshake: Message 1 (ANonce)");

            if self.fourway.is_none() {
                let (pmk, pmkid, rsne, mic_alg) = match self.bss_info.security {
                    SecurityType::Owe => {
                        let Some(ref owe_auth) = self.owe else {
                            log::warn!("no OWE state for 4-way handshake");
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
                            owe_auth.pmkid().unwrap_or([0u8; 16]),
                            elements::owe_ie(),
                            MicAlg::HmacSha256,
                        )
                    }
                    SecurityType::Wpa2Psk => {
                        let Some(pmk) = self.psk_pmk else {
                            log::warn!("no PSK PMK for 4-way handshake");
                            self.state = WifiState::Failed;
                            return;
                        };
                        (
                            pmk,
                            [0u8; 16],
                            elements::wpa2_psk_ie(),
                            MicAlg::HmacSha1,
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
                            self.auth
                                .as_ref()
                                .and_then(|a| a.pmkid())
                                .unwrap_or([0u8; 16]),
                            elements::sae_ie(),
                            MicAlg::AesCmac,
                        )
                    }
                };
                self.fourway = Some(FourWayState::new(
                    &pmk,
                    &pmkid,
                    self.mac,
                    self.bss_info.bssid,
                    rsne,
                    mic_alg,
                ));
            }

            let msg2 = {
                let fw = self.fourway.as_mut().unwrap();
                match fw
                    .process_message_1(&parsed.key_nonce, parsed.replay_counter)
                {
                    Ok(msg2) => msg2,
                    Err(e) => {
                        log::warn!("process_message_1 failed: {e}");
                        self.state = WifiState::Failed;
                        return;
                    }
                }
            };
            if let Err(e) = send_ctrl_port_frame(
                &self.handle,
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

            let (msg4, gtk) = {
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
                        // retry on the short backoff.
                        log::warn!("process_message_3 failed: {e}");
                        self.state = WifiState::Failed;
                        return;
                    }
                }
            };

            if let Err(e) = send_ctrl_port_frame(
                &self.handle,
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
                if let Err(e) = keys::install_ptk(
                    &self.handle,
                    self.if_index,
                    self.bss_info.bssid,
                    &tk,
                )
                .await
                {
                    log::warn!("install PTK failed: {e}");
                    self.state = WifiState::Failed;
                    return;
                }
                log::info!("PTK installed");
            }

            if let Some(ref gtk_data) = gtk {
                let gtk_idx =
                    self.fourway.as_ref().map(|fw| fw.gtk_index()).unwrap_or(0);
                if let Err(e) = keys::install_gtk(
                    &self.handle,
                    self.if_index,
                    gtk_data,
                    gtk_idx,
                )
                .await
                {
                    log::warn!("install GTK failed: {e}");
                    self.state = WifiState::Failed;
                    return;
                }
                log::info!("GTK[{gtk_idx}] installed");
            }

            // Try to offload GTK rekey to the driver/firmware.
            // Falls back to userspace rekey when unsupported
            // (e.g. mac80211_hwsim returns -EOPNOTSUPP).
            let offloaded = if let (Some(kck), Some(kek), Some(fw)) = (
                self.fourway.as_ref().and_then(|f| f.kck()),
                self.fourway.as_ref().and_then(|f| f.kek()),
                &self.fourway,
            ) {
                let rc = fw.replay_counter_bytes();
                match keys::set_rekey_offload(
                    &self.handle,
                    self.if_index,
                    &kek,
                    &kck,
                    &rc,
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
                self.state = WifiState::ConnectedWithOffloadRekey;
            } else {
                log::info!(
                    "keys installed - connection established (userspace rekey)"
                );
                self.state = WifiState::ConnectedWithoutOffloadRekey;
            }
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
                &self.handle,
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
                if let Err(e) = keys::install_gtk(
                    &self.handle,
                    self.if_index,
                    &gtk_data,
                    gtk_idx,
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
}

impl WifiClient {
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

impl WifiClient {
    /// Cleanly disconnect from the AP.  Call this before dropping the
    /// client so the AP receives a proper deauthentication.
    pub async fn shutdown(&mut self) {
        if let Err(e) =
            connect::disconnect(&mut self.conn_handle, self.if_index).await
        {
            log::debug!("disconnect on shutdown: {e}");
        }
    }
}

impl Drop for WifiClient {
    fn drop(&mut self) {
        let mut conn_handle = self.conn_handle.clone();
        let if_index = self.if_index;
        // Best-effort: run the disconnect on a dedicated thread with its
        // own runtime so we never panic outside a tokio context.  The
        // thread is detached; if the process exits first the disconnect
        // is simply lost (same as the old tokio::spawn approach, but
        // without the panic risk).
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            if let Ok(rt) = rt {
                rt.block_on(async {
                    let _ =
                        connect::disconnect(&mut conn_handle, if_index).await;
                });
            }
        });
    }
}

async fn send_ctrl_port_frame(
    handle: &Nl80211Handle,
    if_index: u32,
    bssid: [u8; 6],
    frame: &[u8],
) -> Result<(), WifiError> {
    const ETH_P_PAE: u16 = 0x888E;

    let mut nl_msg = netlink_packet_core::NetlinkMessage::from(
        netlink_packet_generic::GenlMessage::from_payload(
            wl_nl80211::Nl80211Message {
                cmd: wl_nl80211::Nl80211Command::ControlPortFrame,
                attributes: vec![
                    Nl80211Attr::IfIndex(if_index),
                    Nl80211Attr::Mac(bssid),
                    Nl80211Attr::Frame(frame.to_vec()),
                    Nl80211Attr::ControlPortEthertype(ETH_P_PAE),
                ],
            },
        ),
    );
    nl_msg.header.flags =
        netlink_packet_core::NLM_F_REQUEST | netlink_packet_core::NLM_F_ACK;

    let mut h = handle.clone();
    let mut stream = h.request(nl_msg).await?;
    while let Some(_msg) = stream.try_next().await? {}
    Ok(())
}

async fn get_if_index_and_mac(
    handle: &Nl80211Handle,
    ifname: &str,
) -> Result<(u32, [u8; ETH_ALEN]), WifiError> {
    let mut dump = handle.interface().get(vec![]).execute().await;
    while let Some(msg) = dump.try_next().await? {
        if msg.payload.attributes.iter().any(
            |attr| matches!(attr, Nl80211Attr::IfName(name) if name == ifname),
        ) {
            let mut index = 0;
            let mut mac = [0u8; ETH_ALEN];
            for attr in &msg.payload.attributes {
                if let Nl80211Attr::IfIndex(idx) = attr {
                    index = *idx;
                } else if let Nl80211Attr::Mac(mac_addr) = attr {
                    mac.copy_from_slice(mac_addr);
                }
            }
            if index != 0 && mac != [0u8; ETH_ALEN] {
                return Ok((index, mac));
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
