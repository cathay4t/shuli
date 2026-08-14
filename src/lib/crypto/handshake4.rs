// SPDX-License-Identifier: Apache-2.0

//! 4-Way Handshake state machine and crypto operations (IEEE 802.11-2020
//! §12.7). Supports SAE AKM (00-0F-AC:8) and OWE AKM (00-0F-AC:18)
//! with CCMP-128:
//!   - PMK: 32 bytes
//!   - KCK: 16 bytes
//!   - KEK: 16 bytes
//!   - TK: 16 bytes (CCMP-128 temporal key)
//!
//! SAE uses KDF-Hash-Length + AES-CMAC MIC; OWE uses PRF + HMAC-SHA256
//! MIC (RFC 8110 Table 2).

use aws_lc_rs::{cmac, key_wrap, key_wrap::KeyWrap, rand::SecureRandom};

use crate::{ErrorKind, WifiError, crypto::kdf, ieee80211::eapol};

pub(crate) const KCK_LEN: usize = 16;
pub(crate) const KEK_LEN: usize = 16;
const TK_LEN: usize = 16;
const PTK_LEN: usize = KCK_LEN + KEK_LEN + TK_LEN;

pub(crate) const EAPOL_MIC_LEN: usize = 16;

/// MIC / KDF algorithm selection, determined by the AKM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MicAlg {
    /// SAE (00-0F-AC:8): AES-CMAC MIC, KDF-Hash-Length PTK.
    AesCmac,
    /// OWE (00-0F-AC:18): HMAC-SHA256 MIC, KDF-Hash-Length PTK.
    HmacSha256,
    /// WPA2-PSK (00-0F-AC:2): HMAC-SHA1 MIC, PRF-SHA1 PTK.
    HmacSha1,
}

/// 4-Way Handshake state (supplicant side).
#[derive(Clone, Debug)]
pub struct FourWayState {
    pmk: [u8; 32],
    mac_sta: [u8; 6],
    mac_ap: [u8; 6],
    pub(crate) anonce: Option<[u8; 32]>,
    snonce: [u8; 32],
    pub(crate) ptk: Option<[u8; PTK_LEN]>,
    replay_counter: u64,
    rsne: Vec<u8>,
    /// The AP's RSNE as seen in the beacon/probe response, for the
    /// Message 3 downgrade check (802.11-2020 §12.7.6.4; empty when the
    /// caller has none, which disables the check - unit tests).
    ap_rsne: Vec<u8>,
    /// The AP's RSNXE as seen in the beacon/probe response (empty when
    /// the AP advertises none).
    ap_rsnxe: Vec<u8>,
    gtk: Option<Vec<u8>>,
    gtk_index: u8,
    mic_alg: MicAlg,
    /// Key Descriptor Version echoed from Message 1 (0 = AKM-defined,
    /// 2 = HMAC-SHA1 MIC, 3 = AES-128-CMAC MIC).
    desc_version: u16,
    /// FT key hierarchy input: when set (initial association with an FT
    /// AKM), the PTK comes from PMK-R1 instead of the PMK
    /// (802.11-2020 §12.8.2.3).
    ft_pmk_r1: Option<super::ft::PmkR1>,
}

impl FourWayState {
    /// Create the 4-way handshake state, recording the AP's RSNE/RSNXE
    /// from the beacon/probe response so Message 3 can be validated
    /// against them (RSNE downgrade protection, 802.11-2020 §12.7.6.4).
    /// Empty `ap_rsne` disables the downgrade check (unit tests building
    /// handshakes by hand).
    pub fn new_with_ap_ies(
        pmk: &[u8; 32],
        mic_alg: MicAlg,
        mac_sta: [u8; 6],
        mac_ap: [u8; 6],
        rsne: Vec<u8>,
        ap_rsne: Vec<u8>,
        ap_rsnxe: Vec<u8>,
    ) -> Self {
        let mut snonce = [0u8; 32];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut snonce)
            .expect("RNG");
        Self {
            pmk: *pmk,
            mac_sta,
            mac_ap,
            anonce: None,
            snonce,
            ptk: None,
            replay_counter: 0,
            rsne,
            ap_rsne,
            ap_rsnxe,
            gtk: None,
            gtk_index: 0,
            mic_alg,
            desc_version: 0,
            ft_pmk_r1: None,
        }
    }

    /// 4-way state for an initial association with an FT AKM (FT-PSK /
    /// FT-SAE): the PTK is derived from PMK-R1 (which itself comes from
    /// PMK-R0 over the R1KH of the associated AP), and the MIC uses
    /// AES-CMAC regardless of the underlying PSK (802.11-2020 §12.8).
    pub fn new_ft(
        ft_pmk_r1: super::ft::PmkR1,
        mac_sta: [u8; 6],
        mac_ap: [u8; 6],
        rsne: Vec<u8>,
        ap_rsne: Vec<u8>,
        ap_rsnxe: Vec<u8>,
    ) -> Self {
        let mut snonce = [0u8; 32];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut snonce)
            .expect("RNG");
        Self {
            pmk: [0u8; 32],
            mac_sta,
            mac_ap,
            anonce: None,
            snonce,
            ptk: None,
            replay_counter: 0,
            rsne,
            ap_rsne,
            ap_rsnxe,
            gtk: None,
            gtk_index: 0,
            mic_alg: MicAlg::AesCmac,
            desc_version: 0,
            ft_pmk_r1: Some(ft_pmk_r1),
        }
    }

    pub(crate) fn derive_ptk(&self) -> [u8; PTK_LEN] {
        let anonce = self.anonce.expect("ANonce must be set");

        // FT: PTK = KDF-SHA256(PMK-R1, "FT-PTK", SNonce || ANonce ||
        // BSSID || STA-ADDR); the operand order is fixed by the spec.
        if let Some(ref pmk_r1) = self.ft_pmk_r1 {
            return super::ft::derive_ft_ptk(
                pmk_r1,
                &self.snonce,
                &anonce,
                self.mac_ap,
                self.mac_sta,
            );
        }

        let (mac1, mac2) =
            if u64_from_mac(&self.mac_ap) < u64_from_mac(&self.mac_sta) {
                (self.mac_ap, self.mac_sta)
            } else {
                (self.mac_sta, self.mac_ap)
            };

        let (nonce1, nonce2) = if anonce < self.snonce {
            (anonce, self.snonce)
        } else {
            (self.snonce, anonce)
        };

        let mut context = Vec::with_capacity(12 + 64);
        context.extend_from_slice(&mac1);
        context.extend_from_slice(&mac2);
        context.extend_from_slice(&nonce1);
        context.extend_from_slice(&nonce2);

        let result = match self.mic_alg {
            MicAlg::HmacSha1 => kdf::prf_sha1(
                &self.pmk,
                "Pairwise key expansion",
                &context,
                PTK_LEN,
            ),
            _ => {
                kdf::kdf(&self.pmk, "Pairwise key expansion", &context, PTK_LEN)
            }
        };
        let mut ptk = [0u8; PTK_LEN];
        ptk.copy_from_slice(&result);
        ptk
    }

    /// Compute the EAPOL-Key MIC using the AKM-appropriate algorithm.
    fn compute_mic(
        &self,
        kck: &[u8; KCK_LEN],
        data: &[u8],
    ) -> Result<[u8; EAPOL_MIC_LEN], WifiError> {
        match self.mic_alg {
            MicAlg::AesCmac => aes_cmac(kck, data),
            MicAlg::HmacSha256 => Ok(kdf::hmac_sha256_mic(kck, data)),
            MicAlg::HmacSha1 => Ok(kdf::hmac_sha1_mic(kck, data)),
        }
    }

    pub fn kck(&self) -> Option<[u8; KCK_LEN]> {
        self.ptk.map(|p| {
            let mut k = [0u8; KCK_LEN];
            k.copy_from_slice(&p[..KCK_LEN]);
            k
        })
    }

    pub fn kek(&self) -> Option<[u8; KEK_LEN]> {
        self.ptk.map(|p| {
            let mut k = [0u8; KEK_LEN];
            k.copy_from_slice(&p[KCK_LEN..KCK_LEN + KEK_LEN]);
            k
        })
    }

    pub fn replay_counter_bytes(&self) -> [u8; 8] {
        self.replay_counter.to_be_bytes()
    }

    pub fn tk(&self) -> Option<[u8; TK_LEN]> {
        self.ptk.map(|p| {
            let mut k = [0u8; TK_LEN];
            k.copy_from_slice(&p[KCK_LEN + KEK_LEN..]);
            k
        })
    }

    pub fn gtk(&self) -> Option<&[u8]> {
        self.gtk.as_deref()
    }

    pub fn gtk_index(&self) -> u8 {
        self.gtk_index
    }

    /// Process Message 1 of the 4-way handshake (from AP, contains ANonce).
    /// Returns the serialized Message 2 PDU to send back. Message 2 echoes the
    /// AP's replay counter (802.11-2020 §12.7.6.2).
    ///
    /// A fresh SNonce is drawn for every Message 1: this covers both the
    /// initial handshake and an AP-initiated PTK rekey, which arrives as a
    /// new Message 1 mid-connection and must not reuse the old SNonce
    /// (wpa_supplicant renews its SNonce the same way).
    pub fn process_message_1(
        &mut self,
        anonce: &[u8; 32],
        replay_counter: u64,
        key_info: u16,
    ) -> Result<Vec<u8>, WifiError> {
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut self.snonce)
            .expect("RNG");
        self.anonce = Some(*anonce);
        self.replay_counter = replay_counter;
        // Echo the Key Descriptor Version the AP negotiated in Message 1:
        // 0 (AKM-defined) for SAE/OWE, 2 (HMAC-SHA1) for WPA2-PSK and
        // 3 (AES-128-CMAC) for FT-PSK (802.11-2020 §12.7.2); hostapd
        // rejects a Message 2 that uses another version.
        self.desc_version = eapol::desc_version(key_info);
        self.ptk = Some(self.derive_ptk());

        let kck = self.kck().unwrap();

        // Build Message 2 with a zeroed MIC, compute the MIC (AES-CMAC over the
        // entire EAPOL-Key PDU), then patch it in.
        let mut msg2 = eapol::build_message_2(
            &self.snonce,
            self.replay_counter,
            &self.rsne,
            self.desc_version,
        );
        let mic = self.compute_mic(&kck, &eapol::pdu_with_zeroed_mic(&msg2))?;
        eapol::set_mic(&mut msg2, &mic);

        Ok(msg2)
    }

    /// Process Message 3 of the 4-way handshake.
    /// Returns the Message 4 PDU and the KDEs parsed from the (decrypted)
    /// key data: the GTK plus, on PMF-enabled APs, the IGTK / BIGTK and
    /// the AP's RSNE / RSNXE (validated against the beacon copy for
    /// downgrade protection before returning).
    pub fn process_message_3(
        &mut self,
        frame: &eapol::EapolKeyFrame,
    ) -> Result<(Vec<u8>, KeyDataKdes), WifiError> {
        // 802.11-2020 §12.7.6.4: replay counter must be >= Message 1's.
        if frame.replay_counter < self.replay_counter {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                format!(
                    "Message 3 replay counter {} < Message 1 counter {}",
                    frame.replay_counter, self.replay_counter
                ),
            ));
        }
        self.replay_counter = frame.replay_counter;

        let kck = self.kck().ok_or_else(|| {
            WifiError::new(ErrorKind::HandshakeFailed, "PTK not derived")
        })?;

        // Verify MIC over the received PDU with the MIC field zeroed.
        let expected =
            self.compute_mic(&kck, &eapol::pdu_with_zeroed_mic(&frame.raw))?;
        if expected != frame.key_mic {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                "MIC mismatch",
            ));
        }

        // Unwrap the key data and parse its KDEs: GTK plus (with PMF) the
        // IGTK / BIGTK and the AP's RSNE / RSNXE.
        let mut kdes = KeyDataKdes::default();
        if !frame.key_data.is_empty() {
            let kek = self.kek().ok_or_else(|| {
                WifiError::new(ErrorKind::HandshakeFailed, "KEK not derived")
            })?;
            let plain = if frame.is_encrypted_data() {
                aes_key_unwrap(&kek, &frame.key_data)?
            } else {
                frame.key_data.clone()
            };
            kdes = parse_key_data_kdes(&plain);
            // G1b: fail the handshake when the AP's RSNE / RSNXE in
            // Message 3 differ from the beacon/probe response copies
            // (802.11-2020 §12.7.6.4 downgrade protection).
            self.validate_ap_ies(&kdes)?;
            if let Some((idx, gtk)) = &kdes.gtk {
                self.gtk_index = *idx;
                self.gtk = Some(gtk.clone());
            }
        }

        // Build Message 4 (zeroed MIC) and compute its MIC.
        let mut msg4 = eapol::build_message_4(
            &self.snonce,
            self.replay_counter,
            self.desc_version,
        );
        let mic = self.compute_mic(&kck, &eapol::pdu_with_zeroed_mic(&msg4))?;
        eapol::set_mic(&mut msg4, &mic);

        Ok((msg4, kdes))
    }

    /// RSNE / RSNXE downgrade check for Message 3 (G1b). Skipped when no
    /// AP RSNE was recorded (e.g. unit tests building handshakes by hand).
    fn validate_ap_ies(&self, kdes: &KeyDataKdes) -> Result<(), WifiError> {
        if self.ap_rsne.is_empty() {
            return Ok(());
        }
        let Some(rsne) = &kdes.rsne else {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                "Message 3 key data carries no RSNE",
            ));
        };
        // FT AKMs append PMKR1Name as the RSNE's PMKID in Message 3,
        // which the beacon RSNE lacks; compare while ignoring the PMKID
        // list there (wpa_supplicant compares strictly otherwise).
        let rsne_ok = if self.ft_pmk_r1.is_some() {
            crate::ieee80211::elements::rsne_match_ignore_pmkid(
                rsne,
                &self.ap_rsne,
            )
        } else {
            rsne == &self.ap_rsne
        };
        if !rsne_ok {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                format!(
                    "RSNE downgrade detected: Message 3 RSNE {rsne:02x?} \
                     differs from beacon RSNE {:02x?}",
                    self.ap_rsne
                ),
            ));
        }
        if !self.ap_rsnxe.is_empty()
            && kdes.rsnxe.as_deref() != Some(&self.ap_rsnxe[..])
        {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                format!(
                    "RSNXE downgrade detected: Message 3 RSNXE {:02x?} \
                     differs from beacon RSNXE {:02x?}",
                    kdes.rsnxe, self.ap_rsnxe
                ),
            ));
        }
        Ok(())
    }

    /// Process a Group Key Handshake Message 1 (a GTK rekey initiated by the
    /// AP after the connection is up). Verifies the MIC with the existing KCK,
    /// unwraps the new GTK with the KEK, updates the stored GTK/index, and
    /// returns the Group Message 2 PDU to send back.
    pub fn process_group_rekey(
        &mut self,
        frame: &eapol::EapolKeyFrame,
    ) -> Result<Vec<u8>, WifiError> {
        // 802.11-2020 §12.7.7.1: replay counter must be strictly greater
        // than the last accepted value.
        if frame.replay_counter <= self.replay_counter {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                format!(
                    "group rekey replay counter {} <= last accepted {}",
                    frame.replay_counter, self.replay_counter
                ),
            ));
        }
        self.replay_counter = frame.replay_counter;

        let kck = self.kck().ok_or_else(|| {
            WifiError::new(ErrorKind::HandshakeFailed, "PTK not derived")
        })?;

        // Verify MIC over the received PDU with the MIC field zeroed.
        let expected =
            self.compute_mic(&kck, &eapol::pdu_with_zeroed_mic(&frame.raw))?;
        if expected != frame.key_mic {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                "group rekey MIC mismatch",
            ));
        }

        // Decrypt/extract the new GTK from the key data KDEs.
        if frame.key_data.is_empty() {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                "group rekey carries no key data",
            ));
        }
        let kek = self.kek().ok_or_else(|| {
            WifiError::new(ErrorKind::HandshakeFailed, "KEK not derived")
        })?;
        let plain = if frame.is_encrypted_data() {
            aes_key_unwrap(&kek, &frame.key_data)?
        } else {
            frame.key_data.clone()
        };
        let (idx, gtk) = parse_gtk_kde(&plain).ok_or_else(|| {
            WifiError::new(
                ErrorKind::HandshakeFailed,
                "no GTK KDE in group rekey",
            )
        })?;
        self.gtk_index = idx;
        self.gtk = Some(gtk);

        // Build Group Message 2 (zeroed MIC) and compute its MIC.
        let mut msg2 = eapol::build_group_message_2(
            self.replay_counter,
            &frame.key_rsc,
            eapol::desc_version(frame.key_info),
        );
        let mic = self.compute_mic(&kck, &eapol::pdu_with_zeroed_mic(&msg2))?;
        eapol::set_mic(&mut msg2, &mic);

        Ok(msg2)
    }
}

/// Compute AES-128-CMAC over arbitrary bytes (the EAPOL-Key MIC for the SAE
/// AKM with CCMP-128).
pub(crate) fn aes_cmac(
    kck: &[u8; KCK_LEN],
    data: &[u8],
) -> Result<[u8; EAPOL_MIC_LEN], WifiError> {
    let key = cmac::Key::new(cmac::AES_128, kck).map_err(|e| {
        WifiError::new(ErrorKind::HandshakeFailed, e.to_string())
    })?;
    let tag = cmac::sign(&key, data).map_err(|e| {
        WifiError::new(ErrorKind::HandshakeFailed, e.to_string())
    })?;
    let mut mic = [0u8; EAPOL_MIC_LEN];
    mic.copy_from_slice(tag.as_ref());
    Ok(mic)
}

/// An IGTK or BIGTK extracted from its EAPOL-Key key data KDE: key index,
/// the 6-octet IPN (initial packet number = RX sequence counter) and the
/// key itself (802.11-2020 §12.7.2, KDE types 9 and 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MgmtKeyKde {
    pub key_index: u8,
    pub ipn: [u8; 6],
    pub key: Vec<u8>,
}

/// The KDEs / IEs parsed out of a decrypted EAPOL-Key key data field
/// (Message 3 of the 4-way handshake).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KeyDataKdes {
    /// GTK KDE (type 1): (key index, GTK).
    pub gtk: Option<(u8, Vec<u8>)>,
    /// IGTK KDE (type 9), present on every PMF AP.
    pub igtk: Option<MgmtKeyKde>,
    /// BIGTK KDE (type 10), present when the AP enables beacon protection.
    pub bigtk: Option<MgmtKeyKde>,
    /// The AP's RSNE as a full element (ID + length + body).
    pub rsne: Option<Vec<u8>>,
    /// The AP's RSNXE as a full element (ID 244 + length + body).
    pub rsnxe: Option<Vec<u8>>,
    /// Transition Disable KDE bitmap (WFA OUI 50:6F:9A, type 0x20):
    /// bit 0 = WPA3-Personal, 1 = SAE-PK, 2 = WPA3-Enterprise,
    /// 3 = Enhanced Open (Stage 3 M9).
    pub transition_disable: Option<u8>,
}

const KDE_OUI: [u8; 3] = [0x00, 0x0F, 0xAC];
const WFA_OUI: [u8; 3] = [0x50, 0x6F, 0x9A];
const GTK_KDE_TYPE: u8 = 1;
const IGTK_KDE_TYPE: u8 = 9;
const BIGTK_KDE_TYPE: u8 = 10;
const WFA_TRANSITION_DISABLE_TYPE: u8 = 0x20;
const IE_ID_RSN: u8 = 48;
const IE_ID_RSNXE: u8 = 244;

/// Parse the (decrypted) EAPOL-Key key data of Message 3: a sequence of
/// KDEs (vendor elements with OUI 00-0F-AC) and plain IEs. Collects the
/// GTK, IGTK and BIGTK KDEs plus the AP's RSNE / RSNXE for the downgrade
/// check.
pub(crate) fn parse_key_data_kdes(key_data: &[u8]) -> KeyDataKdes {
    let mut kdes = KeyDataKdes::default();
    let mut pos = 0;
    while pos + 2 <= key_data.len() {
        let id = key_data[pos];
        let len = key_data[pos + 1] as usize;
        let body_start = pos + 2;
        let body_end = body_start + len;
        if body_end > key_data.len() {
            break;
        }
        let body = &key_data[body_start..body_end];
        match id {
            0xDD if body.len() >= 4 && body[..3] == WFA_OUI => {
                // WFA vendor KDEs: Transition Disable (type 0x20)
                // carries a bitmap after the OUI + type.
                if body[3] == WFA_TRANSITION_DISABLE_TYPE && body.len() >= 5 {
                    kdes.transition_disable = Some(body[4]);
                }
            }
            0xDD if body.len() >= 4 && body[..3] == KDE_OUI => {
                let data_type = body[3];
                match data_type {
                    GTK_KDE_TYPE => {
                        // body: OUI(3) type(1) keyinfo(1) reserved(1) GTK(..)
                        if body.len() >= 7 {
                            let key_id = body[4] & 0x03;
                            let gtk = body[6..].to_vec();
                            if !gtk.is_empty() {
                                kdes.gtk = Some((key_id, gtk));
                            }
                        }
                    }
                    IGTK_KDE_TYPE | BIGTK_KDE_TYPE
                        if body.len() >= 4 + 8 + 16 =>
                    {
                        // body: OUI(3) type(1) KeyID(2 LE) IPN(6) Key(..)
                        let mgmt_key = MgmtKeyKde {
                            key_index: u16::from_le_bytes([body[4], body[5]])
                                as u8,
                            ipn: [
                                body[6], body[7], body[8], body[9], body[10],
                                body[11],
                            ],
                            key: body[12..].to_vec(),
                        };
                        if data_type == IGTK_KDE_TYPE {
                            kdes.igtk = Some(mgmt_key);
                        } else {
                            kdes.bigtk = Some(mgmt_key);
                        }
                    }
                    _ => {}
                }
            }
            IE_ID_RSN => kdes.rsne = Some(key_data[pos..body_end].to_vec()),
            IE_ID_RSNXE => kdes.rsnxe = Some(key_data[pos..body_end].to_vec()),
            _ => {}
        }
        pos = body_end;
    }
    kdes
}

/// Parse a GTK KDE from (decrypted) EAPOL-Key key data. Returns (key index,
/// GTK). Key data is a sequence of KDEs/IEs; the GTK KDE has element id 0xDD,
/// OUI 00-0F-AC, data type 1, followed by a key-info octet (low 2 bits = key
/// id), a reserved octet, then the GTK.
pub(crate) fn parse_gtk_kde(key_data: &[u8]) -> Option<(u8, Vec<u8>)> {
    parse_key_data_kdes(key_data).gtk
}

/// AES Key Unwrap (RFC 3394 / NIST SP 800-38F) for GTK extraction.
pub(crate) fn aes_key_unwrap(
    kek_bytes: &[u8; KEK_LEN],
    wrapped: &[u8],
) -> Result<Vec<u8>, WifiError> {
    if wrapped.len() < 16 || !wrapped.len().is_multiple_of(8) {
        return Err(WifiError::new(
            ErrorKind::HandshakeFailed,
            "invalid wrapped key length",
        ));
    }
    let out_len = wrapped.len() - 8;
    let mut out = vec![0u8; out_len];
    let kek =
        key_wrap::AesKek::new(&key_wrap::AES_128, kek_bytes).map_err(|e| {
            WifiError::new(
                ErrorKind::HandshakeFailed,
                format!("key unwrap: {e}"),
            )
        })?;
    kek.unwrap(wrapped, &mut out).map_err(|e| {
        WifiError::new(ErrorKind::HandshakeFailed, format!("key unwrap: {e}"))
    })?;
    Ok(out)
}

fn u64_from_mac(mac: &[u8; 6]) -> u64 {
    let mut buf = [0u8; 8];
    buf[2..8].copy_from_slice(mac);
    u64::from_be_bytes(buf)
}
