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

impl MicAlg {
    /// EAPOL-Key descriptor version (key_info bits 0-2).
    pub(crate) fn descriptor_version(self) -> u16 {
        match self {
            MicAlg::AesCmac | MicAlg::HmacSha256 => 0,
            MicAlg::HmacSha1 => 2,
        }
    }
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
    gtk: Option<Vec<u8>>,
    gtk_index: u8,
    mic_alg: MicAlg,
}

impl FourWayState {
    pub fn new(
        pmk: &[u8; 32],
        _pmkid: &[u8; 16],
        mac_sta: [u8; 6],
        mac_ap: [u8; 6],
        rsne: Vec<u8>,
        mic_alg: MicAlg,
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
            gtk: None,
            gtk_index: 0,
            mic_alg,
        }
    }

    pub(crate) fn derive_ptk(&self) -> [u8; PTK_LEN] {
        let anonce = self.anonce.expect("ANonce must be set");

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
    pub fn process_message_1(
        &mut self,
        anonce: &[u8; 32],
        replay_counter: u64,
    ) -> Result<Vec<u8>, WifiError> {
        self.anonce = Some(*anonce);
        self.replay_counter = replay_counter;
        self.ptk = Some(self.derive_ptk());

        let kck = self.kck().unwrap();

        // Build Message 2 with a zeroed MIC, compute the MIC (AES-CMAC over the
        // entire EAPOL-Key PDU), then patch it in.
        let mut msg2 = eapol::build_message_2(
            &self.snonce,
            self.replay_counter,
            &self.rsne,
            self.mic_alg.descriptor_version(),
        );
        let mic = self.compute_mic(&kck, &eapol::pdu_with_zeroed_mic(&msg2))?;
        eapol::set_mic(&mut msg2, &mic);

        Ok(msg2)
    }

    /// Process Message 3 of the 4-way handshake.
    /// Returns (Message 4 PDU, optional GTK).
    pub fn process_message_3(
        &mut self,
        frame: &eapol::EapolKeyFrame,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), WifiError> {
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

        // Extract the GTK from the (AES-Key-Wrapped) key data KDEs.
        let gtk = if !frame.key_data.is_empty() {
            let kek = self.kek().ok_or_else(|| {
                WifiError::new(ErrorKind::HandshakeFailed, "KEK not derived")
            })?;
            let plain = if frame.is_encrypted_data() {
                aes_key_unwrap(&kek, &frame.key_data)?
            } else {
                frame.key_data.clone()
            };
            parse_gtk_kde(&plain).map(|(idx, gtk)| {
                self.gtk_index = idx;
                gtk
            })
        } else {
            None
        };
        if let Some(ref g) = gtk {
            self.gtk = Some(g.clone());
        }

        // Build Message 4 (zeroed MIC) and compute its MIC.
        let mut msg4 = eapol::build_message_4(
            &self.snonce,
            self.replay_counter,
            self.mic_alg.descriptor_version(),
        );
        let mic = self.compute_mic(&kck, &eapol::pdu_with_zeroed_mic(&msg4))?;
        eapol::set_mic(&mut msg4, &mic);

        Ok((msg4, gtk))
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
            self.mic_alg.descriptor_version(),
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

/// Parse a GTK KDE from (decrypted) EAPOL-Key key data. Returns (key index,
/// GTK). Key data is a sequence of KDEs/IEs; the GTK KDE has element id 0xDD,
/// OUI 00-0F-AC, data type 1, followed by a key-info octet (low 2 bits = key
/// id), a reserved octet, then the GTK.
pub(crate) fn parse_gtk_kde(key_data: &[u8]) -> Option<(u8, Vec<u8>)> {
    const GTK_KDE_OUI: [u8; 3] = [0x00, 0x0F, 0xAC];
    let mut i = 0;
    while i + 2 <= key_data.len() {
        let id = key_data[i];
        let len = key_data[i + 1] as usize;
        let body_start = i + 2;
        let body_end = body_start + len;
        if body_end > key_data.len() {
            break;
        }
        let body = &key_data[body_start..body_end];
        // Vendor-specific element carrying a KDE.
        if id == 0xDD && body.len() >= 6 && body[..3] == GTK_KDE_OUI {
            let data_type = body[3];
            if data_type == 0x01 {
                // body: OUI(3) type(1) keyinfo(1) reserved(1) GTK(..)
                let key_id = body[4] & 0x03;
                let gtk = body[6..].to_vec();
                if !gtk.is_empty() {
                    return Some((key_id, gtk));
                }
            }
        }
        i = body_end;
    }
    None
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
