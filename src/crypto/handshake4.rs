// SPDX-License-Identifier: Apache-2.0

//! 4-Way Handshake state machine and crypto operations (IEEE 802.11-2020
//! §12.7). Supports SAE AKM (00-0F-AC:8) with CCMP-128:
//!   - PMK: 32 bytes
//!   - KCK: 16 bytes (AES-CMAC key for MIC)
//!   - KEK: 16 bytes (AES Key Wrap key for GTK delivery)
//!   - TK: 16 bytes (CCMP-128 temporal key)

use aes::{Aes128, cipher::consts::U16};
use aes_kw::Kek;
use cmac::{
    Cmac,
    digest::{KeyInit, Mac},
};
use elliptic_curve::generic_array::GenericArray;

use crate::{ShuliResult, crypto::kdf, ieee80211::eapol};

const KCK_LEN: usize = 16;
const KEK_LEN: usize = 16;
const TK_LEN: usize = 16;
const PTK_LEN: usize = KCK_LEN + KEK_LEN + TK_LEN;

const EAPOL_MIC_LEN: usize = 16;

/// 4-Way Handshake state (supplicant side).
#[derive(Clone, Debug)]
pub struct FourWayState {
    pmk: [u8; 32],
    mac_sta: [u8; 6],
    mac_ap: [u8; 6],
    anonce: Option<[u8; 32]>,
    snonce: [u8; 32],
    ptk: Option<[u8; PTK_LEN]>,
    replay_counter: u64,
    rsne: Vec<u8>,
    gtk: Option<Vec<u8>>,
    gtk_index: u8,
}

impl FourWayState {
    pub fn new(
        pmk: &[u8; 32],
        _pmkid: &[u8; 16],
        mac_sta: [u8; 6],
        mac_ap: [u8; 6],
        rsne: Vec<u8>,
    ) -> Self {
        let mut snonce = [0u8; 32];
        getrandom::fill(&mut snonce).expect("RNG");
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
        }
    }

    fn derive_ptk(&self) -> [u8; PTK_LEN] {
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

        let result =
            kdf::kdf(&self.pmk, "Pairwise key expansion", &context, PTK_LEN);
        let mut ptk = [0u8; PTK_LEN];
        ptk.copy_from_slice(&result);
        ptk
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

    pub fn snonce(&self) -> &[u8; 32] {
        &self.snonce
    }

    pub fn anonce(&self) -> Option<[u8; 32]> {
        self.anonce
    }

    pub fn replay_counter(&self) -> u64 {
        self.replay_counter
    }

    /// Process Message 1 of the 4-way handshake (from AP, contains ANonce).
    /// Returns the serialized Message 2 PDU to send back.
    pub fn process_message_1(
        &mut self,
        anonce: &[u8; 32],
    ) -> ShuliResult<Vec<u8>> {
        self.anonce = Some(*anonce);
        self.replay_counter = 1;
        self.ptk = Some(self.derive_ptk());

        let kck = self.kck().unwrap();

        // Build Message 2 with a zeroed MIC, compute the MIC (AES-CMAC over the
        // entire EAPOL-Key PDU), then patch it in.
        let mut msg2 = eapol::build_message_2(
            &self.snonce,
            self.replay_counter,
            &self.rsne,
        );
        let mic = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&msg2))?;
        eapol::set_mic(&mut msg2, &mic);

        Ok(msg2)
    }

    /// Process Message 3 of the 4-way handshake.
    /// Returns (Message 4 PDU, optional GTK).
    pub fn process_message_3(
        &mut self,
        frame: &eapol::EapolKeyFrame,
    ) -> ShuliResult<(Vec<u8>, Option<Vec<u8>>)> {
        self.replay_counter = frame.replay_counter;

        let kck = self.kck().ok_or_else(|| {
            crate::ShuliError::HandshakeFailed("PTK not derived".into())
        })?;

        // Verify MIC over the received PDU with the MIC field zeroed.
        let expected = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&frame.raw))?;
        if expected != frame.key_mic {
            return Err(crate::ShuliError::HandshakeFailed(
                "MIC mismatch".into(),
            ));
        }

        // Extract the GTK from the (AES-Key-Wrapped) key data KDEs.
        let gtk = if !frame.key_data.is_empty() {
            let kek = self.kek().ok_or_else(|| {
                crate::ShuliError::HandshakeFailed("KEK not derived".into())
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
        let mut msg4 =
            eapol::build_message_4(&self.snonce, self.replay_counter);
        let mic = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&msg4))?;
        eapol::set_mic(&mut msg4, &mic);

        Ok((msg4, gtk))
    }

    pub fn ptk(&self) -> Option<[u8; PTK_LEN]> {
        self.ptk
    }
}

type Aes128Key = GenericArray<u8, U16>;

fn new_cmac(key: &[u8; KCK_LEN]) -> Result<Cmac<Aes128>, crate::ShuliError> {
    KeyInit::new_from_slice(key)
        .map_err(|e| crate::ShuliError::HandshakeFailed(e.to_string()))
}

/// Compute AES-128-CMAC over arbitrary bytes (the EAPOL-Key MIC for the SAE
/// AKM with CCMP-128).
fn aes_cmac(
    kck: &[u8; KCK_LEN],
    data: &[u8],
) -> ShuliResult<[u8; EAPOL_MIC_LEN]> {
    let mut mac = new_cmac(kck)?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut mic = [0u8; EAPOL_MIC_LEN];
    mic.copy_from_slice(&result);
    Ok(mic)
}

/// Parse a GTK KDE from (decrypted) EAPOL-Key key data. Returns (key index,
/// GTK). Key data is a sequence of KDEs/IEs; the GTK KDE has element id 0xDD,
/// OUI 00-0F-AC, data type 1, followed by a key-info octet (low 2 bits = key
/// id), a reserved octet, then the GTK.
fn parse_gtk_kde(key_data: &[u8]) -> Option<(u8, Vec<u8>)> {
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

/// AES Key Unwrap (RFC 3394) for GTK extraction.
fn aes_key_unwrap(kek: &[u8; KEK_LEN], wrapped: &[u8]) -> ShuliResult<Vec<u8>> {
    if wrapped.len() < 16 || !wrapped.len().is_multiple_of(8) {
        return Err(crate::ShuliError::HandshakeFailed(
            "invalid wrapped key length".into(),
        ));
    }
    let out_len = wrapped.len() - 8;
    let mut out = vec![0u8; out_len];
    let key = Aes128Key::from_slice(kek);
    let kek = Kek::<Aes128>::new(key);
    kek.unwrap(wrapped, &mut out).map_err(|e| {
        crate::ShuliError::HandshakeFailed(format!("key unwrap: {e}"))
    })?;
    Ok(out)
}

#[cfg(test)]
fn aes_key_wrap(kek: &[u8; KEK_LEN], plaintext: &[u8]) -> ShuliResult<Vec<u8>> {
    let out_len = plaintext.len() + 8;
    let mut out = vec![0u8; out_len];
    let key = Aes128Key::from_slice(kek);
    let kek = Kek::<Aes128>::new(key);
    kek.wrap(plaintext, &mut out).map_err(|e| {
        crate::ShuliError::HandshakeFailed(format!("key wrap: {e}"))
    })?;
    Ok(out)
}

fn u64_from_mac(mac: &[u8; 6]) -> u64 {
    let mut buf = [0u8; 8];
    buf[2..8].copy_from_slice(mac);
    u64::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptk_derivation() {
        let pmk = [0x01u8; 32];
        let pmkid = [0x02u8; 16];
        let sta = [0x03u8; 6];
        let ap = [0x04u8; 6];
        let mut state = FourWayState::new(&pmk, &pmkid, sta, ap, vec![]);
        let anonce = [0x05u8; 32];

        state.anonce = Some(anonce);
        state.ptk = Some(state.derive_ptk());

        let ptk = state.ptk.unwrap();
        assert_eq!(ptk.len(), 48);
        assert_eq!(state.kck().unwrap().len(), 16);
        assert_eq!(state.kek().unwrap().len(), 16);
        assert_eq!(state.tk().unwrap().len(), 16);
    }

    #[test]
    fn test_mic_roundtrip() {
        let kck = [0xAAu8; 16];
        let data = b"some eapol pdu bytes";
        let mic = aes_cmac(&kck, data).unwrap();
        assert_eq!(mic.len(), 16);
        let mic2 = aes_cmac(&kck, data).unwrap();
        assert_eq!(mic, mic2);
    }

    #[test]
    fn test_gtk_unwrap() {
        let kek = [0xCCu8; 16];
        let gtk = [0xDDu8; 16];
        let wrapped = aes_key_wrap(&kek, &gtk).unwrap();
        assert_eq!(wrapped.len(), 24); // 16 + 8 for RFC 3394
        let unwrapped = aes_key_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, gtk.to_vec());
    }

    #[test]
    fn test_parse_gtk_kde() {
        // GTK KDE: DD len 00-0F-AC 01 keyid res GTK(16)
        let gtk = [0x77u8; 16];
        let mut kde = vec![
            0xDD,
            (6 + gtk.len()) as u8,
            0x00,
            0x0F,
            0xAC,
            0x01,
            0x01,
            0x00,
        ];
        kde.extend_from_slice(&gtk);
        let (idx, parsed) = parse_gtk_kde(&kde).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(parsed, gtk.to_vec());
    }
}
