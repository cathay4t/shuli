// SPDX-License-Identifier: Apache-2.0

//! MACsec Key Agreement (MKA, IEEE 802.1X-2020 Clause 9).
//!
//! This module implements the MKA key hierarchy, MKPDU framing, and the
//! participant/key-server state machine for MACsec.

use std::{
    os::fd::{AsRawFd, OwnedFd},
    time::{Duration, Instant},
};

use aws_lc_rs::{
    cmac,
    key_wrap::{self, KeyWrap},
    rand::{SecureRandom, SystemRandom},
};
use shuli_core::{ErrorKind, WifiError};
use tokio::io::unix::AsyncFd;

use crate::{
    eap::{
        PAE_GROUP_ADDR, open_eapol_socket, recv_eapol_frame_full,
        send_eapol_frame,
    },
    macsec::MacsecDevice,
};

/// Default name of the MACsec netdev created on top of the physical port.
pub const DEFAULT_MACSEC_IFACE: &str = "macsec0";

pub(crate) const MKA_VERSION: u8 = 3;
pub(crate) const EAPOL_TYPE_MKA: u8 = 5;
pub(crate) const EAPOL_VERSION: u8 = 3;
pub(crate) const ICV_LEN: usize = 16;
pub(crate) const MI_LEN: usize = 12;
pub(crate) const MKA_HELLO_SECS: u64 = 2;
pub(crate) const MKA_LIFE_SECS: u64 = 6;
pub(crate) const ALGO_AGILITY: [u8; 4] = [0x00, 0x80, 0xc2, 0x01];
pub(crate) const MACSEC_CAP_INTEGRITY_CONFIDENTIALITY: u8 = 2;

/// Key Identifier: the Key Server's MI plus its Key Number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) struct KeyId {
    pub(crate) mi: [u8; MI_LEN],
    pub(crate) kn: u32,
}

/// An (MI, MN) tuple advertised in the peer lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerId {
    pub(crate) mi: [u8; MI_LEN],
    pub(crate) mn: u32,
}

/// Basic Parameter Set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MkaBasic {
    pub(crate) version: u8,
    pub(crate) priority: u8,
    pub(crate) key_server: bool,
    pub(crate) macsec_desired: bool,
    pub(crate) macsec_capability: u8,
    pub(crate) sci: [u8; 8],
    pub(crate) mi: [u8; MI_LEN],
    pub(crate) mn: u32,
    pub(crate) algo_agility: [u8; 4],
    pub(crate) ckn: Vec<u8>,
}

/// MACsec SAK Use Parameter Set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SakUse {
    pub(crate) latest_an: u8,
    pub(crate) latest_tx: bool,
    pub(crate) latest_rx: bool,
    pub(crate) old_an: u8,
    pub(crate) old_tx: bool,
    pub(crate) old_rx: bool,
    pub(crate) plain_tx: bool,
    pub(crate) plain_rx: bool,
    pub(crate) delay_protect: bool,
    pub(crate) latest_ki: KeyId,
    pub(crate) latest_llpn: u32,
    pub(crate) old_ki: KeyId,
    pub(crate) old_llpn: u32,
}

/// Distributed SAK Parameter Set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DistSak {
    pub(crate) an: u8,
    pub(crate) confidentiality_offset: u8,
    pub(crate) kn: u32,
    pub(crate) wrapped_sak: Vec<u8>,
}

/// A decoded MKPDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MkaPdu {
    pub(crate) basic: MkaBasic,
    pub(crate) live_peers: Vec<PeerId>,
    pub(crate) potential_peers: Vec<PeerId>,
    pub(crate) sak_use: Option<SakUse>,
    pub(crate) dist_sak: Option<DistSak>,
}

fn mka_err(msg: impl Into<String>) -> WifiError {
    WifiError::new(ErrorKind::HandshakeFailed, msg)
}

fn cmac_key(key: &[u8]) -> Result<cmac::Key, WifiError> {
    match key.len() {
        16 => cmac::Key::new(cmac::AES_128, key)
            .map_err(|e| mka_err(format!("AES-CMAC-128: {e}"))),
        32 => cmac::Key::new(cmac::AES_256, key)
            .map_err(|e| mka_err(format!("AES-CMAC-256: {e}"))),
        n => Err(mka_err(format!("invalid CMAC key length {n}"))),
    }
}

/// IEEE 802.1X-2020 6.2.1 KDF (NIST SP 800-108 counter mode,
/// AES-CMAC PRF).
pub(crate) fn aes_kdf(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), WifiError> {
    let key = cmac_key(key)?;
    let length_bits = u16::try_from(out.len() * 8)
        .map_err(|_| mka_err("KDF output too long"))?;
    let mut offset = 0;
    let mut counter = 1u8;
    while offset < out.len() {
        let mut msg =
            Vec::with_capacity(1 + label.len() + 1 + context.len() + 2);
        msg.push(counter);
        msg.extend_from_slice(label);
        msg.push(0);
        msg.extend_from_slice(context);
        msg.extend_from_slice(&length_bits.to_be_bytes());
        let tag = cmac::sign(&key, &msg)
            .map_err(|e| mka_err(format!("KDF AES-CMAC: {e}")))?;
        let take = (out.len() - offset).min(tag.as_ref().len());
        out[offset..offset + take].copy_from_slice(&tag.as_ref()[..take]);
        offset += take;
        counter = counter
            .checked_add(1)
            .ok_or_else(|| mka_err("KDF counter overflow"))?;
    }
    Ok(())
}

fn keyid_from_ckn(ckn: &[u8]) -> [u8; 16] {
    let mut keyid = [0u8; 16];
    let n = ckn.len().min(16);
    keyid[..n].copy_from_slice(&ckn[..n]);
    keyid
}

/// KEK = KDF(CAK, "IEEE8021 KEK", CKN[0..16], CAK length).
pub(crate) fn derive_kek(cak: &[u8], ckn: &[u8]) -> Result<Vec<u8>, WifiError> {
    let mut out = vec![0u8; cak.len()];
    aes_kdf(cak, b"IEEE8021 KEK", &keyid_from_ckn(ckn), &mut out)?;
    Ok(out)
}

/// ICK = KDF(CAK, "IEEE8021 ICK", CKN[0..16], CAK length).
pub(crate) fn derive_ick(cak: &[u8], ckn: &[u8]) -> Result<Vec<u8>, WifiError> {
    let mut out = vec![0u8; cak.len()];
    aes_kdf(cak, b"IEEE8021 ICK", &keyid_from_ckn(ckn), &mut out)?;
    Ok(out)
}

/// CAK = KDF(MSK[0..16], "IEEE8021 EAP CAK", mac1 | mac2, 128).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn derive_eap_cak(
    msk: &[u8],
    mac1: &[u8; 6],
    mac2: &[u8; 6],
) -> Result<Vec<u8>, WifiError> {
    if msk.len() < 16 {
        return Err(mka_err("EAP MSK shorter than 16 octets"));
    }
    let (lo, hi) = if mac1 <= mac2 {
        (mac1, mac2)
    } else {
        (mac2, mac1)
    };
    let mut context = [0u8; 12];
    context[..6].copy_from_slice(lo);
    context[6..].copy_from_slice(hi);
    let mut out = vec![0u8; 16];
    aes_kdf(&msk[..16], b"IEEE8021 EAP CAK", &context, &mut out)?;
    Ok(out)
}

/// CKN = KDF(MSK[0..16], "IEEE8021 EAP CKN",
///           EAP-Session-Id | mac1 | mac2, 128).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn derive_eap_ckn(
    msk: &[u8],
    session_id: &[u8],
    mac1: &[u8; 6],
    mac2: &[u8; 6],
) -> Result<Vec<u8>, WifiError> {
    if msk.len() < 16 {
        return Err(mka_err("EAP MSK shorter than 16 octets"));
    }
    let (lo, hi) = if mac1 <= mac2 {
        (mac1, mac2)
    } else {
        (mac2, mac1)
    };
    let mut context = Vec::with_capacity(session_id.len() + 12);
    context.extend_from_slice(session_id);
    context.extend_from_slice(lo);
    context.extend_from_slice(hi);
    let mut out = vec![0u8; 16];
    aes_kdf(&msk[..16], b"IEEE8021 EAP CKN", &context, &mut out)?;
    Ok(out)
}

/// AES Key Wrap (RFC 3394) with the default IV.
pub(crate) fn wrap_key(
    kek: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, WifiError> {
    let cipher = match kek.len() {
        16 => &key_wrap::AES_128,
        32 => &key_wrap::AES_256,
        n => return Err(mka_err(format!("invalid KEK length {n}"))),
    };
    let kek = key_wrap::AesKek::new(cipher, kek)
        .map_err(|e| mka_err(format!("AES key wrap: {e}")))?;
    let mut out = vec![0u8; plaintext.len() + 8];
    let wrapped = kek
        .wrap(plaintext, &mut out)
        .map_err(|e| mka_err(format!("AES key wrap: {e}")))?;
    Ok(wrapped.to_vec())
}

/// AES Key Unwrap (RFC 3394).
pub(crate) fn unwrap_key(
    kek: &[u8],
    wrapped: &[u8],
) -> Result<Vec<u8>, WifiError> {
    if wrapped.len() < 16 || !wrapped.len().is_multiple_of(8) {
        return Err(mka_err("invalid wrapped key length"));
    }
    let cipher = match kek.len() {
        16 => &key_wrap::AES_128,
        32 => &key_wrap::AES_256,
        n => return Err(mka_err(format!("invalid KEK length {n}"))),
    };
    let kek = key_wrap::AesKek::new(cipher, kek)
        .map_err(|e| mka_err(format!("AES key unwrap: {e}")))?;
    let mut out = vec![0u8; wrapped.len() - 8];
    let plain = kek
        .unwrap(wrapped, &mut out)
        .map_err(|e| mka_err(format!("AES key unwrap: {e}")))?;
    Ok(plain.to_vec())
}

/// ICV over DA | SA | Ethertype | EAPOL PDU (without the ICV).
pub(crate) fn compute_icv(
    ick: &[u8],
    da: &[u8; 6],
    sa: &[u8; 6],
    eapol: &[u8],
) -> Result<[u8; ICV_LEN], WifiError> {
    let key = cmac_key(ick)?;
    let mut msg = Vec::with_capacity(12 + 2 + eapol.len());
    msg.extend_from_slice(da);
    msg.extend_from_slice(sa);
    msg.extend_from_slice(&0x888eu16.to_be_bytes());
    msg.extend_from_slice(eapol);
    let tag = cmac::sign(&key, &msg)
        .map_err(|e| mka_err(format!("ICV AES-CMAC: {e}")))?;
    let mut icv = [0u8; ICV_LEN];
    icv.copy_from_slice(tag.as_ref());
    Ok(icv)
}

fn verify_icv(
    ick: &[u8],
    da: &[u8; 6],
    sa: &[u8; 6],
    eapol: &[u8],
    icv: &[u8],
) -> bool {
    let Ok(expected) = compute_icv(ick, da, sa, eapol) else {
        return false;
    };
    // Constant-time comparison of one 16-octet tag.
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(icv) {
        diff |= a ^ b;
    }
    diff == 0
}

fn read_peers(data: &[u8], offset: usize, count: usize) -> Vec<PeerId> {
    let mut peers = Vec::with_capacity(count);
    for i in 0..count {
        let start = offset + i * 16;
        let Some(chunk) = data.get(start..start + 16) else {
            break;
        };
        let mut mi = [0u8; MI_LEN];
        mi.copy_from_slice(&chunk[..MI_LEN]);
        let mn = u32::from_be_bytes(chunk[MI_LEN..16].try_into().unwrap());
        peers.push(PeerId { mi, mn });
    }
    peers
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

impl MkaPdu {
    /// Parse an EAPOL-MKA payload (`eapol` includes the 4-octet EAPOL
    /// header), verifying the ICV with `ick`.
    pub(crate) fn parse(
        eapol: &[u8],
        da: &[u8; 6],
        sa: &[u8; 6],
        ick: &[u8],
    ) -> Result<Option<Self>, WifiError> {
        if eapol.len() < 4 || eapol[1] != EAPOL_TYPE_MKA {
            return Ok(None);
        }
        let body_len = u16::from_be_bytes([eapol[2], eapol[3]]) as usize;
        if body_len < ICV_LEN + 4 || eapol.len() < 4 + body_len {
            return Err(mka_err("truncated EAPOL-MKA frame"));
        }
        let icv_start = 4 + body_len - ICV_LEN;
        if !verify_icv(ick, da, sa, &eapol[..icv_start], &eapol[icv_start..]) {
            return Err(mka_err("invalid MKPDU ICV"));
        }
        Self::parse_body(&eapol[4..icv_start]).map(Some)
    }

    fn parse_body(body: &[u8]) -> Result<Self, WifiError> {
        if body.len() < 32 {
            return Err(mka_err("MKPDU too short"));
        }
        let version = body[0];
        let priority = body[1];
        let flags = body[2];
        let basic_len = (((flags & 0x0f) as usize) << 8) | body[3] as usize;
        if basic_len < 28 || 4 + basic_len > body.len() {
            return Err(mka_err("invalid Basic Parameter Set length"));
        }
        let mut sci = [0u8; 8];
        sci.copy_from_slice(&body[4..12]);
        let mut mi = [0u8; MI_LEN];
        mi.copy_from_slice(&body[12..24]);
        let mn = u32::from_be_bytes(body[24..28].try_into().unwrap());
        let mut algo_agility = [0u8; 4];
        algo_agility.copy_from_slice(&body[28..32]);
        let basic = MkaBasic {
            version,
            priority,
            key_server: flags & 0x80 != 0,
            macsec_desired: flags & 0x40 != 0,
            macsec_capability: (flags >> 4) & 0x03,
            sci,
            mi,
            mn,
            algo_agility,
            ckn: body[32..4 + basic_len].to_vec(),
        };

        let mut pos = 4 + align4(basic_len);
        let mut live_peers = Vec::new();
        let mut potential_peers = Vec::new();
        let mut sak_use = None;
        let mut dist_sak = None;

        while pos + 4 <= body.len() {
            let type_ = body[pos];
            let octet2 = body[pos + 1];
            let length = (((body[pos + 2] & 0x0f) as usize) << 8)
                | body[pos + 3] as usize;
            let start = pos + 4;
            let end = start + length;
            if end > body.len() {
                return Err(mka_err("truncated MKPDU parameter set"));
            }
            let data = &body[start..end];
            match type_ {
                1 => {
                    if !length.is_multiple_of(16) {
                        return Err(mka_err("invalid Live Peer List length"));
                    }
                    let _ = octet2; // Key Server SSCI (XPN only)
                    live_peers = read_peers(data, 0, length / 16);
                }
                2 => {
                    if !length.is_multiple_of(16) {
                        return Err(mka_err(
                            "invalid Potential Peer List length",
                        ));
                    }
                    potential_peers = read_peers(data, 0, length / 16);
                }
                3 => {
                    if length == 40 {
                        let latest_ki = KeyId {
                            mi: data[0..12].try_into().unwrap(),
                            kn: u32::from_be_bytes(
                                data[12..16].try_into().unwrap(),
                            ),
                        };
                        let old_ki = KeyId {
                            mi: data[20..32].try_into().unwrap(),
                            kn: u32::from_be_bytes(
                                data[32..36].try_into().unwrap(),
                            ),
                        };
                        sak_use = Some(SakUse {
                            latest_an: (octet2 >> 6) & 0x03,
                            latest_tx: octet2 & 0x20 != 0,
                            latest_rx: octet2 & 0x10 != 0,
                            old_an: (octet2 >> 2) & 0x03,
                            old_tx: octet2 & 0x02 != 0,
                            old_rx: octet2 & 0x01 != 0,
                            plain_tx: body[pos + 2] & 0x80 != 0,
                            plain_rx: body[pos + 2] & 0x40 != 0,
                            delay_protect: body[pos + 2] & 0x10 != 0,
                            latest_ki,
                            latest_llpn: u32::from_be_bytes(
                                data[16..20].try_into().unwrap(),
                            ),
                            old_ki,
                            old_llpn: u32::from_be_bytes(
                                data[36..40].try_into().unwrap(),
                            ),
                        });
                    }
                }
                4 => {
                    let (cipher_len, kn) = if length >= 4 {
                        let kn =
                            u32::from_be_bytes(data[..4].try_into().unwrap());
                        let cipher_len = if length >= 36 { 8 } else { 0 };
                        (cipher_len, kn)
                    } else {
                        (0, 0)
                    };
                    let wrapped_start = 4 + cipher_len;
                    let wrapped_sak = if length == 0 {
                        Vec::new()
                    } else if data.len() >= wrapped_start {
                        data[wrapped_start..].to_vec()
                    } else {
                        Vec::new()
                    };
                    dist_sak = Some(DistSak {
                        an: (octet2 >> 6) & 0x03,
                        confidentiality_offset: (octet2 >> 4) & 0x03,
                        kn,
                        wrapped_sak,
                    });
                }
                _ => {}
            }
            pos = start + align4(length);
        }

        Ok(Self {
            basic,
            live_peers,
            potential_peers,
            sak_use,
            dist_sak,
        })
    }

    /// Encode an EAPOL-MKA PDU, computing its ICV.
    pub(crate) fn build_eapol(
        &self,
        da: &[u8; 6],
        sa: &[u8; 6],
        ick: &[u8],
    ) -> Result<Vec<u8>, WifiError> {
        let mut body = Vec::new();
        let ckn_len = self.basic.ckn.len();
        let basic_len = 28 + ckn_len;
        let flags = (u8::from(self.basic.key_server) << 7)
            | (u8::from(self.basic.macsec_desired) << 6)
            | ((self.basic.macsec_capability & 0x03) << 4)
            | (((basic_len >> 8) & 0x0f) as u8);
        body.push(self.basic.version);
        body.push(self.basic.priority);
        body.push(flags);
        body.push(basic_len as u8);
        body.extend_from_slice(&self.basic.sci);
        body.extend_from_slice(&self.basic.mi);
        body.extend_from_slice(&self.basic.mn.to_be_bytes());
        body.extend_from_slice(&self.basic.algo_agility);
        body.extend_from_slice(&self.basic.ckn);
        while body.len() % 4 != 0 {
            body.push(0);
        }

        if !self.live_peers.is_empty() {
            // IEEE 802.1X-2020 Figure 11-9: the Key Server SSCI is
            // octet 2 of the parameter set header and is not part of
            // the body, so the body is exactly 16 octets per peer.
            let length = self.live_peers.len() * 16;
            body.push(1);
            body.push(0); // Key Server SSCI (XPN only)
            body.push(((length >> 8) & 0x0f) as u8);
            body.push(length as u8);
            for peer in &self.live_peers {
                body.extend_from_slice(&peer.mi);
                body.extend_from_slice(&peer.mn.to_be_bytes());
            }
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }

        if !self.potential_peers.is_empty() {
            let length = self.potential_peers.len() * 16;
            body.push(2);
            body.push(0);
            body.push(((length >> 8) & 0x0f) as u8);
            body.push(length as u8);
            for peer in &self.potential_peers {
                body.extend_from_slice(&peer.mi);
                body.extend_from_slice(&peer.mn.to_be_bytes());
            }
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }

        if let Some(use_) = &self.sak_use {
            let length = 40usize;
            let octet2 = ((use_.latest_an & 0x03) << 6)
                | (u8::from(use_.latest_tx) << 5)
                | (u8::from(use_.latest_rx) << 4)
                | ((use_.old_an & 0x03) << 2)
                | (u8::from(use_.old_tx) << 1)
                | u8::from(use_.old_rx);
            let octet3 = (u8::from(use_.plain_tx) << 7)
                | (u8::from(use_.plain_rx) << 6)
                | (u8::from(use_.delay_protect) << 4)
                | (((length >> 8) & 0x0f) as u8);
            body.push(3);
            body.push(octet2);
            body.push(octet3);
            body.push(length as u8);
            body.extend_from_slice(&use_.latest_ki.mi);
            body.extend_from_slice(&use_.latest_ki.kn.to_be_bytes());
            body.extend_from_slice(&use_.latest_llpn.to_be_bytes());
            body.extend_from_slice(&use_.old_ki.mi);
            body.extend_from_slice(&use_.old_ki.kn.to_be_bytes());
            body.extend_from_slice(&use_.old_llpn.to_be_bytes());
        }

        if let Some(dist) = &self.dist_sak {
            let length = 4 + dist.wrapped_sak.len();
            let octet2 = ((dist.an & 0x03) << 6)
                | ((dist.confidentiality_offset & 0x03) << 4);
            let octet3 = ((length >> 8) & 0x0f) as u8;
            body.push(4);
            body.push(octet2);
            body.push(octet3);
            body.push(length as u8);
            body.extend_from_slice(&dist.kn.to_be_bytes());
            body.extend_from_slice(&dist.wrapped_sak);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }

        let mut eapol = Vec::with_capacity(4 + body.len() + ICV_LEN);
        eapol.push(EAPOL_VERSION);
        eapol.push(EAPOL_TYPE_MKA);
        eapol.extend_from_slice(
            &u16::try_from(body.len() + ICV_LEN)
                .map_err(|_| mka_err("MKPDU too long"))?
                .to_be_bytes(),
        );
        eapol.extend_from_slice(&body);
        let icv = compute_icv(ick, da, sa, &eapol)?;
        eapol.extend_from_slice(&icv);
        Ok(eapol)
    }
}

/// MACsec/MKA configuration for one wired port.
#[derive(Debug, Clone)]
pub struct MacsecConfig {
    /// Connectivity Association Key: 16 or 32 octets.
    pub cak: Vec<u8>,
    /// Connectivity Association Key Name: 1..=32 octets.
    pub ckn: Vec<u8>,
    /// Key Server Priority (lower wins). 0xFF never becomes Key Server.
    pub key_server_priority: u8,
    /// Whether this participant may be elected Key Server.
    pub can_be_key_server: bool,
    /// Name of the MACsec netdev to create. Defaults to `macsec0`.
    pub macsec_iface: Option<String>,
    /// Replay protection window; 0 disables replay protection.
    pub replay_window: u32,
    /// Encrypt frames (false = integrity-only MACsec).
    pub encrypt: bool,
}

impl MacsecConfig {
    pub fn new(cak: Vec<u8>, ckn: Vec<u8>) -> Self {
        Self {
            cak,
            ckn,
            key_server_priority: 0xff,
            can_be_key_server: false,
            macsec_iface: None,
            replay_window: 0,
            encrypt: true,
        }
    }

    /// Name of the MACsec netdev, defaulting to
    /// [`DEFAULT_MACSEC_IFACE`].
    pub fn macsec_iface_name(&self) -> &str {
        self.macsec_iface.as_deref().unwrap_or(DEFAULT_MACSEC_IFACE)
    }

    fn validate(&self) -> Result<(), WifiError> {
        if !matches!(self.cak.len(), 16 | 32) {
            return Err(mka_err(format!(
                "MKA CAK must be 16 or 32 octets, got {}",
                self.cak.len()
            )));
        }
        if self.ckn.is_empty() || self.ckn.len() > 32 {
            return Err(mka_err(format!(
                "MKA CKN must be 1..=32 octets, got {}",
                self.ckn.len()
            )));
        }
        Ok(())
    }
}

impl Default for MacsecConfig {
    fn default() -> Self {
        Self {
            cak: Vec::new(),
            ckn: Vec::new(),
            key_server_priority: 0xff,
            can_be_key_server: false,
            macsec_iface: None,
            replay_window: 0,
            encrypt: true,
        }
    }
}

#[derive(Debug, Clone)]
struct Peer {
    mi: [u8; MI_LEN],
    mn: u32,
    sci: [u8; 8],
    priority: u8,
    key_server: bool,
    live: bool,
    last_seen: Instant,
    rx_ready: bool,
}

/// One MKA participant for a wired port.
pub(crate) struct MkaSession {
    iface_name: String,
    fd: OwnedFd,
    async_fd: AsyncFd<OwnedFd>,
    if_index: u32,
    mac: [u8; 6],
    ckn: Vec<u8>,
    kek: Vec<u8>,
    ick: Vec<u8>,
    priority: u8,
    can_be_key_server: bool,
    macsec_iface: String,
    replay_window: u32,
    encrypt: bool,
    macsec: Option<MacsecDevice>,
    mi: [u8; MI_LEN],
    mn: u32,
    peers: Vec<Peer>,
    is_key_server: bool,
    key_server_sci: [u8; 8],
    lki: Option<KeyId>,
    lan: u8,
    ltx: bool,
    lrx: bool,
    oki: Option<KeyId>,
    oan: u8,
    otx: bool,
    orx: bool,
    sak: Option<Vec<u8>>,
    dist_sak: Option<DistSak>,
    next_kn: u32,
    last_hello: Instant,
    need_send: bool,
}

impl MkaSession {
    pub(crate) fn new(
        iface_name: &str,
        config: &MacsecConfig,
    ) -> Result<Self, WifiError> {
        config.validate()?;
        let (fd, if_index, mac) = open_eapol_socket(iface_name)?;
        let async_fd = AsyncFd::new(
            fd.try_clone()
                .map_err(|e| mka_err(format!("EAPOL socket: {e}")))?,
        )
        .map_err(|e| mka_err(format!("EAPOL socket: {e}")))?;
        let kek = derive_kek(&config.cak, &config.ckn)?;
        let ick = derive_ick(&config.cak, &config.ckn)?;
        let mut mi = [0u8; MI_LEN];
        SystemRandom::new()
            .fill(&mut mi)
            .map_err(|e| mka_err(format!("random MI: {e}")))?;
        let mut session = Self {
            iface_name: iface_name.to_string(),
            fd,
            async_fd,
            if_index,
            mac,
            ckn: config.ckn.clone(),
            kek,
            ick,
            priority: config.key_server_priority,
            can_be_key_server: config.can_be_key_server,
            macsec_iface: config.macsec_iface_name().to_string(),
            replay_window: config.replay_window,
            encrypt: config.encrypt,
            macsec: None,
            mi,
            mn: 1,
            peers: Vec::new(),
            is_key_server: config.can_be_key_server,
            key_server_sci: [0u8; 8],
            lki: None,
            lan: 0,
            ltx: false,
            lrx: false,
            oki: None,
            oan: 0,
            otx: false,
            orx: false,
            sak: None,
            dist_sak: None,
            next_kn: 1,
            last_hello: Instant::now()
                .checked_sub(Duration::from_secs(MKA_HELLO_SECS))
                .unwrap_or_else(Instant::now),
            need_send: true,
        };
        session.elect_key_server();
        Ok(session)
    }

    fn actor_sci(&self) -> [u8; 8] {
        let mut sci = [0u8; 8];
        sci[..6].copy_from_slice(&self.mac);
        sci[6..].copy_from_slice(&1u16.to_be_bytes());
        sci
    }

    pub(crate) async fn run(&mut self) -> Result<bool, WifiError> {
        self.ensure_macsec().await?;
        self.expire_peers();
        self.drop_unsecure_sak().await?;

        let now = Instant::now();
        let next_hello = self.last_hello + Duration::from_secs(MKA_HELLO_SECS);
        if self.need_send || now >= next_hello {
            self.send_mkpdu().await?;
        }

        let next_hello = self.last_hello + Duration::from_secs(MKA_HELLO_SECS);
        let wait = next_hello.saturating_duration_since(Instant::now());
        let readable =
            tokio::time::timeout(wait, self.async_fd.readable()).await;
        match readable {
            Ok(Ok(mut guard)) => {
                let result = guard.try_io(|inner| {
                    recv_eapol_frame_full(inner.get_ref().as_raw_fd())
                });
                match result {
                    Ok(Ok(Some(frame))) => {
                        self.handle_frame(frame).await?;
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(e)) => {
                        return Err(mka_err(format!("EAPOL socket: {e}")));
                    }
                    Err(_) => {}
                }
            }
            Ok(Err(e)) => {
                return Err(mka_err(format!("EAPOL socket: {e:?}")));
            }
            Err(_) => {}
        }

        self.expire_peers();
        self.drop_unsecure_sak().await?;
        if self.need_send {
            self.send_mkpdu().await?;
        }
        Ok(self.secured())
    }

    async fn ensure_macsec(&mut self) -> Result<(), WifiError> {
        if self.macsec.is_some() {
            return Ok(());
        }
        let sci = self.actor_sci();
        let dev = MacsecDevice::create(
            &self.iface_name,
            &self.macsec_iface,
            sci,
            self.replay_window,
            self.encrypt,
        )
        .await?;
        log::info!("MACsec device {} ready", dev.name());
        self.macsec = Some(dev);
        Ok(())
    }

    fn find_peer(&self, mi: &[u8; MI_LEN]) -> Option<usize> {
        self.peers.iter().position(|p| &p.mi == mi)
    }

    async fn handle_frame(
        &mut self,
        frame: crate::eap::EapolFrame,
    ) -> Result<(), WifiError> {
        if frame.payload.len() < 4 || frame.payload[1] != EAPOL_TYPE_MKA {
            return Ok(());
        }
        let pdu = match MkaPdu::parse(
            &frame.payload,
            &frame.dst,
            &frame.src,
            &self.ick,
        ) {
            Ok(Some(pdu)) => pdu,
            Ok(None) => return Ok(()),
            Err(e) => {
                // Another CA or an attacker can send EAPOL-MKA on
                // the same segment; a bad ICV must not tear down
                // the session.
                log::debug!("ignoring invalid MKPDU: {e}");
                return Ok(());
            }
        };
        if pdu.basic.ckn != self.ckn {
            return Ok(());
        }
        if pdu.basic.mi == self.mi {
            return Ok(());
        }
        if pdu.basic.version > MKA_VERSION {
            log::debug!(
                "ignoring MKA version {} MKPDU (we speak {})",
                pdu.basic.version,
                MKA_VERSION
            );
            return Ok(());
        }

        let now = Instant::now();
        let peer_idx = self.find_peer(&pdu.basic.mi);
        let is_new = peer_idx.is_none();
        let idx = match peer_idx {
            Some(idx) => idx,
            None => {
                self.peers.push(Peer {
                    mi: pdu.basic.mi,
                    mn: 0,
                    sci: pdu.basic.sci,
                    priority: pdu.basic.priority,
                    key_server: pdu.basic.key_server,
                    live: false,
                    last_seen: now,
                    rx_ready: false,
                });
                self.peers.len() - 1
            }
        };
        if !is_new && self.peers[idx].mn >= pdu.basic.mn {
            return Ok(());
        }
        let peer = &mut self.peers[idx];
        let changed = peer.mn != pdu.basic.mn
            || peer.sci != pdu.basic.sci
            || peer.priority != pdu.basic.priority
            || peer.key_server != pdu.basic.key_server
            || !peer.live;
        peer.mn = pdu.basic.mn;
        peer.sci = pdu.basic.sci;
        peer.priority = pdu.basic.priority;
        peer.key_server = pdu.basic.key_server;
        peer.last_seen = now;
        if changed {
            self.need_send = true;
        }

        // MI collision: our MI was used with a higher MN.
        let collision = pdu
            .live_peers
            .iter()
            .chain(pdu.potential_peers.iter())
            .any(|p| p.mi == self.mi && p.mn > self.mn);
        if collision {
            log::warn!("MKA MI collision detected; choosing a new MI");
            self.reset_mi();
            self.need_send = true;
            return Ok(());
        }

        let knows_us = pdu
            .live_peers
            .iter()
            .chain(pdu.potential_peers.iter())
            .any(|p| p.mi == self.mi);
        if knows_us && !self.peers[idx].live {
            self.peers[idx].live = true;
            self.peers[idx].last_seen = now;
            self.need_send = true;
            log::debug!("MKA peer {:02x?} is live", self.peers[idx].mi);
        }
        if self.peers[idx].live {
            // Live peers learn about the sender's other peers.
            for id in &pdu.live_peers {
                if id.mi == self.mi || self.find_peer(&id.mi).is_some() {
                    continue;
                }
                self.peers.push(Peer {
                    mi: id.mi,
                    mn: id.mn,
                    sci: [0u8; 8],
                    priority: 0xff,
                    key_server: false,
                    live: false,
                    last_seen: now,
                    rx_ready: false,
                });
                self.need_send = true;
            }
        }

        let sender_is_live = self.peers[idx].live;
        let sender_is_key_server = self.peers[idx].key_server;
        let sender_sci = self.peers[idx].sci;
        let sender_mi = self.peers[idx].mi;

        self.elect_key_server();

        if let Some(use_) = &pdu.sak_use
            && use_.latest_ki == self.lki.unwrap_or_default()
        {
            if self.is_key_server && sender_is_live {
                self.peers[idx].rx_ready = use_.latest_rx;
                if self.peers.iter().filter(|p| p.live).all(|p| p.rx_ready)
                    && !self.ltx
                {
                    self.ltx = true;
                    self.activate_tx_sa().await?;
                    self.need_send = true;
                }
                if self.peers.iter().filter(|p| p.live).all(|p| p.rx_ready) {
                    self.dist_sak = None;
                }
            } else if !self.is_key_server
                && sender_is_key_server
                && use_.latest_tx
                && !self.ltx
            {
                self.ltx = true;
                self.activate_tx_sa().await?;
                self.need_send = true;
            }
        }

        if let Some(dist) = &pdu.dist_sak
            && sender_is_live
            && sender_is_key_server
            && !self.is_key_server
            && !dist.wrapped_sak.is_empty()
        {
            let ki = KeyId {
                mi: sender_mi,
                kn: dist.kn,
            };
            if self.lki != Some(ki) {
                let sak = match unwrap_key(&self.kek, &dist.wrapped_sak) {
                    Ok(sak) => sak,
                    Err(e) => {
                        log::warn!("ignoring invalid distributed SAK: {e}");
                        return Ok(());
                    }
                };
                if sak.len() != 16 {
                    log::warn!(
                        "ignoring distributed SAK with unsupported length {}",
                        sak.len()
                    );
                    return Ok(());
                }
                self.oki = self.lki;
                self.oan = self.lan;
                self.otx = self.ltx;
                self.orx = self.lrx;
                self.lki = Some(ki);
                self.lan = dist.an;
                self.lrx = true;
                self.ltx = false;
                self.sak = Some(sak);
                if let Some(dev) = self.macsec.as_mut() {
                    dev.install_rx_sa(
                        &sender_sci,
                        dist.an,
                        &ki,
                        self.sak.as_ref().unwrap(),
                    )
                    .await?;
                    dev.install_tx_sa(
                        dist.an,
                        &ki,
                        self.sak.as_ref().unwrap(),
                        false,
                    )
                    .await?;
                }
                self.need_send = true;
                log::info!(
                    "MKA: installed SAK KN={} from key server {:02x?}",
                    dist.kn,
                    sender_mi
                );
            }
        }

        if self.is_key_server {
            self.ensure_sak().await?;
        }
        Ok(())
    }

    fn reset_mi(&mut self) {
        let mut mi = [0u8; MI_LEN];
        if SystemRandom::new().fill(&mut mi).is_err() {
            mi = [0x5a; MI_LEN];
        }
        self.mi = mi;
        self.mn = 1;
        self.peers.clear();
        self.is_key_server = self.can_be_key_server;
        self.key_server_sci = [0u8; 8];
        self.lki = None;
        self.oki = None;
        self.sak = None;
        self.dist_sak = None;
        self.ltx = false;
        self.lrx = false;
    }

    fn expire_peers(&mut self) {
        let now = Instant::now();
        let before = self.peers.len();
        self.peers.retain(|p| {
            now.duration_since(p.last_seen) < Duration::from_secs(MKA_LIFE_SECS)
        });
        if self.peers.len() != before {
            self.need_send = true;
            self.elect_key_server();
        }
    }

    fn has_live_peer(&self) -> bool {
        self.peers.iter().any(|p| p.live)
    }

    /// Once the last live peer is gone the association is no longer
    /// alive: stop claiming Connected and drop the installed SAs.
    async fn drop_unsecure_sak(&mut self) -> Result<(), WifiError> {
        if self.lki.is_none() || self.has_live_peer() {
            return Ok(());
        }
        log::info!("MKA: no live peers left; dropping SAs");
        if let Some(dev) = self.macsec.as_mut() {
            dev.clear_sas().await?;
        }
        self.lki = None;
        self.oki = None;
        self.lan = 0;
        self.oan = 0;
        self.ltx = false;
        self.lrx = false;
        self.otx = false;
        self.orx = false;
        self.sak = None;
        self.dist_sak = None;
        for peer in &mut self.peers {
            peer.rx_ready = false;
        }
        self.need_send = true;
        Ok(())
    }

    /// Remove the MACsec netdev and its SAs.
    pub(crate) async fn shutdown(&mut self) -> Result<(), WifiError> {
        if let Some(dev) = self.macsec.take() {
            dev.remove().await?;
        }
        Ok(())
    }

    fn elect_key_server(&mut self) {
        let self_sci = self.actor_sci();
        let mut best: Option<(u8, [u8; 8], bool)> = None;
        if self.can_be_key_server {
            best = Some((self.priority, self_sci, true));
        }
        for peer in self.peers.iter().filter(|p| p.live && p.key_server) {
            let candidate = (peer.priority, peer.sci, false);
            let replace = match best {
                None => true,
                Some(current) => {
                    (candidate.0, candidate.1) < (current.0, current.1)
                }
            };
            if replace {
                best = Some(candidate);
            }
        }
        match best {
            Some((_, sci, true)) => {
                if !self.is_key_server {
                    self.need_send = true;
                }
                self.is_key_server = true;
                self.key_server_sci = sci;
            }
            Some((_, sci, false)) => {
                if self.is_key_server {
                    self.need_send = true;
                    self.dist_sak = None;
                }
                self.is_key_server = false;
                self.key_server_sci = sci;
            }
            None => {
                if self.is_key_server {
                    self.need_send = true;
                }
                self.is_key_server = false;
                self.key_server_sci = [0u8; 8];
            }
        }
    }

    async fn ensure_sak(&mut self) -> Result<(), WifiError> {
        if !self.is_key_server {
            return Ok(());
        }
        if self.peers.iter().all(|p| !p.live) {
            return Ok(());
        }
        if self.lki.is_some() {
            return Ok(());
        }
        let mut sak = vec![0u8; 16];
        SystemRandom::new()
            .fill(&mut sak)
            .map_err(|e| mka_err(format!("random SAK: {e}")))?;
        let kn = self.next_kn;
        self.next_kn = self.next_kn.wrapping_add(1).max(1);
        let an = (self.lan + 1) & 0x03;
        let ki = KeyId { mi: self.mi, kn };
        let wrapped = wrap_key(&self.kek, &sak)?;
        self.oki = self.lki;
        self.oan = self.lan;
        self.otx = self.ltx;
        self.orx = self.lrx;
        self.lki = Some(ki);
        self.lan = an;
        self.ltx = false;
        self.lrx = true;
        self.sak = Some(sak.clone());
        self.dist_sak = Some(DistSak {
            an,
            confidentiality_offset: 0,
            kn,
            wrapped_sak: wrapped,
        });

        let peer_scis: Vec<[u8; 8]> = self
            .peers
            .iter()
            .filter(|p| p.live && p.sci != [0u8; 8])
            .map(|p| p.sci)
            .collect();
        if let Some(dev) = self.macsec.as_mut() {
            dev.install_tx_sa(an, &ki, &sak, false).await?;
            for sci in peer_scis {
                dev.install_rx_sa(&sci, an, &ki, &sak).await?;
            }
        }
        self.need_send = true;
        log::info!("MKA: generated SAK KN={kn} AN={an}");
        Ok(())
    }

    async fn activate_tx_sa(&mut self) -> Result<(), WifiError> {
        if let (Some(dev), Some(ki)) = (self.macsec.as_mut(), self.lki) {
            let _ = ki;
            dev.set_tx_sa_active(self.lan).await?;
        }
        Ok(())
    }

    async fn send_mkpdu(&mut self) -> Result<(), WifiError> {
        let mut live_peers: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|p| p.live)
            .map(|p| PeerId { mi: p.mi, mn: p.mn })
            .collect();
        live_peers.sort_by_key(|a| std::cmp::Reverse(a.mi));
        let mut potential_peers: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|p| !p.live)
            .map(|p| PeerId { mi: p.mi, mn: p.mn })
            .collect();
        potential_peers.sort_by_key(|a| std::cmp::Reverse(a.mi));

        let sak_use = self.lki.map(|ki| SakUse {
            latest_an: self.lan,
            latest_tx: self.ltx,
            latest_rx: self.lrx,
            old_an: self.oan,
            old_tx: self.otx,
            old_rx: self.orx,
            plain_tx: false,
            plain_rx: false,
            delay_protect: false,
            latest_ki: ki,
            latest_llpn: 0,
            old_ki: self.oki.unwrap_or_default(),
            old_llpn: 0,
        });

        let pdu = MkaPdu {
            basic: MkaBasic {
                version: MKA_VERSION,
                priority: self.priority,
                key_server: self.is_key_server,
                macsec_desired: true,
                macsec_capability: MACSEC_CAP_INTEGRITY_CONFIDENTIALITY,
                sci: self.actor_sci(),
                mi: self.mi,
                mn: self.mn,
                algo_agility: ALGO_AGILITY,
                ckn: self.ckn.clone(),
            },
            live_peers,
            potential_peers,
            sak_use,
            dist_sak: if self.is_key_server {
                self.dist_sak.clone()
            } else {
                None
            },
        };
        let frame = pdu.build_eapol(&PAE_GROUP_ADDR, &self.mac, &self.ick)?;
        send_eapol_frame(
            self.fd.as_raw_fd(),
            self.if_index,
            &self.mac,
            &frame,
        )?;
        self.mn = self.mn.wrapping_add(1).max(1);
        self.last_hello = Instant::now();
        self.need_send = false;
        Ok(())
    }

    /// Whether both directions have an installed SAK and at least one
    /// peer is still live.
    pub(crate) fn secured(&self) -> bool {
        self.lki.is_some() && self.lrx && self.ltx && self.has_live_peer()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_kdf_128_vector() {
        let key = hex("1ab9024fa04a03feb9024fa04a03fe11");
        let mut out = [0u8; 16];
        aes_kdf(&key, b"HI THERE", &hex("01020104"), &mut out).unwrap();
        assert_eq!(out, hex("b57a0b05f43e9600c3c4d15c1e3c26e8").as_slice());
    }

    #[test]
    fn test_kdf_256_vector() {
        let key = hex(
            "3946ec36f59017f1267e914abed2dbf6633f52ae7e20309d3eefdda4073adfad",
        );
        let mut out = [0u8; 32];
        aes_kdf(&key, b"HI THERE", &hex("01020104"), &mut out).unwrap();
        assert_eq!(
            out,
            hex(
                "0efd01e5b03a0951a6df9bbffe419016\
                 ee40fdbfc3335ebf92ea03802214a307"
            )
            .as_slice()
        );
    }

    #[test]
    fn test_kek_ick_vectors() {
        let cak = hex("135bd758b0ee5c11c55ff6ab19fdb199");
        let ckn = hex("96437a93ccf10d9dfe347846cce52c7d");
        assert_eq!(
            derive_kek(&cak, &ckn).unwrap(),
            hex("8f5a384c15d6ae9302b462e363d03ca6")
        );
        assert_eq!(
            derive_ick(&cak, &ckn).unwrap(),
            hex("8f1c5cb1c8ed2e5f047906e0473aad4d")
        );
    }

    #[test]
    fn test_eap_cak_vector() {
        let msk = hex("e68a1ab90313024fda7a04a03fea010f");
        let mac1 = [0x00, 0x1b, 0x63, 0x93, 0xfc, 0xbc];
        let mac2 = [0x00, 0xd0, 0xb7, 0x1a, 0x77, 0x17];
        assert_eq!(
            derive_eap_cak(&msk, &mac1, &mac2).unwrap(),
            hex("135bd758b0ee5c11c55ff6ab19fdb199")
        );
    }

    #[test]
    fn test_eap_ckn_vector() {
        let msk = hex("e68a1ab90313024fda7a04a03fea010f");
        let session_id = hex(
            "0d\
             d075693f54b2b2eb01da61f0af5d429b\
             65b1ebcaf536fba350777598571728f6\
             30c5c8da5475489ad47b6e3489a97372\
             e5a8fd550617972c020d42a3b13a4eae",
        );
        let mac1 = [0x00, 0x1b, 0x63, 0x93, 0xfc, 0xbc];
        let mac2 = [0x00, 0xd0, 0xb7, 0x1a, 0x77, 0x17];
        assert_eq!(
            derive_eap_ckn(&msk, &session_id, &mac1, &mac2).unwrap(),
            hex("96437a93ccf10d9dfe347846cce52c7d")
        );
    }

    #[test]
    fn test_key_wrap_roundtrip() {
        let kek = hex("8f5a384c15d6ae9302b462e363d03ca6");
        let sak = [0x11u8; 16];
        let wrapped = wrap_key(&kek, &sak).unwrap();
        assert_eq!(wrapped.len(), 24);
        assert_eq!(unwrap_key(&kek, &wrapped).unwrap(), sak);
    }

    #[tokio::test]
    async fn test_secured_requires_live_peer() {
        let config = MacsecConfig::new(vec![0x11; 16], vec![0x22; 16]);
        let mut session = MkaSession::new("lo", &config).unwrap();
        session.lki = Some(KeyId {
            mi: [1; MI_LEN],
            kn: 1,
        });
        session.lrx = true;
        session.ltx = true;
        assert!(!session.secured(), "no live peer means not secured");

        session.peers.push(Peer {
            mi: [2; MI_LEN],
            mn: 1,
            sci: [2, 0, 0, 0, 0, 1, 0, 1],
            priority: 0xff,
            key_server: false,
            live: true,
            last_seen: Instant::now(),
            rx_ready: true,
        });
        assert!(session.secured());

        session.peers.clear();
        session.drop_unsecure_sak().await.unwrap();
        assert!(session.lki.is_none());
        assert!(!session.secured());
    }

    #[test]
    fn test_macsec_iface_name() {
        let mut config = MacsecConfig::new(vec![0x11; 16], vec![0x22; 16]);
        assert_eq!(config.macsec_iface_name(), DEFAULT_MACSEC_IFACE);
        config.macsec_iface = Some("ms1".to_string());
        assert_eq!(config.macsec_iface_name(), "ms1");
    }

    #[test]
    fn test_mkpdu_roundtrip() {
        let ick = [0x42u8; 16];
        let pdu = MkaPdu {
            basic: MkaBasic {
                version: MKA_VERSION,
                priority: 0x10,
                key_server: true,
                macsec_desired: true,
                macsec_capability: MACSEC_CAP_INTEGRITY_CONFIDENTIALITY,
                sci: [1, 2, 3, 4, 5, 6, 0, 1],
                mi: [7u8; MI_LEN],
                mn: 3,
                algo_agility: ALGO_AGILITY,
                ckn: b"test-ckn".to_vec(),
            },
            live_peers: vec![PeerId {
                mi: [8u8; MI_LEN],
                mn: 9,
            }],
            potential_peers: vec![PeerId {
                mi: [9u8; MI_LEN],
                mn: 10,
            }],
            sak_use: Some(SakUse {
                latest_an: 1,
                latest_tx: true,
                latest_rx: true,
                old_an: 0,
                old_tx: false,
                old_rx: true,
                plain_tx: false,
                plain_rx: false,
                delay_protect: false,
                latest_ki: KeyId {
                    mi: [7u8; MI_LEN],
                    kn: 4,
                },
                latest_llpn: 0,
                old_ki: KeyId {
                    mi: [7u8; MI_LEN],
                    kn: 3,
                },
                old_llpn: 0,
            }),
            dist_sak: Some(DistSak {
                an: 1,
                confidentiality_offset: 0,
                kn: 4,
                wrapped_sak: vec![0xa5; 24],
            }),
        };
        let da = PAE_GROUP_ADDR;
        let sa = [0x02, 0, 0, 0, 0, 1];
        let frame = pdu.build_eapol(&da, &sa, &ick).unwrap();
        let parsed = MkaPdu::parse(&frame, &da, &sa, &ick)
            .unwrap()
            .expect("MKA frame");
        assert_eq!(parsed, pdu);
    }

    #[test]
    fn test_live_peer_list_encoding() {
        // IEEE 802.1X-2020 Figure 11-9: the Live Peer List body is
        // exactly 16 octets per peer; the Key Server SSCI is octet 2
        // of the parameter set header, not part of the body.
        let ick = [0x42u8; 16];
        let peer = PeerId {
            mi: [0x11; MI_LEN],
            mn: 7,
        };
        let pdu = MkaPdu {
            basic: MkaBasic {
                version: MKA_VERSION,
                priority: 0x10,
                key_server: true,
                macsec_desired: true,
                macsec_capability: MACSEC_CAP_INTEGRITY_CONFIDENTIALITY,
                sci: [1, 2, 3, 4, 5, 6, 0, 1],
                mi: [7u8; MI_LEN],
                mn: 1,
                algo_agility: ALGO_AGILITY,
                ckn: b"ckn".to_vec(),
            },
            live_peers: vec![peer],
            potential_peers: Vec::new(),
            sak_use: None,
            dist_sak: None,
        };
        let frame = pdu
            .build_eapol(&PAE_GROUP_ADDR, &[2, 0, 0, 0, 0, 1], &ick)
            .unwrap();
        let body = &frame[4..];
        let basic_len = (((body[2] & 0x0f) as usize) << 8) | body[3] as usize;
        let pos = 4 + align4(basic_len);
        assert_eq!(body[pos], 1, "Live Peer List type");
        assert_eq!(body[pos + 1], 0, "Key Server SSCI");
        let length =
            (((body[pos + 2] & 0x0f) as usize) << 8) | body[pos + 3] as usize;
        assert_eq!(length, 16, "body length must be 16 * peer count");
        assert_eq!(&body[pos + 4..pos + 16], &peer.mi);
        assert_eq!(&body[pos + 16..pos + 20], &peer.mn.to_be_bytes());
    }

    #[test]
    fn test_mkpdu_rejects_bad_icv() {
        let ick = [0x42u8; 16];
        let pdu = MkaPdu {
            basic: MkaBasic {
                version: MKA_VERSION,
                priority: 0x10,
                key_server: false,
                macsec_desired: true,
                macsec_capability: 2,
                sci: [1, 2, 3, 4, 5, 6, 0, 1],
                mi: [7u8; MI_LEN],
                mn: 1,
                algo_agility: ALGO_AGILITY,
                ckn: b"test-ckn".to_vec(),
            },
            live_peers: Vec::new(),
            potential_peers: Vec::new(),
            sak_use: None,
            dist_sak: None,
        };
        let da = PAE_GROUP_ADDR;
        let sa = [0x02, 0, 0, 0, 0, 1];
        let mut frame = pdu.build_eapol(&da, &sa, &ick).unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 1;
        assert!(MkaPdu::parse(&frame, &da, &sa, &ick).is_err());
    }
}
