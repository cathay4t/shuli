// SPDX-License-Identifier: Apache-2.0

//! Fast BSS Transition (IEEE 802.11r) key hierarchy, over-the-air.
//!
//! Implements the FT-PSK / FT-SAE (SHA-256) key derivations of
//! 802.11-2020 §12.8.2 plus the FTIE MIC of §12.8.4 / §12.8.5, as
//! exercised by the over-the-air transition:
//!
//! ```text
//! R0-Key-Data = KDF-Hash-Length(XXKey, "FT-R0",
//!                 SSIDlength || SSID || MDID || R0KHlength ||
//!                 R0KH-ID || S0KH-ID)
//! PMK-R0      = L(R0-Key-Data, 0, 256)
//! PMK-R0Name-Salt = L(R0-Key-Data, 256, 128)
//! PMKR0Name   = Truncate-128(SHA256("FT-R0N" || PMK-R0Name-Salt))
//!
//! PMK-R1      = KDF-Hash-Length(PMK-R0, "FT-R1", R1KH-ID || S1KH-ID)
//! PMKR1Name   = Truncate-128(SHA256("FT-R1N" || PMKR0Name ||
//!                                    R1KH-ID || S1KH-ID))
//!
//! PTK         = KDF-Hash-Length(PMK-R1, "FT-PTK",
//!                 SNonce || ANonce || BSSID || STA-ADDR)
//! ```
//!
//! with XXKey = PMK for both FT-PSK and FT-SAE.

use aws_lc_rs::digest;

use super::kdf::kdf;
use crate::{ETH_ALEN, WifiError};

pub(crate) const FT_PTK_LEN: usize = 48;
pub(crate) const FT_KCK_LEN: usize = 16;
pub(crate) const FT_KEK_LEN: usize = 16;
pub(crate) const FT_TK_LEN: usize = 16;
pub(crate) const FT_R1KH_ID_LEN: usize = 6;

/// Result of the PMK-R0 derivation: the key and its name (PMKR0Name).
#[derive(Debug, Clone)]
pub(crate) struct PmkR0 {
    pub key: [u8; 32],
    pub name: [u8; 16],
}

/// Result of the PMK-R1 derivation: the key and its name (PMKR1Name).
#[derive(Debug, Clone)]
pub(crate) struct PmkR1 {
    pub key: [u8; 32],
    pub name: [u8; 16],
}

/// PMK-R0 = L(KDF-SHA256(XXKey, "FT-R0", SSIDlength || SSID || MDID ||
/// R0KHlength || R0KH-ID || S0KH-ID), 0, 256); PMKR0Name comes from the
/// salt that follows it (802.11-2020 §12.8.2.1).
///
/// `xxkey` is the PMK (SAE or PSK); `s0kh_id` is the STA's own MAC
/// address (the supplicant-side R0 key holder).
pub(crate) fn derive_pmk_r0(
    xxkey: &[u8; 32],
    ssid: &str,
    mdid: [u8; 2],
    r0kh_id: &[u8],
    s0kh_id: [u8; ETH_ALEN],
) -> PmkR0 {
    let mut context =
        Vec::with_capacity(1 + ssid.len() + 2 + 1 + r0kh_id.len() + 6);
    context.push(ssid.len() as u8);
    context.extend_from_slice(ssid.as_bytes());
    context.extend_from_slice(&mdid);
    context.push(r0kh_id.len() as u8);
    context.extend_from_slice(r0kh_id);
    context.extend_from_slice(&s0kh_id);

    let r0_key_data = kdf(xxkey, "FT-R0", &context, 32 + 16);
    let mut key = [0u8; 32];
    key.copy_from_slice(&r0_key_data[..32]);
    let salt = &r0_key_data[32..48];

    // PMKR0Name = Truncate-128(SHA256("FT-R0N" || PMK-R0Name-Salt))
    let mut hash_input = Vec::with_capacity(6 + 16);
    hash_input.extend_from_slice(b"FT-R0N");
    hash_input.extend_from_slice(salt);
    let hash = digest::digest(&digest::SHA256, &hash_input);

    let mut name = [0u8; 16];
    name.copy_from_slice(&hash.as_ref()[..16]);
    PmkR0 { key, name }
}

/// PMK-R1 = KDF-SHA256(PMK-R0, "FT-R1", R1KH-ID || S1KH-ID); PMKR1Name =
/// Truncate-128(SHA256("FT-R1N" || PMKR0Name || R1KH-ID || S1KH-ID))
/// (802.11-2020 §12.8.2.2). `s1kh_id` is the STA MAC address.
pub(crate) fn derive_pmk_r1(
    pmk_r0: &PmkR0,
    r1kh_id: [u8; FT_R1KH_ID_LEN],
    s1kh_id: [u8; ETH_ALEN],
) -> PmkR1 {
    let mut context = Vec::with_capacity(FT_R1KH_ID_LEN + ETH_ALEN);
    context.extend_from_slice(&r1kh_id);
    context.extend_from_slice(&s1kh_id);

    let key: [u8; 32] =
        kdf(&pmk_r0.key, "FT-R1", &context, 32).try_into().unwrap();

    let mut hash_input = Vec::with_capacity(6 + 16 + 6 + 6);
    hash_input.extend_from_slice(b"FT-R1N");
    hash_input.extend_from_slice(&pmk_r0.name);
    hash_input.extend_from_slice(&r1kh_id);
    hash_input.extend_from_slice(&s1kh_id);
    let hash = digest::digest(&digest::SHA256, &hash_input);

    let mut name = [0u8; 16];
    name.copy_from_slice(&hash.as_ref()[..16]);
    PmkR1 { key, name }
}

/// PTK = KDF-SHA256(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID ||
/// STA-ADDR) (802.11-2020 §12.8.2.3), 48 bytes: KCK (16) || KEK (16) ||
/// TK (16) for CCMP-128 pairwise.
pub(crate) fn derive_ft_ptk(
    pmk_r1: &PmkR1,
    snonce: &[u8; 32],
    anonce: &[u8; 32],
    bssid: [u8; ETH_ALEN],
    sta_addr: [u8; ETH_ALEN],
) -> [u8; FT_PTK_LEN] {
    let mut context = Vec::with_capacity(32 + 32 + 6 + 6);
    context.extend_from_slice(snonce);
    context.extend_from_slice(anonce);
    context.extend_from_slice(&bssid);
    context.extend_from_slice(&sta_addr);

    kdf(&pmk_r1.key, "FT-PTK", &context, FT_PTK_LEN)
        .try_into()
        .unwrap()
}

/// FTIE MIC over the FT protocol elements (802.11-2020 §12.8.4):
/// AES-128-CMAC(KCK, STA-ADDR || AP-ADDR || TransactionSeqNum ||
/// [RSNE] || MDIE || FTIE-with-MIC-zeroed || [RSNXE]).
///
/// `elements` is the concatenation of RSNE (optional), MDIE, the FTIE
/// with its 16-byte MIC field zeroed, and RSNXE (optional) - each
/// element including its 2-byte IE header, in that order.
pub(crate) fn ft_mic(
    kck: &[u8; FT_KCK_LEN],
    sta_addr: [u8; ETH_ALEN],
    ap_addr: [u8; ETH_ALEN],
    transaction_seqnum: u8,
    elements: &[u8],
) -> Result<[u8; 16], WifiError> {
    let mut data = Vec::with_capacity(6 + 6 + 1 + elements.len());
    data.extend_from_slice(&sta_addr);
    data.extend_from_slice(&ap_addr);
    data.push(transaction_seqnum);
    data.extend_from_slice(elements);
    super::handshake4::aes_cmac(kck, &data)
}
