// SPDX-License-Identifier: Apache-2.0

// KDF/PRF functions as defined in IEEE 802.11-2020.
// Used by SAE (key derivation, confirm) and 4-way handshake.

use aws_lc_rs::hmac;

/// IEEE 802.11 KDF-Hash-Length using HMAC-SHA256
/// (sha256_prf_bits, 802.11-2020 §12.7.1.7.2).
///
/// `Result = HMAC-SHA256(K, counter_le16 || label || context || length_le16)`
/// concatenated for counter = 1, 2, ... until `length` bytes are produced.
/// Note: counter and length are 16-bit little-endian and there is NO 0x00
/// separator between label and context.
pub fn kdf(key: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let label_bytes = label.as_bytes();
    let len_bits = (length * 8) as u16;
    let mut result = Vec::with_capacity(length);

    let mut counter: u16 = 1;
    while result.len() < length {
        let mut ctx = hmac::Context::with_key(&hmac_key);
        ctx.update(&counter.to_le_bytes());
        ctx.update(label_bytes);
        ctx.update(context);
        ctx.update(&len_bits.to_le_bytes());
        let tag = ctx.sign();
        result.extend_from_slice(tag.as_ref());
        counter += 1;
    }

    result.truncate(length);
    result
}

/// HKDF-Extract (RFC 5869): `PRK = HMAC-Hash(salt, ikm)`.
pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let tag = hmac::sign(&hmac_key, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// SAE confirm CN function (802.11-2020 §12.4.5.5).
/// `CN(KCK, send_confirm, scalar1, element1, scalar2, element2) =`
/// `HMAC-SHA256(KCK, send_confirm_le16 || scalar1 || element1 ||`
/// `scalar2 || element2)`
pub fn sae_confirm(
    kck: &[u8],
    send_confirm: u16,
    scalar1: &[u8],
    element1: &[u8],
    scalar2: &[u8],
    element2: &[u8],
) -> Vec<u8> {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, kck);
    let mut ctx = hmac::Context::with_key(&hmac_key);
    ctx.update(&send_confirm.to_le_bytes());
    ctx.update(scalar1);
    ctx.update(element1);
    ctx.update(scalar2);
    ctx.update(element2);
    ctx.sign().as_ref().to_vec()
}

/// HKDF-Expand (RFC 5869) using HMAC-SHA256.
/// Fills `okm` with OKM = HKDF-Expand(prk, info, okm.len()).
pub fn hkdf_expand(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut prev = Vec::new();
    let mut filled = 0;
    let mut i: u8 = 1;
    while filled < okm.len() {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&prev);
        ctx.update(info);
        ctx.update(&[i]);
        prev = ctx.sign().as_ref().to_vec();
        let to_copy = prev.len().min(okm.len() - filled);
        okm[filled..filled + to_copy].copy_from_slice(&prev[..to_copy]);
        filled += to_copy;
        i += 1;
    }
}

/// HMAC-SHA256 MIC for OWE 4-way handshake:
/// `Truncate-128(HMAC-SHA256(KCK, data))`.
pub fn hmac_sha256_mic(kck: &[u8], data: &[u8]) -> [u8; 16] {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, kck);
    let tag = hmac::sign(&hmac_key, data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag.as_ref()[..16]);
    out
}

/// IEEE 802.11 PRF using HMAC-SHA1 (802.11-2020 §12.7.1.2).
/// Used by WPA2-PSK for PTK derivation.
///
/// `Result = HMAC-SHA1(K, label || 0x00 || context || i)`
/// concatenated for i = 0, 1, ... until `length` bytes are produced.
pub fn prf_sha1(
    key: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let label_bytes = label.as_bytes();
    let mut result = Vec::with_capacity(length);

    let mut counter: u8 = 0;
    while result.len() < length {
        let mut ctx = hmac::Context::with_key(&hmac_key);
        ctx.update(label_bytes);
        ctx.update(&[0x00]);
        ctx.update(context);
        ctx.update(&[counter]);
        let tag = ctx.sign();
        result.extend_from_slice(tag.as_ref());
        counter += 1;
    }

    result.truncate(length);
    result
}

/// HMAC-SHA1 MIC for WPA2-PSK 4-way handshake:
/// `Truncate-128(HMAC-SHA1(KCK, data))`.
pub fn hmac_sha1_mic(kck: &[u8], data: &[u8]) -> [u8; 16] {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, kck);
    let tag = hmac::sign(&hmac_key, data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag.as_ref()[..16]);
    out
}

/// WPA2-PSK PMK derivation: PBKDF2(HMAC-SHA1, password, SSID, 4096, 256).
pub fn pbkdf2_pmk(password: &str, ssid: &str) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    aws_lc_rs::pbkdf2::derive(
        aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA1,
        std::num::NonZeroU32::new(4096).unwrap(),
        ssid.as_bytes(),
        password.as_bytes(),
        &mut pmk,
    );
    pmk
}

/// PMKID for SHA-256 based AKMs (PSK-SHA256, 802.1X-SHA256, ...),
/// 802.11-2020 §9.4.2.25.3 / §12.7.1.5:
/// `PMKID = Truncate-128(HMAC-SHA256(PMK, "PMK Name" || AA || SPA))`
/// with AA = authenticator address (BSSID), SPA = supplicant address.
/// No SHA-256 AKM is wired up yet (SAE caches the SAE-derived PMKID and
/// WPA2-PSK the SHA-1 variant), so keep the derivation ready here.
#[allow(dead_code)]
pub fn pmkid_sha256(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6]) -> [u8; 16] {
    let mut data = Vec::with_capacity(8 + 6 + 6);
    data.extend_from_slice(b"PMK Name");
    data.extend_from_slice(aa);
    data.extend_from_slice(spa);
    hmac_sha256_mic(pmk, &data)
}

/// PMKID for the legacy AKMs (WPA2-PSK / 802.1X, AKM 00-0F-AC:1/2):
/// `PMKID = Truncate-128(HMAC-SHA1(PMK, "PMK Name" || AA || SPA))`.
pub fn pmkid_sha1(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6]) -> [u8; 16] {
    let mut data = Vec::with_capacity(8 + 6 + 6);
    data.extend_from_slice(b"PMK Name");
    data.extend_from_slice(aa);
    data.extend_from_slice(spa);
    hmac_sha1_mic(pmk, &data)
}
