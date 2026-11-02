// SPDX-License-Identifier: Apache-2.0

// KDF/PRF functions as defined in IEEE 802.11-2020.
// Used by SAE (key derivation, confirm) and 4-way handshake.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// IEEE 802.11 KDF-Hash-Length using HMAC-SHA256
/// (sha256_prf_bits, 802.11-2020 §12.7.1.7.2).
///
/// `Result = HMAC-SHA256(K, counter_le16 || label || context || length_le16)`
/// concatenated for counter = 1, 2, ... until `length` bytes are produced.
/// Note: counter and length are 16-bit little-endian and there is NO 0x00
/// separator between label and context.
pub fn kdf(key: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let label_bytes = label.as_bytes();
    let len_bits = (length * 8) as u16;
    let mut result = Vec::with_capacity(length);

    let mut counter: u16 = 1;
    while result.len() < length {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC accepts keys of any length");
        mac.update(&counter.to_le_bytes());
        mac.update(label_bytes);
        mac.update(context);
        mac.update(&len_bits.to_le_bytes());
        let tag = mac.finalize().into_bytes();
        result.extend_from_slice(&tag);
        counter += 1;
    }

    result.truncate(length);
    result
}

/// HKDF-Extract (RFC 5869): `PRK = HMAC-Hash(salt, ikm)`.
pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(salt)
        .expect("HMAC accepts keys of any length");
    mac.update(ikm);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
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
    let mut mac = HmacSha256::new_from_slice(kck)
        .expect("HMAC accepts keys of any length");
    mac.update(&send_confirm.to_le_bytes());
    mac.update(scalar1);
    mac.update(element1);
    mac.update(scalar2);
    mac.update(element2);
    mac.finalize().into_bytes().to_vec()
}

/// HKDF-Expand (RFC 5869) using HMAC-SHA256.
/// Fills `okm` with OKM = HKDF-Expand(prk, info, okm.len()).
///
/// The PRK is typed as a 32-byte array because it is the output of
/// [`hkdf_extract_sha256`] and RFC 5869 requires a PRK of at least the hash
/// length for HKDF-Expand. This makes the length check a compile-time
/// invariant instead of a runtime panic.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) {
    Hkdf::<Sha256>::from_prk(prk)
        .expect("32-byte PRK is valid")
        .expand(info, okm)
        .expect("OKM length is at most 255 * hash output length");
}

/// HMAC-SHA256 MIC for OWE 4-way handshake:
/// `Truncate-128(HMAC-SHA256(KCK, data))`.
pub fn hmac_sha256_mic(kck: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(kck)
        .expect("HMAC accepts keys of any length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag[..16]);
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
    let label_bytes = label.as_bytes();
    let mut result = Vec::with_capacity(length);

    let mut counter: u8 = 0;
    while result.len() < length {
        let mut mac = HmacSha1::new_from_slice(key)
            .expect("HMAC accepts keys of any length");
        mac.update(label_bytes);
        mac.update(&[0x00]);
        mac.update(context);
        mac.update(&[counter]);
        let tag = mac.finalize().into_bytes();
        result.extend_from_slice(&tag);
        counter += 1;
    }

    result.truncate(length);
    result
}

/// HMAC-SHA1 MIC for WPA2-PSK 4-way handshake:
/// `Truncate-128(HMAC-SHA1(KCK, data))`.
pub fn hmac_sha1_mic(kck: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac =
        HmacSha1::new_from_slice(kck).expect("HMAC accepts keys of any length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag[..16]);
    out
}

/// WPA2-PSK PMK derivation: PBKDF2(HMAC-SHA1, password, SSID, 4096, 256).
pub fn pbkdf2_pmk(password: &str, ssid: &str) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(
        password.as_bytes(),
        ssid.as_bytes(),
        4096,
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
