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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_kdf() {
        let key = [0x01u8; 32];
        let ctx = [0x02u8; 8];
        let result = kdf(&key, "Test Label", &ctx, 32);
        assert_eq!(result.len(), 32);
        // Deterministic: same inputs → same output
        let result2 = kdf(&key, "Test Label", &ctx, 32);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hkdf_extract() {
        let prk = hkdf_extract_sha256(b"salt", b"ikm");
        assert_eq!(prk.len(), 32);
    }

    #[test]
    fn test_hkdf_expand() {
        let prk = hkdf_extract_sha256(b"salt", b"ikm");
        let mut okm = [0u8; 48];
        hkdf_expand(&prk, b"test label", &mut okm);
        assert_eq!(okm.len(), 48);
    }
}
