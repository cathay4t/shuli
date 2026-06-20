// SPDX-License-Identifier: Apache-2.0

// KDF/PRF functions as defined in IEEE 802.11-2020.
// Used by SAE (key derivation, confirm) and 4-way handshake.

use hmac::Mac;
use sha2::Sha256;

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
        let mut mac =
            hmac::Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
        mac.update(&counter.to_le_bytes());
        mac.update(label_bytes);
        mac.update(context);
        mac.update(&len_bits.to_le_bytes());
        let output = mac.finalize().into_bytes();
        result.extend_from_slice(&output);
        counter += 1;
    }

    result.truncate(length);
    result
}

/// HKDF-Extract (RFC 5869): `PRK = HMAC-Hash(salt, ikm)`.
pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(salt).expect("HMAC key");
    mac.update(ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
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
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(kck).expect("HMAC key");
    mac.update(&send_confirm.to_le_bytes());
    mac.update(scalar1);
    mac.update(element1);
    mac.update(scalar2);
    mac.update(element2);
    mac.finalize().into_bytes().to_vec()
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
}
