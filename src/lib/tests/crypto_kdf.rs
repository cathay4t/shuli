// SPDX-License-Identifier: Apache-2.0

use crate::crypto::kdf::{hkdf_expand, hkdf_extract_sha256, kdf};

#[test]
fn test_basic_kdf() {
    let key = [0x01u8; 32];
    let ctx = [0x02u8; 8];
    let result = kdf(&key, "Test Label", &ctx, 32);
    assert_eq!(result.len(), 32);
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
