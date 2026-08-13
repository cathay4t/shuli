// SPDX-License-Identifier: Apache-2.0

//! Unit tests for RSNE builders (Stage 3 M5: WPA3-Enterprise PMF).

use crate::ieee80211::elements::{wpa2_ent_ie, wpa2_ent_sha256_ie};

/// RSN capabilities at body offset: version(2) group(4) pcount(2)
/// pciphers(4*n) acount(2) akms(4*m) capab(2).
fn rsne_capabilities(ie: &[u8]) -> u16 {
    let body = &ie[2..];
    let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
    let mut pos = 8 + pcount * 4;
    let acount = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + acount * 4;
    u16::from_le_bytes([body[pos], body[pos + 1]])
}

#[test]
fn wpa3_enterprise_rsne_requires_mfp() {
    // WPA3-Enterprise (AKM 5): MFPR + MFPC both set.
    let ie = wpa2_ent_sha256_ie();
    assert_eq!(
        &ie[16..20],
        &[0x00, 0x0F, 0xAC, 0x05],
        "AKM suite must be 802.1X-SHA256"
    );
    let capab = rsne_capabilities(&ie);
    assert_ne!(capab & 0x40, 0, "MFPR must be set");
    assert_ne!(capab & 0x80, 0, "MFPC must be set");
}

#[test]
fn wpa2_enterprise_rsne_keeps_pmf_optional() {
    // WPA2-Enterprise (AKM 1): MFPC only - PMF optional.
    let ie = wpa2_ent_ie();
    let capab = rsne_capabilities(&ie);
    assert_eq!(capab & 0x40, 0, "AKM 1 must not require PMF");
    assert_ne!(capab & 0x80, 0, "AKM 1 offers PMF (MFPC)");
}
