// SPDX-License-Identifier: Apache-2.0

//! Unit tests for RSNE builders (Stage 3 M5: WPA3-Enterprise PMF).

use wl_nl80211::Ieee80211CipherSuite;

use crate::ieee80211::elements::{
    negotiate_group_mgmt_cipher, parse_group_mgmt_cipher, rsne_set_ext_key_id,
    wpa2_ent_ie_cipher, wpa2_ent_sha256_ie_cipher,
    wpa2_psk_ie_with_pmkid_cipher,
};

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
    let ie = wpa2_ent_sha256_ie_cipher(Ieee80211CipherSuite::BipCmac128);
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
    let ie = wpa2_ent_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    let capab = rsne_capabilities(&ie);
    assert_eq!(capab & 0x40, 0, "AKM 1 must not require PMF");
    assert_ne!(capab & 0x80, 0, "AKM 1 offers PMF (MFPC)");
}

/// Stage 3 M8: the negotiated BIP cipher is parsed back from built
/// RSNEs (with and without a PMKID) and defaults to BIP-CMAC-128.
#[test]
fn group_mgmt_cipher_negotiation_roundtrip() {
    let gmac256 = wpa2_ent_sha256_ie_cipher(Ieee80211CipherSuite::BipGmac256);
    assert_eq!(
        parse_group_mgmt_cipher(&gmac256),
        Some(Ieee80211CipherSuite::BipGmac256)
    );
    assert_eq!(
        negotiate_group_mgmt_cipher(&gmac256),
        Ieee80211CipherSuite::BipGmac256
    );

    let cmac256 = wpa2_psk_ie_with_pmkid_cipher(
        Some([0xAB; 16]),
        Ieee80211CipherSuite::BipCmac256,
    );
    assert_eq!(
        parse_group_mgmt_cipher(&cmac256),
        Some(Ieee80211CipherSuite::BipCmac256),
        "parse must skip the PMKID list before the mgmt cipher"
    );
    assert_eq!(
        negotiate_group_mgmt_cipher(&cmac256),
        Ieee80211CipherSuite::BipCmac256
    );

    let cmac128 = wpa2_ent_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    assert_eq!(
        negotiate_group_mgmt_cipher(&cmac128),
        Ieee80211CipherSuite::BipCmac128
    );
    assert_eq!(
        negotiate_group_mgmt_cipher(&[]),
        Ieee80211CipherSuite::BipCmac128,
        "missing group mgmt cipher defaults to BIP-CMAC-128"
    );
}

/// Stage 3 M11: the Extended Key ID capability bit (bit 13) can be set
/// and cleared on a built RSNE.
#[test]
fn ext_key_id_rsne_bit() {
    let mut ie = wpa2_ent_sha256_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    rsne_set_ext_key_id(&mut ie, true);
    assert_ne!(rsne_capabilities(&ie) & 0x2000, 0);
    rsne_set_ext_key_id(&mut ie, false);
    assert_eq!(rsne_capabilities(&ie) & 0x2000, 0);
}
