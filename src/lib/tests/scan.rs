// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the scan-phase security classification (G5/M7).

use crate::scan::{SecurityType, detect_security};

/// Build an RSNE element (ID 48 + length + body) advertising a single
/// AKM suite 00-0F-AC:`akm`, CCMP group + pairwise ciphers.
fn rsne_ie(akm: u8) -> Vec<u8> {
    let body = vec![
        0x01, 0x00, // version 1
        0x00, 0x0F, 0xAC, 0x04, // group cipher: CCMP
        0x01, 0x00, // pairwise cipher count
        0x00, 0x0F, 0xAC, 0x04, // pairwise cipher: CCMP
        0x01, 0x00, // AKM suite count
        0x00, 0x0F, 0xAC, akm, // AKM suite
    ];
    let mut ie = vec![48, body.len() as u8];
    ie.extend_from_slice(&body);
    ie
}

/// Build an RSNE with a TKIP group cipher (00-0F-AC:2) - the WPA1/WPA2
/// hybrid shape shuli must reject.
fn rsne_ie_tkip_group(akm: u8) -> Vec<u8> {
    let body = vec![
        0x01, 0x00, // version 1
        0x00, 0x0F, 0xAC, 0x02, // group cipher: TKIP
        0x01, 0x00, // pairwise cipher count
        0x00, 0x0F, 0xAC, 0x04, // pairwise cipher: CCMP
        0x01, 0x00, // AKM suite count
        0x00, 0x0F, 0xAC, akm, // AKM suite
    ];
    let mut ie = vec![48, body.len() as u8];
    ie.extend_from_slice(&body);
    ie
}

/// Build the vendor-specific WPA IE (element ID 0xDD, OUI 00:50:F2,
/// type 1) of a WPA1 AP - no RSNE.
fn wpa1_ie() -> Vec<u8> {
    let body = vec![
        0x00, 0x50, 0xF2, 0x01, // OUI + WPA type
        0x01, 0x00, // version
        0x00, 0x50, 0xF2, 0x02, // multicast cipher: TKIP
        0x01, 0x00, // unicast cipher count
        0x00, 0x50, 0xF2, 0x02, // unicast cipher: TKIP
        0x01, 0x00, // AKM count
        0x00, 0x50, 0xF2, 0x02, // AKM: PSK
    ];
    let mut ie = vec![0xDD, body.len() as u8];
    ie.extend_from_slice(&body);
    ie
}

#[test]
fn test_open_bss_without_security_ies() {
    // No RSNE, no WPA IE: open.
    let sec = detect_security(&[]);
    assert_eq!(sec.security, SecurityType::Open);
    assert!(sec.ap_rsne.is_empty());
}

#[test]
fn test_supported_akms_are_recognized() {
    // Regression: every supported AKM keeps its type.
    for (akm, expected) in [
        (2, SecurityType::Wpa2Psk),
        (6, SecurityType::Wpa2PskSha256),
        (4, SecurityType::FtPsk),
        (8, SecurityType::Sae),
        (9, SecurityType::FtSae),
        (18, SecurityType::Owe),
    ] {
        let sec = detect_security(&rsne_ie(akm));
        assert_eq!(sec.security, expected, "AKM 00-0F-AC:{akm}");
        assert!(!sec.ap_rsne.is_empty(), "RSNE must be collected");
    }
}

#[test]
fn test_unsupported_akm_is_not_open() {
    // WPA-Enterprise / 802.1X (AKM 1) is not joinable; classifying it
    // open would associate without encryption.
    let sec = detect_security(&rsne_ie(1));
    assert_eq!(
        sec.security,
        SecurityType::Unsupported,
        "AKM 00-0F-AC:1 must classify as Unsupported"
    );
}

#[test]
fn test_mixed_psk_and_psk_sha256_prefers_sha256() {
    // An RSNE advertising both WPA2-PSK (2) and PSK-SHA256 (6) must
    // pick the stronger SHA-256 AKM.
    let body = vec![
        0x01, 0x00, // version 1
        0x00, 0x0F, 0xAC, 0x04, // group cipher: CCMP
        0x01, 0x00, // pairwise cipher count
        0x00, 0x0F, 0xAC, 0x04, // pairwise cipher: CCMP
        0x02, 0x00, // AKM suite count: 2
        0x00, 0x0F, 0xAC, 0x02, // AKM: PSK
        0x00, 0x0F, 0xAC, 0x06, // AKM: PSK-SHA256
    ];
    let mut ies = vec![48, body.len() as u8];
    ies.extend_from_slice(&body);
    let sec = detect_security(&ies);
    assert_eq!(sec.security, SecurityType::Wpa2PskSha256);
}

#[test]
fn test_unsupported_akm_alongside_supported_one_wins_supported() {
    // An RSNE advertising both PSK (2) and 802.1X (1): the supported
    // AKM wins (hostapd multi-AKM APs).
    let body = vec![
        0x01, 0x00, // version 1
        0x00, 0x0F, 0xAC, 0x04, // group cipher: CCMP
        0x01, 0x00, // pairwise cipher count
        0x00, 0x0F, 0xAC, 0x04, // pairwise cipher: CCMP
        0x02, 0x00, // AKM suite count: 2
        0x00, 0x0F, 0xAC, 0x02, // AKM: PSK
        0x00, 0x0F, 0xAC, 0x01, // AKM: 802.1X
    ];
    let mut ies = vec![48, body.len() as u8];
    ies.extend_from_slice(&body);
    let sec = detect_security(&ies);
    assert_eq!(sec.security, SecurityType::Wpa2Psk);
}

#[test]
fn test_tkip_group_cipher_is_unsupported() {
    let sec = detect_security(&rsne_ie_tkip_group(2));
    assert_eq!(
        sec.security,
        SecurityType::Unsupported,
        "TKIP group cipher must be rejected even with AKM PSK"
    );
}

#[test]
fn test_wpa1_ie_without_rsne_is_unsupported() {
    // A WPA1/TKIP AP has no RSNE; without this check it would be
    // classified open and shuli would associate without encryption.
    let sec = detect_security(&wpa1_ie());
    assert_eq!(sec.security, SecurityType::Unsupported);
    assert!(sec.ap_rsne.is_empty());
}

#[test]
fn test_rsne_with_bogus_akm_suite_oid_is_unsupported() {
    // RSNE whose AKM OUI is not 00-0F-AC (e.g. a WAPI suite selector):
    // encrypted but unjoinable.
    let body = vec![
        0x01, 0x00, // version 1
        0x00, 0x0F, 0xAC, 0x04, // group cipher: CCMP
        0x01, 0x00, // pairwise cipher count
        0x00, 0x0F, 0xAC, 0x04, // pairwise cipher: CCMP
        0x01, 0x00, // AKM suite count
        0x00, 0x14, 0x72, 0x01, // WAPI AKM (not 00-0F-AC)
    ];
    let mut ies = vec![48, body.len() as u8];
    ies.extend_from_slice(&body);
    let sec = detect_security(&ies);
    assert_eq!(sec.security, SecurityType::Unsupported);
}
