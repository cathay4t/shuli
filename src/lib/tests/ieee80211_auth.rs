// SPDX-License-Identifier: Apache-2.0

use crate::ieee80211::auth::{build_sae_auth_frame, parse_sae_auth_frame};

#[test]
fn roundtrip_sae_commit_frame() {
    let sta = [0x02u8; 6];
    let ap = [0x01u8; 6];
    let payload = b"0123456789abcdef0123456789abcdef".to_vec();
    let frame = build_sae_auth_frame(sta, ap, 1, 0, &payload);
    assert!(frame.len() > 24);
    let parsed = parse_sae_auth_frame(&frame);
    assert!(parsed.is_some());
    let (seq, status, pl) = parsed.unwrap();
    assert_eq!(seq, 1);
    assert_eq!(status, 0);
    assert_eq!(pl, payload);
}

#[test]
fn parse_wrong_auth_alg() {
    let frame = build_sae_auth_frame([0u8; 6], [0u8; 6], 1, 0, &[]);
    let mut modified = frame.clone();
    modified[24] = 0;
    modified[25] = 1;
    assert!(parse_sae_auth_frame(&modified).is_none());
}

#[test]
fn parse_too_short() {
    assert!(parse_sae_auth_frame(&[0u8; 10]).is_none());
}
