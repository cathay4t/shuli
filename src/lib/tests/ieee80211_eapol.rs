// SPDX-License-Identifier: Apache-2.0

use crate::ieee80211::eapol::{
    OFF_MIC, build_message_2, build_message_4, parse_eapol_key_frame,
    pdu_with_zeroed_mic,
};

#[test]
fn roundtrip_msg2() {
    let snonce = [0xABu8; 32];
    let rsne = vec![0x30, 0x14, 0x01, 0x00];
    let pdu = build_message_2(&snonce, 1, &rsne, 0);
    let parsed = parse_eapol_key_frame(&pdu).unwrap();
    assert!(parsed.has_mic());
    assert!(parsed.is_pairwise());
    assert_eq!(parsed.key_nonce, snonce);
    assert_eq!(parsed.key_data, rsne);
    assert_eq!(parsed.replay_counter, 1);
}

#[test]
fn mic_offset_is_correct() {
    assert_eq!(OFF_MIC, 81);
    let pdu = build_message_4(&[0u8; 32], 2, 0);
    let zeroed = pdu_with_zeroed_mic(&pdu);
    assert_eq!(&zeroed[OFF_MIC..OFF_MIC + 16], &[0u8; 16]);
}

#[test]
fn reject_non_eapol() {
    assert!(parse_eapol_key_frame(&[0u8; 20]).is_none());
}
