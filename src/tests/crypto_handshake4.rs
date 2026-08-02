// SPDX-License-Identifier: Apache-2.0

use aws_lc_rs::key_wrap::{self, KeyWrap};

use crate::{
    ErrorKind, WpaError,
    crypto::handshake4::{
        FourWayState, KEK_LEN, aes_cmac, aes_key_unwrap, parse_gtk_kde,
    },
    ieee80211::eapol,
};

fn aes_key_wrap(
    kek_bytes: &[u8; KEK_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, WpaError> {
    let out_len = plaintext.len() + 8;
    let mut out = vec![0u8; out_len];
    let kek =
        key_wrap::AesKek::new(&key_wrap::AES_128, kek_bytes).map_err(|e| {
            WpaError::new(ErrorKind::HandshakeFailed, format!("key wrap: {e}"))
        })?;
    kek.wrap(plaintext, &mut out).map_err(|e| {
        WpaError::new(ErrorKind::HandshakeFailed, format!("key wrap: {e}"))
    })?;
    Ok(out)
}

#[test]
fn test_ptk_derivation() {
    let pmk = [0x01u8; 32];
    let pmkid = [0x02u8; 16];
    let sta = [0x03u8; 6];
    let ap = [0x04u8; 6];
    let mut state = FourWayState::new(&pmk, &pmkid, sta, ap, vec![]);
    let anonce = [0x05u8; 32];

    state.anonce = Some(anonce);
    state.ptk = Some(state.derive_ptk());

    let ptk = state.ptk.unwrap();
    assert_eq!(ptk.len(), 48);
    assert_eq!(state.kck().unwrap().len(), 16);
    assert_eq!(state.kek().unwrap().len(), 16);
    assert_eq!(state.tk().unwrap().len(), 16);
}

#[test]
fn test_mic_roundtrip() {
    let kck = [0xAAu8; 16];
    let data = b"some eapol pdu bytes";
    let mic = aes_cmac(&kck, data).unwrap();
    assert_eq!(mic.len(), 16);
    let mic2 = aes_cmac(&kck, data).unwrap();
    assert_eq!(mic, mic2);
}

#[test]
fn test_gtk_unwrap() {
    let kek = [0xCCu8; 16];
    let gtk = [0xDDu8; 16];
    let wrapped = aes_key_wrap(&kek, &gtk).unwrap();
    assert_eq!(wrapped.len(), 24);
    let unwrapped = aes_key_unwrap(&kek, &wrapped).unwrap();
    assert_eq!(unwrapped, gtk.to_vec());
}

#[test]
fn test_parse_gtk_kde() {
    let gtk = [0x77u8; 16];
    let mut kde = vec![
        0xDD,
        (6 + gtk.len()) as u8,
        0x00,
        0x0F,
        0xAC,
        0x01,
        0x01,
        0x00,
    ];
    kde.extend_from_slice(&gtk);
    let (idx, parsed) = parse_gtk_kde(&kde).unwrap();
    assert_eq!(idx, 1);
    assert_eq!(parsed, gtk.to_vec());
}

#[test]
fn test_group_rekey() {
    let pmk = [0x11u8; 32];
    let pmkid = [0x22u8; 16];
    let sta = [0x03u8; 6];
    let ap = [0x04u8; 6];
    let mut state = FourWayState::new(&pmk, &pmkid, sta, ap, vec![]);
    state.anonce = Some([0x05u8; 32]);
    state.ptk = Some(state.derive_ptk());
    let kck = state.kck().unwrap();
    let kek = state.kek().unwrap();

    let new_gtk = [0x99u8; 16];
    let mut kde = vec![
        0xDD,
        (6 + new_gtk.len()) as u8,
        0x00,
        0x0F,
        0xAC,
        0x01,
        0x02,
        0x00,
    ];
    kde.extend_from_slice(&new_gtk);
    let wrapped = aes_key_wrap(&kek, &kde).unwrap();
    let key_info = 0x0100 | 0x0080 | 0x0200 | 0x1000;
    let mut g1 = eapol::build_eapol_key_pdu(
        key_info, 16, 5, &[0u8; 32], &[0u8; 16], &[0u8; 8], &[0u8; 8],
        &[0u8; 16], &wrapped,
    );
    let g1_mic = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&g1)).unwrap();
    eapol::set_mic(&mut g1, &g1_mic);

    let parsed = eapol::parse_eapol_key_frame(&g1).unwrap();
    let msg2 = state.process_group_rekey(&parsed).unwrap();

    assert_eq!(state.gtk(), Some(new_gtk.as_slice()));
    assert_eq!(state.gtk_index(), 2);

    let m2 = eapol::parse_eapol_key_frame(&msg2).unwrap();
    assert!(m2.has_mic() && m2.is_secure() && !m2.is_pairwise());
    let m2_mic = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&msg2)).unwrap();
    assert_eq!(m2.key_mic, m2_mic);
}
