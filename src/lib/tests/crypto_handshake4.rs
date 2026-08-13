// SPDX-License-Identifier: Apache-2.0

use aws_lc_rs::key_wrap::{self, KeyWrap};

use crate::{
    ErrorKind, WifiError,
    crypto::handshake4::{
        FourWayState, KEK_LEN, KeyDataKdes, MicAlg, aes_cmac, aes_key_unwrap,
        parse_gtk_kde, parse_key_data_kdes,
    },
    ieee80211::eapol,
};

fn aes_key_wrap(
    kek_bytes: &[u8; KEK_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, WifiError> {
    let out_len = plaintext.len() + 8;
    let mut out = vec![0u8; out_len];
    let kek =
        key_wrap::AesKek::new(&key_wrap::AES_128, kek_bytes).map_err(|e| {
            WifiError::new(ErrorKind::HandshakeFailed, format!("key wrap: {e}"))
        })?;
    kek.wrap(plaintext, &mut out).map_err(|e| {
        WifiError::new(ErrorKind::HandshakeFailed, format!("key wrap: {e}"))
    })?;
    Ok(out)
}

#[test]
fn test_ptk_derivation() {
    let pmk = [0x01u8; 32];
    let sta = [0x03u8; 6];
    let ap = [0x04u8; 6];
    let mut state = FourWayState::new_with_ap_ies(
        &pmk,
        MicAlg::AesCmac,
        sta,
        ap,
        vec![],
        vec![],
        vec![],
    );
    let anonce = [0x05u8; 32];

    state.anonce = Some(anonce);
    state.ptk = Some(state.derive_ptk());

    let ptk = state.ptk.unwrap();
    assert_eq!(ptk.len(), 48);
    assert_eq!(state.kck().unwrap().len(), 16);
    assert_eq!(state.kek().unwrap().len(), 16);
    assert_eq!(state.tk().unwrap().len(), 16);
}

/// Stage 3 M1: PSK-SHA256 (AKM 00-0F-AC:6) uses KDF-Hash-Length for
/// the PTK and AES-CMAC MIC with Key Descriptor Version 3, and echoes
/// KDV 3 in Messages 2 and 4.
#[test]
fn test_psk_sha256_kdv3_handshake() {
    let pmk = [0x01u8; 32];
    let sta = [0x03u8; 6];
    let ap = [0x04u8; 6];
    let mut state = FourWayState::new_with_ap_ies(
        &pmk,
        MicAlg::AesCmac,
        sta,
        ap,
        vec![],
        vec![],
        vec![],
    );

    // Message 1 with Key Descriptor Version 3 (AES-128-CMAC), as sent
    // by a PSK-SHA256 AP.
    let msg1_key_info = 0x0080 | 0x0008 | 0x0003; // ack + pairwise + KDV 3
    let msg1 = eapol::build_eapol_key_pdu(
        msg1_key_info,
        16,
        1,
        &[0x55u8; 32],
        &[0u8; 16],
        &[0u8; 8],
        &[0u8; 8],
        &[0u8; 16],
        b"",
    );
    let parsed1 = eapol::parse_eapol_key_frame(&msg1).unwrap();
    let msg2 = state
        .process_message_1(
            &parsed1.key_nonce,
            parsed1.replay_counter,
            parsed1.key_info,
        )
        .unwrap();
    let m2 = eapol::parse_eapol_key_frame(&msg2).unwrap();
    assert_eq!(eapol::desc_version(m2.key_info), 3);
    let kck = state.kck().unwrap();
    let m2_mic = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&msg2)).unwrap();
    assert_eq!(m2.key_mic, m2_mic);

    // Message 3 with an encrypted GTK; MIC verified with AES-CMAC.
    let kek = state.kek().unwrap();
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
    let mut padded = kde.clone();
    while padded.len() < 16 || !padded.len().is_multiple_of(8) {
        padded.push(0);
    }
    let wrapped = aes_key_wrap(&kek, &padded).unwrap();
    let msg3_key_info =
        0x0008 | 0x0040 | 0x0080 | 0x0100 | 0x0200 | 0x1000 | 0x0003;
    let mut msg3 = eapol::build_eapol_key_pdu(
        msg3_key_info,
        16,
        2,
        &[0u8; 32],
        &[0u8; 16],
        &[0u8; 8],
        &[0u8; 8],
        &[0u8; 16],
        &wrapped,
    );
    let msg3_mic = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&msg3)).unwrap();
    eapol::set_mic(&mut msg3, &msg3_mic);
    let parsed3 = eapol::parse_eapol_key_frame(&msg3).unwrap();
    let (msg4, kdes) = state.process_message_3(&parsed3).unwrap();
    assert_eq!(kdes.gtk, Some((1, gtk.to_vec())));
    let m4 = eapol::parse_eapol_key_frame(&msg4).unwrap();
    assert_eq!(eapol::desc_version(m4.key_info), 3);
    let m4_mic = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&msg4)).unwrap();
    assert_eq!(m4.key_mic, m4_mic);
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
    let sta = [0x03u8; 6];
    let ap = [0x04u8; 6];
    let mut state = FourWayState::new_with_ap_ies(
        &pmk,
        MicAlg::AesCmac,
        sta,
        ap,
        vec![],
        vec![],
        vec![],
    );
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

// --- G1 tests ---

/// Build an IGTK or BIGTK KDE: OUI 00-0F-AC, type 9 / 10, KeyID (2 LE),
/// IPN (6), key (16).
fn build_mgmt_key_kde(
    kde_type: u8,
    key_id: u16,
    ipn: &[u8; 6],
    key: &[u8; 16],
) -> Vec<u8> {
    let mut kde = vec![0xDD, 4 + 2 + 6 + 16, 0x00, 0x0F, 0xAC, kde_type];
    kde.extend_from_slice(&key_id.to_le_bytes());
    kde.extend_from_slice(ipn);
    kde.extend_from_slice(key);
    kde
}

#[test]
fn test_parse_key_data_kdes_all() {
    let gtk = [0x77u8; 16];
    let igtk = [0x88u8; 16];
    let bigtk = [0x99u8; 16];
    let ipn = [1, 2, 3, 4, 5, 6];
    let rsne = vec![0x30, 0x02, 0x01, 0x00];
    let rsnxe = vec![0xF4, 0x01, 0x20];

    let mut key_data = vec![
        0xDD,
        (6 + gtk.len()) as u8,
        0x00,
        0x0F,
        0xAC,
        0x01,
        0x02,
        0x00,
    ];
    key_data.extend_from_slice(&gtk);
    key_data.extend_from_slice(&build_mgmt_key_kde(9, 4, &ipn, &igtk));
    key_data.extend_from_slice(&build_mgmt_key_kde(10, 6, &ipn, &bigtk));
    key_data.extend_from_slice(&rsne);
    key_data.extend_from_slice(&rsnxe);

    let kdes = parse_key_data_kdes(&key_data);
    assert_eq!(kdes.gtk, Some((2, gtk.to_vec())));
    assert_eq!(
        kdes.igtk
            .as_ref()
            .map(|k| (k.key_index, k.ipn, k.key.clone())),
        Some((4, ipn, igtk.to_vec()))
    );
    assert_eq!(
        kdes.bigtk
            .as_ref()
            .map(|k| (k.key_index, k.ipn, k.key.clone())),
        Some((6, ipn, bigtk.to_vec()))
    );
    assert_eq!(kdes.rsne.as_deref(), Some(rsne.as_slice()));
    assert_eq!(kdes.rsnxe.as_deref(), Some(rsnxe.as_slice()));
    // parse_gtk_kde keeps its GTK-only contract on top of the full parser.
    assert_eq!(parse_gtk_kde(&key_data), Some((2, gtk.to_vec())));
}

/// Run Message 1 then a wrapped Message 3 against `state`, returning the
/// parsed Message 4 and the Message 3 KDEs.
fn run_msg1_msg3(
    state: &mut FourWayState,
    key_data_plain: &[u8],
) -> Result<(Vec<u8>, KeyDataKdes), WifiError> {
    let msg1 = eapol::build_eapol_key_pdu(
        0x0080 | 0x0008, // ack + pairwise
        16,
        1,
        &[0x55u8; 32],
        &[0u8; 16],
        &[0u8; 8],
        &[0u8; 8],
        &[0u8; 16],
        b"",
    );
    let msg1 = eapol::parse_eapol_key_frame(&msg1).unwrap();
    state.process_message_1(
        &msg1.key_nonce,
        msg1.replay_counter,
        msg1.key_info,
    )?;

    let kck = state.kck().unwrap();
    let kek = state.kek().unwrap();
    // RFC 3394 wraps multiples of 64 bits (at least two blocks); real
    // EAPOL-Key senders zero-pad the key data accordingly.
    let mut padded = key_data_plain.to_vec();
    while padded.len() < 16 || !padded.len().is_multiple_of(8) {
        padded.push(0);
    }
    let wrapped = aes_key_wrap(&kek, &padded)?;
    let key_info = 0x0008 | 0x0040 | 0x0080 | 0x0100 | 0x0200 | 0x1000;
    let mut msg3 = eapol::build_eapol_key_pdu(
        key_info, 16, 2, &[0u8; 32], &[0u8; 16], &[0u8; 8], &[0u8; 8],
        &[0u8; 16], &wrapped,
    );
    let msg3_mic = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&msg3)).unwrap();
    eapol::set_mic(&mut msg3, &msg3_mic);

    let parsed = eapol::parse_eapol_key_frame(&msg3).unwrap();
    state.process_message_3(&parsed)
}

#[test]
fn test_msg3_igtk_kde_and_rsne_check() {
    let pmk = [0x01u8; 32];
    let ap_rsne = vec![0x30, 0x02, 0x01, 0x00];
    let ap_rsnxe = vec![0xF4, 0x01, 0x20];
    let igtk = [0x88u8; 16];
    let ipn = [9, 8, 7, 6, 5, 4];

    let mut state = FourWayState::new_with_ap_ies(
        &pmk,
        MicAlg::AesCmac,
        [0x03u8; 6],
        [0x04u8; 6],
        ap_rsne.clone(),
        ap_rsne.clone(),
        ap_rsnxe.clone(),
    );

    let mut key_data = ap_rsne.clone();
    key_data.extend_from_slice(ap_rsnxe.as_slice());
    key_data.extend_from_slice(&build_mgmt_key_kde(9, 5, &ipn, &igtk));

    let (msg4, kdes) = run_msg1_msg3(&mut state, &key_data).unwrap();
    assert_eq!(
        kdes.igtk
            .as_ref()
            .map(|k| (k.key_index, k.ipn, k.key.clone())),
        Some((5, ipn, igtk.to_vec()))
    );
    // Message 4: valid MIC, pairwise + secure.
    let m4 = eapol::parse_eapol_key_frame(&msg4).unwrap();
    assert!(m4.has_mic() && m4.is_secure() && m4.is_pairwise());
    let kck = state.kck().unwrap();
    let m4_mic = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&msg4)).unwrap();
    assert_eq!(m4.key_mic, m4_mic);
}

#[test]
fn test_msg3_rsne_downgrade_rejected() {
    let pmk = [0x01u8; 32];
    let ap_rsne = vec![0x30, 0x02, 0x01, 0x00];
    let mut state = FourWayState::new_with_ap_ies(
        &pmk,
        MicAlg::AesCmac,
        [0x03u8; 6],
        [0x04u8; 6],
        ap_rsne.clone(),
        ap_rsne,
        vec![],
    );
    // The attacker downgraded the RSNE in Message 3 (no MFP bits).
    let downgraded = vec![0x30, 0x02, 0x00, 0x00];
    let err = run_msg1_msg3(&mut state, &downgraded).unwrap_err();
    assert_eq!(err.kind, ErrorKind::HandshakeFailed);
    assert!(err.to_string().contains("RSNE downgrade"));
}

#[test]
fn test_msg3_rsnxe_downgrade_rejected() {
    let pmk = [0x01u8; 32];
    let ap_rsne = vec![0x30, 0x02, 0x01, 0x00];
    let ap_rsnxe = vec![0xF4, 0x01, 0x20];
    let mut state = FourWayState::new_with_ap_ies(
        &pmk,
        MicAlg::AesCmac,
        [0x03u8; 6],
        [0x04u8; 6],
        ap_rsne.clone(),
        ap_rsne.clone(),
        ap_rsnxe,
    );
    // Message 3 carries the beacon RSNE but drops the RSNXE.
    let err = run_msg1_msg3(&mut state, &ap_rsne).unwrap_err();
    assert_eq!(err.kind, ErrorKind::HandshakeFailed);
    assert!(err.to_string().contains("RSNXE downgrade"));
}

/// G1c: an AP-initiated PTK rekey arrives as a fresh Message 1
/// mid-connection; the supplicant must derive a fresh SNonce/PTK and
/// answer with a valid Message 2.
#[test]
fn test_ptk_rekey_fresh_snonce() {
    let pmk = [0x01u8; 32];
    let mut state = FourWayState::new_with_ap_ies(
        &pmk,
        MicAlg::AesCmac,
        [0x03u8; 6],
        [0x04u8; 6],
        vec![],
        vec![],
        vec![],
    );

    // Initial handshake Message 1.
    let msg2_1 = state.process_message_1(&[0x11u8; 32], 1, 0).unwrap();
    let ptk_1 = state.ptk.unwrap();

    // PTK rekey: new ANonce, new replay counter.
    let msg2_2 = state.process_message_1(&[0x22u8; 32], 2, 0).unwrap();
    let ptk_2 = state.ptk.unwrap();

    assert_ne!(ptk_1, ptk_2, "rekey must derive a fresh PTK");

    // Both Message 2 PDUs carry valid MICs and echo the AP's replay
    // counter.
    let kck = state.kck().unwrap();
    let m2 = eapol::parse_eapol_key_frame(&msg2_2).unwrap();
    assert_eq!(m2.replay_counter, 2);
    let mic = aes_cmac(&kck, &eapol::pdu_with_zeroed_mic(&msg2_2)).unwrap();
    assert_eq!(m2.key_mic, mic);
    let m2_1 = eapol::parse_eapol_key_frame(&msg2_1).unwrap();
    assert_eq!(m2_1.replay_counter, 1);
}

/// G1c: EAPOL-Key frames with the Request bit set are dropped by
/// supplicants; shuli must recognise them so the client can drop them
/// before any handshake processing.
#[test]
fn test_request_bit_detection() {
    let key_info = 0x0800 | 0x0080; // request + ack
    let pdu = eapol::build_eapol_key_pdu(
        key_info, 16, 1, &[0u8; 32], &[0u8; 16], &[0u8; 8], &[0u8; 8],
        &[0u8; 16], b"",
    );
    let parsed = eapol::parse_eapol_key_frame(&pdu).unwrap();
    assert!(parsed.is_request());
    assert!(eapol::fmt_key_info(parsed.key_info).contains("request"));
}
