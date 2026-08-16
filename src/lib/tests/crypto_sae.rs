// SPDX-License-Identifier: Apache-2.0

use p256::{
    AffinePoint,
    elliptic_curve::{Group, point::AffineCoordinates},
};

use crate::{
    auth::{AuthAction, AuthMethod},
    crypto::sae::{
        SaeAuth, compute_pwe_h2e, compute_pwe_h2e_with_id, compute_pwe_hnp,
        parse_anti_clogging_token,
    },
};

fn affine_x_bytes(point: &AffinePoint) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(point.x().as_ref());
    bytes
}

fn test_macs() -> ([u8; 6], [u8; 6]) {
    let mac_sta = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mac_ap = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
    (mac_sta, mac_ap)
}

#[test]
fn test_pwe_derivation() {
    let (mac_sta, mac_ap) = test_macs();
    let pwe = compute_pwe_h2e("12345678", "Test-WIFI", &mac_sta, &mac_ap);
    assert!(pwe.is_ok());
    assert!(!bool::from(pwe.unwrap().is_identity()));
}

/// the hunting-and-pecking PWE derivation must be deterministic,
/// land on a real curve point, and differ from the H2E point (the two
/// methods deliberately pick different password elements).
#[test]
fn test_hnp_pwe_derivation() {
    let (mac_sta, mac_ap) = test_macs();
    let pwe1 = compute_pwe_hnp("12345678", "Test-WIFI", &mac_sta, &mac_ap)
        .expect("hnp pwe");
    let pwe2 = compute_pwe_hnp("12345678", "Test-WIFI", &mac_sta, &mac_ap)
        .expect("hnp pwe");
    assert!(!bool::from(pwe1.is_identity()));
    assert_eq!(
        affine_x_bytes(&pwe1.to_affine()),
        affine_x_bytes(&pwe2.to_affine()),
        "HnP PWE must be deterministic"
    );
    let h2e = compute_pwe_h2e("12345678", "Test-WIFI", &mac_sta, &mac_ap)
        .expect("h2e pwe");
    assert_ne!(
        affine_x_bytes(&pwe1.to_affine()),
        affine_x_bytes(&h2e.to_affine()),
        "HnP and H2E PWE must differ"
    );
}

/// an SAE password identifier changes the H2E PWE (it is
/// mixed into `pwd-seed`), is carried in the commit's Password
/// Identifier element, and must produce matching PMKs on both sides.
#[test]
fn test_sae_password_identifier() {
    let (mac_sta, mac_ap) = test_macs();
    let password = "12345678";
    let ssid = "Test-WIFI";

    let plain =
        compute_pwe_h2e(password, ssid, &mac_sta, &mac_ap).expect("plain");
    let with_id = compute_pwe_h2e_with_id(
        password,
        ssid,
        &mac_sta,
        &mac_ap,
        Some("corp-id"),
    )
    .expect("with id");
    assert_ne!(
        affine_x_bytes(&plain.to_affine()),
        affine_x_bytes(&with_id.to_affine()),
        "password identifier must change the H2E PWE"
    );

    // Commit payload: group(2) || scalar(32) || element(64) ||
    // FF || 1+len || 33 || id
    let mut sae = SaeAuth::new_with_password_id(
        password,
        ssid,
        mac_sta,
        mac_ap,
        true,
        false,
        Some("corp-id"),
    )
    .unwrap();
    let auth_data = sae.build_init_auth_msg();
    let body = &auth_data[4..];
    let id = b"corp-id";
    assert_eq!(
        &body[98..101],
        &[0xff, 1 + id.len() as u8, 33],
        "Password Identifier element header"
    );
    assert_eq!(&body[101..101 + id.len()], id, "identifier bytes");

    // Same identifier on both sides -> matching PMK.
    let mut rng = getrandom::SysRng;
    let mut supp = SaeAuth::new_with_password_id(
        password,
        ssid,
        mac_sta,
        mac_ap,
        true,
        false,
        Some("corp-id"),
    )
    .unwrap();
    let (supp_scalar, supp_elem) = supp.build_commit(&mut rng).unwrap();
    let mut ap = SaeAuth::new_with_password_id(
        password,
        ssid,
        mac_ap,
        mac_sta,
        true,
        false,
        Some("corp-id"),
    )
    .unwrap();
    let (ap_scalar, ap_elem) = ap.build_commit(&mut rng).unwrap();
    supp.process_commit(&ap_scalar, &ap_elem).unwrap();
    ap.process_commit(&supp_scalar, &supp_elem).unwrap();
    assert_eq!(supp.pmk(), ap.pmk(), "PMK must match with the same id");
}

/// an AP that requires SAE-PK (status 127) fails cleanly
/// with a clear error - the SAE-PK crypto itself is not implemented.
#[test]
fn test_sae_pk_status_127_fails_cleanly() {
    let (mac_sta, mac_ap) = test_macs();
    let mut auth = AuthMethod::new_sae(
        "12345678",
        "Test-WIFI",
        mac_sta,
        mac_ap,
        true,
        false,
        None,
    )
    .unwrap();
    let err = match auth.process_frame(1, 127, &[0u8; 2]) {
        Err(e) => e,
        Ok(_) => panic!("expected a SAE-PK failure"),
    };
    assert_eq!(err.kind, crate::ErrorKind::AuthFailed);
    assert!(err.to_string().contains("SAE-PK"));
}

/// A transient SAE commit rejection (status 30 "refused temporarily")
/// must not be treated as a fatal credential failure: 802.11-2020
/// §12.4.8.6.4 discards the frame and retransmits the commit on the
/// SAE retransmission timer. Regression: a home AP answered the commit
/// with status 30 and shuli backed off for 10 minutes, so the
/// connection only came up after a daemon restart.
#[test]
fn test_sae_status_30_retries_temporarily() {
    let (mac_sta, mac_ap) = test_macs();
    let mut auth = AuthMethod::new_sae(
        "12345678",
        "Test-WIFI",
        mac_sta,
        mac_ap,
        true,
        false,
        None,
    )
    .unwrap();
    let action = auth
        .process_frame(1, 30, &[])
        .expect("status 30 must be retryable, not fatal");
    assert!(
        matches!(action, AuthAction::RetryTemporarily),
        "status 30 must map to RetryTemporarily"
    );
}

/// a full SAE exchange where both sides derive the PWE with
/// hunting-and-pecking must yield the same PMK (RFC 7664 interop path).
#[test]
fn test_hnp_full_exchange() {
    let mut rng = getrandom::SysRng;
    let (mac_sta, mac_ap) = test_macs();
    let password = "12345678";
    let ssid = "Test-WIFI";

    let mut supp =
        SaeAuth::new(password, ssid, mac_sta, mac_ap, false, false).unwrap();
    let (supp_scalar, supp_elem) = supp.build_commit(&mut rng).unwrap();

    let mut ap =
        SaeAuth::new(password, ssid, mac_ap, mac_sta, false, false).unwrap();
    let (ap_scalar, ap_elem) = ap.build_commit(&mut rng).unwrap();

    let _supp_confirm = supp.process_commit(&ap_scalar, &ap_elem).unwrap();
    let ap_confirm = ap.process_commit(&supp_scalar, &supp_elem).unwrap();
    assert_eq!(supp.pmk(), ap.pmk(), "HnP PMK must match");
    assert_eq!(supp.pmkid(), ap.pmkid(), "HnP PMKID must match");

    let mut ap_confirm_body = vec![1u8, 0u8];
    ap_confirm_body.extend_from_slice(&ap_confirm);
    supp.process_confirm(&ap_confirm_body).unwrap();
}

/// the anti-clogging token container format - an extended element
/// `FF || 1+len || 0x5D || token` after the commit element (matching
/// hostapd's `auth_build_token_req` / wpa_supplicant `sae_write_commit`),
/// and the raw-token form for hunting-and-pecking.
#[test]
fn test_commit_with_token_format() {
    let (mac_sta, mac_ap) = test_macs();
    let mut sae =
        SaeAuth::new("12345678", "Test-WIFI", mac_sta, mac_ap, true, false)
            .unwrap();
    let initial = sae.build_init_auth_msg();
    assert_eq!(initial.len(), 6 + 32 + 64);

    // A hostapd-style 32-byte anti-clogging token.
    let token: Vec<u8> = (0u8..32).collect();
    let auth_data = sae
        .build_commit_with_token(&token)
        .expect("commit with token");
    assert!(auth_data.len() > initial.len());
    assert_eq!(&auth_data[..6], &initial[..6], "trans/status/group prefix");

    // Payload: group(2) || scalar(32) || element(64) || FF || 1+32 || 5D ||
    // token
    let body = &auth_data[4..];
    assert_eq!(body.len(), 2 + 32 + 64 + 3 + 32);
    assert_eq!(&body[98..101], &[0xff, 33, 0x5d], "token container header");
    assert_eq!(&body[101..], &token[..], "token bytes");
}

/// parse the AP's status-76 response payload back into the token.
#[test]
fn test_parse_anti_clogging_token() {
    let _ = test_macs();
    let group = 19u16.to_le_bytes();
    let token: Vec<u8> = (0xab..0xcb).collect(); // 32 bytes

    // H2E: group || FF || 1+32 || 0x5D || token
    let mut h2e_payload = vec![group[0], group[1], 0xff, 33, 0x5d];
    h2e_payload.extend_from_slice(&token);
    let parsed =
        parse_anti_clogging_token(true, &h2e_payload).expect("parse h2e");
    assert_eq!(parsed, token);

    // HnP: group || token (raw)
    let mut hnp_payload = vec![group[0], group[1]];
    hnp_payload.extend_from_slice(&token);
    let parsed =
        parse_anti_clogging_token(false, &hnp_payload).expect("parse hnp");
    assert_eq!(parsed, token);

    // Malformed containers must be rejected, not mis-parsed.
    assert!(parse_anti_clogging_token(true, &h2e_payload[..4]).is_err());
    assert!(
        parse_anti_clogging_token(true, &[group[0], group[1], 0xfe]).is_err()
    );
    assert!(parse_anti_clogging_token(true, &[]).is_err());
    assert!(parse_anti_clogging_token(false, &[]).is_err());
}

#[test]
fn test_full_sae_exchange() {
    let mut rng = getrandom::SysRng;
    let (mac_sta, mac_ap) = test_macs();
    let password = "12345678";
    let ssid = "Test-WIFI";

    let mut supp =
        SaeAuth::new(password, ssid, mac_sta, mac_ap, true, false).unwrap();
    let (supp_scalar, supp_elem) = supp.build_commit(&mut rng).unwrap();

    let mut ap =
        SaeAuth::new(password, ssid, mac_ap, mac_sta, true, false).unwrap();
    let (ap_scalar, ap_elem) = ap.build_commit(&mut rng).unwrap();

    let supp_pwe_x = affine_x_bytes(&supp.pwe.to_affine());
    let ap_pwe_x = affine_x_bytes(&ap.pwe.to_affine());
    assert_eq!(supp_pwe_x, ap_pwe_x, "PWE x must match");

    let supp_confirm = supp.process_commit(&ap_scalar, &ap_elem).unwrap();
    let ap_confirm = ap.process_commit(&supp_scalar, &supp_elem).unwrap();

    assert_eq!(supp.pmk(), ap.pmk(), "PMK must match");
    assert_eq!(supp.pmkid(), ap.pmkid(), "PMKID must match");

    let mut ap_confirm_body = vec![1u8, 0u8];
    ap_confirm_body.extend_from_slice(&ap_confirm);
    supp.process_confirm(&ap_confirm_body).unwrap();

    let mut supp_confirm_body = vec![1u8, 0u8];
    supp_confirm_body.extend_from_slice(&supp_confirm);
    ap.process_confirm(&supp_confirm_body).unwrap();
}

#[test]
fn test_sae_different_passwords() {
    let mut rng = getrandom::SysRng;
    let (mac_sta, mac_ap) = test_macs();
    let ssid = "Test-WIFI";

    let mut supp =
        SaeAuth::new("12345678", ssid, mac_sta, mac_ap, true, false).unwrap();
    let (supp_scalar, supp_elem) = supp.build_commit(&mut rng).unwrap();

    let mut ap =
        SaeAuth::new("wrong_password", ssid, mac_ap, mac_sta, true, false)
            .unwrap();
    let (ap_scalar, ap_elem) = ap.build_commit(&mut rng).unwrap();

    supp.process_commit(&ap_scalar, &ap_elem).unwrap();
    ap.process_commit(&supp_scalar, &supp_elem).unwrap();

    assert_ne!(supp.pmk(), ap.pmk(), "PMK must differ");
}
