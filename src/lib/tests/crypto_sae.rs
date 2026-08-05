// SPDX-License-Identifier: Apache-2.0

use p256::{
    AffinePoint,
    elliptic_curve::{Group, point::AffineCoordinates},
};

use crate::crypto::sae::{SaeAuth, compute_pwe_h2e};

fn affine_x_bytes(point: &AffinePoint) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(point.x().as_ref());
    bytes
}

#[test]
fn test_pwe_derivation() {
    let mac_sta = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mac_ap = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
    let pwe = compute_pwe_h2e("12345678", "Test-WIFI", &mac_sta, &mac_ap);
    assert!(pwe.is_ok());
    assert!(!bool::from(pwe.unwrap().is_identity()));
}

#[test]
fn test_full_sae_exchange() {
    let mut rng = getrandom::SysRng;
    let mac_sta = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mac_ap = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
    let password = "12345678";
    let ssid = "Test-WIFI";

    let mut supp = SaeAuth::new(password, ssid, mac_sta, mac_ap).unwrap();
    let (supp_scalar, supp_elem) = supp.build_commit(&mut rng).unwrap();

    let mut ap = SaeAuth::new(password, ssid, mac_ap, mac_sta).unwrap();
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
    let mac_sta = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mac_ap = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
    let ssid = "Test-WIFI";

    let mut supp = SaeAuth::new("12345678", ssid, mac_sta, mac_ap).unwrap();
    let (supp_scalar, supp_elem) = supp.build_commit(&mut rng).unwrap();

    let mut ap = SaeAuth::new("wrong_password", ssid, mac_ap, mac_sta).unwrap();
    let (ap_scalar, ap_elem) = ap.build_commit(&mut rng).unwrap();

    supp.process_commit(&ap_scalar, &ap_elem).unwrap();
    ap.process_commit(&supp_scalar, &supp_elem).unwrap();

    assert_ne!(supp.pmk(), ap.pmk(), "PMK must differ");
}
