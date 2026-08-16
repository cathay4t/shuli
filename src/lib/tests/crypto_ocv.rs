// SPDX-License-Identifier: Apache-2.0

//! Unit tests for OCV: OCI derivation, KDE framing and
//! verification.

use crate::{
    ErrorKind,
    crypto::ocv::{
        build_oci_kde, oci_from_freq, oci_matches_freq, parse_oci_kde,
        verify_oci,
    },
};

#[test]
fn oci_from_freq_maps_channels_and_op_classes() {
    assert_eq!(oci_from_freq(2412), Some([81, 1, 0]));
    assert_eq!(oci_from_freq(2462), Some([81, 11, 0]));
    assert_eq!(oci_from_freq(5180), Some([115, 36, 0]));
    assert_eq!(oci_from_freq(5220), Some([115, 44, 0]));
    assert_eq!(oci_from_freq(5745), Some([118, 149, 0]));
    assert_eq!(oci_from_freq(2410), None);
    assert_eq!(oci_from_freq(5000), None);
}

#[test]
fn oci_matches_primary_frequency() {
    assert!(oci_matches_freq(&[81, 1, 0], 2412));
    assert!(!oci_matches_freq(&[81, 6, 0], 2412));
    assert!(oci_matches_freq(&[115, 36, 0], 5180));
    assert!(!oci_matches_freq(&[81, 1, 0], 5180));
}

#[test]
fn oci_kde_roundtrip() {
    let oci = [81, 1, 0];
    let kde = build_oci_kde(&oci);
    assert_eq!(&kde[..6], &[0xDD, 7, 0x00, 0x0F, 0xAC, 13]);
    assert_eq!(parse_oci_kde(&kde), Some(oci));
}

#[test]
fn verify_oci_rejects_missing_and_mismatched() {
    let err = verify_oci(&[], 2412).unwrap_err();
    assert_eq!(err.kind, ErrorKind::HandshakeFailed);
    assert!(err.to_string().contains("no OCI"));

    let wrong = build_oci_kde(&[81, 6, 0]);
    let err = verify_oci(&wrong, 2412).unwrap_err();
    assert_eq!(err.kind, ErrorKind::HandshakeFailed);
    assert!(err.to_string().contains("does not match"));

    let right = build_oci_kde(&[81, 1, 0]);
    assert!(verify_oci(&right, 2412).is_ok());
}
