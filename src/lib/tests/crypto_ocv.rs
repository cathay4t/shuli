// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the OCV policy check. The OCI codec itself (deriving
//! an OCI from a frequency, KDE framing/parsing) is covered by the
//! `wl-nl80211` crate.

use wl_nl80211::{Ieee80211Oci, build_oci_kde};

use crate::{ErrorKind, crypto::ocv::verify_oci};

#[test]
fn verify_oci_rejects_missing_and_mismatched() {
    let err = verify_oci(&[], 2412).unwrap_err();
    assert_eq!(err.kind, ErrorKind::HandshakeFailed);
    assert!(err.to_string().contains("no OCI"));

    let wrong = build_oci_kde(Ieee80211Oci::from([81, 6, 0]));
    let err = verify_oci(&wrong, 2412).unwrap_err();
    assert_eq!(err.kind, ErrorKind::HandshakeFailed);
    assert!(err.to_string().contains("does not match"));

    let right = build_oci_kde(Ieee80211Oci::from([81, 1, 0]));
    assert!(verify_oci(&right, 2412).is_ok());
}
