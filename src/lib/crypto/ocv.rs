// SPDX-License-Identifier: Apache-2.0

//! Operating Channel Validation (OCV) for non-FT AKMs.
//!
//! Basic supplicant support: when enabled, the STA advertises the
//! OCVC RSN capability, includes its Operating Channel Information
//! (OCI) as a KDE in 4-way Message 2, and verifies the AP's OCI in
//! Message 3 and group-key handshakes against the BSS frequency.
//! Channel width/secondary-channel checking is out of scope for now
//! (a 20 MHz STA assumption), matching the plan's non-FT scope.
//!
//! The OCI codec itself lives in `wl_nl80211`; this module keeps only
//! the policy check on top of it.

use wl_nl80211::parse_oci_kde;

use crate::{ErrorKind, WifiError};

/// Validate an OCI KDE against the expected frequency; returns an error
/// when OCV is enabled but the OCI is missing or mismatched.
pub(crate) fn verify_oci(
    key_data: &[u8],
    freq_mhz: u32,
) -> Result<(), WifiError> {
    let Some(oci) = parse_oci_kde(key_data) else {
        return Err(WifiError::new(
            ErrorKind::HandshakeFailed,
            "OCV: AP Message 3 carries no OCI KDE",
        ));
    };
    if !oci.matches_freq(freq_mhz) {
        return Err(WifiError::new(
            ErrorKind::HandshakeFailed,
            format!(
                "OCV: AP OCI {:02x?} does not match freq {freq_mhz}",
                oci.to_bytes()
            ),
        ));
    }
    Ok(())
}
