// SPDX-License-Identifier: Apache-2.0

//! Operating Channel Validation (OCV) for non-FT AKMs (Stage 3 M10).
//!
//! Basic supplicant support: when enabled, the STA advertises the
//! OCVC RSN capability, includes its Operating Channel Information
//! (OCI) as a KDE in 4-way Message 2, and verifies the AP's OCI in
//! Message 3 and group-key handshakes against the BSS frequency.
//! Channel width/secondary-channel checking is out of scope for now
//! (a 20 MHz STA assumption), matching the plan's non-FT scope.

use crate::{ErrorKind, WifiError};

/// OCI payload length: operating class(1) || channel(1) || segment(1).
pub(crate) const OCI_LEN: usize = 3;

/// Build the OCI KDE carried in EAPOL-Key key data: element `DD`,
/// OUI 00:0F:AC, type 13 (RSN_KEY_DATA_OCI), then the 3 OCI octets.
pub(crate) fn build_oci_kde(oci: &[u8; OCI_LEN]) -> Vec<u8> {
    let mut kde = vec![0xDD, 4 + OCI_LEN as u8, 0x00, 0x0F, 0xAC, 13];
    kde.extend_from_slice(oci);
    kde
}

/// Derive the OCI (operating class, channel, segment 0) for the STA's
/// BSS frequency.  20 MHz primary-channel mapping only: 2.4 GHz uses
/// operating class 81 (channels 1-13), 5 GHz uses the global operating
/// classes 115-118 by channel range.
pub(crate) fn oci_from_freq(freq_mhz: u32) -> Option<[u8; OCI_LEN]> {
    if (2412..=2472).contains(&freq_mhz) && (freq_mhz - 2407).is_multiple_of(5)
    {
        let channel = ((freq_mhz - 2407) / 5) as u8;
        return Some([81, channel, 0]);
    }
    if freq_mhz >= 5000 && (freq_mhz - 5000).is_multiple_of(5) {
        let channel = ((freq_mhz - 5000) / 5) as u8;
        let op_class = match channel {
            36..=48 => 115,
            52..=64 => 116,
            100..=144 => 117,
            149..=177 => 118,
            _ => return None,
        };
        return Some([op_class, channel, 0]);
    }
    None
}

/// Verify the peer's OCI against the BSS frequency: the OCI channel
/// must map to the same primary frequency (segment and channel width
/// are not checked - 20 MHz STA assumption).
pub(crate) fn oci_matches_freq(oci: &[u8; OCI_LEN], freq_mhz: u32) -> bool {
    let Some(expected) = oci_from_freq(freq_mhz) else {
        return false;
    };
    oci[1] == expected[1]
}

/// Parse an OCI KDE (OUI 00:0F:AC, type 13) from key data; returns the
/// 3 OCI octets.
pub(crate) fn parse_oci_kde(key_data: &[u8]) -> Option<[u8; OCI_LEN]> {
    let mut pos = 0;
    while pos + 2 <= key_data.len() {
        let len = key_data[pos + 1] as usize;
        let body_start = pos + 2;
        let body_end = body_start + len;
        if body_end > key_data.len() {
            break;
        }
        let body = &key_data[body_start..body_end];
        if key_data[pos] == 0xDD
            && body.len() >= 4 + OCI_LEN
            && body[..3] == [0x00, 0x0F, 0xAC]
            && body[3] == 13
        {
            return Some([body[4], body[5], body[6]]);
        }
        pos = body_end;
    }
    None
}

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
    if !oci_matches_freq(&oci, freq_mhz) {
        return Err(WifiError::new(
            ErrorKind::HandshakeFailed,
            format!("OCV: AP OCI {oci:02x?} does not match freq {freq_mhz}"),
        ));
    }
    Ok(())
}
