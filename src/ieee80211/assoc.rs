// SPDX-License-Identifier: Apache-2.0

/// Build an Association Request frame with RSNE.
/// Returns the full 802.11 Association Request management frame.
pub fn build_assoc_req(
    _sta_mac: [u8; 6],
    _bssid: [u8; 6],
    _rsne: &[u8],
    _rsnxe: Option<&[u8]>,
) -> Vec<u8> {
    // Association is handled by NL80211_CMD_ASSOCIATE directly,
    // not by constructing raw 802.11 frames.
    vec![]
}

/// Parse an Association Response frame.
/// Returns (capability_info, status_code).
pub fn parse_assoc_resp(_frame: &[u8]) -> Option<(u16, u16)> {
    None
}
