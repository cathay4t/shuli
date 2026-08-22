// SPDX-License-Identifier: Apache-2.0

//! Radio Resource Measurement (RRM, 802.11k) action frames: the
//! Neighbor Report Request / Response used to narrow a signal-triggered
//! roam scan to the channels the connected AP considers part of the ESS.
//!
//! Action numbers follow 802.11-2016 Table 9-43: 4 is the Neighbor
//! Report Request, 5 the Neighbor Report Response (iwd uses the same
//! numbers in `src/netdev.c`).

use crate::ETH_ALEN;

/// Radio Measurement action category (802.11-2016 Table 9-42).
pub const RRM_ACTION_CATEGORY: u8 = 5;
/// Radio Measurement action: Neighbor Report Request.
pub const NEIGHBOR_REPORT_REQUEST_ACTION: u8 = 4;
/// Radio Measurement action: Neighbor Report Response.
pub const NEIGHBOR_REPORT_RESPONSE_ACTION: u8 = 5;

/// Neighbor Report element ID.
const IE_ID_NEIGHBOR_REPORT: u8 = 52;

/// One Neighbor Report element (802.11k): BSSID + BSSID Information +
/// Operating Class + Channel Number + PHY type, followed by optional
/// subelements. This is the format hostapd and iwd use (the minimum
/// element payload is 13 octets).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NeighborReportEntry {
    pub bssid: [u8; ETH_ALEN],
    pub bssid_info: u32,
    pub operating_class: u8,
    pub channel: u8,
    pub phy_type: u8,
}

/// A parsed Neighbor Report Response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NeighborReportResponse {
    pub dialog_token: u8,
    pub entries: Vec<NeighborReportEntry>,
}

/// Build a Neighbor Report Request action frame body (category, action,
/// and dialog token). iwd sends just the dialog token; a non-zero token
/// is required.
pub fn build_neighbor_report_request(dialog_token: u8) -> Vec<u8> {
    vec![
        RRM_ACTION_CATEGORY,
        NEIGHBOR_REPORT_REQUEST_ACTION,
        dialog_token,
    ]
}

/// Parse a Neighbor Report Response from the action frame body (after
/// the category and action octets): dialog token followed by Neighbor
/// Report elements.
pub fn parse_neighbor_report_response(
    body: &[u8],
) -> Option<NeighborReportResponse> {
    let dialog_token = *body.first()?;
    let mut entries = Vec::new();
    let mut pos = 1;
    while pos + 2 <= body.len() {
        let id = body[pos];
        let len = body[pos + 1] as usize;
        let start = pos + 2;
        if start + len > body.len() {
            break;
        }
        let elem = &body[start..start + len];
        if id == IE_ID_NEIGHBOR_REPORT && elem.len() >= 13 {
            entries.push(NeighborReportEntry {
                bssid: elem[0..6].try_into().unwrap(),
                bssid_info: u32::from_le_bytes([
                    elem[6], elem[7], elem[8], elem[9],
                ]),
                operating_class: elem[10],
                channel: elem[11],
                phy_type: elem[12],
            });
        }
        pos = start + len;
    }
    Some(NeighborReportResponse {
        dialog_token,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_neighbor_report_request_layout() {
        assert_eq!(build_neighbor_report_request(0x2a), vec![5, 4, 0x2a]);
    }

    #[test]
    fn parse_neighbor_report_response_entries() {
        // Dialog token + one 13-octet element (hostapd style).
        let mut body = vec![0x2a];
        body.push(IE_ID_NEIGHBOR_REPORT);
        body.push(13);
        body.extend_from_slice(&[0x02, 0, 0, 0, 0x03, 0]); // BSSID
        body.extend_from_slice(&[1, 0, 0, 0]); // BSSID info
        body.extend_from_slice(&[81, 6, 7]); // op class, channel, PHY
        // Optional wide-bandwidth subelement: id 6, len 3, payload.
        body.extend_from_slice(&[6, 3, 1, 2, 3]);

        let resp = parse_neighbor_report_response(&body).expect("parse");
        assert_eq!(resp.dialog_token, 0x2a);
        assert_eq!(resp.entries.len(), 1);
        let entry = &resp.entries[0];
        assert_eq!(entry.bssid, [0x02, 0, 0, 0, 0x03, 0]);
        assert_eq!(entry.bssid_info, 1);
        assert_eq!(entry.operating_class, 81);
        assert_eq!(entry.channel, 6);
        assert_eq!(entry.phy_type, 7);
    }

    #[test]
    fn parse_neighbor_report_response_skips_foreign_elements() {
        // SSID element (id 0) plus a too-short neighbor element (len 5).
        let body = vec![1, 0, 3, b'a', b'b', b'c', 52, 5, 1, 2, 3, 4, 5];
        let resp = parse_neighbor_report_response(&body).expect("parse");
        assert_eq!(resp.dialog_token, 1);
        assert!(resp.entries.is_empty());
    }

    #[test]
    fn parse_neighbor_report_response_empty() {
        assert!(parse_neighbor_report_response(&[]).is_none());
    }
}
