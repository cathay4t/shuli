// SPDX-License-Identifier: Apache-2.0

//! BSS Transition Management (IEEE 802.11v / 802.11-2020 §11.11.9).
//!
//! The AP asks the STA to move to another BSS with a BTM Request; the
//! STA answers with a BTM Response and, when accepting, roams to the
//! chosen candidate.

use crate::ETH_ALEN;

/// WNM action category (802.11-2020 Table 9-46).
pub const WNM_ACTION_CATEGORY: u8 = 10;
/// BSS Transition Management Request (802.11-2020 Table 9-459; note:
/// action 6 is the BTM *Query*).
pub const BTM_REQUEST_ACTION: u8 = 7;
/// BSS Transition Management Response (802.11-2020 Table 9-459).
pub const BTM_RESPONSE_ACTION: u8 = 8;

/// Request Mode bits (802.11-2020 Table 9-459).
const REQ_MODE_PREF_CAND_LIST: u8 = 1 << 0;
const REQ_MODE_BSS_TERMINATION: u8 = 1 << 3;
const REQ_MODE_ESS_DISASSOC_IMMINENT: u8 = 1 << 4;

/// Neighbor Report element ID carrying BTM candidate entries
/// (802.11-2020 §9.4.2.21).
const IE_ID_NEIGHBOR_REPORT: u8 = 52;

/// BTM Response status codes (802.11-2020 Table 9-461).
pub const BTM_STATUS_ACCEPT: u8 = 0;
pub const BTM_STATUS_REJECT_UNSPECIFIED: u8 = 1;

/// One BSS Transition Management candidate: the fields of its Neighbor
/// Report element body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BtmCandidate {
    pub bssid: [u8; ETH_ALEN],
    pub bssid_info: u32,
    pub operating_class: u8,
    pub channel: u8,
    pub phy_type: u8,
    /// Preference octet (present when the request carries a preferred
    /// candidate list; higher = preferred).
    pub preference: Option<u8>,
}

/// A parsed BSS Transition Management Request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BtmRequest {
    pub dialog_token: u8,
    pub preferred_candidates: bool,
    pub disassoc_timer: u16,
    pub validity_interval: u8,
    pub candidates: Vec<BtmCandidate>,
}

/// Parse a BTM Request from the action frame body (after the category
/// and action octets). Layout: Dialog Token (1) || Request Mode (1) ||
/// Disassociation Timer (2 LE) || Validity Interval (1) || optional
/// BSS Termination Duration (12) || optional Session Information URL
/// (length-prefixed) || candidate list (Neighbor Report elements).
pub fn parse_btm_request(body: &[u8]) -> Option<BtmRequest> {
    if body.len() < 5 {
        return None;
    }
    let dialog_token = body[0];
    let req_mode = body[1];
    let disassoc_timer = u16::from_le_bytes([body[2], body[3]]);
    let validity_interval = body[4];
    let mut pos = 5;

    if req_mode & REQ_MODE_BSS_TERMINATION != 0 {
        // Subelement: ID(1) + length(1) + 10 octets of data.
        pos += 12;
    }
    if req_mode & REQ_MODE_ESS_DISASSOC_IMMINENT != 0 {
        if body.len() < pos + 1 {
            return None;
        }
        let url_len = body[pos] as usize;
        pos += 1 + url_len;
    }

    let mut candidates = Vec::new();
    while pos + 2 <= body.len() {
        let id = body[pos];
        let len = body[pos + 1] as usize;
        let start = pos + 2;
        if start + len > body.len() {
            break;
        }
        let elem = &body[start..start + len];
        if id == IE_ID_NEIGHBOR_REPORT && elem.len() >= 13 {
            candidates.push(BtmCandidate {
                bssid: elem[0..6].try_into().unwrap(),
                bssid_info: u32::from_le_bytes([
                    elem[6], elem[7], elem[8], elem[9],
                ]),
                operating_class: elem[10],
                channel: elem[11],
                phy_type: elem[12],
                // The preference octet trails the mandatory part when
                // the AP sends preferred candidates.
                preference: elem.get(13).copied(),
            });
        }
        pos = start + len;
    }

    Some(BtmRequest {
        dialog_token,
        preferred_candidates: req_mode & REQ_MODE_PREF_CAND_LIST != 0,
        disassoc_timer,
        validity_interval,
        candidates,
    })
}

/// Build a BTM Response action frame (category + action + body):
/// Dialog Token (1) || Status Code (1) || BSS Termination Delay (1) ||
/// Target BSSID (6). The target BSSID is the accepted candidate; zero
/// bytes reject without naming a BSS.
pub fn build_btm_response(
    dialog_token: u8,
    status: u8,
    target_bssid: [u8; ETH_ALEN],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + 9);
    frame.push(WNM_ACTION_CATEGORY);
    frame.push(BTM_RESPONSE_ACTION);
    frame.push(dialog_token);
    frame.push(status);
    frame.push(0); // BSS Termination Delay (unused)
    frame.extend_from_slice(&target_bssid);
    frame
}
