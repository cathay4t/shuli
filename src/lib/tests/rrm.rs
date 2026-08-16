// SPDX-License-Identifier: Apache-2.0

use crate::ieee80211::rrm::{
    NEIGHBOR_REPORT_RESPONSE_ACTION, RRM_ACTION_CATEGORY,
    build_neighbor_report_request, parse_neighbor_report_response,
};

#[test]
fn build_neighbor_report_request_layout() {
    let body = build_neighbor_report_request(0x2a);
    assert_eq!(body, vec![RRM_ACTION_CATEGORY, 4, 0x2a]);
}

#[test]
fn parse_neighbor_report_response_entries() {
    // Dialog token + one 13-octet element (hostapd style).
    let mut body = vec![0x2a];
    body.push(52);
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

#[test]
fn response_action_number() {
    assert_eq!(NEIGHBOR_REPORT_RESPONSE_ACTION, 5);
    // iwd registers the RRM response with the same category/action
    // prefix, so a frame delivered to us starts with these bytes.
    assert_eq!(
        [RRM_ACTION_CATEGORY, NEIGHBOR_REPORT_RESPONSE_ACTION],
        [5, 5]
    );
}
