// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the OWE Diffie-Hellman Parameter element parser.

use crate::crypto::owe::find_owe_dh_element;

/// Build an IE buffer from (id, body) pairs.
fn ies(parts: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (id, body) in parts {
        out.push(*id);
        out.push(body.len() as u8);
        out.extend_from_slice(body);
    }
    out
}

/// The DH Parameter element (Element ID 255, Element ID Extension 32)
/// yields everything after the extension octet: the Group and the
/// public key.
#[test]
fn find_owe_dh_element_skips_element_header_and_extension() {
    let dh = [32, 19, 0, 0xAA, 0xBB];
    let buf = ies(&[(48, &[0x01, 0x00]), (255, &dh)]);
    assert_eq!(find_owe_dh_element(&buf), Some(&[19, 0, 0xAA, 0xBB][..]));
}

/// Elements that are not the DH Parameter element are skipped, and the
/// DH Parameter element is found wherever it sits in the buffer.
#[test]
fn find_owe_dh_element_skips_other_elements() {
    assert_eq!(find_owe_dh_element(&[]), None);
    // Another Element ID 255 element: HE Capabilities (extension 35).
    let he = ies(&[(255, &[35, 0x11])]);
    assert_eq!(find_owe_dh_element(&he), None);
    // A vendor element, and an extensible element without the Element
    // ID Extension octet.
    assert_eq!(find_owe_dh_element(&ies(&[(221, &[0xAA, 0xBB])])), None);
    assert_eq!(find_owe_dh_element(&ies(&[(255, &[])])), None);

    let mut buf = he;
    buf.extend_from_slice(&ies(&[(255, &[32, 19, 0x01])]));
    assert_eq!(find_owe_dh_element(&buf), Some(&[19, 0x01][..]));
}

/// A trailing element whose Length field runs past the buffer ends the
/// parse; a DH Parameter element before it is still returned.
#[test]
fn find_owe_dh_element_ignores_truncated_tail() {
    let mut buf = ies(&[(255, &[32, 19, 0xAA])]);
    buf.extend_from_slice(&[255, 8, 32]);
    assert_eq!(find_owe_dh_element(&buf), Some(&[19, 0xAA][..]));
    assert_eq!(find_owe_dh_element(&[255, 8, 32]), None);
}
