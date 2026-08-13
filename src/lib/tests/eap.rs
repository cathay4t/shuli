// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the EAP transport (Stage 3 M2): EAP packet codec,
//! EAPOL type-0 framing, and the peer state machine.

use crate::{
    ErrorKind, WifiError,
    eap::{
        CODE_FAILURE, CODE_REQUEST, CODE_RESPONSE, CODE_SUCCESS, EapAction,
        EapMethod, EapPacket, EapPeer, EapState, MSK_LEN, TYPE_IDENTITY,
        TYPE_NAK, TYPE_NOTIFICATION, TYPE_TLS,
    },
    ieee80211::eapol::{build_eapol_eap_frame, parse_eapol_eap_frame},
};

#[test]
fn test_eap_packet_roundtrip() {
    // Request and Response carry a Type.
    for (code, type_, body) in [
        (CODE_REQUEST, Some(TYPE_IDENTITY), b"".to_vec()),
        (CODE_RESPONSE, Some(TYPE_TLS), vec![1, 2, 3]),
    ] {
        let pdu = EapPacket::build(code, 7, type_, &body);
        let parsed = EapPacket::parse(&pdu).expect("parse");
        assert_eq!(
            parsed,
            EapPacket {
                code,
                identifier: 7,
                type_,
                body,
            }
        );
    }

    // Success / Failure carry no Type.
    for code in [CODE_SUCCESS, CODE_FAILURE] {
        let pdu = EapPacket::build(code, 3, None, b"");
        let parsed = EapPacket::parse(&pdu).expect("parse");
        assert_eq!(parsed.code, code);
        assert_eq!(parsed.type_, None);
        assert!(parsed.body.is_empty());
        assert_eq!(parsed.is_success(), code == CODE_SUCCESS);
        assert_eq!(parsed.is_failure(), code == CODE_FAILURE);
    }
}

#[test]
fn test_eap_packet_parse_rejects_bad_input() {
    // Too short.
    assert!(EapPacket::parse(&[1, 2]).is_none());
    // Length longer than the buffer.
    assert!(EapPacket::parse(&[1, 2, 0, 16, 1]).is_none());
    // Unknown code.
    assert!(EapPacket::parse(&[9, 1, 0, 4]).is_none());
    // Request without a Type field.
    assert!(EapPacket::parse(&[CODE_REQUEST, 1, 0, 4]).is_none());
}

#[test]
fn test_eapol_eap_frame_roundtrip() {
    let eap = EapPacket::build(CODE_REQUEST, 1, Some(TYPE_IDENTITY), b"");
    let frame = build_eapol_eap_frame(&eap);
    assert_eq!(frame[0], 2, "EAPOL version");
    assert_eq!(frame[1], 0, "EAPOL type 0 = EAP");
    let payload = parse_eapol_eap_frame(&frame).expect("parse");
    assert_eq!(payload, eap.as_slice());

    // Non-EAP EAPOL and truncated frames are rejected.
    assert!(parse_eapol_eap_frame(&[2, 3, 0, 0]).is_none());
    assert!(parse_eapol_eap_frame(&[2, 0, 0, 16, 1]).is_none());
}

#[test]
fn test_peer_identity_exchange() {
    let mut peer = EapPeer::new("user@example.org".to_string());
    let request = EapPacket::build(CODE_REQUEST, 1, Some(TYPE_IDENTITY), b"");
    let action = peer.handle_packet(&EapPacket::parse(&request).unwrap());
    let EapAction::Respond(response) = action.unwrap() else {
        panic!("expected a response");
    };
    let parsed = EapPacket::parse(&response).unwrap();
    assert_eq!(parsed.code, CODE_RESPONSE);
    assert_eq!(parsed.identifier, 1);
    assert_eq!(parsed.type_, Some(TYPE_IDENTITY));
    assert_eq!(parsed.body, b"user@example.org");
    assert_eq!(peer.state(), EapState::Identity);
}

#[test]
fn test_peer_notification_acknowledged() {
    let mut peer = EapPeer::new("user".to_string());
    let request = EapPacket::build(
        CODE_REQUEST,
        2,
        Some(TYPE_NOTIFICATION),
        b"Password will expire",
    );
    let action = peer
        .handle_packet(&EapPacket::parse(&request).unwrap())
        .unwrap();
    let EapAction::Respond(response) = action else {
        panic!("expected a response");
    };
    let parsed = EapPacket::parse(&response).unwrap();
    assert_eq!(parsed.type_, Some(TYPE_NOTIFICATION));
    assert!(parsed.body.is_empty());
}

#[test]
fn test_peer_nak_unsupported_method() {
    let mut peer = EapPeer::new("user".to_string());
    peer.set_supported_types(vec![TYPE_TLS]);
    // No method installed: EAP-TLS is answered with a Nak offering
    // the supported types.
    let request = EapPacket::build(CODE_REQUEST, 3, Some(TYPE_TLS), b"");
    let action = peer.handle_packet(&EapPacket::parse(&request).unwrap());
    let EapAction::Respond(response) = action.unwrap() else {
        panic!("expected a response");
    };
    let parsed = EapPacket::parse(&response).unwrap();
    assert_eq!(parsed.type_, Some(TYPE_NAK));
    assert_eq!(parsed.body, vec![TYPE_TLS]);
    assert_eq!(peer.state(), EapState::Method);
}

/// A minimal EAP-TLS stand-in for state machine tests; the real
/// rustls-backed method lands in M3.
struct FakeMethod {
    done: bool,
}

impl EapMethod for FakeMethod {
    fn method_type(&self) -> u8 {
        TYPE_TLS
    }

    fn handle_request(
        &mut self,
        identifier: u8,
        body: &[u8],
    ) -> Result<Vec<u8>, WifiError> {
        self.done = true;
        let mut response = vec![identifier];
        response.extend_from_slice(body);
        Ok(response)
    }

    fn msk(&self) -> Option<[u8; MSK_LEN]> {
        self.done.then_some([0x5A; MSK_LEN])
    }
}

#[test]
fn test_peer_delegates_to_method() {
    let mut peer = EapPeer::new("user".to_string());
    peer.set_method(Box::new(FakeMethod { done: false }));
    let request =
        EapPacket::build(CODE_REQUEST, 4, Some(TYPE_TLS), b"tls-data");
    let action = peer.handle_packet(&EapPacket::parse(&request).unwrap());
    let EapAction::Respond(response) = action.unwrap() else {
        panic!("expected a response");
    };
    let parsed = EapPacket::parse(&response).unwrap();
    assert_eq!(parsed.code, CODE_RESPONSE);
    assert_eq!(parsed.identifier, 4);
    assert_eq!(parsed.type_, Some(TYPE_TLS));
    assert_eq!(
        parsed.body.as_slice(),
        &[4, b't', b'l', b's', b'-', b'd', b'a', b't', b'a']
    );
    assert_eq!(peer.state(), EapState::Method);
    assert_eq!(peer.msk(), Some([0x5A; MSK_LEN]));
}

#[test]
fn test_peer_success_and_failure() {
    let mut peer = EapPeer::new("user".to_string());
    let success = EapPacket::build(CODE_SUCCESS, 5, None, b"");
    let action = peer
        .handle_packet(&EapPacket::parse(&success).unwrap())
        .unwrap();
    assert_eq!(action, EapAction::Success);
    assert_eq!(peer.state(), EapState::Success);

    let mut peer = EapPeer::new("user".to_string());
    let failure = EapPacket::build(CODE_FAILURE, 5, None, b"");
    let action = peer
        .handle_packet(&EapPacket::parse(&failure).unwrap())
        .unwrap();
    assert_eq!(action, EapAction::Failure);
    assert_eq!(peer.state(), EapState::Failure);
}

#[test]
fn test_peer_ignores_authenticator_responses() {
    let mut peer = EapPeer::new("user".to_string());
    let response =
        EapPacket::build(CODE_RESPONSE, 1, Some(TYPE_IDENTITY), b"nobody");
    let action = peer
        .handle_packet(&EapPacket::parse(&response).unwrap())
        .unwrap();
    assert_eq!(action, EapAction::Wait);
    assert_eq!(peer.state(), EapState::Initial);
}

#[test]
fn test_peer_rejects_request_without_type() {
    let mut peer = EapPeer::new("user".to_string());
    let malformed = EapPacket {
        code: CODE_REQUEST,
        identifier: 1,
        type_: None,
        body: Vec::new(),
    };
    let err = peer.handle_packet(&malformed);
    assert_eq!(err.unwrap_err().kind, ErrorKind::HandshakeFailed);
}
