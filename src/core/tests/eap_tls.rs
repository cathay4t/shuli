// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the EAP-TLS method: RFC 5216 framing
//! and an in-process TLS 1.3 handshake deriving the RFC 9190 MSK.

use std::{io::Cursor, sync::Arc};

use rustls::{ServerConfig, ServerConnection};

use crate::{
    ErrorKind,
    eap::{
        CODE_REQUEST, CODE_RESPONSE, CODE_SUCCESS, EapAction, EapMethod,
        EapPacket, EapPeer, TYPE_IDENTITY, TYPE_TLS,
    },
    eap_tls::{
        EAP_TLS_FLAG_L, EAP_TLS_FLAG_M, EAP_TLS_FLAG_START, EapTlsMethod,
        build_tls_message, cert_from_pem, certs_from_pem, client_config,
        key_from_pem, parse_tls_message,
    },
};

/// Self-signed test CA / server / client certificates (test fixtures
/// only - generated once with openssl, never used in production).
const CA_PEM: &str = include_str!("../../../testdata/certs/ca.pem");
const SERVER_PEM: &str = include_str!("../../../testdata/certs/server.pem");
const SERVER_KEY_PEM: &str = include_str!("../../../testdata/certs/server.key");
const CLIENT_PEM: &str = include_str!("../../../testdata/certs/client.pem");
const CLIENT_KEY_PEM: &str = include_str!("../../../testdata/certs/client.key");
const SERVER_NAME: &str = "eap-tls.test";

fn client_method() -> EapTlsMethod {
    let ca = cert_from_pem(CA_PEM).expect("CA PEM");
    let cert = cert_from_pem(CLIENT_PEM).expect("client PEM");
    let key = key_from_pem(CLIENT_KEY_PEM).expect("client key PEM");
    let config = client_config(&[ca], vec![cert], key).expect("client config");
    EapTlsMethod::new(config, SERVER_NAME).expect("EAP-TLS method")
}

fn server_connection() -> ServerConnection {
    let cert = cert_from_pem(SERVER_PEM).expect("server PEM");
    let key = key_from_pem(SERVER_KEY_PEM).expect("server key PEM");
    let config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .expect("server config");
    ServerConnection::new(Arc::new(config)).expect("server connection")
}

#[test]
fn test_tls_message_framing_roundtrip() {
    let data = b"hello tls";
    let msg = build_tls_message(data);
    let (flags, parsed) = parse_tls_message(&msg).unwrap();
    assert_eq!(flags & 0x80, 0x80, "L bit set");
    assert_eq!(parsed, data);

    // Empty data is the RFC 5216 ACK: a one-octet flags field.
    assert_eq!(build_tls_message(b""), vec![0]);
    let (flags, parsed) = parse_tls_message(&[0]).unwrap();
    assert_eq!(flags, 0);
    assert!(parsed.is_empty());

    // L bit without the 4-octet length field is malformed.
    let err = parse_tls_message(&[0x80, 1, 2]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::HandshakeFailed);
}

#[test]
fn test_pem_chain_loads_every_certificate() {
    let chain = format!("{CA_PEM}\n{SERVER_PEM}");
    assert_eq!(certs_from_pem(&chain).unwrap().len(), 2);
    let bundle = format!("{CA_PEM}\n{SERVER_PEM}\n{CLIENT_PEM}");
    assert_eq!(certs_from_pem(&bundle).unwrap().len(), 3);
    assert!(certs_from_pem("not a pem").unwrap().is_empty());
}

#[test]
fn test_outgoing_tls_message_is_fragmented() {
    let mut client = client_method();
    client.set_max_fragment_len(10);
    let first = client
        .handle_request(1, &[EAP_TLS_FLAG_START])
        .expect("start");
    assert_ne!(first[0] & EAP_TLS_FLAG_L, 0, "first fragment has L");
    assert_ne!(first[0] & EAP_TLS_FLAG_M, 0, "first fragment has M");
    let total = u32::from_be_bytes(first[1..5].try_into().unwrap()) as usize;
    let mut data = first[5..].to_vec();
    assert!(data.len() <= 10);
    let mut flags = first[0];
    let mut rounds = 0;
    while flags & EAP_TLS_FLAG_M != 0 {
        let next = client.handle_request(1, &[0]).expect("next fragment");
        flags = next[0];
        if round_more(flags) {
            assert_eq!(flags & EAP_TLS_FLAG_L, 0, "L only on the first");
        }
        data.extend_from_slice(&next[1..]);
        rounds += 1;
        assert!(rounds < 100, "fragmentation did not finish");
    }
    assert_eq!(data.len(), total, "all announced bytes were sent");
}

fn round_more(flags: u8) -> bool {
    flags & EAP_TLS_FLAG_M != 0
}

#[test]
fn test_incoming_fragment_cannot_exceed_announced_length() {
    let mut client = client_method();
    client.handle_request(1, &[EAP_TLS_FLAG_START]).unwrap();
    let mut body = vec![EAP_TLS_FLAG_L, 0, 0, 0, 10];
    body.extend_from_slice(&[0u8; 8]);
    body[0] |= EAP_TLS_FLAG_M;
    let ack = client.handle_request(1, &body).unwrap();
    assert_eq!(ack, vec![0]);

    let mut overlong = vec![0u8; 4];
    overlong.extend_from_slice(&[0u8; 4]);
    let err = client.handle_request(1, &overlong).unwrap_err();
    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[test]
fn test_incoming_first_fragment_cannot_exceed_announced_length() {
    let mut client = client_method();
    client.handle_request(1, &[EAP_TLS_FLAG_START]).unwrap();
    let mut body = vec![EAP_TLS_FLAG_L, 0, 0, 0, 4];
    body.extend_from_slice(&[0u8; 8]);
    let err = client.handle_request(1, &body).unwrap_err();
    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[test]
fn test_eap_tls_rejects_data_before_start() {
    let mut client = client_method();
    let err = client.handle_request(1, &[0, 1, 2]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::HandshakeFailed);
    assert!(err.to_string().contains("before Start"));
}

/// Drive a full TLS 1.3 handshake over EAP-TLS messages between the
/// shuli peer method and a rustls server, then compare the MSK both
/// sides derive from the RFC 9190 exporter.
#[test]
fn test_eap_tls_handshake_derives_matching_msk() {
    let mut client = client_method();
    let mut server = server_connection();

    let mut server_tx = Vec::new();
    let mut first = true;
    let mut rounds = 0;
    loop {
        // Server -> client EAP-TLS message: Start on the first round,
        // then any TLS records the server produced.
        let request = if first {
            first = false;
            vec![EAP_TLS_FLAG_START]
        } else {
            build_tls_message(&server_tx)
        };
        server_tx.clear();

        let response = client.handle_request(1, &request).expect("client");
        let (_, tls_data) =
            parse_tls_message(&response).expect("parse response");
        if !tls_data.is_empty() {
            let used =
                server.read_tls(&mut Cursor::new(tls_data)).expect("read");
            assert_eq!(used, tls_data.len(), "server consumed all TLS data");
        }
        server.process_new_packets().expect("server process");
        server.write_tls(&mut server_tx).expect("server write");

        rounds += 1;
        assert!(rounds < 20, "TLS handshake did not converge");
        if !server.is_handshaking() && client.msk().is_some() {
            break;
        }
    }

    let client_msk = client.msk().expect("client MSK");
    let mut km = [0u8; 128];
    let km = server
        .export_keying_material(
            &mut km,
            b"EXPORTER_EAP_TLS_Key_Material",
            Some(&[TYPE_TLS]),
        )
        .expect("server exporter");
    assert_eq!(
        client_msk,
        km[..64],
        "peer and server must derive the same MSK"
    );
}

/// Sanity check that a mismatched CA rejects the server certificate.
#[test]
fn test_eap_tls_verifies_server_certificate() {
    // Use an empty root store: any server certificate must be rejected
    // by rustls when the handshake processes the Certificate message.
    let roots = rustls::RootCertStore::empty();
    let cert = cert_from_pem(CLIENT_PEM).expect("client PEM");
    let key = key_from_pem(CLIENT_KEY_PEM).expect("client key PEM");
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
    ])
    .with_root_certificates(roots)
    .with_client_auth_cert(vec![cert], key)
    .expect("client config");
    let mut client =
        EapTlsMethod::new(Arc::new(config), SERVER_NAME).expect("method");
    let mut server = server_connection();

    // Exchange until the client hits the certificate error or
    // completes (it must not complete).
    let mut server_tx = Vec::new();
    let mut first = true;
    let mut failed = false;
    for _ in 0..10 {
        let request = if first {
            first = false;
            vec![EAP_TLS_FLAG_START]
        } else {
            build_tls_message(&server_tx)
        };
        server_tx.clear();
        match client.handle_request(1, &request) {
            Err(e) => {
                failed = true;
                assert_eq!(e.kind, ErrorKind::HandshakeFailed);
                break;
            }
            Ok(response) => {
                let (_, data) =
                    parse_tls_message(&response).expect("parse response");
                if !data.is_empty() {
                    server.read_tls(&mut Cursor::new(data)).expect("read");
                }
                server.process_new_packets().expect("server process");
                server.write_tls(&mut server_tx).expect("server write");
            }
        }
    }
    assert!(
        failed,
        "client must reject a server certificate from an unknown CA"
    );
}

/// Drive the complete EAP flow through the EapPeer state machine with
/// the real EAP-TLS method: Identity, TLS handshake, MSK, Success.
#[test]
fn test_eap_peer_full_tls_exchange() {
    let mut peer = EapPeer::new("shuli-test".to_string());
    let ca = cert_from_pem(CA_PEM).expect("CA PEM");
    let cert = cert_from_pem(CLIENT_PEM).expect("client PEM");
    let key = key_from_pem(CLIENT_KEY_PEM).expect("client key PEM");
    let config = client_config(&[ca], vec![cert], key).expect("client config");
    peer.set_method(Box::new(
        EapTlsMethod::new(config, SERVER_NAME).expect("method"),
    ));
    let mut server = server_connection();

    // 1. Identity exchange.
    let request = EapPacket::build(CODE_REQUEST, 1, Some(TYPE_IDENTITY), b"");
    let action = peer
        .handle_packet(&EapPacket::parse(&request).unwrap())
        .unwrap();
    let EapAction::Respond(response) = action else {
        panic!("expected identity response");
    };
    let identity = EapPacket::parse(&response).unwrap();
    assert_eq!(identity.code, CODE_RESPONSE);
    assert_eq!(identity.type_, Some(TYPE_IDENTITY));
    assert_eq!(identity.body, b"shuli-test");

    // 2. EAP-TLS handshake.
    let mut server_tx = Vec::new();
    let mut first = true;
    let mut rounds = 0;
    loop {
        let tls_body = if first {
            first = false;
            vec![EAP_TLS_FLAG_START]
        } else {
            build_tls_message(&server_tx)
        };
        server_tx.clear();
        let request =
            EapPacket::build(CODE_REQUEST, 2, Some(TYPE_TLS), &tls_body);
        let action = peer
            .handle_packet(&EapPacket::parse(&request).unwrap())
            .unwrap();
        let EapAction::Respond(response) = action else {
            panic!("expected TLS response");
        };
        let response = EapPacket::parse(&response).unwrap();
        assert_eq!(response.type_, Some(TYPE_TLS));
        let (_, tls_data) =
            parse_tls_message(&response.body).expect("parse TLS body");
        if !tls_data.is_empty() {
            server.read_tls(&mut Cursor::new(tls_data)).expect("read");
        }
        server.process_new_packets().expect("server process");
        server.write_tls(&mut server_tx).expect("server write");

        rounds += 1;
        assert!(rounds < 20, "TLS handshake did not converge");
        if !server.is_handshaking() && peer.msk().is_some() {
            break;
        }
    }

    // 3. EAP-Success authorizes the port.
    let success = EapPacket::build(CODE_SUCCESS, 3, None, b"");
    let action = peer
        .handle_packet(&EapPacket::parse(&success).unwrap())
        .unwrap();
    assert_eq!(action, EapAction::Success);
    assert!(
        peer.msk().expect("MSK") != [0u8; 64],
        "MSK must be non-zero"
    );
}

#[test]
fn test_eap_tls_handshake_with_fragmented_server_flights() {
    let mut client = client_method();
    let mut server = server_connection();

    let mut server_tx = Vec::new();
    let mut first = true;
    let mut rounds = 0;
    loop {
        let request = if first {
            first = false;
            vec![EAP_TLS_FLAG_START]
        } else {
            build_tls_message(&server_tx)
        };
        server_tx.clear();

        let mut next_request = request;
        loop {
            let response =
                client.handle_request(1, &next_request).expect("client");
            let (_, tls_data) =
                parse_tls_message(&response).expect("parse response");
            if !tls_data.is_empty() {
                let used =
                    server.read_tls(&mut Cursor::new(tls_data)).expect("read");
                assert_eq!(
                    used,
                    tls_data.len(),
                    "server consumed all TLS data"
                );
            }
            server.process_new_packets().expect("server process");
            server.write_tls(&mut server_tx).expect("server write");
            if tls_data.is_empty() || server_tx.is_empty() {
                break;
            }
            next_request = vec![0];
        }

        // Fragment the server flight into 5-byte EAP-TLS messages.
        let flight = std::mem::take(&mut server_tx);
        if !flight.is_empty() {
            let total = flight.len();
            let mut offset = 0;
            while offset < total {
                let take = (total - offset).min(5);
                let mut body = Vec::new();
                let more = offset + take < total;
                body.push(if offset == 0 { EAP_TLS_FLAG_L } else { 0 });
                if offset == 0 {
                    body.extend_from_slice(&(total as u32).to_be_bytes());
                }
                if more {
                    body[0] |= EAP_TLS_FLAG_M;
                }
                body.extend_from_slice(&flight[offset..offset + take]);
                let response =
                    client.handle_request(1, &body).expect("fragment");
                if more {
                    assert_eq!(response, vec![0], "fragment ACK");
                } else {
                    let (_, tls_data) =
                        parse_tls_message(&response).expect("parse final");
                    if !tls_data.is_empty() {
                        server
                            .read_tls(&mut Cursor::new(tls_data))
                            .expect("read");
                    }
                    server.process_new_packets().expect("process");
                    server.write_tls(&mut server_tx).expect("write");
                }
                offset += take;
            }
        }

        rounds += 1;
        assert!(rounds < 30, "TLS handshake did not converge");
        if !server.is_handshaking() && client.msk().is_some() {
            break;
        }
    }

    let client_msk = client.msk().expect("client MSK");
    let mut km = [0u8; 128];
    let km = server
        .export_keying_material(
            &mut km,
            b"EXPORTER_EAP_TLS_Key_Material",
            Some(&[TYPE_TLS]),
        )
        .expect("server exporter");
    assert_eq!(&client_msk[..], &km[..64]);
}
