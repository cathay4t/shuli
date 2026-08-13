// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the EAP-TLS method (Stage 3 M3): RFC 5216 framing
//! and an in-process TLS 1.3 handshake deriving the RFC 9190 MSK.

use std::{io::Cursor, sync::Arc};

use rustls::{ServerConfig, ServerConnection};

use crate::{
    ErrorKind,
    eap::{EapMethod, TYPE_TLS},
    eap_tls::{
        EAP_TLS_FLAG_START, EapTlsMethod, build_tls_message, cert_from_pem,
        client_config, key_from_pem, parse_tls_message,
    },
};

/// Self-signed test CA / server / client certificates (test fixtures
/// only - generated once with openssl, never used in production).
const CA_PEM: &str = include_str!("certs/ca.pem");
const SERVER_PEM: &str = include_str!("certs/server.pem");
const SERVER_KEY_PEM: &str = include_str!("certs/server.key");
const CLIENT_PEM: &str = include_str!("certs/client.pem");
const CLIENT_KEY_PEM: &str = include_str!("certs/client.key");
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

    // Empty data is the RFC 5216 ACK (zero-length message).
    assert!(build_tls_message(b"").is_empty());
    let (flags, parsed) = parse_tls_message(b"").unwrap();
    assert_eq!(flags, 0);
    assert!(parsed.is_empty());

    // L bit without the 4-octet length field is malformed.
    let err = parse_tls_message(&[0x80, 1, 2]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::HandshakeFailed);
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
