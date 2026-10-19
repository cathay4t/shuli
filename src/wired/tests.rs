// SPDX-License-Identifier: Apache-2.0

//! Integration test for wired 802.1X (EAP-TLS) against an in-process
//! EAP-TLS authenticator over a veth pair.

use std::{io::Cursor, os::fd::AsRawFd, sync::Arc};

use rustls::{ServerConfig, ServerConnection};
use shuli_core::{
    EapConfig,
    eap::{CODE_REQUEST, CODE_SUCCESS, EapPacket, TYPE_IDENTITY, TYPE_TLS},
    eap_tls::{
        EAP_TLS_FLAG_START, build_tls_message, cert_from_pem, key_from_pem,
        parse_tls_message,
    },
    eapol::EapolEapFrame,
};

use crate::{
    WiredClient, WiredState,
    eap::{open_eapol_socket, recv_eapol_frame, send_eapol_frame},
};

const CERT_DIR: &str = "/tmp/shuli_rs_wired_certs";

/// Initialise `env_logger` once per test process when `RUST_LOG` is set.
fn init_logger() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("trace"),
    )
    .try_init();
}

/// Whether the test process runs with root privileges (needed to create
/// the veth pair and raw EAPOL sockets).
fn is_root() -> bool {
    std::process::Command::new("id")
        .args(["-u"])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
        .unwrap_or(false)
}

fn sh_ok(cmd: &str) {
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .output()
        .expect("spawn shell");
    assert!(
        out.status.success(),
        "command failed ({cmd}) status={:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn sh_allow_fail(cmd: &str) {
    let _ = std::process::Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .output();
}

/// Wired test environment: a veth pair in the default netns.
struct WiredVethEnv;

impl WiredVethEnv {
    fn setup() -> Self {
        sh_allow_fail("ip link del veth0");
        sh_ok("ip link add veth0 type veth peer name veth1");
        sh_ok("ip link set veth0 up");
        sh_ok("ip link set veth1 up");
        WiredVethEnv
    }
}

impl Drop for WiredVethEnv {
    fn drop(&mut self) {
        sh_allow_fail("ip link del veth0");
    }
}

/// TLS 1.3 server config for the in-test wired authenticator.
fn wired_server_config() -> ServerConfig {
    let cert =
        cert_from_pem(include_str!("../../testdata/certs/server.pem")).unwrap();
    let key =
        key_from_pem(include_str!("../../testdata/certs/server.key")).unwrap();
    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap()
}

/// Block on one EAPOL frame from the authenticator's raw socket.
fn recv_wired_auth(fd: &std::os::fd::OwnedFd) -> Vec<u8> {
    loop {
        match recv_eapol_frame(fd.as_raw_fd()) {
            Ok(frame) if !frame.is_empty() => return frame,
            Ok(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Err(e) => panic!("wired authenticator recv: {e}"),
        }
    }
}

/// In-test wired 802.1X authenticator: EAP-Identity, EAP-TLS 1.3 via a
/// rustls server, then EAP-Success.
fn run_wired_authenticator() {
    let (fd, if_index, mac) =
        open_eapol_socket("veth1").expect("authenticator socket");

    // Client sends EAPOL-Start first; answer with Identity.
    let _start = recv_wired_auth(&fd);
    let identity = EapPacket::build(CODE_REQUEST, 1, Some(TYPE_IDENTITY), b"");
    send_eapol_frame(
        fd.as_raw_fd(),
        if_index,
        &mac,
        &EapolEapFrame::build(&identity),
    )
    .unwrap();
    // Read the client's EAP-Response/Identity before starting TLS.
    let _identity_response = recv_wired_auth(&fd);

    // EAP-TLS: Start, then exchange TLS records until both sides are
    // done, then EAP-Success.
    let start = EapPacket::build(
        CODE_REQUEST,
        2,
        Some(TYPE_TLS),
        &[EAP_TLS_FLAG_START],
    );
    send_eapol_frame(
        fd.as_raw_fd(),
        if_index,
        &mac,
        &EapolEapFrame::build(&start),
    )
    .unwrap();

    let mut server =
        ServerConnection::new(Arc::new(wired_server_config())).unwrap();
    let mut tx = Vec::new();
    loop {
        let frame = recv_wired_auth(&fd);
        let eap = EapolEapFrame::parse(&frame).expect("authenticator EAPOL");
        let packet = EapPacket::parse(&eap.payload).expect("authenticator EAP");
        assert_eq!(
            packet.type_,
            Some(TYPE_TLS),
            "authenticator expected EAP-TLS"
        );
        let (_, tls_data) =
            parse_tls_message(&packet.body).expect("authenticator TLS");
        if !tls_data.is_empty() {
            let used = server.read_tls(&mut Cursor::new(tls_data)).unwrap();
            assert_eq!(used, tls_data.len());
            server.process_new_packets().unwrap();
            server.write_tls(&mut tx).unwrap();
        }

        if !server.is_handshaking() {
            // Deliver any remaining server data, then authorize.
            if !tx.is_empty() {
                let msg = EapPacket::build(
                    CODE_REQUEST,
                    2,
                    Some(TYPE_TLS),
                    &build_tls_message(&tx),
                );
                send_eapol_frame(
                    fd.as_raw_fd(),
                    if_index,
                    &mac,
                    &EapolEapFrame::build(&msg),
                )
                .unwrap();
                tx.clear();
                // Client ACKs the final flight.
                let _ack = recv_wired_auth(&fd);
            }
            let success = EapPacket::build(CODE_SUCCESS, 3, None, b"");
            send_eapol_frame(
                fd.as_raw_fd(),
                if_index,
                &mac,
                &EapolEapFrame::build(&success),
            )
            .unwrap();
            return;
        }

        if !tx.is_empty() {
            let msg = EapPacket::build(
                CODE_REQUEST,
                2,
                Some(TYPE_TLS),
                &build_tls_message(&tx),
            );
            send_eapol_frame(
                fd.as_raw_fd(),
                if_index,
                &mac,
                &EapolEapFrame::build(&msg),
            )
            .unwrap();
            tx.clear();
        }
    }
}

/// Copy the test certificates needed by the wired client to a private
/// directory (the authenticator embeds its own copies at compile time).
fn write_test_certs() {
    std::fs::create_dir_all(CERT_DIR).expect("create cert dir");
    for name in ["ca.pem", "client.pem", "client.key"] {
        let src = format!(
            "{}/../../testdata/certs/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::copy(src, format!("{CERT_DIR}/{name}")).expect("copy cert");
    }
}

/// Wired 802.1X (EAP-TLS): EAP-Success authorizes the port; there is no
/// 4-way handshake or key install on wired links.
#[tokio::test]
async fn wired_8021x_eap_tls_connect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wired_8021x_eap_tls_connect: test binary not running as \
             root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }

    write_test_certs();
    let _env = WiredVethEnv::setup();
    let auth = std::thread::spawn(run_wired_authenticator);

    let mut eap = EapConfig::default();
    eap.identity = "shuli-test".to_string();
    eap.ca_cert = Some(format!("{CERT_DIR}/ca.pem").into());
    eap.client_cert = Some(format!("{CERT_DIR}/client.pem").into());
    eap.client_key = Some(format!("{CERT_DIR}/client.key").into());
    eap.server_name = Some("eap-tls.test".to_string());
    let mut client = WiredClient::init("veth0", &eap).expect("wired client");

    let mut connected = false;
    for _ in 0..20 {
        let step = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(WiredState::Connected)) => {
                connected = true;
                break;
            }
            Ok(Ok(WiredState::Failed)) => {
                panic!("wired 802.1X failed");
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("wired client error: {e}"),
            Err(_) => panic!("wired client made no progress within 20 s"),
        }
    }
    assert!(
        connected,
        "wired 802.1X EAP-TLS never reached the Connected state"
    );
    assert_eq!(client.state(), WiredState::Connected);
    auth.join().expect("wired authenticator thread");
}
