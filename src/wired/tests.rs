// SPDX-License-Identifier: Apache-2.0

//! Integration test for wired 802.1X (EAP-TLS) against an in-process
//! EAP-TLS authenticator over a veth pair.

use std::{
    io::Cursor,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
    time::{Duration, Instant},
};

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
    MacsecConfig, WiredAuth, WiredClient, WiredState,
    eap::{
        PAE_GROUP_ADDR, open_eapol_socket, recv_eapol_frame, send_eapol_frame,
    },
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
struct WiredVethEnv {
    first: &'static str,
}

impl WiredVethEnv {
    fn setup() -> Self {
        Self::setup_named("veth0", "veth1")
    }

    fn setup_named(first: &'static str, second: &'static str) -> Self {
        sh_allow_fail(&format!("ip link del {first}"));
        sh_ok(&format!("ip link add {first} type veth peer name {second}"));
        sh_ok(&format!("ip link set {first} up"));
        sh_ok(&format!("ip link set {second} up"));
        WiredVethEnv { first }
    }
}

impl Drop for WiredVethEnv {
    fn drop(&mut self) {
        sh_allow_fail(&format!("ip link del {}", self.first));
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

/// MACsec/MKA end-to-end: two participants with the same pre-shared
/// CAK/CKN over a veth pair elect a key server, distribute a SAK,
/// install it into the kernel MACsec devices, and pass traffic.
#[tokio::test]
async fn wired_macsec_mka_connect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wired_macsec_mka_connect: test binary not running as \
             root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }

    let _env = WiredVethEnv::setup_named("mka0", "mka1");
    sh_allow_fail("ip link del macsec-a");
    sh_allow_fail("ip link del macsec-b");

    let cak = vec![0x11u8; 16];
    let ckn = vec![0x22u8; 16];
    let mut a = WiredClient::init_with_auth(
        "mka0",
        WiredAuth::Macsec(MacsecConfig {
            cak: cak.clone(),
            ckn: ckn.clone(),
            key_server_priority: 0x10,
            can_be_key_server: true,
            macsec_iface: Some("macsec-a".to_string()),
            replay_window: 0,
            encrypt: true,
        }),
    )
    .expect("MKA client A");
    let mut b = WiredClient::init_with_auth(
        "mka1",
        WiredAuth::Macsec(MacsecConfig {
            cak,
            ckn,
            key_server_priority: 0xff,
            can_be_key_server: false,
            macsec_iface: Some("macsec-b".to_string()),
            replay_window: 0,
            encrypt: true,
        }),
    )
    .expect("MKA client B");

    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let (mut a_ok, mut b_ok) = (false, false);
    while tokio::time::Instant::now() < deadline && !(a_ok && b_ok) {
        let (ra, rb) = tokio::join!(a.run(), b.run());
        match ra {
            Ok(WiredState::Connected) => a_ok = true,
            Ok(WiredState::Failed) => panic!("MKA client A failed"),
            Ok(_) => {}
            Err(e) => panic!("MKA client A error: {e}"),
        }
        match rb {
            Ok(WiredState::Connected) => b_ok = true,
            Ok(WiredState::Failed) => panic!("MKA client B failed"),
            Ok(_) => {}
            Err(e) => panic!("MKA client B error: {e}"),
        }
    }
    assert!(
        a_ok && b_ok,
        "MKA never secured both participants (A={a_ok}, B={b_ok})"
    );
    assert_eq!(a.state(), WiredState::Connected);
    assert_eq!(b.state(), WiredState::Connected);

    // Both endpoints live in the same network namespace, so routing
    // between their IP addresses short-circuits via `lo`. Exercise the
    // kernel MACsec data path directly with raw Ethernet frames instead.
    let mac_a = read_iface_mac("macsec-a");
    let mac_b = read_iface_mac("macsec-b");
    let ifindex_a = iface_index("macsec-a");
    let ifindex_b = iface_index("macsec-b");
    let raw_a = open_raw_socket("macsec-a");
    let raw_b = open_raw_socket("macsec-b");

    let payload = b"shuli-mka-data-path";
    send_raw_frame(&raw_a, ifindex_a, &mac_a, &mac_b, 0x88b5, payload);
    assert!(
        recv_raw_frame(&raw_b, 0x88b5, payload, Duration::from_secs(5)),
        "MACsec A->B data path never delivered the frame"
    );

    let reply = b"shuli-mka-reply";
    send_raw_frame(&raw_b, ifindex_b, &mac_b, &mac_a, 0x88b5, reply);
    assert!(
        recv_raw_frame(&raw_a, 0x88b5, reply, Duration::from_secs(5)),
        "MACsec B->A data path never delivered the frame"
    );

    // An MKPDU with a bad ICV (another CA or an attacker on the
    // segment) must be ignored, not tear the session down.
    let raw_peer = open_raw_socket("mka1");
    let peer_ifindex = iface_index("mka1");
    let peer_mac = read_iface_mac("mka1");
    let mut bad_mkpdu = vec![0x03u8, 0x05, 0x00, 0x20];
    bad_mkpdu.extend_from_slice(&[0u8; 28]);
    send_raw_frame(
        &raw_peer,
        peer_ifindex,
        &peer_mac,
        &PAE_GROUP_ADDR,
        0x888e,
        &bad_mkpdu,
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    for _ in 0..3 {
        assert!(
            a.run().await.is_ok(),
            "invalid MKPDU must not abort the MKA session"
        );
    }
}

fn read_iface_mac(iface: &str) -> [u8; 6] {
    let text =
        std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
            .unwrap_or_else(|e| panic!("read {iface} address: {e}"));
    let mut mac = [0u8; 6];
    for (i, part) in text.trim().split(':').enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .unwrap_or_else(|e| panic!("invalid MAC octet {part:?}: {e}"));
    }
    mac
}

fn iface_index(iface: &str) -> u32 {
    let name = std::ffi::CString::new(iface).expect("iface name");
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    assert_ne!(index, 0, "interface {iface} not found");
    index
}

fn open_raw_socket(iface: &str) -> OwnedFd {
    let ifindex = iface_index(iface);
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0x0003u16.to_be() as i32,
        )
    };
    assert!(
        fd >= 0,
        "raw socket on {iface}: {}",
        std::io::Error::last_os_error()
    );
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = 0x0003u16.to_be();
    sll.sll_ifindex = ifindex as i32;
    let rc = unsafe {
        libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    assert!(
        rc >= 0,
        "bind raw socket on {iface}: {}",
        std::io::Error::last_os_error()
    );
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn send_raw_frame(
    fd: &OwnedFd,
    ifindex: u32,
    src: &[u8; 6],
    dst: &[u8; 6],
    ethertype: u16,
    payload: &[u8],
) {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(dst);
    frame.extend_from_slice(src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);

    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = 0x0003u16.to_be();
    sll.sll_ifindex = ifindex as i32;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(dst);
    let rc = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        frame.len() as isize,
        "send raw frame: {}",
        std::io::Error::last_os_error()
    );
}

fn recv_raw_frame(
    fd: &OwnedFd,
    ethertype: u16,
    payload: &[u8],
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let wait = (deadline - Instant::now()).as_millis().clamp(1, 500) as i32;
        let rc = unsafe { libc::poll(&mut pfd, 1, wait) };
        if rc <= 0 {
            continue;
        }
        let mut buf = [0u8; 2048];
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 14 {
            continue;
        }
        let n = n as usize;
        if u16::from_be_bytes([buf[12], buf[13]]) != ethertype {
            continue;
        }
        if n >= 14 + payload.len() && &buf[14..14 + payload.len()] == payload {
            return true;
        }
    }
    false
}
