// SPDX-License-Identifier: Apache-2.0

//! Integration tests for [`WifiClient::run()`] against real
//! mac80211_hwsim radios + hostapd.
//!
//! These tests are fully self-contained: [`WifiTestEnv::setup`] provisions
//! the virtual radios (`modprobe mac80211_hwsim radios=2`), moves one radio
//! into a dedicated network namespace, starts `hostapd` there, and [`Drop`]
//! tears everything down again afterwards (hostapd, netns, module). No
//! manual environment preparation is needed.
//!
//! They require root (they touch the kernel wifi stack) and are skipped
//! with a message when the test binary is not running as root. They run
//! as root automatically: `.cargo/config.toml` sets the test runner to
//! `sudo`, so plain `cargo test --workspace` is enough. A process-level
//! [`Mutex`] serialises all tests that touch the shared hwsim hardware
//! (same pattern as iproute-rs wwan tests).
//!
//! A stray wifi daemon on the node (wpa_supplicant, NetworkManager, iwd)
//! will grab the fresh hwsim radios, run its own scans / connect them, and
//! make the client's first scan fail with "Device or resource busy" — stop
//! such daemons before running these tests.
//!
//! Set `RUST_LOG=info` (or `debug`) to get the client's `log` output while
//! debugging.

use std::{
    io::Cursor,
    os::fd::AsRawFd,
    sync::{Arc, LazyLock},
};

use rustls::{ServerConfig, ServerConnection};
use tokio::sync::Mutex;

use crate::{
    ErrorKind, WifiClient, WifiConfig, WifiState,
    client::RETRY_BACKOFF_INIT_SEC,
    eap::{CODE_REQUEST, CODE_SUCCESS, EapPacket, TYPE_IDENTITY, TYPE_TLS},
    eap_tls::{
        EAP_TLS_FLAG_START, build_tls_message, cert_from_pem, key_from_pem,
        parse_tls_message,
    },
    ieee80211::eapol::{
        build_eapol_eap_frame, build_eapol_key_pdu, parse_eapol_eap_frame,
    },
    wired::{open_eapol_socket, recv_eapol_frame, send_eapol_frame},
};

static WIFI_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Initialise `env_logger` once per test process when `RUST_LOG` is set.
/// Defaults to `trace` so the full client flow is captured and printed by
/// the test harness when a test fails.
pub fn init_logger() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("trace"),
    )
    .try_init();
}

const HWSIM0_PERM_MAC: &str = "02:00:00:00:00:00";
const HWSIM1_PERM_MAC: &str = "02:00:00:00:01:00";
const HWSIM2_PERM_MAC: &str = "02:00:00:00:02:00";
const TEST_NIC: &str = "test-wlan0";
const AP_NIC: &str = "wifi_ap";
const AP_NIC2: &str = "wifi_ap2";
const TEST_NS: &str = "shuli_test";
const AP_IP: &str = "192.0.2.1";
const AP_IP2: &str = "192.0.2.2";

struct WifiTestEnv {
    hostapd_pid: Option<String>,
}

impl WifiTestEnv {
    /// Provision the environment (hwsim radios + netns + NICs) AND start
    /// hostapd right away. Tests that want to observe the client's
    /// background scan before any AP exists should use
    /// [`provision`](Self::provision) + [`start_hostapd`](Self::start_hostapd)
    /// instead.
    fn setup(hostapd_conf: &str) -> Self {
        let mut env = Self::provision();
        env.start_hostapd(hostapd_conf);
        env
    }

    /// Provision hwsim radios + netns + NICs, but do NOT start hostapd,
    /// so the client's background scan can be observed while no AP is on
    /// air. Start the AP later with [`start_hostapd`](Self::start_hostapd).
    fn provision() -> Self {
        // Pre-clean leftovers from a previous crashed run.
        sh_allow_fail("modprobe -r mac80211_hwsim");
        sh_allow_fail(&format!("ip netns del {TEST_NS}"));

        sh_ok(&format!("ip netns add {TEST_NS}"));
        sh_ok("modprobe mac80211_hwsim radios=2");
        std::thread::sleep(std::time::Duration::from_secs(2));

        let nic0 = find_nic_by_mac(HWSIM0_PERM_MAC).expect("hwsim NIC 0");
        let nic1 = find_nic_by_mac(HWSIM1_PERM_MAC).expect("hwsim NIC 1");
        if nic0 != TEST_NIC {
            sh_ok(&format!("ip link set {nic0} name {TEST_NIC}"));
        }
        if nic1 != AP_NIC {
            sh_ok(&format!("ip link set {nic1} name {AP_NIC}"));
        }

        let phy = get_phy_id(AP_NIC);
        sh_ok(&format!("iw phy#{phy} set netns name {TEST_NS}"));
        sh_ok(&format!("ip link set {TEST_NIC} up"));
        sh_ok(&format!("ip netns exec {TEST_NS} ip link set {AP_NIC} up"));
        sh_ok(&format!(
            "ip netns exec {TEST_NS} ip addr add {AP_IP}/24 dev {AP_NIC}"
        ));

        Self { hostapd_pid: None }
    }

    /// Start hostapd with `hostapd_conf` in the test netns. Idempotent
    /// only in the sense of being callable once; a second call would
    /// start a second instance. Debug output goes to a log file so
    /// failures can be inspected afterwards.
    fn start_hostapd(&mut self, hostapd_conf: &str) {
        let conf_path = "/tmp/shuli_rs_test_hostapd.conf";
        std::fs::write(conf_path, hostapd_conf).expect("write hostapd conf");
        let pid_path = "/tmp/shuli_rs_test_hostapd.pid";
        let bin = hostapd_bin("hostapd");
        sh_ok(&format!(
            "ip netns exec {TEST_NS} {bin} -B -dd -t -f \
             /tmp/shuli_rs_test_hostapd.log -P {pid_path} {conf_path}"
        ));
        std::thread::sleep(std::time::Duration::from_secs(1));

        let hostapd_pid = std::fs::read_to_string(pid_path)
            .ok()
            .map(|s| s.trim().to_string());
        self.hostapd_pid = hostapd_pid;
    }
}

impl Drop for WifiTestEnv {
    fn drop(&mut self) {
        if let Some(ref pid) = self.hostapd_pid {
            sh_allow_fail(&format!("kill {pid}"));
        }
        sh_allow_fail(&format!("ip netns del {TEST_NS}"));
        // The STA radio stays in the default netns and would pin the module
        // (rmmod fails with "resource busy" while it exists), so remove it
        // before unloading.
        sh_allow_fail(&format!("ip link del {TEST_NIC}"));
        sh_allow_fail("modprobe -r mac80211_hwsim");
        let _ = std::fs::remove_file("/tmp/shuli_rs_test_hostapd.conf");
        let _ = std::fs::remove_file("/tmp/shuli_rs_test_hostapd.pid");
    }
}

const OPEN_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-NOPASS
wpa=0
auth_algs=1
ctrl_interface=/var/run/hostapd
";

const SAE_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=2
sae_password=12345678
ctrl_interface=/var/run/hostapd
";

/// `anti_clogging_threshold=0` makes hostapd require an
/// anti-clogging token for every SAE commit.
const SAE_ANTI_CLOGGING_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=2
anti_clogging_threshold=0
sae_password=12345678
ctrl_interface=/var/run/hostapd
";

/// `sae_pwe=0` restricts hostapd to hunting-and-pecking commits,
/// so an H2E commit is rejected with UNSPECIFIED_FAILURE.
const SAE_HNP_ONLY_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=0
sae_password=12345678
ctrl_interface=/var/run/hostapd
";

/// the AP only accepts the SAE password with identifier
/// `corp-id` (`sae_password=<pass>|id=<id>`).
const SAE_PASSWORD_ID_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-PWID
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=2
sae_password=12345678|id=corp-id
ctrl_interface=/var/run/hostapd
";

/// hostapd with a non-default BIP group management cipher
/// (BIP-GMAC-256).  shuli must advertise the same cipher in its RSNE
/// and install the IGTK with it for protected frames to work.
const SAE_BIP_GMAC256_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-BIP
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
group_mgmt_cipher=BIP-GMAC-256
sae_pwe=2
sae_password=12345678
ctrl_interface=/var/run/hostapd
";

/// hostapd sends the Transition Disable KDE (bitmap 0x08 =
/// Enhanced Open disabled) in 4-way Message 3.  The connection must
/// still complete.
const SAE_TRANSITION_DISABLE_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-TD
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=2
sae_password=12345678
transition_disable=0x08
ctrl_interface=/var/run/hostapd
";

/// hostapd with Extended Key ID enabled for pairwise
/// keys.
const SAE_EXT_KEY_ID_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-EKID
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=2
sae_password=12345678
extended_key_id=1
ctrl_interface=/var/run/hostapd
";

const WPA2_PSK_PMF_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-PSK
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
ieee80211w=1
wpa_passphrase=12345678
ctrl_interface=/var/run/hostapd
";

/// Plain WPA2-PSK (no PMF) - "full 4-way + data path" case.
/// `ieee80211w` defaults to 0 here, so the handshake is the classic
/// WPA2-PSK 4-way (PRF-384 PTK + HMAC-SHA1 MIC, no IGTK KDE).
const WPA2_PSK_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-PSK
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=12345678
bss_transition=1
rrm_neighbor_report=1
ctrl_interface=/var/run/hostapd
";

/// WPA2-Personal with SHA-256 algorithms (AKM 6).
const WPA2_PSK_SHA256_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-PSK-SHA256
wpa=2
wpa_key_mgmt=WPA-PSK-SHA256
rsn_pairwise=CCMP
wpa_passphrase=12345678
ctrl_interface=/var/run/hostapd
";

/// WPA2-Enterprise (AKM 1) with hostapd's internal
/// EAP-TLS server.  Certificate paths are filled in by the test.
fn wpa2_eap_hostapd_conf() -> &'static str {
    r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-EAP
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
tls_flags=[ENABLE-TLSv1.3]
eap_user_file=/tmp/shuli_rs_test_eap_users
ca_cert=/tmp/shuli_rs_test_certs/ca.pem
server_cert=/tmp/shuli_rs_test_certs/server.pem
private_key=/tmp/shuli_rs_test_certs/server.key
ctrl_interface=/var/run/hostapd
"
}

/// WPA3-Enterprise (AKM 5, mandatory PMF).
fn wpa3_eap_hostapd_conf() -> &'static str {
    r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-EAP3
wpa=2
wpa_key_mgmt=WPA-EAP-SHA256
rsn_pairwise=CCMP
ieee8021x=1
ieee80211w=2
eap_server=1
tls_flags=[ENABLE-TLSv1.3]
eap_user_file=/tmp/shuli_rs_test_eap_users
ca_cert=/tmp/shuli_rs_test_certs/ca.pem
server_cert=/tmp/shuli_rs_test_certs/server.pem
private_key=/tmp/shuli_rs_test_certs/server.key
ctrl_interface=/var/run/hostapd
"
}

/// Wired test environment: a veth pair in the default netns.  The
/// installed hostapd lacks the `wired` driver, so the test supplies an
/// in-process EAP-TLS authenticator on the other end.
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
    let cert = cert_from_pem(include_str!("certs/server.pem")).unwrap();
    let key = key_from_pem(include_str!("certs/server.key")).unwrap();
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
        &build_eapol_eap_frame(&identity),
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
        &build_eapol_eap_frame(&start),
    )
    .unwrap();

    let mut server =
        ServerConnection::new(Arc::new(wired_server_config())).unwrap();
    let mut tx = Vec::new();
    loop {
        let frame = recv_wired_auth(&fd);
        let eap_pdu =
            parse_eapol_eap_frame(&frame).expect("authenticator EAPOL");
        let packet = EapPacket::parse(eap_pdu).expect("authenticator EAP");
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
                    &build_eapol_eap_frame(&msg),
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
                &build_eapol_eap_frame(&success),
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
                &build_eapol_eap_frame(&msg),
            )
            .unwrap();
            tx.clear();
        }
    }
}

/// Copy the self-signed test certificates to /tmp and write the EAP
/// user file for hostapd's internal EAP server.
fn write_test_certs() {
    let cert_dir = "/tmp/shuli_rs_test_certs";
    std::fs::create_dir_all(cert_dir).expect("create cert dir");
    for name in [
        "ca.pem",
        "server.pem",
        "server.key",
        "client.pem",
        "client.key",
    ] {
        let src = format!("{}/tests/certs/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::copy(&src, format!("{cert_dir}/{name}")).expect("copy cert");
    }
    std::fs::write("/tmp/shuli_rs_test_eap_users", "\"shuli-test\" TLS\n")
        .expect("write eap_user_file");
}

/// Run `hostapd_cli` against the test AP inside the test netns.
fn hostapd_cli(args: &str) {
    hostapd_cli_if(AP_NIC, args);
}

/// The hostapd/hostapd_cli binaries to use: prefer a locally built
/// copy in /usr/local/bin (the tests need CONFIG_WNM_AP + CONFIG_IEEE80211R
/// for the roaming tests, which distro packages may lack), and fall
/// back to whatever is on PATH.
fn hostapd_bin(name: &str) -> String {
    let local = format!("/usr/local/bin/{name}");
    if std::path::Path::new(&local).exists() {
        local
    } else {
        name.to_string()
    }
}

/// Run `hostapd_cli` against a specific BSS interface (multi-BSS setups).
fn hostapd_cli_if(iface: &str, args: &str) {
    let bin = hostapd_bin("hostapd_cli");
    sh_ok(&format!(
        "ip netns exec {TEST_NS} {bin} -p /var/run/hostapd -i {iface} {args}"
    ));
}

/// hostapd interface name serving a given BSSID in the two-BSS FT tests.
fn ft_ap_iface(bssid: [u8; 6]) -> &'static str {
    if bssid == [0x02, 0x00, 0x00, 0x00, 0x01, 0x00] {
        "wifi_ap"
    } else {
        "wifi_ap_2"
    }
}

/// Run [`WifiClient::run()`] in a loop until a connected state is
/// reached or `max_iters` is exhausted. Each call is bounded so a
/// client stuck waiting for events fails the test instead of hanging.
async fn run_until_connected(
    client: &mut WifiClient,
    max_iters: u32,
) -> Result<WifiState, crate::WifiError> {
    for _ in 0..max_iters {
        let step = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(state)) => match state {
                WifiState::ConnectedWithoutOffloadRekey
                | WifiState::ConnectedWithOffloadRekey => return Ok(state),
                _ => {}
            },
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(crate::WifiError::new(
                    crate::ErrorKind::ConnectFailed,
                    "client.run() made no progress within 20 s",
                ));
            }
        }
    }
    Err(crate::WifiError::new(
        crate::ErrorKind::ConnectFailed,
        "did not reach connected state",
    ))
}

/// Pump events until the socket goes quiet: the kernel delivers a few
/// trailing events (TX status reports etc.) after a connection settles;
/// this drains them before a test injects new input.
async fn drain_pending_events(client: &mut WifiClient) {
    let mut idle = 0;
    while idle < 2 {
        let step = tokio::time::timeout(
            std::time::Duration::from_millis(400),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(_)) => idle = 0,
            Ok(Err(e)) => panic!("client error while draining events: {e}"),
            Err(_) => idle += 1, // 400 ms without an event
        }
    }
}

#[tokio::test]
async fn wifi_client_open_connect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_open_connect: test binary not running as \
             root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(OPEN_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-NOPASS", None);
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

/// mac80211_hwsim has no WoWLAN support, so arming (with
/// `wowlan: true` configured) must degrade gracefully (report
/// unsupported, keep connecting) instead of failing. WoWLAN is opt-in
/// and defaults to off.
#[tokio::test]
async fn wifi_client_wowlan_unsupported_graceful() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_wowlan_unsupported_graceful: test binary \
             not running as root (`.cargo/config.toml` runs tests via `sudo`, \
             so plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(OPEN_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-NOPASS", None);
    config.networks[0].wowlan = true;
    let mut client = WifiClient::init(config).await.expect("init");
    assert!(
        !client.wowlan_supported(),
        "mac80211_hwsim must not advertise WoWLAN triggers"
    );
    let armed = client.arm_wowlan().await.expect("arm is best-effort");
    assert!(!armed, "WoWLAN must not be armed on hwsim");

    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

#[tokio::test]
async fn wifi_client_sae_connect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_sae_connect: test binary not running as \
             root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(SAE_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

/// anti-clogging token. `anti_clogging_threshold=0` makes hostapd
/// demand a token on every SAE commit (`use_anti_clogging()` returns 1
/// unconditionally), so a successful connection proves the client
/// re-sends its commit with the echoed token.
#[tokio::test]
async fn wifi_client_sae_anti_clogging() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_sae_anti_clogging: test binary not running \
             as root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(SAE_ANTI_CLOGGING_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

/// hunting-and-pecking fallback. `sae_pwe=0` makes hostapd both
/// omit SAE H2E support from its RSNXE and accept only HnP commits
/// (`sae_status_success()` rejects the H2E status 126 with
/// UNSPECIFIED_FAILURE). With the default `SaePwe::Auto` the client
/// reads that from the scan's RSNXE up front and connects directly
/// with HnP - no H2E commit is sent, so the reactive
/// rejection-triggered restart (`sae_hnp_attempted`) never fires for a
/// well-behaved AP; that restart remains a safety net for APs that
/// omit/misreport RSNXE yet still only accept HnP. An H2E-only network
/// must fail instead.
#[tokio::test]
async fn wifi_client_sae_hnp_fallback() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_sae_hnp_fallback: test binary not running \
             as root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(SAE_HNP_ONLY_HOSTAPD_CONF);

    // Auto (default): the AP's RSNXE doesn't advertise H2E, so the
    // client picks hunting-and-pecking up front and connects without
    // ever needing the reactive restart.
    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert!(
        !client.sae_hnp_attempted,
        "expected the RSNXE up-front check to pick hunting-and-pecking \
         directly, without needing an H2E-rejection restart"
    );
    client.shutdown().await;

    // H2E-only: the same AP must defeat an H2E-only network.
    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI", Some("12345678"));
    config.networks[0].sae_pwe = crate::SaePwe::H2E;
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await;
    assert!(
        state.is_err(),
        "H2E-only network must not connect to an HnP-only AP"
    );
    client.shutdown().await;
}

/// with `sae_password_id` configured, the client mixes the
/// identifier into the H2E PWE and the commit's Password Identifier
/// element, so hostapd (which only knows `12345678|id=corp-id`)
/// accepts the connection.
#[tokio::test]
async fn wifi_client_sae_password_identifier() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_sae_password_identifier: test binary not \
             running as root (`.cargo/config.toml` runs tests via `sudo`, so \
             plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(SAE_PASSWORD_ID_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-PWID", Some("12345678"));
    config.networks[0].set_sae_password_id(Some("corp-id"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

/// BIP-GMAC-256 negotiation.  The client picks the AP's
/// group management cipher, installs the IGTK with it, and survives an
/// SA Query (protected action frames must reach the kernel).
#[tokio::test]
async fn wifi_client_sae_bip_gmac256() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_sae_bip_gmac256: test binary not running as \
             root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(SAE_BIP_GMAC256_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-BIP", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert_eq!(
        client.bss_info.group_mgmt_cipher,
        wl_nl80211::Ieee80211CipherSuite::BipGmac256,
        "BIP-GMAC-256 must be negotiated"
    );

    // SA Query survival proves the IGTK was installed with a working
    // BIP cipher (mac80211 protects/answers the action frame).
    let sta_mac = client
        .mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    hostapd_cli(&format!("SA_QUERY {sta_mac}"));
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        let step = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(state)) => {
                assert!(
                    matches!(
                        state,
                        WifiState::ConnectedWithoutOffloadRekey
                            | WifiState::ConnectedWithOffloadRekey
                    ),
                    "SA Query broke the connection: {state:?}"
                );
            }
            Ok(Err(e)) => panic!("client error during SA Query: {e}"),
            Err(_) => {} // 500 ms without an event: still connected
        }
    }
    assert!(matches!(
        client.state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

/// a hostapd AP that sends the Transition Disable KDE must
/// still connect (the KDE is parsed and logged; the bits are a policy
/// hint for future profile changes).
#[tokio::test]
async fn wifi_client_sae_transition_disable() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_sae_transition_disable: test binary not \
             running as root (`.cargo/config.toml` runs tests via `sudo`, so \
             plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(SAE_TRANSITION_DISABLE_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-TD", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

/// Extended Key ID SAE connection - the AP selects a
/// pairwise key id and the client installs the PTK RX-then-TX.
#[tokio::test]
async fn wifi_client_sae_ext_key_id() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_sae_ext_key_id: test binary not running as \
             root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(SAE_EXT_KEY_ID_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-EKID", Some("12345678"));
    config.networks[0].ext_key_id = true;
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

#[tokio::test]
async fn wifi_client_multi_network_connect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_multi_network_connect: test binary not \
             running as root (`.cargo/config.toml` runs tests via `sudo`, so \
             plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    // Radios + netns up, but NO hostapd yet: the client must run its
    // background scan on its own while no AP is on air.
    let mut env = WifiTestEnv::provision();

    // Only `Test-WIFI` will exist on air; the decoy listed first must
    // not shadow it. One scan probes both SSIDs.
    let mut config = WifiConfig::new(TEST_NIC);
    config
        .add_network("Ghost-Network", Some("wrong-password"))
        .add_network("Test-WIFI", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");

    // First cycle: scan triggered. The empty result then hands the
    // periodic scanning to the firmware when PNO is available, or arms
    // the host-side retry backoff otherwise.
    assert_eq!(
        client.run().await.expect("scan triggered"),
        WifiState::Scanning
    );
    if client.sched_scan_supported {
        assert_eq!(
            client.run().await.expect("sched scan"),
            WifiState::SchedScanWait
        );
    } else {
        let err = client.run().await.expect_err("empty scan");
        assert_eq!(err.kind, ErrorKind::SsidNotFound);
        assert_eq!(client.state, WifiState::Failed);
        assert_eq!(client.scan_retry_interval, RETRY_BACKOFF_INIT_SEC);
    }

    // Bring the AP up late: the background scan picks it up on a later
    // cycle and connects with the right passphrase.
    env.start_hostapd(SAE_HOSTAPD_CONF);
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert_eq!(client.current_ssid(), "Test-WIFI");
    client.shutdown().await;
}

/// end-to-end: with PMF (ieee80211w=2) the AP sends an SA Query
/// request - a protected action frame - to the STA. mac80211 only lets
/// it through when shuli installed the IGTK from 4-way Message 3 (the
/// kernel's SA Query responder answers it), and hostapd disassociates a
/// STA that gives no answer. Surviving the SA Query therefore proves
/// the IGTK reached the kernel.
#[tokio::test]
async fn wifi_client_sae_pmf_sa_query() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_sae_pmf_sa_query: test binary not running \
             as root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(SAE_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));

    let sta_mac = client
        .mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    hostapd_cli(&format!("SA_QUERY {sta_mac}"));

    // hostapd disassociates a STA that does not answer the SA Query
    // within ~2s (response timeout + retries). Keep the client pumping
    // events for longer than that; the connection must survive.
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        let step = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(state)) => {
                assert!(
                    matches!(
                        state,
                        WifiState::ConnectedWithoutOffloadRekey
                            | WifiState::ConnectedWithOffloadRekey
                    ),
                    "SA Query broke the connection: {state:?}"
                );
            }
            Ok(Err(e)) => panic!("client error during SA Query: {e}"),
            Err(_) => {} // 500 ms without an event: still connected
        }
    }
    assert!(matches!(
        client.state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

/// WPA2-PSK with optional PMF (MFPC). The AP has ieee80211w=1, so
/// the MFPC-bit RSNE negotiates PMF and the 4-way Message 3 carries an
/// IGTK KDE; the connection must complete through PORT_AUTHORIZED.
#[tokio::test]
async fn wifi_client_wpa2_psk_pmf_connect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_wpa2_psk_pmf_connect: test binary not \
             running as root (`.cargo/config.toml` runs tests via `sudo`, so \
             plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(WPA2_PSK_PMF_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-PSK", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

/// WPA2-PSK (AKM 00-0F-AC:2) full 4-way handshake against hostapd
/// without PMF - the classic WPA2 setup. Mirrors the SAE connect test and
/// additionally pushes traffic over the encrypted data path: with the STA
/// and AP on the same 192.0.2.0/24, an ICMP echo must round-trip through
/// the installed PTK/GTK.
#[tokio::test]
async fn wifi_client_wpa2_psk_connect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_wpa2_psk_connect: test binary not running \
             as root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(WPA2_PSK_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-PSK", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));

    // Data path: give the STA an address on the AP's subnet and ping the
    // AP through the encrypted link. The first ping after association can
    // lose a packet to ARP/first-encryption latency, so retry a few times.
    // `-I test-wlan0` pins the source interface: the test net 192.0.2.0/24
    // may also exist on the host's own NICs (RFC 5737), which would make a
    // plain ping route its ARP out the wrong device.
    sh_ok("ip addr add 192.0.2.100/24 dev test-wlan0");
    let mut ponged = false;
    let mut last_err = String::new();
    for _ in 0..5 {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg("ping -I test-wlan0 -c 1 -W 1 192.0.2.1")
            .output()
            .expect("spawn ping");
        if out.status.success() {
            ponged = true;
            break;
        }
        last_err = format!(
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    sh_allow_fail("ip addr del 192.0.2.100/24 dev test-wlan0");
    assert!(
        ponged,
        "ICMP echo through the WPA2-PSK data path never succeeded:\n{last_err}"
    );
    client.shutdown().await;
}

/// WPA2-PSK-SHA256 (AKM 00-0F-AC:6) full 4-way handshake
/// against hostapd, with the encrypted data path exercised end-to-end
/// (KDV 3 + AES-CMAC MIC + KDF-Hash-Length PTK must be correct for
/// traffic to flow).
#[tokio::test]
async fn wifi_client_wpa2_psk_sha256_connect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_wpa2_psk_sha256_connect: test binary not \
             running as root (`.cargo/config.toml` runs tests via `sudo`, so \
             plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(WPA2_PSK_SHA256_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-PSK-SHA256", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert_eq!(
        client.bss_info.security,
        crate::SecurityType::Wpa2PskSha256,
        "scan must classify the AP as WPA2-PSK-SHA256"
    );

    // Data path: same ICMP check as the plain WPA2-PSK test.
    sh_ok("ip addr add 192.0.2.100/24 dev test-wlan0");
    let mut ponged = false;
    let mut last_err = String::new();
    for _ in 0..5 {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg("ping -I test-wlan0 -c 1 -W 1 192.0.2.1")
            .output()
            .expect("spawn ping");
        if out.status.success() {
            ponged = true;
            break;
        }
        last_err = format!(
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    sh_allow_fail("ip addr del 192.0.2.100/24 dev test-wlan0");
    assert!(
        ponged,
        "ICMP echo through the WPA2-PSK-SHA256 data path never \
         succeeded:\n{last_err}"
    );
    client.shutdown().await;
}

/// WPA2-Enterprise (802.1X / EAP-TLS, AKM 1) full flow:
/// open-system auth, association, EAP identity + TLS over the control
/// port, MSK -> PMK, 4-way handshake, and the encrypted data path.
#[tokio::test]
async fn wifi_client_wpa2_eap_connect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_wpa2_eap_connect: test binary not running \
             as root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }

    // hostapd's internal EAP server reads its config from /tmp.
    write_test_certs();
    let cert_dir = "/tmp/shuli_rs_test_certs";

    let _guard = WIFI_LOCK.lock().await;
    let conf = wpa2_eap_hostapd_conf();
    let _env = WifiTestEnv::setup(conf);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-EAP", None);
    config.networks[0].eap = Some(crate::EapConfig {
        identity: "shuli-test".to_string(),
        ca_cert: Some(format!("{cert_dir}/ca.pem").into()),
        client_cert: Some(format!("{cert_dir}/client.pem").into()),
        client_key: Some(format!("{cert_dir}/client.key").into()),
        server_name: Some("eap-tls.test".to_string()),
    });
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert_eq!(
        client.bss_info.security,
        crate::SecurityType::Wpa2Ent,
        "scan must classify the AP as WPA2-Enterprise"
    );
    assert!(
        client.eap_pmk.is_some(),
        "EAP-Success must have produced the PMK from the MSK"
    );

    // Data path over the installed PTK.
    sh_ok("ip addr add 192.0.2.100/24 dev test-wlan0");
    let mut ponged = false;
    let mut last_err = String::new();
    for _ in 0..5 {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg("ping -I test-wlan0 -c 1 -W 1 192.0.2.1")
            .output()
            .expect("spawn ping");
        if out.status.success() {
            ponged = true;
            break;
        }
        last_err = format!(
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    sh_allow_fail("ip addr del 192.0.2.100/24 dev test-wlan0");
    assert!(
        ponged,
        "ICMP echo through the WPA2-Enterprise data path never \
         succeeded:\n{last_err}"
    );
    client.shutdown().await;
}

/// WPA3-Enterprise baseline (802.1X-SHA256, AKM 5) with
/// mandatory PMF.  EAP-TLS + 4-way must complete, the IGTK must be
/// installed (an SA Query is answered by the kernel and the
/// connection survives), and traffic must flow.
#[tokio::test]
async fn wifi_client_wpa3_eap_connect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_wpa3_eap_connect: test binary not running \
             as root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }

    write_test_certs();
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(wpa3_eap_hostapd_conf());

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-EAP3", None);
    config.networks[0].eap = Some(crate::EapConfig {
        identity: "shuli-test".to_string(),
        ca_cert: Some("/tmp/shuli_rs_test_certs/ca.pem".into()),
        client_cert: Some("/tmp/shuli_rs_test_certs/client.pem".into()),
        client_key: Some("/tmp/shuli_rs_test_certs/client.key".into()),
        server_name: Some("eap-tls.test".to_string()),
    });
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert_eq!(
        client.bss_info.security,
        crate::SecurityType::Wpa2EntSha256,
        "scan must classify the AP as 802.1X-SHA256 / WPA3-Enterprise"
    );

    // Mandatory PMF: the kernel must have the IGTK installed to
    // answer the AP's protected SA Query (same check as the SAE PMF
    // test); hostapd disassociates a STA that does not respond.
    let sta_mac = client
        .mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    hostapd_cli(&format!("SA_QUERY {sta_mac}"));
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        let step = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(state)) => {
                assert!(
                    matches!(
                        state,
                        WifiState::ConnectedWithoutOffloadRekey
                            | WifiState::ConnectedWithOffloadRekey
                    ),
                    "SA Query broke the connection: {state:?}"
                );
            }
            Ok(Err(e)) => panic!("client error during SA Query: {e}"),
            Err(_) => {} // 500 ms without an event: still connected
        }
    }
    assert!(matches!(
        client.state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

/// wired 802.1X (EAP-TLS) against hostapd's wired
/// authenticator driver over a veth pair.  EAP-Success authorizes the
/// port; there is no 4-way handshake or key install on wired links.
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
    let _guard = WIFI_LOCK.lock().await;
    let _env = WiredVethEnv::setup();
    let auth = std::thread::spawn(run_wired_authenticator);

    let eap = crate::EapConfig {
        identity: "shuli-test".to_string(),
        ca_cert: Some("/tmp/shuli_rs_test_certs/ca.pem".into()),
        client_cert: Some("/tmp/shuli_rs_test_certs/client.pem".into()),
        client_key: Some("/tmp/shuli_rs_test_certs/client.key".into()),
        server_name: Some("eap-tls.test".to_string()),
    };
    let mut client =
        crate::WiredClient::init("veth0", &eap).expect("wired client");

    let mut connected = false;
    for _ in 0..20 {
        let step = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(crate::WiredState::Connected)) => {
                connected = true;
                break;
            }
            Ok(Ok(crate::WiredState::Failed)) => {
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
    assert_eq!(client.state(), crate::WiredState::Connected);
    auth.join().expect("wired authenticator thread");
}

/// after the first SAE connection the PMKSA is cached. When the AP
/// disconnects the STA, the client must reconnect without a new SAE
/// exchange: the association carries the cached PMKID and the AP runs
/// the 4-way handshake directly with the cached PMK.
#[tokio::test]
async fn wifi_client_sae_pmksa_reconnect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_sae_pmksa_reconnect: test binary not \
             running as root (`.cargo/config.toml` runs tests via `sudo`, so \
             plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(SAE_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    // First connection: full SAE exchange, PMKSA cached afterwards.
    assert!(client.auth.is_some(), "first connect must run full SAE");
    assert!(
        client
            .pmksa_cache
            .lookup("Test-WIFI", client.bss_info.bssid)
            .is_some(),
        "PMKSA must be cached after the first connection"
    );

    // Drain the trailing events of the first connection (e.g. the
    // control-port TX status) so the disconnect below is seen cleanly.
    drain_pending_events(&mut client).await;

    // Force an AP-initiated disconnect; the retry loop must reconnect
    // through the cached PMKID.
    let sta_mac = client
        .mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    hostapd_cli(&format!("DISASSOCIATE {sta_mac}"));

    // Disconnect event -> Failed -> 10 s backoff -> scan -> PMKSA-cached
    // association; allow enough iterations for the whole walk.
    let state = run_until_connected(&mut client, 40)
        .await
        .expect("reconnect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    // No SAE auth state means no commit/confirm exchange happened on
    // the reconnect - the AP accepted the PMKID.
    assert!(
        client.auth.is_none(),
        "reconnect must skip SAE when the PMKSA cache hits"
    );
    client.shutdown().await;
}

/// exit criterion 3: after the first WPA2-PSK connection the PMKSA
/// is cached. When the AP disconnects the STA, the client must
/// reconnect through the cached PMK: `psk_pmk` stays `None` on the
/// cache-hit path (PBKDF2 is skipped), unlike the first connection
/// which derives it from the passphrase.
#[tokio::test]
async fn wifi_client_wpa2_psk_pmksa_reconnect() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_wpa2_psk_pmksa_reconnect: test binary not \
             running as root (`.cargo/config.toml` runs tests via `sudo`, so \
             plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(WPA2_PSK_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-PSK", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    // First connection: PMK derived via PBKDF2, then cached.
    assert!(
        client.psk_pmk.is_some(),
        "first connect must derive the PSK PMK"
    );
    assert!(
        client
            .pmksa_cache
            .lookup("Test-WIFI-PSK", client.bss_info.bssid)
            .is_some(),
        "PMKSA must be cached after the first connection"
    );

    // Drain the trailing events of the first connection so the
    // disconnect below is seen cleanly.
    drain_pending_events(&mut client).await;

    // Force an AP-initiated disconnect; the retry loop must reconnect
    // through the cached PMKID.
    let sta_mac = client
        .mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    hostapd_cli(&format!("DISASSOCIATE {sta_mac}"));

    let state = run_until_connected(&mut client, 40)
        .await
        .expect("reconnect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    // Cache hit: PBKDF2 was skipped, so the PSK PMK was never derived
    // for the reconnect (the 4-way runs with the cached PMK).
    assert!(
        client.psk_pmk.is_none(),
        "reconnect must use the cached PMKSA instead of re-deriving the PMK"
    );
    client.shutdown().await;
}

/// Two-BSS FT-SAE topology on a single radio: both BSSes share the
/// SSID and mobility domain, and r0kh/r1kh entries cross-connect them
/// so PMK-R1 is available on both (pmk_r1_push=1). `sae_pwe` selects the
/// AP-side PWE mode: 2 (H2E) for the H2E tests, 0 (HnP-only) for the HnP
/// FT roam test.
fn ft_sae_hostapd_conf(sae_pwe: u8) -> String {
    format!(
        r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-FT
wpa=2
wpa_key_mgmt=FT-SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe={sae_pwe}
sae_password=12345678
nas_identifier=ap1
mobility_domain=a1b2
r0_key_lifetime=10000
pmk_r1_push=1
r0kh=02:00:00:00:03:00 ap2 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
r1kh=02:00:00:00:03:00 02:00:00:00:03:00 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
ctrl_interface=/var/run/hostapd

bss=wifi_ap_2
bssid=02:00:00:00:03:00
ssid=Test-WIFI-FT
wpa=2
wpa_key_mgmt=FT-SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe={sae_pwe}
sae_password=12345678
nas_identifier=ap2
mobility_domain=a1b2
r0_key_lifetime=10000
pmk_r1_push=1
r0kh=02:00:00:00:01:00 ap1 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
r1kh=02:00:00:00:01:00 02:00:00:00:01:00 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
ctrl_interface=/var/run/hostapd
"
    )
}

/// Same topology with FT-PSK (WPA2, optional PMF).
const FT_PSK_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-FT
wpa=2
wpa_key_mgmt=FT-PSK
rsn_pairwise=CCMP
ieee80211w=1
wpa_passphrase=12345678
bss_transition=1
rrm_neighbor_report=1
nas_identifier=ap1
mobility_domain=a1b2
r0_key_lifetime=10000
pmk_r1_push=1
r0kh=02:00:00:00:03:00 ap2 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
r1kh=02:00:00:00:03:00 02:00:00:00:03:00 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
ctrl_interface=/var/run/hostapd

bss=wifi_ap_2
bssid=02:00:00:00:03:00
ssid=Test-WIFI-FT
wpa=2
wpa_key_mgmt=FT-PSK
rsn_pairwise=CCMP
ieee80211w=1
wpa_passphrase=12345678
bss_transition=1
rrm_neighbor_report=1
nas_identifier=ap2
mobility_domain=a1b2
r0_key_lifetime=10000
pmk_r1_push=1
r0kh=02:00:00:00:01:00 ap1 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
r1kh=02:00:00:00:01:00 02:00:00:00:01:00 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
ctrl_interface=/var/run/hostapd
";

/// connect to a two-BSS FT-SAE ESS, then let a BSS Transition
/// Management Request steer the client to the other BSS - an
/// over-the-air Fast BSS Transition, no new SAE exchange.
#[tokio::test]
async fn wifi_client_ft_sae_btm_roam() {
    ft_sae_btm_roam_with(2, "wifi_client_ft_sae_btm_roam").await;
}

/// Same BTM roam on an FT-SAE ESS configured with hunting-and-pecking
/// only (`sae_pwe=0`, no SAE-H2E RSNXE in beacons). Mirrors the
/// SweatHome5G topology from the roam failure: the FT Reassociation
/// Request must not carry the H2E RSNXE when the SAE exchange used HnP.
#[tokio::test]
async fn wifi_client_ft_sae_hnp_btm_roam() {
    ft_sae_btm_roam_with(0, "wifi_client_ft_sae_hnp_btm_roam").await;
}

async fn ft_sae_btm_roam_with(sae_pwe: u8, test_name: &str) {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping {test_name}: test binary not running as root \
             (`.cargo/config.toml` runs tests via `sudo`, so plain `cargo \
             test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(&ft_sae_hostapd_conf(sae_pwe));

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-FT", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    // Initial connection: full SAE (FT-SAE), FT context established.
    assert!(client.auth.is_some(), "first connect must run full SAE");
    assert!(client.ft.is_some(), "FT context expected after connecting");
    let start_bssid = client.bss_info.bssid;

    drain_pending_events(&mut client).await;

    // The roam target is the other BSS of the ESS.
    let target = client
        .last_scan_candidates
        .iter()
        .map(|(bss, _)| bss)
        .find(|bss| bss.bssid != start_bssid)
        .expect("two BSSes in scan results")
        .clone();
    let target_bssid_str = target
        .bssid
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    // BTM Request with a preferred candidate list pointing at the
    // target BSS (Neighbor Report entry), issued on the BSS the STA is
    // currently associated with.
    let sta_mac = client
        .mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    hostapd_cli_if(
        ft_ap_iface(start_bssid),
        &format!(
            "BSS_TM_REQ {sta_mac} pref=1 neighbor={target_bssid_str},0,81,1,10"
        ),
    );

    // BTM accept + FT authentication + reassociation + key install.
    let state = run_until_connected(&mut client, 20).await.expect("roam");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert_eq!(
        client.bss_info.bssid, target.bssid,
        "the roam must land on the BTM candidate BSS"
    );
    assert!(
        client.auth.is_none(),
        "an FT roam must not run a new SAE exchange"
    );
    assert!(client.ft_roam.is_none(), "the FT roam must be complete");

    // Stability: no BTM is outstanding, so the client must stay on the
    // target BSS (the roam cooldown suppresses immediate re-roaming).
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(12);
    while tokio::time::Instant::now() < deadline {
        let step = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.run(),
        )
        .await;
        if let Ok(Err(e)) = step {
            panic!("client error after the BTM roam: {e}");
        }
        assert_eq!(
            client.bss_info.bssid, target.bssid,
            "the client must stay on the BTM candidate BSS"
        );
    }
    client.shutdown().await;
}

/// Regression test for the SweatHome5G failure: an FT-SAE reconnect must
/// not reuse the previous connection's FT context. The AP sent 4-way
/// Message 1 before the association response event, shuli answered with a
/// Message 2 built from the stale PMK-R1, the AP retransmitted Message 1
/// (replay 2..4) and never sent Message 3 - ending in "authentication
/// timed out". An early Message 1 must be buffered until the new
/// association response establishes the fresh FT context.
#[tokio::test]
async fn wifi_client_ft_sae_reconnect_buffers_early_msg1() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_ft_sae_reconnect_buffers_early_msg1: test \
             binary not running as root (`.cargo/config.toml` runs tests via \
             `sudo`, so plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(&ft_sae_hostapd_conf(2));

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-FT", Some("12345678"));
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert!(client.ft.is_some(), "FT context expected after connecting");
    drain_pending_events(&mut client).await;

    // Begin a reconnect attempt like the retry loop does: tear down the
    // kernel association, then start a fresh authentication. This resets
    // the per-attempt 4-way state, but the previous FT context (PMK-R1
    // derived from the old SAE PMK) must not survive into the new attempt.
    crate::nl80211::connect::disconnect(
        &mut client.conn_handle,
        client.if_index,
    )
    .await
    .expect("disconnect before reconnect");
    client
        .send_out_auth_request()
        .await
        .expect("start reconnect authentication");
    assert!(
        client.ft.is_none(),
        "stale FT context must be cleared when a new attempt starts"
    );
    assert!(client.fourway.is_none(), "4-way state must be reset");

    // The AP's first EAPOL-Key (Message 1, ANonce) arrives before the
    // association response event, as seen against SweatHome5G. With no FT
    // context yet, it must be buffered - never answered with a Message 2
    // carrying the old PMKR1Name.
    let msg1 = build_eapol_key_pdu(
        0x0088, // ACK | Pairwise, KDV 0 (AKM-defined for FT-SAE)
        16,
        1,
        &[0x55u8; 32],
        &[0u8; 16],
        &[0u8; 8],
        &[0u8; 8],
        &[0u8; 16],
        b"",
    );
    client
        .handle_event(wl_nl80211::Nl80211Event::ControlPortFrame {
            frame: msg1,
        })
        .await;

    assert!(
        client.pending_ft_msg1.is_some(),
        "early Message 1 must be buffered until the new FT context exists"
    );
    assert!(
        client.fourway.is_none(),
        "no 4-way state may be built from a stale FT context"
    );
    client.shutdown().await;
}

/// with a roam threshold configured, a weak signal triggers a scan
/// and the client FT-roams to the stronger/other BSS of the ESS on its
/// own (no BTM Request involved). The threshold is set high so hwsim's
/// fixed signal always qualifies.
#[tokio::test]
async fn wifi_client_ft_psk_signal_roam() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_ft_psk_signal_roam: test binary not running \
             as root (`.cargo/config.toml` runs tests via `sudo`, so plain \
             `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let _env = WifiTestEnv::setup(FT_PSK_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-FT", Some("12345678"));
    // hwsim reports a fixed (weak) signal; any threshold above it starts
    // the roam engine.
    config.networks[0].roaming_threshold = -10;
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    let start_bssid = client.bss_info.bssid;

    drain_pending_events(&mut client).await;

    let target = client
        .last_scan_candidates
        .iter()
        .map(|(bss, _)| bss)
        .find(|bss| bss.bssid != start_bssid)
        .expect("two BSSes in scan results")
        .clone();

    // Signal check interval is 5 s; give the roam engine a few rounds.
    // The per-run timeout must exceed the client's internal 5 s signal
    // check interval, or the check never gets a chance to run.
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let step = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("client error during signal roam: {e}"),
            Err(_) => {} // 15 s without a state change
        }
        if client.bss_info.bssid == target.bssid {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "signal-triggered FT roam did not happen in time (still on \
             {:02x?})",
            client.bss_info.bssid
        );
    }
    assert!(matches!(
        client.state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert!(
        client.auth.is_none(),
        "an FT roam must not run a new PSK/4-way full authentication"
    );
    assert!(
        client.neighbor_report_responses > 0,
        "the signal roam must actively request and receive an 802.11k \
         neighbor report before the quick scan"
    );

    // Stability: the signal is still "weak", but the roam cooldown must
    // keep the client on the target BSS instead of roaming right back.
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(12);
    while tokio::time::Instant::now() < deadline {
        let step = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.run(),
        )
        .await;
        if let Ok(Err(e)) = step {
            panic!("client error after the signal roam: {e}");
        }
        assert_eq!(
            client.bss_info.bssid, target.bssid,
            "the roam cooldown must keep the client on the target BSS"
        );
    }
    client.shutdown().await;
}

/// regression: a signal-triggered roam scan that finds no better BSS
/// must keep the client connected on the current BSS. Previously the
/// "staying" path left the state machine in `Scanning`, so the next
/// `run()` iteration fell through into a fresh authentication to the AP
/// the client was already connected to - which the kernel rejects with
/// -EALREADY ("Operation already in progress"), and the client spun in a
/// scan -> select -> SAE -> EALREADY retry loop forever. `run()` must not
/// surface the transient `Scanning` state (nor a repeated `Connected`) for
/// these scans at all.
#[tokio::test]
async fn wifi_client_roam_scan_stays_connected() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_roam_scan_stays_connected: test binary not \
             running as root (`.cargo/config.toml` runs tests via `sudo`, so \
             plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    // Single-BSS AP: a roam scan can never find a better candidate, so it
    // must decide to stay.
    let _env = WifiTestEnv::setup(WPA2_PSK_HOSTAPD_CONF);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-PSK", Some("12345678"));
    // hwsim reports a fixed (weak) signal; any threshold above it starts
    // the roam engine.
    config.networks[0].roaming_threshold = -10;
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    let start_bssid = client.bss_info.bssid;
    let start_ssid = client.current_ssid().to_string();

    drain_pending_events(&mut client).await;

    // Let the roam engine run several signal-check rounds. With no better
    // BSS on air the roam scan must "stay" and the client must return to
    // connected on the same BSS - never fall through into a fresh
    // authentication to the AP it is already on.
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let step = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(WifiState::Scanning)) => {
                panic!("roam scans must not surface Scanning to run() callers")
            }
            Ok(Ok(state))
                if matches!(
                    state,
                    WifiState::ConnectedWithoutOffloadRekey
                        | WifiState::ConnectedWithOffloadRekey
                ) =>
            {
                panic!(
                    "a roam scan that stays must not re-emit Connected (got \
                     {state:?})"
                );
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                panic!("client error while roam scan stays connected: {e}")
            }
            Err(_) => {} // 15 s without a state change
        }
        assert!(
            client.state == WifiState::Scanning
                || matches!(
                    client.state,
                    WifiState::ConnectedWithoutOffloadRekey
                        | WifiState::ConnectedWithOffloadRekey
                ),
            "client must stay connected after a roam scan that finds no \
             better BSS, got state {:?}",
            client.state
        );
        assert_eq!(
            client.bss_info.bssid, start_bssid,
            "the client must stay on its current BSS"
        );
        assert_eq!(
            client.current_ssid(),
            start_ssid,
            "the client must stay on its current network"
        );
        assert!(
            client.auth.is_none(),
            "no new authentication may start while the roam scan stays"
        );
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        // Give the roam engine time to run its 5 s signal check and the
        // resulting scan, then keep polling.
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    }
    assert!(
        client.roam_scan_count > 0,
        "the weak-signal roam engine must have run at least one scan"
    );
    assert!(
        client.neighbor_report_responses > 0,
        "the roam engine must actively request and receive an 802.11k \
         neighbor report before the quick scan"
    );
    client.shutdown().await;
}

/// Custom 3-radio environment for the cross-SSID roam test: one STA radio
/// plus two AP radios on separate phys (so each AP can report a different
/// signal via the hwsim `rx_rssi` debugfs knob), both APs hostapd in the
/// test netns. [`Drop`] tears everything down.
struct TwoApEnv {
    hostapd1_pid: Option<String>,
    hostapd2_pid: Option<String>,
}

impl TwoApEnv {
    /// Provision: 3 hwsim radios, move the two AP phys into the netns,
    /// start one hostapd per AP. Returns the hwsim phys of the two APs
    /// (needed to steer their reported signal via debugfs later).
    fn provision() -> (Self, String, String) {
        Self::provision_with_configs(AP1_HOSTAPD_CONF, AP2_HOSTAPD_CONF)
    }

    fn provision_with_configs(
        ap1_conf: &str,
        ap2_conf: &str,
    ) -> (Self, String, String) {
        sh_allow_fail("modprobe -r mac80211_hwsim");
        sh_allow_fail(&format!("ip netns del {TEST_NS}"));
        sh_ok(&format!("ip netns add {TEST_NS}"));
        sh_ok("modprobe mac80211_hwsim radios=3");
        std::thread::sleep(std::time::Duration::from_secs(2));

        let nic0 = find_nic_by_mac(HWSIM0_PERM_MAC).expect("hwsim NIC 0 (STA)");
        let nic1 =
            find_nic_by_mac(HWSIM1_PERM_MAC).expect("hwsim NIC 1 (AP 1)");
        let nic2 =
            find_nic_by_mac(HWSIM2_PERM_MAC).expect("hwsim NIC 2 (AP 2)");
        if nic0 != TEST_NIC {
            sh_ok(&format!("ip link set {nic0} name {TEST_NIC}"));
        }
        if nic1 != AP_NIC {
            sh_ok(&format!("ip link set {nic1} name {AP_NIC}"));
        }
        if nic2 != AP_NIC2 {
            sh_ok(&format!("ip link set {nic2} name {AP_NIC2}"));
        }

        // The hwsim rx_rssi debugfs knob is per-phy and indexed by phy;
        // record the ids before the phys leave this netns.
        let ap1_phy = get_phy_id(AP_NIC);
        let ap2_phy = get_phy_id(AP_NIC2);
        let phy1 = iw_phy_netns_move(&ap1_phy);
        let phy2 = iw_phy_netns_move(&ap2_phy);

        sh_ok(&format!("ip link set {TEST_NIC} up"));
        sh_ok(&format!("ip netns exec {TEST_NS} ip link set {AP_NIC} up"));
        sh_ok(&format!(
            "ip netns exec {TEST_NS} ip addr add {AP_IP}/24 dev {AP_NIC}"
        ));
        sh_ok(&format!("ip netns exec {TEST_NS} ip link set {AP_NIC2} up"));
        sh_ok(&format!(
            "ip netns exec {TEST_NS} ip addr add {AP_IP2}/24 dev {AP_NIC2}"
        ));

        let bin = hostapd_bin("hostapd");
        let conf1 = "/tmp/shuli_rs_test_ap1_hostapd.conf";
        let conf2 = "/tmp/shuli_rs_test_ap2_hostapd.conf";
        std::fs::write(conf1, ap1_conf).expect("write AP1 conf");
        std::fs::write(conf2, ap2_conf).expect("write AP2 conf");
        let pid1 = "/tmp/shuli_rs_test_ap1_hostapd.pid";
        let pid2 = "/tmp/shuli_rs_test_ap2_hostapd.pid";
        sh_ok(&format!(
            "ip netns exec {TEST_NS} {bin} -B -dd -t -f \
             /tmp/shuli_rs_test_ap1_hostapd.log -P {pid1} {conf1}"
        ));
        sh_ok(&format!(
            "ip netns exec {TEST_NS} {bin} -B -dd -t -f \
             /tmp/shuli_rs_test_ap2_hostapd.log -P {pid2} {conf2}"
        ));
        std::thread::sleep(std::time::Duration::from_secs(1));

        let env = TwoApEnv {
            hostapd1_pid: std::fs::read_to_string(pid1)
                .ok()
                .map(|s| s.trim().to_string()),
            hostapd2_pid: std::fs::read_to_string(pid2)
                .ok()
                .map(|s| s.trim().to_string()),
        };
        (env, phy1, phy2)
    }

    /// Set the transmit power (mBm) of a given AP radio. The hwsim
    /// measured signal is the fixed `rx_rssi` (-50 dBm) plus this tx
    /// power, so it slides between -50 dBm (0 mBm) and -30 dBm (20 dBm).
    fn set_ap_txpower(phy: &str, mbm: i32) {
        sh_ok(&format!(
            "ip netns exec {TEST_NS} iw phy phy{phy} set txpower fixed {mbm}"
        ));
    }
}

impl Drop for TwoApEnv {
    fn drop(&mut self) {
        if let Some(ref pid) = self.hostapd1_pid {
            sh_allow_fail(&format!("kill {pid}"));
        }
        if let Some(ref pid) = self.hostapd2_pid {
            sh_allow_fail(&format!("kill {pid}"));
        }
        sh_allow_fail(&format!("ip netns del {TEST_NS}"));
        sh_allow_fail(&format!("ip link del {TEST_NIC}"));
        sh_allow_fail("modprobe -r mac80211_hwsim");
        let _ = std::fs::remove_file("/tmp/shuli_rs_test_ap1_hostapd.conf");
        let _ = std::fs::remove_file("/tmp/shuli_rs_test_ap2_hostapd.conf");
        let _ = std::fs::remove_file("/tmp/shuli_rs_test_ap1_hostapd.pid");
        let _ = std::fs::remove_file("/tmp/shuli_rs_test_ap2_hostapd.pid");
    }
}

fn iw_phy_netns_move(phy: &str) -> String {
    sh_ok(&format!("iw phy#{phy} set netns name {TEST_NS}"));
    phy.to_string()
}

/// Two WPA2-PSK APs with different SSIDs, both advertising BSS
/// Transition (802.11v) so signal-triggered roaming applies. AP1
/// ("Test-WIFI-A") starts with the default signal; AP2 ("Test-WIFI-B")
/// is set weaker so the client connects to AP1 first.
const AP1_HOSTAPD_CONF: &str = r"
interface=wifi_ap
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-A
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=12345678
bss_transition=1
ctrl_interface=/var/run/hostapd
";

const AP2_HOSTAPD_CONF: &str = r"
interface=wifi_ap2
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-B
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=12345678
bss_transition=1
ctrl_interface=/var/run/hostapd
";

const AP2_OPEN_HOSTAPD_CONF: &str = r"
interface=wifi_ap2
driver=nl80211
hw_mode=g
channel=1
ssid=Test-WIFI-B
bss_transition=1
ctrl_interface=/var/run/hostapd
";

/// a roam scan that finds the connected BSS below the critical
/// threshold must switch to a well-signalled BSS of a *different*
/// configured SSID, even though that terminates the current session.
/// The client starts on AP1 (Test-WIFI-A); AP1's signal is then dropped
/// below the critical threshold and AP2 (Test-WIFI-B) is strengthened, so
/// the next roam engine run must move the client across SSIDs.
#[tokio::test]
async fn wifi_client_cross_ssid_critical_switch() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_cross_ssid_critical_switch: test binary not \
             running as root (`.cargo/config.toml` runs tests via `sudo`, so \
             plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let (_env, ap1_phy, ap2_phy) = TwoApEnv::provision();
    // AP2 weaker than AP1 (default -30 dBm) so the initial connection
    // lands on AP1.
    TwoApEnv::set_ap_txpower(&ap2_phy, 0);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-A", Some("12345678"));
    config.add_network("Test-WIFI-B", Some("12345678"));
    for network in &mut config.networks {
        // hwsim signals slide between -50 dBm (0 mBm) and -30 dBm
        // (20 dBm) as the tx power changes: tune the roam thresholds so
        // AP1 (initially -30) is healthy, AP2 (-50) is not yet good, and
        // a critical AP1 (-50) triggers the SSID switch to a good AP2
        // (-30).
        network.roaming_threshold = -40;
        network.switch_ssid_lower_than_dbm = -45;
    }
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert_eq!(
        "Test-WIFI-A",
        client.current_ssid(),
        "the client must connect to the stronger AP1 first"
    );

    drain_pending_events(&mut client).await;

    // Drop AP1 below the critical threshold and strengthen AP2; the
    // roam engine (CQM event) must then switch SSIDs to AP2.
    TwoApEnv::set_ap_txpower(&ap1_phy, 0);
    TwoApEnv::set_ap_txpower(&ap2_phy, 20000);

    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let step = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("client error during cross-SSID roam: {e}"),
            Err(_) => {}
        }
        if client.current_ssid() == "Test-WIFI-B"
            && matches!(
                client.state,
                WifiState::ConnectedWithoutOffloadRekey
                    | WifiState::ConnectedWithOffloadRekey
            )
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "cross-SSID switch did not happen in time (still on {} at bssid \
             {:02x?})",
            client.current_ssid(),
            client.bss_info.bssid
        );
    }
    assert!(matches!(
        client.state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert_eq!(
        "Test-WIFI-B",
        client.current_ssid(),
        "the client must land on the other configured SSID"
    );
    client.shutdown().await;
}

/// Regression for the cross-SSID critical roam downgrade: a saved SSID
/// with credentials must not switch to an open BSS just because it has
/// the right SSID and stronger signal.
#[tokio::test]
async fn wifi_client_cross_ssid_critical_switch_rejects_open_downgrade() {
    init_logger();
    if !is_root() {
        eprintln!(
            "skipping wifi_client_cross_ssid_critical_switch_rejects_open_downgrade: test binary not \
             running as root (`.cargo/config.toml` runs tests via `sudo`, so \
             plain `cargo test` is root)"
        );
        return;
    }
    let _guard = WIFI_LOCK.lock().await;
    let (_env, ap1_phy, ap2_phy) = TwoApEnv::provision_with_configs(
        AP1_HOSTAPD_CONF,
        AP2_OPEN_HOSTAPD_CONF,
    );
    TwoApEnv::set_ap_txpower(&ap2_phy, 0);

    let mut config = WifiConfig::new(TEST_NIC);
    config.add_network("Test-WIFI-A", Some("12345678"));
    config.add_network("Test-WIFI-B", Some("12345678"));
    for network in &mut config.networks {
        network.roaming_threshold = -40;
        network.switch_ssid_lower_than_dbm = -45;
    }
    let mut client = WifiClient::init(config).await.expect("init");
    let state = run_until_connected(&mut client, 20).await.expect("connect");
    assert!(matches!(
        state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    assert_eq!(
        "Test-WIFI-A",
        client.current_ssid(),
        "the client must connect to AP1 first"
    );

    drain_pending_events(&mut client).await;
    TwoApEnv::set_ap_txpower(&ap1_phy, 0);
    TwoApEnv::set_ap_txpower(&ap2_phy, 20000);

    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        let step = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            client.run(),
        )
        .await;
        match step {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                panic!("client error during open-downgrade regression: {e}")
            }
            Err(_) => {}
        }
        assert_ne!(
            "Test-WIFI-B",
            client.current_ssid(),
            "the client must not roam to an open impostor SSID"
        );
    }
    assert_eq!(
        "Test-WIFI-A",
        client.current_ssid(),
        "the client must stay on the protected SSID"
    );
    assert!(matches!(
        client.state,
        WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey
    ));
    client.shutdown().await;
}

// --- helpers ---

/// Whether the test process runs with root privileges (needed to touch the
/// kernel wifi stack: modprobe, netns, nl80211 connection commands).
fn is_root() -> bool {
    std::process::Command::new("id")
        .args(["-u"])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Run a command that must succeed; panic with the failure otherwise so a
/// broken environment never silently masquerades as a passing test.
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

/// Run a best-effort command (pre-cleanup / teardown); failures are ignored
/// because the target may legitimately not exist (e.g. `modprobe -r` when the
/// module is already unloaded).
fn sh_allow_fail(cmd: &str) {
    let _ = std::process::Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .output();
}

fn find_nic_by_mac(mac: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["-j", "link", "show"])
        .output()
        .ok()?;
    let links: Vec<serde_json::Value> =
        serde_json::from_slice(&out.stdout).ok()?;
    for link in &links {
        if link.get("address").and_then(|a| a.as_str()) == Some(mac) {
            return link
                .get("ifname")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string());
        }
    }
    None
}

fn get_phy_id(nic: &str) -> String {
    let out = std::process::Command::new("iw")
        .args(["dev", nic, "info"])
        .output()
        .expect("iw dev info");
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(pos) = line.find("wiphy ") {
            return line[pos + 6..].trim().to_string();
        }
    }
    panic!("no wiphy found for {nic}");
}
