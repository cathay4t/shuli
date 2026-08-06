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

use std::sync::LazyLock;

use tokio::sync::Mutex;

use crate::{
    ErrorKind, WifiClient, WifiConfig, WifiState,
    client::RETRY_BACKOFF_INIT_SEC,
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
const TEST_NIC: &str = "test-wlan0";
const AP_NIC: &str = "wifi_ap";
const TEST_NS: &str = "shuli_test";
const AP_IP: &str = "192.0.2.1";

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
    /// start a second instance.
    fn start_hostapd(&mut self, hostapd_conf: &str) {
        let conf_path = "/tmp/shuli_rs_test_hostapd.conf";
        std::fs::write(conf_path, hostapd_conf).expect("write hostapd conf");
        let pid_path = "/tmp/shuli_rs_test_hostapd.pid";
        sh_ok(&format!(
            "ip netns exec {TEST_NS} hostapd -B -P {pid_path} {conf_path}"
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
";

/// Run [`WifiClient::run()`] in a loop until a connected state is
/// reached or `max_iters` is exhausted.
async fn run_until_connected(
    client: &mut WifiClient,
    max_iters: u32,
) -> Result<WifiState, crate::WifiError> {
    for _ in 0..max_iters {
        let state = client.run().await?;
        match state {
            WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey => return Ok(state),
            _ => {}
        }
    }
    Err(crate::WifiError::new(
        crate::ErrorKind::ConnectFailed,
        "did not reach connected state",
    ))
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
