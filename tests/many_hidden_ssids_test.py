# SPDX-License-Identifier: Apache-2.0

import os
import pathlib
import subprocess

import pytest

from .testlib.cmdlib import exec_cmd
from .testlib.env import has_kernel_module
from .testlib.retry import retry_till_true_or_timeout
from .testlib.wifi import (
    HWSIM0_PERM_MAC,
    HWSIM1_PERM_MAC,
    TEST_NET_NS,
    TEST_NIC,
    TIMEOUT_SECS_SIM_WIFI_NICS,
    get_nic_name_by_perm_mac,
    get_wifi_phy_name,
    unload_wifi_sim_kernel_module,
)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="root required (mac80211_hwsim, netns and hostapd)",
)

HWSIM2_PERM_MAC = "02:00:00:00:02:00"
AP_NIC = "wifi_ap"
AP_NIC2 = "wifi_ap2"
HIDDEN_A_SSID = "Hidden-Alpha"
HIDDEN_B_SSID = "Hidden-Beta"
HIDDEN_PSK = "12345678"

HOSTAPD_A_CONF_PATH = "/tmp/shuli_test_hostapd_many_a.conf"
HOSTAPD_A_PID_PATH = "/tmp/shuli_test_hostapd_many_a.pid"
HOSTAPD_B_CONF_PATH = "/tmp/shuli_test_hostapd_many_b.conf"
HOSTAPD_B_PID_PATH = "/tmp/shuli_test_hostapd_many_b.pid"

SHULI_BIN = (
    f"{pathlib.Path(__file__).parent.parent.resolve()}/target/debug/shulid"
)
SHULI_MANY_CONFIG = "/tmp/shuli_test_many_hidden_config.yml"
SHULI_MANY_LOG = "/tmp/shuli_test_many_hidden_shulid.log"
CONNECT_TIMEOUT = 60
NETWORK_COUNT = 100

# Two strict hidden WPA2-PSK APs (`ignore_broadcast_ssid=2`): the SSIDs
# are omitted from beacons and hostapd only answers directed probe
# requests that carry the specific SSID.
HOSTAPD_A_CONF = f"""
interface={AP_NIC}
driver=nl80211
hw_mode=g
channel=1
ssid={HIDDEN_A_SSID}
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase={HIDDEN_PSK}
ignore_broadcast_ssid=2
"""

HOSTAPD_B_CONF = f"""
interface={AP_NIC2}
driver=nl80211
hw_mode=g
channel=6
ssid={HIDDEN_B_SSID}
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase={HIDDEN_PSK}
ignore_broadcast_ssid=2
"""


def has_three_sim_wifi_nics():
    try:
        exec_cmd("udevadm settle".split(), check=False)
        return all(
            get_nic_name_by_perm_mac(mac)
            for mac in (HWSIM0_PERM_MAC, HWSIM1_PERM_MAC, HWSIM2_PERM_MAC)
        )
    except Exception:
        return False


def hostapd_a_is_up():
    output = exec_cmd(f"iw {TEST_NIC} scan".split(), check=False)[1]
    return HWSIM1_PERM_MAC in output


def hostapd_b_is_up():
    output = exec_cmd(f"iw {TEST_NIC} scan".split(), check=False)[1]
    return HWSIM2_PERM_MAC in output


@pytest.fixture(scope="module")
def two_hidden_aps_env():
    exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())

    exec_cmd("modprobe mac80211_hwsim radios=3".split())
    assert retry_till_true_or_timeout(
        TIMEOUT_SECS_SIM_WIFI_NICS, has_three_sim_wifi_nics
    )

    nic0 = get_nic_name_by_perm_mac(HWSIM0_PERM_MAC)
    nic1 = get_nic_name_by_perm_mac(HWSIM1_PERM_MAC)
    nic2 = get_nic_name_by_perm_mac(HWSIM2_PERM_MAC)
    assert nic0 and nic1 and nic2
    if nic0 != TEST_NIC:
        exec_cmd(f"ip link set {nic0} name {TEST_NIC}".split())
    if nic1 != AP_NIC:
        exec_cmd(f"ip link set {nic1} name {AP_NIC}".split())
    if nic2 != AP_NIC2:
        exec_cmd(f"ip link set {nic2} name {AP_NIC2}".split())

    phy1 = get_wifi_phy_name(AP_NIC)
    phy2 = get_wifi_phy_name(AP_NIC2)
    exec_cmd(f"iw phy#{phy1} set netns name {TEST_NET_NS}".split())
    exec_cmd(f"iw phy#{phy2} set netns name {TEST_NET_NS}".split())
    exec_cmd(f"ip link set {TEST_NIC} up".split())
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} ip link set {AP_NIC} up".split()
    )
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} ip link set {AP_NIC2} up".split()
    )

    with open(HOSTAPD_A_CONF_PATH, "w") as fd:
        fd.write(HOSTAPD_A_CONF)
    with open(HOSTAPD_B_CONF_PATH, "w") as fd:
        fd.write(HOSTAPD_B_CONF)
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} hostapd -B "
        f"-P {HOSTAPD_A_PID_PATH} {HOSTAPD_A_CONF_PATH}".split()
    )
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} hostapd -B "
        f"-P {HOSTAPD_B_PID_PATH} {HOSTAPD_B_CONF_PATH}".split()
    )
    assert retry_till_true_or_timeout(5, hostapd_a_is_up)
    assert retry_till_true_or_timeout(5, hostapd_b_is_up)

    # Prove both APs are really hidden: a plain scan sees the BSSes but
    # no SSID names.
    scan_out = exec_cmd(f"iw {TEST_NIC} scan".split(), check=False)[1]
    assert HIDDEN_A_SSID not in scan_out, (
        "hidden AP A leaked its SSID in a broadcast scan:\n" + scan_out
    )
    assert HIDDEN_B_SSID not in scan_out, (
        "hidden AP B leaked its SSID in a broadcast scan:\n" + scan_out
    )

    yield

    for pid_path in (HOSTAPD_A_PID_PATH, HOSTAPD_B_PID_PATH):
        if not os.path.exists(pid_path):
            continue
        with open(pid_path) as fd:
            pid = fd.read().strip()
        if pid:
            exec_cmd(f"kill {pid}".split(), check=False)
        try:
            os.remove(pid_path)
        except FileNotFoundError:
            pass
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


def many_network_config():
    """100 networks: 95 visible dummies, 3 dummy hidden SSIDs and the
    two real hidden APs at the end of the hidden list."""
    lines = ["---", "version: 1", "wifis:"]
    for i in range(1, 96):
        lines.append(f"  - ssid: Visible-{i:02d}")
        lines.append(f"    interface: {TEST_NIC}")
    for i in range(1, 4):
        lines.append(f"  - ssid: Hidden-Dummy-{i}")
        lines.append("    hidden: true")
        lines.append(f"    interface: {TEST_NIC}")
    for ssid in (HIDDEN_A_SSID, HIDDEN_B_SSID):
        lines.append(f"  - ssid: {ssid}")
        lines.append(f'    password: "{HIDDEN_PSK}"')
        lines.append("    hidden: true")
        lines.append(f"    interface: {TEST_NIC}")
    return "\n".join(lines) + "\n"


@pytest.fixture(scope="module")
def shulid_many_hidden_connection(two_hidden_aps_env):
    if not os.path.isfile(SHULI_BIN):
        pytest.skip(f"{SHULI_BIN} not found, build it first (cargo build)")

    with open(SHULI_MANY_CONFIG, "w") as fd:
        fd.write(many_network_config())

    log_f = open(SHULI_MANY_LOG, "w")
    daemon_proc = subprocess.Popen(
        [SHULI_BIN, SHULI_MANY_CONFIG],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        env={**os.environ, "RUST_LOG": "info"},
        start_new_session=True,
    )
    try:
        assert retry_till_true_or_timeout(
            CONNECT_TIMEOUT, shulid_many_hidden_connected
        ), "shulid did not connect to a hidden AP; log:\n" + _read_log()
    except BaseException:
        if daemon_proc.poll() is not None:
            print(f"shulid exited early with rc={daemon_proc.returncode}")
        raise
    yield
    daemon_proc.terminate()
    try:
        daemon_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        daemon_proc.kill()
        daemon_proc.wait()


def shulid_many_hidden_connected():
    if not os.path.exists(SHULI_MANY_LOG):
        return False
    return "connection established to 'Hidden-" in _read_log()


def _read_log():
    with open(SHULI_MANY_LOG) as fd:
        return fd.read()


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestManyHiddenSsidRotation:
    def test_daemon_loads_100_networks(self, shulid_many_hidden_connection):
        log = _read_log()
        assert f"({NETWORK_COUNT} ssid)" in log, (
            "shulid did not report 100 configured networks; log:\n" + log
        )

    def test_scan_uses_wildcard_and_connects_to_hidden_ap(
        self, shulid_many_hidden_connection
    ):
        log = _read_log()
        assert "connection established to 'Hidden-" in log, (
            "shulid did not connect to a hidden AP; log:\n" + log
        )
        scan_lines = [
            line
            for line in log.splitlines()
            if "scanning for SSIDs [" in line
        ]
        assert scan_lines, "shulid never started a scan; log:\n" + log
        # Every scan reserves the wildcard slot; hidden SSIDs are probed
        # by name (directed probes).
        assert "*" in scan_lines[0], (
            "scan did not include the wildcard entry; log:\n" + log
        )
        assert HIDDEN_A_SSID in log and HIDDEN_B_SSID in log, (
            "hidden AP SSIDs were not probed; log:\n" + log
        )
