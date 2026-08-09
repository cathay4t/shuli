# SPDX-License-Identifier: Apache-2.0

import os
import pathlib
import subprocess

import pytest

from .testlib.cmdlib import exec_cmd
from .testlib.env import has_kernel_module
from .testlib.retry import retry_till_true_or_timeout
from .testlib.wifi import (
    AP_IP,
    AP_NIC,
    HWSIM0_PERM_MAC,
    HWSIM1_PERM_MAC,
    IPV4_BLOCK,
    TEST_NET_NS,
    TEST_NIC,
    TIMEOUT_SECS_SIM_WIFI_NICS,
    get_nic_name_by_perm_mac,
    get_wifi_phy_name,
    has_sim_wifi_nics,
    unload_wifi_sim_kernel_module,
)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="root required (mac80211_hwsim, netns and hostapd)",
)

OWE_SSID = "Test-WIFI-OWE"
STA_IP = f"{IPV4_BLOCK}.10"

# The distro hostapd may lack OWE support; use a locally built one
# if available (e.g. from /home/fge/Public_Sources/hostap).
HOSTAPD_OWE_BIN = "/home/fge/Public_Sources/hostap/hostapd/hostapd"
HOSTAPD_OWE_CONF_PATH = "/tmp/shuli_test_hostapd_owe.conf"
HOSTAPD_OWE_PID_PATH = "/tmp/shuli_test_hostapd_owe.pid"

SHULI_BIN = (
    f"{pathlib.Path(__file__).parent.parent.resolve()}/target/debug/shulid"
)
SHULI_OWE_CONFIG = "/tmp/shuli_test_owe_config.yml"
SHULI_OWE_LOG = "/tmp/shuli_test_owe_shulid.log"
CONNECT_TIMEOUT = 15

HOSTAPD_OWE_CONF = f"""
interface={AP_NIC}
driver=nl80211

hw_mode=g
channel=1
ssid={OWE_SSID}

wpa=2
wpa_key_mgmt=OWE
rsn_pairwise=CCMP
ieee80211w=2
"""


def hostapd_owe_is_up():
    output = exec_cmd(f"iw {TEST_NIC} scan".split(), check=False)[1]
    return OWE_SSID in output


def _find_hostapd_owe():
    """Return the path to an OWE-capable hostapd, or None."""
    if os.path.isfile(HOSTAPD_OWE_BIN):
        return HOSTAPD_OWE_BIN
    # Fall back to system hostapd (may not support OWE).
    rc, _, _ = exec_cmd("which hostapd".split(), check=False)
    if rc == 0:
        return "hostapd"
    return None


@pytest.fixture(scope="module")
def wifi_env_owe():
    hostapd_bin = _find_hostapd_owe()
    if not hostapd_bin:
        pytest.skip("no OWE-capable hostapd found")

    exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())

    exec_cmd("modprobe mac80211_hwsim radios=2".split())
    assert retry_till_true_or_timeout(
        TIMEOUT_SECS_SIM_WIFI_NICS, has_sim_wifi_nics
    )

    nic0 = get_nic_name_by_perm_mac(HWSIM0_PERM_MAC)
    nic1 = get_nic_name_by_perm_mac(HWSIM1_PERM_MAC)
    assert nic0 and nic1
    if nic0 != TEST_NIC:
        exec_cmd(f"ip link set {nic0} name {TEST_NIC}".split())
    if nic1 != AP_NIC:
        exec_cmd(f"ip link set {nic1} name {AP_NIC}".split())

    phy_id = get_wifi_phy_name(AP_NIC)
    exec_cmd(f"iw phy#{phy_id} set netns name {TEST_NET_NS}".split())
    exec_cmd(f"ip link set {TEST_NIC} up".split())
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} ip link set {AP_NIC} up".split()
    )
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} "
        f"ip addr add {AP_IP}/24 dev {AP_NIC}".split()
    )
    with open(HOSTAPD_OWE_CONF_PATH, "w") as fd:
        fd.write(HOSTAPD_OWE_CONF)
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} {hostapd_bin} -B "
        f"-P {HOSTAPD_OWE_PID_PATH} {HOSTAPD_OWE_CONF_PATH}".split()
    )
    assert retry_till_true_or_timeout(5, hostapd_owe_is_up)

    yield

    if os.path.exists(HOSTAPD_OWE_PID_PATH):
        with open(HOSTAPD_OWE_PID_PATH) as fd:
            pid = fd.read().strip()
        if pid:
            exec_cmd(f"kill {pid}".split(), check=False)
        try:
            os.remove(HOSTAPD_OWE_PID_PATH)
        except FileNotFoundError:
            pass
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


@pytest.fixture(scope="module")
def shulid_owe_connection(wifi_env_owe):
    if not os.path.isfile(SHULI_BIN):
        pytest.skip(f"{SHULI_BIN} not found, build it first (cargo build)")

    with open(SHULI_OWE_CONFIG, "w") as fd:
        fd.write(f"""---
version: 1
wifis:
  - ssid: {OWE_SSID}
    interface: {TEST_NIC}
""")

    log_f = open(SHULI_OWE_LOG, "w")
    daemon_proc = subprocess.Popen(
        [SHULI_BIN, SHULI_OWE_CONFIG],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        env={**os.environ, "RUST_LOG": "info"},
        start_new_session=True,
    )
    try:
        assert retry_till_true_or_timeout(
            CONNECT_TIMEOUT, shulid_owe_connected
        ), "shulid did not connect to OWE AP; log:\n" + _read_log()
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


def shulid_owe_connected():
    if not os.path.exists(SHULI_OWE_LOG):
        return False
    return "connection established" in _read_log()


def _read_log():
    with open(SHULI_OWE_LOG) as fd:
        return fd.read()


def ping_ap():
    rc, _, _ = exec_cmd(f"ping -I {TEST_NIC} {AP_IP} -c 1 -w 2".split(), check=False)
    return rc == 0


def _add_sta_ip():
    rc, _, _ = exec_cmd(
        f"ip addr add {STA_IP}/24 dev {TEST_NIC}".split(), check=False
    )
    if rc != 0:
        _, out, _ = exec_cmd(f"ip addr show {TEST_NIC}".split(), check=False)
        assert f"{STA_IP}/24" in out


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestOweWifi:
    def test_shulid_establishes_owe_connection(
        self, shulid_owe_connection
    ):
        pass

    def test_owe_data_path(self, shulid_owe_connection):
        exec_cmd(f"ip link set {TEST_NIC} up".split())
        _add_sta_ip()
        assert retry_till_true_or_timeout(5, ping_ap)
