# SPDX-License-Identifier: Apache-2.0

"""The daemon runs one `WifiClient` per configured interface, so
two interfaces connect to two APs concurrently.  Each interface gets its
own static IP config applied.

Topology: 4 mac80211_hwsim radios - two STAs (default netns, driven by
`shulid`) and two APs (moved into the test netns, one hostapd each).
"""

import json
import os
import pathlib
import subprocess
import time

import pytest

from .testlib.cmdlib import exec_cmd
from .testlib.env import has_kernel_module
from .testlib.retry import retry_till_true_or_timeout
from .testlib.wifi import (
    HWSIM0_PERM_MAC,
    HWSIM1_PERM_MAC,
    TEST_WIFI_PSK,
    TEST_WIFI_SSID,
    get_nic_name_by_perm_mac,
    get_wifi_phy_name,
    unload_wifi_sim_kernel_module,
)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="root required (mac80211_hwsim, netns and hostapd)",
)

HWSIM2_PERM_MAC = "02:00:00:00:02:00"
HWSIM3_PERM_MAC = "02:00:00:00:03:00"

TEST_NIC_1 = "test-wlan0"
TEST_NIC_2 = "test-wlan1"
AP_NIC_1 = "wifi_ap"
AP_NIC_2 = "wifi_ap_2"
TEST_NS = "shuli_test"

TEST_WIFI_SSID_2 = "Test-WIFI-2"

IPV4_BLOCK_1 = "192.0.2"
IPV4_BLOCK_2 = "192.0.3"
AP1_IP = f"{IPV4_BLOCK_1}.1"
AP2_IP = f"{IPV4_BLOCK_2}.1"
STA1_IP = f"{IPV4_BLOCK_1}.10"
STA2_IP = f"{IPV4_BLOCK_2}.10"

SHULI_BIN = (
    f"{pathlib.Path(__file__).parent.parent.resolve()}/target/debug/shulid"
)
SHULI_CONFIG = "/tmp/shuli_test_multi_config.yml"
SHULI_LOG = "/tmp/shuli_test_multi_shulid.log"
CONNECT_TIMEOUT = 20

HOSTAPD1_PID = "/tmp/shuli_test_multi_hostapd1.pid"
HOSTAPD2_PID = "/tmp/shuli_test_multi_hostapd2.pid"

HOSTAPD1_CONF = f"""
interface={AP_NIC_1}
driver=nl80211
hw_mode=g
channel=1
ssid={TEST_WIFI_SSID}
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=2
sae_password={TEST_WIFI_PSK}
"""

HOSTAPD2_CONF = f"""
interface={AP_NIC_2}
driver=nl80211
hw_mode=g
channel=6
ssid={TEST_WIFI_SSID_2}
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=2
sae_password={TEST_WIFI_PSK}
"""

# Each interface binds one SSID with its own static IP config; a second
# interface with the same SSID list would prove nothing about the
# grouping, so the two SSIDs are distinct.
CONFIG = f"""\
---
version: 1
wifis:
  - ssid: {TEST_WIFI_SSID}
    password: "{TEST_WIFI_PSK}"
    interface: {TEST_NIC_1}
    ipv4:
      auto: false
      address:
        - ip: {STA1_IP}
          prefix-length: 24
      gateway: {AP1_IP}
  - ssid: {TEST_WIFI_SSID_2}
    password: "{TEST_WIFI_PSK}"
    interface: {TEST_NIC_2}
    ipv4:
      auto: false
      address:
        - ip: {STA2_IP}
          prefix-length: 24
      gateway: {AP2_IP}
"""


@pytest.fixture(scope="module")
def two_ap_env():
    """4 hwsim radios: 2 STAs + 2 APs (both APs in the test netns)."""
    exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NS}".split())
    exec_cmd("modprobe mac80211_hwsim radios=4".split())
    assert retry_till_true_or_timeout(30, has_four_nics)

    nic0 = get_nic_name_by_perm_mac(HWSIM0_PERM_MAC)
    nic1 = get_nic_name_by_perm_mac(HWSIM1_PERM_MAC)
    nic2 = get_nic_name_by_perm_mac(HWSIM2_PERM_MAC)
    nic3 = get_nic_name_by_perm_mac(HWSIM3_PERM_MAC)
    assert nic0 and nic1 and nic2 and nic3
    if nic0 != TEST_NIC_1:
        exec_cmd(f"ip link set {nic0} name {TEST_NIC_1}".split())
    if nic1 != AP_NIC_1:
        exec_cmd(f"ip link set {nic1} name {AP_NIC_1}".split())
    if nic2 != TEST_NIC_2:
        exec_cmd(f"ip link set {nic2} name {TEST_NIC_2}".split())
    if nic3 != AP_NIC_2:
        exec_cmd(f"ip link set {nic3} name {AP_NIC_2}".split())

    for phy_nic in (AP_NIC_1, AP_NIC_2):
        phy = get_wifi_phy_name(phy_nic)
        exec_cmd(f"iw phy#{phy} set netns name {TEST_NS}".split())
    exec_cmd(f"ip link set {TEST_NIC_1} up".split())
    exec_cmd(f"ip link set {TEST_NIC_2} up".split())
    for ap_nic, ap_ip in ((AP_NIC_1, AP1_IP), (AP_NIC_2, AP2_IP)):
        exec_cmd(
            f"ip netns exec {TEST_NS} ip link set {ap_nic} up".split()
        )
        exec_cmd(
            f"ip netns exec {TEST_NS} ip addr add {ap_ip}/24 "
            f"dev {ap_nic}".split()
        )

    with open("/tmp/shuli_test_multi_hostapd1.conf", "w") as fd:
        fd.write(HOSTAPD1_CONF)
    with open("/tmp/shuli_test_multi_hostapd2.conf", "w") as fd:
        fd.write(HOSTAPD2_CONF)
    exec_cmd(
        f"ip netns exec {TEST_NS} hostapd -B -dd -t "
        f"-f /tmp/shuli_test_multi_hostapd1.log "
        f"-P {HOSTAPD1_PID} /tmp/shuli_test_multi_hostapd1.conf".split()
    )
    exec_cmd(
        f"ip netns exec {TEST_NS} hostapd -B -dd -t "
        f"-f /tmp/shuli_test_multi_hostapd2.log "
        f"-P {HOSTAPD2_PID} /tmp/shuli_test_multi_hostapd2.conf".split()
    )
    assert retry_till_true_or_timeout(10, both_aps_up)
    yield

    for pid_path in (HOSTAPD1_PID, HOSTAPD2_PID):
        if os.path.exists(pid_path):
            with open(pid_path) as fd:
                pid = fd.read().strip()
            if pid:
                exec_cmd(f"kill {pid}".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NS}".split(), check=False)
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


def has_four_nics():
    try:
        exec_cmd("udevadm settle".split(), check=False)
        return all(
            get_nic_name_by_perm_mac(mac)
            for mac in (HWSIM0_PERM_MAC, HWSIM1_PERM_MAC,
                        HWSIM2_PERM_MAC, HWSIM3_PERM_MAC)
        )
    except Exception:
        return False


def both_aps_up():
    output = exec_cmd(f"iw {TEST_NIC_1} scan".split(), check=False)[1]
    return TEST_WIFI_SSID in output and TEST_WIFI_SSID_2 in output


def _read_log():
    with open(SHULI_LOG) as fd:
        return fd.read()


def _start_shulid():
    if not os.path.isfile(SHULI_BIN):
        pytest.skip(f"{SHULI_BIN} not found, build it first (cargo build)")

    with open(SHULI_CONFIG, "w") as fd:
        fd.write(CONFIG)

    log_f = open(SHULI_LOG, "w")
    daemon_proc = subprocess.Popen(
        [SHULI_BIN, SHULI_CONFIG],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        env={**os.environ, "RUST_LOG": "info"},
        start_new_session=True,
    )
    try:
        assert retry_till_true_or_timeout(
            CONNECT_TIMEOUT, lambda: "2 interface(s)" in _read_log()
        ), "shulid did not start both interfaces; log:\n" + _read_log()
    except BaseException:
        if daemon_proc.poll() is not None:
            print(f"shulid exited early with rc={daemon_proc.returncode}")
        raise
    return daemon_proc


def _terminate_shulid(daemon_proc):
    daemon_proc.terminate()
    try:
        daemon_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        daemon_proc.kill()
        daemon_proc.wait()


def _iface_addrs(nic):
    rc, out, err = exec_cmd(f"ip -j addr show dev {nic}".split(), check=False)
    assert rc == 0, f"ip addr show {nic} failed: {err}"
    addrs = []
    for entry in json.loads(out):
        for info in entry.get("addr_info", []):
            addrs.append(info["local"])
    return addrs


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestMultiInterface:
    def test_two_interfaces_connect_concurrently(self, two_ap_env):
        daemon_proc = _start_shulid()
        try:
            # Both SSIDs reach a connected state, each on its own
            # interface, and both static IP configs get applied.
            assert retry_till_true_or_timeout(
                CONNECT_TIMEOUT,
                lambda: (
                    f"connection established to '{TEST_WIFI_SSID}' on "
                    f"{TEST_NIC_1}"
                    in _read_log()
                    and f"connection established to '{TEST_WIFI_SSID_2}' "
                    f"on {TEST_NIC_2}"
                    in _read_log()
                ),
            ), "both interfaces did not connect; log:\n" + _read_log()

            assert retry_till_true_or_timeout(
                CONNECT_TIMEOUT,
                lambda: STA1_IP in _iface_addrs(TEST_NIC_1),
            ), f"static IP {STA1_IP} not applied; log:\n" + _read_log()
            assert retry_till_true_or_timeout(
                CONNECT_TIMEOUT,
                lambda: STA2_IP in _iface_addrs(TEST_NIC_2),
            ), f"static IP {STA2_IP} not applied; log:\n" + _read_log()

            # Data path on both encrypted links: an ICMP echo to each
            # AP through its own STA interface.
            for nic, ap_ip in ((TEST_NIC_1, AP1_IP), (TEST_NIC_2, AP2_IP)):
                ponged = False
                last_err = ""
                for _ in range(5):
                    out = subprocess.run(
                        f"ping -I {nic} -c 1 -W 1 {ap_ip}".split(),
                        capture_output=True,
                        text=True,
                    )
                    if out.returncode == 0:
                        ponged = True
                        break
                    last_err = out.stdout + out.stderr
                    time.sleep(0.5)
                assert ponged, (
                    f"ICMP echo via {nic} to {ap_ip} never succeeded: "
                    f"{last_err}; log:\n" + _read_log()
                )
        finally:
            _terminate_shulid(daemon_proc)
