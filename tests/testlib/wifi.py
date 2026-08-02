# SPDX-License-Identifier: Apache-2.0

import json
import os
import re

import pytest

from .cmdlib import exec_cmd
from .retry import retry_till_true_or_timeout

HWSIM0_PERM_MAC = "02:00:00:00:00:00"
HWSIM1_PERM_MAC = "02:00:00:00:01:00"

TEST_NET_NS = "shuli_test"
TEST_WIFI_SSID = "Test-WIFI"
TEST_WIFI_PSK = "12345678"

# The STA NIC lives in the default net namespace (shulid runs there), while the
# AP NIC is moved into TEST_NET_NS together with hostapd.
TEST_NIC = "test-wlan0"
AP_NIC = "wifi_ap"

IPV4_BLOCK = "192.0.2"
AP_IP = f"{IPV4_BLOCK}.1"
STA_IP = f"{IPV4_BLOCK}.10"

HOSTAPD_CONF_PATH = "/tmp/shuli_test_hostapd.conf"
HOSTAPD_PID_PATH = "/tmp/shuli_test_hostapd.pid"
DNSMASQ_PID_PATH = "/tmp/shuli_test_dnsmasq.pid"

TIMEOUT_SECS_SIM_WIFI_NICS = 30

# WPA3-Personal (SAE) AP configuration, same as the old tests/integration.sh.
HOSTAPD_CONF = f"""
interface={AP_NIC}
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


@pytest.fixture(scope="module")
def wifi_env():
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
    start_hostapd()
    yield
    stop_hostapd()
    stop_dhcp_server()
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


def unload_wifi_sim_kernel_module():
    try:
        exec_cmd("modprobe -r mac80211_hwsim".split())
        return True
    except Exception:
        return False


def get_nic_name_by_perm_mac(mac):
    rc, out, err = exec_cmd("ip -j link show".split())
    if rc != 0:
        return None
    links = json.loads(out)
    for link in links:
        if link.get("address") == mac:
            return link["ifname"]
    # Fallback for udev-renamed interfaces (e.g. wlx020000000000).
    udev_name = "wlx" + mac.replace(":", "")
    for link in links:
        if link.get("ifname") == udev_name:
            return udev_name
    return None


def has_sim_wifi_nics():
    try:
        exec_cmd("udevadm settle".split(), check=False)
        return bool(
            get_nic_name_by_perm_mac(HWSIM0_PERM_MAC)
            and get_nic_name_by_perm_mac(HWSIM1_PERM_MAC)
        )
    except Exception:
        return False


def get_wifi_phy_name(nic_name):
    output = exec_cmd(f"iw dev {nic_name} info".split())[1]
    match = re.search(r"[^a-zA-Z]wiphy ([0-9]+)", output)
    assert match, f"failed to get wiphy number of {nic_name}"
    return match.group(1)


def hostapd_is_up():
    output = exec_cmd(f"iw {TEST_NIC} scan".split(), check=False)[1]
    return TEST_WIFI_SSID in output


def start_hostapd():
    phy_id = get_wifi_phy_name(AP_NIC)
    assert phy_id
    # Move the AP phy into the net namespace that runs hostapd.
    exec_cmd(f"iw phy#{phy_id} set netns name {TEST_NET_NS}".split())
    exec_cmd(f"ip link set {TEST_NIC} up".split())
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} ip link set {AP_NIC} up".split()
    )
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} "
        f"ip addr add {AP_IP}/24 dev {AP_NIC}".split()
    )
    with open(HOSTAPD_CONF_PATH, "w") as fd:
        fd.write(HOSTAPD_CONF)
    start_dhcp_server()
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} hostapd -B "
        f"-P {HOSTAPD_PID_PATH} {HOSTAPD_CONF_PATH}".split()
    )
    assert retry_till_true_or_timeout(5, hostapd_is_up)


def stop_hostapd():
    if not os.path.exists(HOSTAPD_PID_PATH):
        return
    with open(HOSTAPD_PID_PATH) as fd:
        pid = fd.read().strip()
    if pid:
        exec_cmd(f"kill {pid}".split(), check=False)
    try:
        os.remove(HOSTAPD_PID_PATH)
    except FileNotFoundError:
        pass


def start_dhcp_server():
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} dnsmasq "
        f"--pid-file={DNSMASQ_PID_PATH} --conf-file=/dev/null "
        f"--no-hosts --interface={AP_NIC} "
        f"--dhcp-range={IPV4_BLOCK}.2,{IPV4_BLOCK}.50,2m --no-ping".split()
    )


def stop_dhcp_server():
    if not os.path.exists(DNSMASQ_PID_PATH):
        return
    with open(DNSMASQ_PID_PATH) as fd:
        pid = fd.read().strip()
    if pid:
        exec_cmd(f"kill {pid}".split(), check=False)
    try:
        os.remove(DNSMASQ_PID_PATH)
    except FileNotFoundError:
        pass
