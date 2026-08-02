# SPDX-License-Identifier: Apache-2.0

import os

import pytest

from .testlib.cmdlib import exec_cmd
from .testlib.env import has_kernel_module
from .testlib.retry import retry_till_true_or_timeout
from .testlib.wifi import AP_IP
from .testlib.wifi import STA_IP
from .testlib.wifi import TEST_NIC

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="root required (mac80211_hwsim, netns and hostapd)",
)


def ping_ap():
    rc, _, _ = exec_cmd(f"ping {AP_IP} -c 1 -w 2".split(), check=False)
    return rc == 0


def _add_sta_ip():
    rc, _, _ = exec_cmd(
        f"ip addr add {STA_IP}/24 dev {TEST_NIC}".split(), check=False
    )
    if rc != 0:
        # `ip addr add` fails with EEXIST if the address is already present.
        _, out, _ = exec_cmd(f"ip addr show {TEST_NIC}".split(), check=False)
        assert f"{STA_IP}/24" in out


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestWpa3Sae:
    def test_shulid_establishes_wpa3_sae_connection(
        self, shulid_connection
    ):
        # The shulid_connection fixture already waited for the
        # "connection established" log message (SAE auth + 4-way handshake
        # + key install), so this test just needs the connection to hold.
        pass

    def test_wpa3_sae_data_path(self, shulid_connection):
        exec_cmd(f"ip link set {TEST_NIC} up".split())
        _add_sta_ip()
        assert retry_till_true_or_timeout(5, ping_ap)
