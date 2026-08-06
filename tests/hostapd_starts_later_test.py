# SPDX-License-Identifier: Apache-2.0

"""shulid must back off (not hammer scans at 10 s) while the AP is
absent, then connect once hostapd starts later.

mac80211_hwsim does not implement sched_scan_start, so shulid falls back
to host-side exponential backoff here; that fallback path is what this
test exercises end-to-end.
"""

import os
import pathlib
import re
import subprocess
import time

import pytest

from .testlib.cmdlib import exec_cmd
from .testlib.env import has_kernel_module
from .testlib.retry import retry_till_true_or_timeout
from .testlib.wifi import (
    AP_NIC,
    HWSIM0_PERM_MAC,
    HWSIM1_PERM_MAC,
    TEST_NET_NS,
    TEST_NIC,
    TEST_WIFI_PSK,
    TEST_WIFI_SSID,
    TIMEOUT_SECS_SIM_WIFI_NICS,
    get_nic_name_by_perm_mac,
    has_sim_wifi_nics,
    start_hostapd,
    stop_hostapd,
    unload_wifi_sim_kernel_module,
)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="root required (mac80211_hwsim, netns and hostapd)",
)

SHULI_BIN = (
    f"{pathlib.Path(__file__).parent.parent.resolve()}/target/debug/shulid"
)
SHULI_CONFIG = "/tmp/shuli_test_later_config.yml"
SHULI_LOG = "/tmp/shuli_test_later_shulid.log"

# How many backoff retries to observe before starting the AP.  Each step
# costs ~3 s of scanning plus the backoff sleep (10, 20, 40, 80 s), so
# observing 4 retries takes ~80 s.
MIN_BACKOFF_STEPS = 4
PHASE1_TIMEOUT = 150
# After the last observed retry, the next scan can be up to the current
# backoff interval away, plus scan and auth time.
CONNECT_TIMEOUT = 150

RETRY_RE = re.compile(r"retrying in (\d+) seconds")


@pytest.fixture(scope="module")
def wifi_env_no_ap():
    """mac80211_hwsim + netns with the AP radio present but hostapd NOT
    running.  The AP phy is moved into the netns later by start_hostapd().
    """
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
    exec_cmd(f"ip link set {TEST_NIC} up".split())

    yield

    stop_hostapd()
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestHostapdStartsLater:
    def test_shulid_backs_off_then_connects(self, wifi_env_no_ap):
        if not os.path.isfile(SHULI_BIN):
            pytest.skip(f"{SHULI_BIN} not found, build it first (cargo build)")

        with open(SHULI_CONFIG, "w") as fd:
            fd.write(f"""---
version: 1
wifis:
  - ssid: {TEST_WIFI_SSID}
    password: "{TEST_WIFI_PSK}"
    interface: {TEST_NIC}
""")

        log_f = open(SHULI_LOG, "w")
        daemon_proc = subprocess.Popen(
            [SHULI_BIN, SHULI_CONFIG],
            stdout=log_f,
            stderr=subprocess.STDOUT,
            env={**os.environ, "RUST_LOG": "info"},
            start_new_session=True,
        )
        try:
            # Phase 1: no AP present - shulid must retry with growing
            # backoff instead of hammering scans on a fixed 10 s cycle.
            values, first_ts, last_ts = _wait_for_retry_count(
                MIN_BACKOFF_STEPS, PHASE1_TIMEOUT
            )
            log = _read_log()
            assert len(values) >= MIN_BACKOFF_STEPS, (
                f"expected >= {MIN_BACKOFF_STEPS} retries, got "
                f"{values};\n{log}"
            )
            assert values[:MIN_BACKOFF_STEPS] == [10, 20, 40, 80], (
                f"expected exponential backoff 10,20,40,80..., got "
                f"{values};\n{log}"
            )
            # A fixed 10 s retry loop would span only ~39 s between the
            # 1st and 4th retry; exponential backoff needs ~79 s.  This
            # proves the scans are not hammering at 10 s.
            span = last_ts - first_ts
            assert span >= 60, (
                f"retries only spanned {span:.0f}s - looks like a fixed "
                f"10 s loop;\n{log}"
            )
            scans = len(re.findall(r"scanning for SSID", log))
            assert scans <= 5, (
                f"too many scans ({scans}) during the backoff window;\n{log}"
            )

            # Phase 2: the AP appears; shulid must find it on a later
            # periodic scan and connect.
            start_hostapd()
            assert retry_till_true_or_timeout(
                CONNECT_TIMEOUT, _shulid_connected
            ), "shulid did not connect after the AP appeared;\n" + _read_log()
        finally:
            daemon_proc.terminate()
            try:
                daemon_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon_proc.kill()
                daemon_proc.wait()
            log_f.close()


def _retry_values():
    return [int(m) for m in RETRY_RE.findall(_read_log())]


def _wait_for_retry_count(n, timeout):
    deadline = time.time() + timeout
    first_ts = None
    last_ts = None
    while time.time() < deadline:
        values = _retry_values()
        if values and first_ts is None:
            first_ts = time.time()
        if len(values) >= n:
            last_ts = time.time()
            return values, first_ts, last_ts
        time.sleep(1)
    values = _retry_values()
    return values, first_ts, time.time()


def _shulid_connected():
    return "connection established" in _read_log()


def _read_log():
    with open(SHULI_LOG) as fd:
        return fd.read()
