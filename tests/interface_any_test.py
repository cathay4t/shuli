# SPDX-License-Identifier: Apache-2.0

"""`interface: any` (or an absent `interface`) must resolve to the first
WiFi interface found and apply the SSID's IP config (static or DHCP) to
it.  This mirrors `examples/config.yml`: `Test-WIFI` has no `interface`
key, `Test-WIFI-OPEN` uses `interface: any`; both mean "any".
"""

import json
import os
import pathlib
import re
import subprocess

import pytest

from .testlib.cmdlib import exec_cmd
from .testlib.env import has_kernel_module
from .testlib.retry import retry_till_true_or_timeout
from .testlib.wifi import (
    AP_IP,
    HWSIM0_PERM_MAC,
    IPV4_BLOCK,
    TEST_WIFI_PSK,
    TEST_WIFI_SSID,
    get_nic_name_by_perm_mac,
    wifi_env,  # noqa: F401  (module-scoped fixture)
)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="root required (mac80211_hwsim, netns and hostapd)",
)

SHULI_BIN = (
    f"{pathlib.Path(__file__).parent.parent.resolve()}/target/debug/shulid"
)
SHULI_CONFIG = "/tmp/shuli_test_any_config.yml"
SHULI_LOG = "/tmp/shuli_test_any_shulid.log"
CONNECT_TIMEOUT = 15
# mozim's DHCP has a 30 s timeout; give the lease a margin on top.
DHCP_TIMEOUT = 40

# dnsmasq lease pool configured in testlib/wifi.py: .2 .. .50.
DHCP_LEASE_MIN = 2
DHCP_LEASE_MAX = 50

STA_STATIC_IP = f"{IPV4_BLOCK}.10"

# Explicit `interface: any` + full static IP config (mirrors the
# Test-WIFI-OPEN shape in examples/config.yml, but static).
CONFIG_ANY_STATIC = f"""\
---
version: 1
wifis:
  - ssid: {TEST_WIFI_SSID}
    password: "{TEST_WIFI_PSK}"
    interface: any
    ipv4:
      auto: false
      address:
        - ip: {STA_STATIC_IP}
          prefix-length: 24
      gateway: {AP_IP}
"""

# No `interface` key at all: must behave exactly like `interface: any`.
# DHCP (mirrors Test-WIFI in examples/config.yml).
CONFIG_ABSENT_DHCP = f"""\
---
version: 1
wifis:
  - ssid: {TEST_WIFI_SSID}
    password: "{TEST_WIFI_PSK}"
    ipv4:
      auto: true
"""


def _read_log():
    with open(SHULI_LOG) as fd:
        return fd.read()


def _shulid_connected():
    if not os.path.exists(SHULI_LOG):
        return False
    return "connection established" in _read_log()


def _start_shulid(config_yaml):
    """Launch shulid with `config_yaml`, wait for the connection to be
    up, and return the process (caller terminates it)."""
    if not os.path.isfile(SHULI_BIN):
        pytest.skip(f"{SHULI_BIN} not found, build it first (cargo build)")

    with open(SHULI_CONFIG, "w") as fd:
        fd.write(config_yaml)

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
            CONNECT_TIMEOUT, _shulid_connected
        ), "shulid did not establish a connection; log:\n" + _read_log()
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


def _resolved_iface():
    """The WiFi interface shulid bound to after resolving `any`."""
    match = re.search(
        r"shulid: \d+ interface\(s\): (\S+) \(\d+ ssid\)", _read_log()
    )
    assert match, "shulid did not log the resolved iface:\n" + _read_log()
    return match.group(1)


def _iface_addrs(nic):
    rc, out, err = exec_cmd(f"ip -j addr show dev {nic}".split(), check=False)
    assert rc == 0, f"ip addr show {nic} failed: {err}"
    addrs = []
    for entry in json.loads(out):
        for info in entry.get("addr_info", []):
            addrs.append(info["local"])
    return addrs


def _default_routes():
    """Existing default routes as (dev, gateway, metric) tuples; metric
    is None when the route carries none."""
    rc, out, err = exec_cmd("ip -j route show default".split(), check=False)
    assert rc == 0, f"ip route show default failed: {err}"
    routes = []
    for route in json.loads(out):
        routes.append(
            (
                route.get("dev"),
                route.get("gateway"),
                route.get("metric"),
            )
        )
    return routes


def _default_route_via(nic, gateway):
    """(exists, metric) of the default route via `gateway` on `nic`;
    metric is None when the route exists without one."""
    for dev, gw, metric in _default_routes():
        if dev == nic and gw == gateway:
            return (True, metric)
    return (False, None)


def _expected_default_route_metric():
    """The metric shulid must pick for a new default route: one larger
    than every existing default route's metric, or 500 when none of the
    existing ones has a metric; None when no default route exists at all
    (kernel-default priority).  Mirrors src/daemon/ip.rs: only default
    routes with a gateway count (the daemon's route dump skips
    gateway-less ones)."""
    # (dev, gateway, metric) - keep only gateway routes.
    existing = [r for r in _default_routes() if r[1] is not None]
    if not existing:
        return None
    metrics = [metric for (_, _, metric) in existing if metric is not None]
    if not metrics:
        return 500
    return max(metrics) + 1


def _flush_iface_ip(nic):
    """Reset the STA NIC's L3 state so tests are independent."""
    exec_cmd(f"ip addr flush dev {nic}".split(), check=False)
    exec_cmd(f"ip route flush dev {nic}".split(), check=False)


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestInterfaceAny:
    def test_interface_any_applies_static_ip(self, wifi_env):
        nic = get_nic_name_by_perm_mac(HWSIM0_PERM_MAC)
        assert nic
        _flush_iface_ip(nic)
        # Baseline before shulid runs: what the daemon must add the
        # route with (larger metric than existing, or 500).
        expected_metric = _expected_default_route_metric()

        daemon_proc = _start_shulid(CONFIG_ANY_STATIC)
        try:
            # SSID connection on the interface `any` resolved to.
            assert _resolved_iface() == nic
            assert (
                f"connection established to '{TEST_WIFI_SSID}'"
                in _read_log()
            )

            # Static IP config applied to that same interface.
            assert retry_till_true_or_timeout(
                CONNECT_TIMEOUT,
                lambda: STA_STATIC_IP in _iface_addrs(nic),
            ), "static IP was not applied; log:\n" + _read_log()
            # The gateway route must coexist with the host's own default
            # route: less preferred (bigger metric), 500 when the
            # current one has no metric.
            assert retry_till_true_or_timeout(
                CONNECT_TIMEOUT,
                lambda: _default_route_via(nic, AP_IP)
                == (True, expected_metric),
            ), (
                f"default route via {AP_IP} not applied with metric "
                f"{expected_metric}; log:\n" + _read_log()
            )
        finally:
            _terminate_shulid(daemon_proc)

    def test_absent_interface_applies_dhcp(self, wifi_env):
        nic = get_nic_name_by_perm_mac(HWSIM0_PERM_MAC)
        assert nic
        _flush_iface_ip(nic)
        expected_metric = _expected_default_route_metric()

        # The daemon writes the lease DNS to /etc/resolv.conf; keep the
        # host file intact across the test.
        resolv_conf = "/etc/resolv.conf"
        resolv_backup = None
        if os.path.exists(resolv_conf):
            with open(resolv_conf) as fd:
                resolv_backup = fd.read()

        daemon_proc = _start_shulid(CONFIG_ABSENT_DHCP)
        try:
            # SSID connection on the interface the absent `interface`
            # key resolved to.
            assert _resolved_iface() == nic
            assert (
                f"connection established to '{TEST_WIFI_SSID}'"
                in _read_log()
            )

            # DHCP lease applied to that same interface.  The lease pool
            # of the test dnsmasq is 192.0.2.2 .. 192.0.2.50.
            def dhcp_lease_addr():
                for addr in _iface_addrs(nic):
                    if addr.startswith(f"{IPV4_BLOCK}."):
                        last = int(addr.rsplit(".", 1)[1])
                        if DHCP_LEASE_MIN <= last <= DHCP_LEASE_MAX:
                            return addr
                return None

            lease = retry_till_true_or_timeout(DHCP_TIMEOUT, dhcp_lease_addr)
            assert lease, (
                "no DHCP lease on the resolved interface; log:\n"
                + _read_log()
            )
            assert "DHCPv4 lease acquired" in _read_log()

            # The lease gateway route must coexist with the host's own
            # default route, same metric rule as the static path.
            assert retry_till_true_or_timeout(
                CONNECT_TIMEOUT,
                lambda: _default_route_via(nic, AP_IP)
                == (True, expected_metric),
            ), (
                f"DHCP gateway route via {AP_IP} not applied with metric "
                f"{expected_metric}; log:\n" + _read_log()
            )
        finally:
            _terminate_shulid(daemon_proc)
            if resolv_backup is not None:
                with open(resolv_conf, "w") as fd:
                    fd.write(resolv_backup)
