# SPDX-License-Identifier: Apache-2.0

import os
import pathlib
import subprocess

import pytest

from .testlib.retry import retry_till_true_or_timeout
from .testlib.wifi import TEST_NIC
from .testlib.wifi import TEST_WIFI_PSK
from .testlib.wifi import TEST_WIFI_SSID
from .testlib.wifi import wifi_env  # noqa: F401

project_dir = pathlib.Path(__file__).parent.parent.resolve()
SHULI_BIN = f"{project_dir}/target/debug/shulid"
SHULI_CONFIG = "/tmp/shuli_test_config.yml"
SHULI_LOG = "/tmp/shuli_test_shulid.log"
CONNECT_TIMEOUT = 15


@pytest.fixture(scope="module")
def shulid_connection(wifi_env):
    """Run shulid against the WPA3-SAE AP until the connection is up.

    The fixture waits for ``connection established`` in the shulid log and
    fails (with the log dumped) if the connection is not made in time.
    """
    if not os.path.isfile(SHULI_BIN):
        pytest.skip(f"{SHULI_BIN} not found, build it first (cargo build)")

    with open(SHULI_CONFIG, "w") as fd:
        fd.write(f"""---
interfaces:
  - name: {TEST_NIC}
    type: wifi-phy
    wifi:
      ssid: {TEST_WIFI_SSID}
      password: "{TEST_WIFI_PSK}"
""")

    log_f = open(SHULI_LOG, "w")
    daemon_proc = subprocess.Popen(
        [SHULI_BIN, "--config", SHULI_CONFIG],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        env={**os.environ, "RUST_LOG": "info"},
        start_new_session=True,
    )
    try:
        assert retry_till_true_or_timeout(
            CONNECT_TIMEOUT, shulid_connected
        ), "shulid did not establish a connection; log:\n" + _read_log()
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


def shulid_connected():
    if not os.path.exists(SHULI_LOG):
        return False
    return "connection established" in _read_log()


def _read_log():
    with open(SHULI_LOG) as fd:
        return fd.read()
