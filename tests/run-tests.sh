#!/bin/bash -e
# SPDX-License-Identifier: Apache-2.0
#
# Run the shuli integration tests (WPA3-Personal SAE) via pytest.
#
# Sets up a mac80211_hwsim virtual AP (hostapd, WPA3-SAE/H2E) and STA (shulid),
# then verifies that shulid completes SAE authentication + the 4-way handshake,
# installs keys, and that data flows by pinging the AP's IP address.
#
# Prerequisites:
#   - root (uses sudo when invoked as non-root)
#   - mac80211_hwsim, hostapd (SAE), dnsmasq, iw, pytest

EXEC_PATH=$(dirname "$(realpath "$0")")
PROJECT_PATH="$(dirname "$EXEC_PATH")"

if [ $UID -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# Build the shulid binary if it is missing.
cd "$PROJECT_PATH"
[ -x target/debug/shulid ] || cargo build

cd "$EXEC_PATH"
$SUDO pytest --verbose --verbose --durations=5 "$@"
