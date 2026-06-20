#!/bin/bash -e
# SPDX-License-Identifier: Apache-2.0
#
# Integration test for shulid (WPA3-Personal SAE).
#
# Sets up a mac80211_hwsim virtual AP (hostapd, WPA3-SAE/H2E) and STA (shulid),
# then verifies that shulid completes SAE authentication + the 4-way handshake,
# installs keys, and that data flows by pinging the AP's IP address.
#
# Prerequisites:
#   - root, mac80211_hwsim, hostapd (SAE), dnsmasq, jq, iw

TEST_NS="shuli_test"
AP_SSID="Test-WIFI"
AP_PASSWORD="12345678"
IPV4_BLOCK="192.0.2"
AP_IP="${IPV4_BLOCK}.1"
STA_IP="${IPV4_BLOCK}.10"

PID_DNSMASQ="/tmp/shuli_test_dnsmasq.pid"
SHULI_CONFIG="/tmp/shuli_test_config.yml"
HOSTAPD_CONF="/tmp/shuli_test_hostapd.conf"
SHULI_LOG="/tmp/shuli_test_shulid.log"
CONNECT_TIMEOUT=15

[ "$(id -u)" -ne 0 ] && { echo "SKIP: root required"; exit 0; }

SHULI_BIN="./target/debug/shulid"
[ ! -x "$SHULI_BIN" ] && { echo "SKIP: $SHULI_BIN not found"; exit 0; }

SHULI_PID=""
function cleanup {
    set +e
    [ -n "$SHULI_PID" ] && kill "$SHULI_PID" 2>/dev/null
    sudo kill "$(cat $PID_DNSMASQ 2>/dev/null)" 2>/dev/null
    sudo ip netns exec $TEST_NS pkill -f hostapd 2>/dev/null
    sudo ip netns del $TEST_NS 2>/dev/null
    sudo modprobe -r mac80211_hwsim 2>/dev/null
    rm -f "$SHULI_CONFIG" "$HOSTAPD_CONF" "$PID_DNSMASQ"
}
trap cleanup EXIT
cleanup

echo "=== Loading mac80211_hwsim ==="
sudo modprobe mac80211_hwsim radios=2
sleep 1

NIC1=$(ip -j link show wlx020000000000 | jq -r '.[0]["ifname"]')
NIC2=$(ip -j link show wlx020000000100 | jq -r '.[0]["ifname"]')
PHY2=$(iw dev "$NIC2" info | sed -ne 's/.\+wiphy \([0-9]\+\)$/\1/p')
echo "NIC1 (STA) = $NIC1"
echo "NIC2 (AP)  = $NIC2"

echo "=== Setting up AP namespace ==="
sudo ip netns add $TEST_NS 2>/dev/null || true
sudo ip link set "$NIC1" up
sudo iw phy#"$PHY2" set netns name $TEST_NS
sudo ip netns exec $TEST_NS ip link set "$NIC2" up
sudo ip netns exec $TEST_NS ip addr add "${AP_IP}/24" dev "$NIC2"

cat > "$HOSTAPD_CONF" <<EOF
interface=$NIC2
driver=nl80211
hw_mode=g
channel=1
ssid=$AP_SSID
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=2
sae_password=$AP_PASSWORD
EOF

sudo ip netns exec $TEST_NS dnsmasq \
    --pid-file="$PID_DNSMASQ" --conf-file=/dev/null \
    --no-hosts --interface="$NIC2" \
    --dhcp-range=${IPV4_BLOCK}.2,${IPV4_BLOCK}.50,2m --no-ping
sudo ip netns exec $TEST_NS hostapd -B "$HOSTAPD_CONF"
sleep 2

cat > "$SHULI_CONFIG" <<EOF
---
interfaces:
  - name: $NIC1
    type: wifi-phy
    wifi:
      ssid: $AP_SSID
      password: "$AP_PASSWORD"
EOF

echo "=== Running shulid ==="
export RUST_LOG=info
"$SHULI_BIN" --config "$SHULI_CONFIG" > "$SHULI_LOG" 2>&1 &
SHULI_PID=$!

# Wait for the connection to be established.
for _ in $(seq 1 "$CONNECT_TIMEOUT"); do
    grep -q "connection established" "$SHULI_LOG" && break
    kill -0 "$SHULI_PID" 2>/dev/null || break
    sleep 1
done

cat "$SHULI_LOG"

if ! grep -q "connection established" "$SHULI_LOG"; then
    echo "FAIL: shulid did not establish a connection"
    exit 1
fi
echo "PASS: shulid established the WPA3-SAE connection"

echo "=== Verifying data path (ping ${AP_IP}) ==="
sudo ip addr add "${STA_IP}/24" dev "$NIC1"
sudo ip link set "$NIC1" up
sleep 1
if ping -c 3 -W 2 "$AP_IP" > /dev/null 2>&1; then
    echo "PASS: ping ${AP_IP} succeeded - data path works"
else
    echo "FAIL: ping ${AP_IP} failed"
    exit 1
fi

echo "=== Integration test PASSED ==="
