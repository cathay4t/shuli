#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Capture everything needed to debug a WiFi disconnect/reconnect:
#   - nl80211 netlink packets (commands, replies and events)
#   - nipart/shuli events
#   - kernel messages
#   - `iw event` stream
#   - periodic interface/stations/power-save snapshots
#
# Usage:
#   tools/monitor_wifi.sh
#   CHUNK=600 SNAPSHOT_INTERVAL=30 tools/monitor_wifi.sh
#   WIFI_IFACE=wlan0 tools/monitor_wifi.sh
#
# Environment:
#   WIFI_DEBUG_DIR      output root (default: ~/tmp/wifi_debug)
#   WIFI_IFACE          wireless interface (default: first interface from iw)
#   NIPART_SERVICE      systemd unit to log (default: nipart.service)
#   CHUNK               seconds per capture file (default: 600)
#   SNAPSHOT_INTERVAL   seconds between state snapshots (default: 30)
#
# Stop with Ctrl-C. Data goes to $WIFI_DEBUG_DIR/<timestamp>/ and
# $WIFI_DEBUG_DIR/latest points at the newest session.
#
# Requires root, or passwordless sudo for: modprobe, ip, tcpdump,
# journalctl and iw.

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname -- "$SCRIPT_DIR")

BASE="${WIFI_DEBUG_DIR:-$HOME/tmp/wifi_debug}"
CHUNK="${CHUNK:-600}"
SNAPSHOT_INTERVAL="${SNAPSHOT_INTERVAL:-30}"
IFACE="${WIFI_IFACE:-}"
SERVICE="${NIPART_SERVICE:-nipart.service}"

if [ "$(id -u)" -eq 0 ]; then
    SUDO=()
else
    SUDO=(sudo)
fi

have() {
    command -v "$1" >/dev/null 2>&1
}

if [ "$(id -u)" -ne 0 ] && ! have sudo; then
    echo "error: run as root or install sudo" >&2
    exit 1
fi
for cmd in ip iw tcpdump tshark timeout mergecap; do
    if ! have "$cmd"; then
        echo "error: required command not found: $cmd" >&2
        exit 1
    fi
done

SESSION="$BASE/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$SESSION" || exit 1
rm -f "$BASE/latest"
ln -s "$SESSION" "$BASE/latest"

BGPIDS=()
CREATED_NLMON=0

log() {
    printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$SESSION/monitor.log" >&2
}

if [ -z "$IFACE" ]; then
    IFACE=$(iw dev 2>/dev/null |
        awk '$1 == "Interface" { print $2; exit }')
fi

snapshot() {
    {
        echo
        echo "===== $(date -Is) ====="
        ip -br link
        ip -br addr
        ip route
        ip -s link show "$IFACE" 2>/dev/null
        iw dev
        if [ -n "$IFACE" ]; then
            iw dev "$IFACE" link
            iw dev "$IFACE" station dump
            iw dev "$IFACE" get power_save
            if have ethtool; then
                ethtool -S "$IFACE" 2>/dev/null
            fi
        fi
    } >>"$SESSION/snapshots.log" 2>&1
}

cleanup() {
    trap - INT TERM EXIT
    log "stopping monitor"
    for pid in "${BGPIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    if [ "$CREATED_NLMON" = 1 ]; then
        "${SUDO[@]}" ip link del nlmon0 2>/dev/null || true
    fi
    sync
    log "session saved: $SESSION"
    exit 0
}
trap cleanup INT TERM EXIT

log "session=$SESSION iface=${IFACE:-none} chunk=${CHUNK}s snapshot=${SNAPSHOT_INTERVAL}s"

# One-time environment snapshot. Do not copy configuration files: they may
# contain credentials.
{
    echo "session: $SESSION"
    echo "started: $(date -Is)"
    echo "script: $SCRIPT_DIR/$(basename -- "$0")"
    echo "iface: ${IFACE:-none}"
    echo "chunk: ${CHUNK}s"
    echo "snapshot: ${SNAPSHOT_INTERVAL}s"
    echo
    uname -a
    uptime
    hostname
    echo
    echo "=== nipart ==="
    if have systemctl; then
        systemctl show "$SERVICE" \
            -p ActiveEnterTimestamp -p ExecMainStartTimestamp \
            -p ExecMainPID --no-pager 2>&1
    fi
    for bin in nipart nipart-plugin-wifi; do
        path=$(command -v "$bin" 2>/dev/null || true)
        if [ -n "$path" ]; then
            sha256sum "$path" 2>&1 || true
            ls -l "$path" 2>&1 || true
        fi
    done
    echo
    echo "=== shuli ==="
    git -C "$REPO_DIR" rev-parse HEAD 2>&1 || true
    git -C "$REPO_DIR" status --short 2>&1 || true
    echo
    echo "=== interfaces ==="
    ip -br link
    ip -br addr
    ip route
    echo
    echo "=== wireless ==="
    iw dev
    iw phy
    iw reg get
    if [ -n "$IFACE" ]; then
        iw dev "$IFACE" link
        iw dev "$IFACE" station dump
        iw dev "$IFACE" get power_save
        if have ethtool; then
            ethtool -i "$IFACE"
            ethtool -S "$IFACE"
        fi
    fi
    echo
    echo "=== rfkill ==="
    if have rfkill; then
        rfkill list 2>&1 || true
    fi
    echo
    echo "=== modules ==="
    lsmod | grep -E \
        'mac80211|cfg80211|mt76|mt792|iwl|ath|rtw|brcm|hwsim|nlmon' \
        2>&1 || true
    echo
    echo "=== pci ==="
    if have lspci; then
        lspci -nnk 2>&1 | grep -A4 -iE 'network|wireless' || true
    fi
} >"$SESSION/session-info.txt" 2>&1

cat >"$SESSION/README.txt" <<EOF
WiFi debug session: $SESSION

Files:
  genl-family-map.pcapng
                     generic-netlink family map for nl80211
  nl80211-*.pcapng   nl80211 netlink packets (commands, replies, events)
  nl80211-*.tcpdump.log / .tshark.log
                     capture diagnostics (check for dropped packets)
  nipart-events.log  filtered nipart/shuli events
  kernel.log         live kernel log
  iw-events.log      nl80211 event stream with timestamps
  snapshots.log      interface/station/power-save snapshots
  session-info.txt   environment, versions, initial state
  monitor.log        this script's own log

Inspect packets:
  mergecap -a -w /tmp/nl80211-all.pcapng $SESSION/genl-family-map.pcapng \\
      $SESSION/nl80211-*.pcapng
  tshark -r /tmp/nl80211-all.pcapng -Y nl80211
  tshark -r /tmp/nl80211-all.pcapng -Y 'nl80211.ifname == "$IFACE"'
  wireshark /tmp/nl80211-all.pcapng

Note: nlmon captures all netlink traffic. Each chunk starts with the
generic-netlink family mapping for nl80211 so Wireshark/tshark can decode
the nl80211 messages after the capture was filtered.
EOF

# Load/attach the netlink monitor device.
if have modprobe; then
    "${SUDO[@]}" modprobe nlmon 2>/dev/null || true
fi
if ! ip link show nlmon0 >/dev/null 2>&1; then
    "${SUDO[@]}" ip link add nlmon0 type nlmon || {
        log "could not create nlmon0; is the nlmon module available?"
        exit 1
    }
    CREATED_NLMON=1
fi
"${SUDO[@]}" ip link set nlmon0 up || exit 1

# Save the generic-netlink family mapping for nl80211. Without it a
# filtered capture cannot be decoded again later: the family id is
# assigned dynamically and the resolution packet is not an nl80211
# packet itself. Prepend this small capture to every chunk.
FAMILY_MAP="$SESSION/genl-family-map.pcapng"
FAMILY_ALL="$SESSION/genl-family-all.pcapng"
rm -f "$FAMILY_ALL" "$FAMILY_MAP"
(timeout 3 "${SUDO[@]}" tcpdump -U -i nlmon0 -s0 -w "$FAMILY_ALL" \
    2>"$SESSION/family-map.tcpdump.log") &
FAMILY_PID=$!
sleep 0.5
# Any new nl80211 userspace socket resolves the family before its first
# command, so `iw dev` reliably emits the mapping we need.
for _ in 1 2 3; do
    iw dev >/dev/null 2>&1 || true
    sleep 0.2
done
wait "$FAMILY_PID" 2>/dev/null || true
tshark -r "$FAMILY_ALL" \
    -Y 'genl.ctrl.family_name == "nl80211"' \
    -w "$FAMILY_MAP" >/dev/null 2>"$SESSION/family-map.tshark.log" \
    || true
rm -f "$FAMILY_ALL"

# Kernel log, nipart/shuli events, and the nl80211 event stream.
"${SUDO[@]}" journalctl -k -f -n 0 -o short-iso-precise \
    >"$SESSION/kernel.log" 2>&1 &
BGPIDS+=("$!")

"${SUDO[@]}" journalctl -u "$SERVICE" -f -n 0 -o short-iso-precise \
    2>/dev/null |
    grep -E --line-buffered \
        'shuli_wifi|nipart_plugin_wifi|WIFI connected|WIFI .* state|connection lost|disconnect|reconnect|nl80211|DHCP|Failed; retrying|PMKSA|EAPOL|4-way|SAE|assoc|auth|driver/firmware|WARN|ERROR' \
        >"$SESSION/nipart-events.log" 2>&1 &
BGPIDS+=("$!")

"${SUDO[@]}" stdbuf -oL iw event -t >"$SESSION/iw-events.log" 2>&1 &
BGPIDS+=("$!")

# Periodic state snapshots.
(
    while :; do
        sleep "$SNAPSHOT_INTERVAL"
        snapshot
    done
) &
BGPIDS+=("$!")

# Stream every netlink message through tshark and write only nl80211.
# Chunk the output so a multi-hour run cannot create one unbounded file.
while :; do
    f="$SESSION/nl80211-$(date +%Y%m%d-%H%M%S).pcapng"
    log "capture chunk -> $(basename -- "$f")"
    timeout "$CHUNK" \
        "${SUDO[@]}" tcpdump -U -B 8192 -i nlmon0 -s0 -w - \
        2>"$f.tcpdump.log" |
        tshark -n -r - -Y nl80211 -w "$f" >/dev/null 2>"$f.tshark.log"
    if [ -s "$FAMILY_MAP" ] && have mergecap; then
        if mergecap -a -w "$f.tmp" "$FAMILY_MAP" "$f" \
            >>"$f.tshark.log" 2>&1; then
            mv "$f.tmp" "$f"
        else
            rm -f "$f.tmp"
        fi
    fi
    # timeout ends one chunk; SIGINT is handled by cleanup.
    sleep 1
done
