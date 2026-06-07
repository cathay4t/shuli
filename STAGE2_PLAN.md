<!-- SPDX-License-Identifier: Apache-2.0 -->
# 书立 (shuli) — Stage 2 Development Plan

> Builds on Stage 1 (working WPA3-Personal STA). Stage 2 makes shuli a
> usable, controllable daemon and a drop-in replacement for nipart's
> wpa_supplicant control code.

## 1. Stage 2 Goals

### Primary (from product brief)

1. **Control interface over a UNIX abstract socket** exposed by `shulid`,
   enabling a CLI:
   - `shulictl show` — current state of all managed interfaces / WiFi
     connections (SSID, BSSID, state, signal, auth type, rates, frequency).
   - `shulictl apply [FILE]` — apply desired state (same YAML schema as the
     daemon config) at runtime.
2. **A sufficient Rust API/library** for **nipart** (`~/Source/nipart`) to
   consume, so nipart can talk to `shulid` instead of `wpa_supplicant`.
3. **Replace nipart's wpa_supplicant control code** (the D-Bus client in
   `src/lib/no_daemon/wifi/`) with calls into shuli.

### Added goals (ready for daily WPA3-Personal use)

4. **Live query/apply** without restart: add/remove/modify networks, connect,
   disconnect, switch SSID at runtime.
5. **Scan API**: trigger scans and return BSS lists with security/signal info
   (nipart needs this for its `scan` feature).
6. **Persistence & secrets**: persist applied config to `/etc/shuli/`, keep
   passwords out of logs and query output (mirror nipart's hide-secrets
   behaviour).
7. **Event/notification stream**: clients can subscribe to connection-state
   changes (connected/disconnected/auth-failed) for monitoring.
8. **Packaging & service**: systemd unit, default config dir, man pages;
   correct privilege handling (`CAP_NET_ADMIN`).
9. **Robustness for daily use**: auto-reconnect with backoff, handle AP
   roaming/BSS loss, PMKSA caching to speed reconnects, multiple managed
   interfaces.

### Non-goals for Stage 2

- WPA2-Personal, 802.1X, WPA3-Enterprise (Stage 3).
- AP mode, mesh, P2P, DPP, OWE.
- Routing / IP / DHCP management (left to nipart / external tools).

---

## 2. Control protocol design

Mirror nipart's proven IPC so integration is natural and low-risk
(nipart: *"IPC is UNIX socket … JSON messages with 4-byte big-endian length
prefix"*, `src/lib/ipc.rs`).

- **Transport:** UNIX **abstract** socket (Linux abstract namespace, no
  filesystem path), default name e.g. `\0shuli` (configurable). Optionally also
  bind a filesystem path for tooling that can't use abstract sockets.
- **Framing:** `u32` big-endian length prefix + JSON body (identical scheme to
  nipart → trivial interop, can reuse logic).
- **Messages (request/response, versioned):**
  - `Ping → Pong`
  - `Show { filter? } → NetworkState` (all managed interfaces + wifi status)
  - `Apply { desired: DesiredState } → ApplyResult`
  - `Scan { ifaces?, ssids?, passive? } → Vec<Bss>`
  - `Subscribe { events } → stream of Event` (state changes)
- **Schema:** YAML/JSON `serde` types intentionally **field-compatible with
  nipart's `WifiConfig`** (`ssid`, `password`, `bssid`, `auth_types`,
  `base_iface`, `state`, `signal_dbm`, `signal_percent`, `frequency_mhz`,
  `rx_bitrate_mb`, `tx_bitrate_mb`, `generation`). Reuse kebab-case,
  `deny_unknown_fields`, and hide-secrets-in-Debug/Display conventions.

### Library crate for consumers

Ship a `shuli` **library crate** (separate from the `shulid` binary) exposing:

```rust
pub struct ShuliClient { /* connects to abstract socket */ }
impl ShuliClient {
    pub async fn new() -> Result<Self, ShuliError>;
    pub async fn new_with_socket(name: &str) -> Result<Self, ShuliError>;
    pub async fn ping(&mut self) -> Result<String, ShuliError>;
    pub async fn show(&mut self) -> Result<NetworkState, ShuliError>;
    pub async fn apply(&mut self, desired: DesiredState) -> Result<(), ShuliError>;
    pub async fn scan(&mut self, req: ScanRequest) -> Result<Vec<Bss>, ShuliError>;
    pub async fn subscribe(&mut self, ev: EventFilter) -> Result<EventStream, ShuliError>;
}
```

This is the surface nipart consumes. Keep it stable and documented.

---

## 3. Workspace layout (Stage 2)

Split into a Cargo workspace:

```
shuli/
├── Cargo.toml                # [workspace]
├── shuli/                    # library crate (client + schema + protocol)
│   └── src/{lib,client,protocol,schema,error}.rs
├── shulid/                   # daemon binary (Stage 1 engine + server)
│   └── src/{main,server,manager,...}.rs   # reuses Stage 1 nl80211/crypto/sm
└── shulictl/                 # CLI binary
    └── src/main.rs           # show / apply / scan subcommands
```

- `shuli` (lib): protocol messages, `ShuliClient`, `WifiConfig`/`NetworkState`
  schema, errors — **no root required**, usable by nipart and `shulictl`.
- `shulid`: the Stage 1 connection engine + a tokio server task per client
  connection + a central manager (config, interfaces, event bus).
- `shulictl`: thin CLI over `shuli::ShuliClient`.

---

## 4. nipart integration plan

### What nipart has today (to replace)

- `src/lib/no_daemon/wifi/` — a **wpa_supplicant D-Bus client**:
  `dbus.rs`, `apply.rs`, `scan.rs`, `bss.rs`, `network.rs`, `interface.rs`,
  the `NipartWpaConn` struct, and `dbus_macros.rs`.
- Schema lives in `src/lib/schema/ifaces/wifi.rs` (`WifiConfig`,
  `WifiPhyInterface`, `WifiCfgInterface`, `WifiAuthType`, `WifiState`).
- Query path uses `nispor` for read-only wifi status
  (`wifi_nispor.rs`).

### Replacement strategy

1. **Schema alignment:** make shuli's `WifiConfig`/`WifiAuthType`/`WifiState`
   byte-compatible with nipart's. Easiest: shuli's lib exposes types that
   nipart can `From`/`Into` convert, or nipart depends on `shuli` for these
   types directly. Decide with nipart maintainer (we control both).
2. **Swap the backend:** replace `NipartWpaConn::apply/query/scan` internals so
   that instead of building wpa_supplicant D-Bus calls, they call
   `shuli::ShuliClient::{apply, show, scan}`. The public nipart behaviour
   (apply desired YAML, query state, scan) stays the same.
3. **Keep nispor for read-only status** if desired, or migrate status to
   `shulictl show`/`ShuliClient::show`. Prefer shuli as the single source of
   truth for wifi auth state to avoid divergence.
4. **Feature flag / phased rollout:** add a nipart build/runtime switch
   (`wifi-backend = wpa_supplicant | shuli`) so we can land shuli support and
   cut over once it's proven, then delete the D-Bus code.

### API sufficiency checklist (must satisfy nipart's needs)

- [ ] Apply a list of `(iface, WifiConfig)` to connect (incl. "bind to any
      wifi NIC" semantics nipart uses in `apply.rs`).
- [ ] Delete/disconnect a network by SSID; delete by interface.
- [ ] Active scan with retry and SSID filter (nipart does up to
      `MAX_SCAN_RETRY = 5`).
- [ ] Return BSS list with auth types, signal (dBm + percent), frequency.
- [ ] Report per-interface `WifiState` (Disconnected/Scanning/Connecting/
      Completed).
- [ ] Hide secrets in all query output and logs.
- [ ] Behave correctly when multiple interfaces / multiple SSIDs are applied.

---

## 5. Work breakdown / milestones

### M1 — Library + protocol crate
- Extract Stage 1 schema into `shuli` lib; define protocol messages; implement
  framed JSON codec over UNIX abstract socket; `ShuliClient`.
- Unit tests for codec + schema (round-trip, hide-secrets).

### M2 — Daemon server
- `shulid` listens on the abstract socket; one tokio task per connection;
  central manager owns interface state machines (from Stage 1) and an event bus
  (mpsc/broadcast).
- Implement `Ping`, `Show`.

### M3 — Runtime apply
- Implement `Apply`: diff desired vs current, connect/disconnect/switch SSID at
  runtime without restart; persist applied config to `/etc/shuli/`.
- Implement `Scan`.

### M4 — `shulictl`
- `shulictl show` (table + `--json`/`--yaml`), `shulictl apply [FILE]`,
  `shulictl scan`. Man pages + `--help`.

### M5 — Events & resilience
- `Subscribe` event stream; auto-reconnect with backoff; BSS-loss/roam
  handling; PMKSA caching for fast reconnect; multi-interface.

### M6 — nipart integration
- Land `shuli` backend in nipart behind a switch; port `apply`/`query`/`scan`;
  validate against nipart's existing wifi tests
  (`src/lib/schema/unit_tests/wifi.rs`, integration tests under `tests/`).
- Remove the D-Bus `wifi/` module once parity is proven.

### M7 — Packaging & docs
- systemd unit (`shulid.service`), default `/etc/shuli/` layout, capability
  setup (`CAP_NET_ADMIN`), README, man pages, `docs/` for the protocol + client
  API.

---

## 6. Engineering conventions (align with nipart where shared)

- **Edition 2024**; pick an MSRV compatible with nipart (nipart MSRV **1.88**)
  if code/types are shared.
- **SPDX header** on every source file (`// SPDX-License-Identifier: Apache-2.0`
  unless a different licence is chosen for shuli — confirm with owner).
- rustfmt: `max_width=80`, `group_imports=StdExternalCrate`,
  `imports_granularity=Crate` (matches both shuli's `.rustfmt.toml` and nipart).
- `cargo clippy -- -D warnings` clean; `cargo +nightly fmt --all -- --check`.
- Secrets never logged; hidden in `Debug`/`Display` (copy nipart's pattern).

## 7. Stage 2 exit criteria

1. `shulid` exposes a UNIX abstract-socket control interface; `shulictl show`
   and `shulictl apply` work for WPA3-Personal.
2. `shuli` client library is documented and stable enough for nipart to depend
   on.
3. nipart drives WPA3-Personal through shuli (D-Bus/wpa_supplicant path removed
   or switchable-off) and its wifi tests pass.
4. Daily-use robustness: auto-reconnect, PMKSA caching, multi-interface, secret
   hygiene; systemd packaging present.
5. CI green: fmt/clippy/test + an integration test (mac80211_hwsim + hostapd
   WPA3) exercising show/apply/scan through the socket.
