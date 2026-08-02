<!-- SPDX-License-Identifier: Apache-2.0 -->
# 书立 (shuli) — Stage 2 Development Plan

> Builds on Stage 1 (working WPA3-Personal STA). Stage 2 makes shuli a
> usable, controllable daemon and a drop-in replacement for nipart's
> wpa_supplicant control code.

## 0. Current state (post-Stage 1)

Stage 1 delivered a working `shulid` daemon with:

- **Modules:** `client.rs` (linear per-interface connection walk over
  `WpaState`), `auth.rs` (SAE `AuthMethod` abstraction), `scan.rs`
  (trigger/wait/pick BSS), `config.rs` (YAML schema + loader), `mac.rs`
  (MAC helpers), `nl80211/` (scan, auth/assoc, keys, events, connect,
  mcast), `crypto/` (SAE H2E, 4-way handshake, KDF — built on `p256`
  + `aws-lc-rs`), `ieee80211/` (auth frames, EAPOL-Key, RSNE/RSNXE
  elements).
- **Crypto stack:** `p256` (ECC group 19 / SSWU hash-to-curve) and
  `aws-lc-rs` (HMAC-SHA256, AES-CMAC, AES Key Wrap, HKDF).  The
  RustCrypto suite originally planned in Stage 1 §6 was replaced by
  `aws-lc-rs` for the symmetric/KDF primitives (commit `2589f1f`).
- **Robustness already in place:** auto-reconnect with backoff
  (10 s general / 10 min auth-failure), SIGINT + SIGTERM clean
  teardown, GTK rekey offload to driver when supported (falls back
  to userspace rekey), replay-counter validation, constant-time
  SAE confirm comparison.
- **Packaging:** `man/shulid.8` man page, SPDX headers on all
  source files, `cargo clippy -- -D warnings` clean.
- **Tests:** 20 Rust unit tests (SAE KATs, KDF vectors, EAPOL
  round-trips, config parsing) + Python pytest integration suite
  (mac80211_hwsim + hostapd WPA3-SAE/H2E, full SAE + 4-way
  handshake + data path).

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
8. **Packaging & service**: systemd unit, default config dir;
   correct privilege handling (`CAP_NET_ADMIN`).
   *(Man page `shulid.8` and SIGTERM handling already done in Stage 1.)*
9. **Robustness for daily use**: handle AP roaming/BSS loss, PMKSA
   caching to speed reconnects, multiple managed interfaces.
   *(Auto-reconnect with backoff and GTK rekey offload already done
   in Stage 1.)*
10. **WPA2-Personal (PSK)**: connect to WPA2-PSK networks
    (AKM `00-0F-AC:2`), covering the vast majority of existing
    home/office APs that have not upgraded to WPA3.

### Non-goals for Stage 2

- 802.1X, WPA3-Enterprise (Stage 3).
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
│   └── src/
│       ├── main.rs           # entry, arg parse, signal handling
│       ├── server.rs         # UNIX socket server, per-client tasks
│       ├── manager.rs        # central config + interface state owner
│       ├── client.rs         # per-interface connection walk (Stage 1)
│       ├── auth.rs           # AuthMethod abstraction (Stage 1)
│       ├── scan.rs           # scan flow (Stage 1)
│       ├── config.rs         # YAML schema + loader (Stage 1)
│       ├── mac.rs            # MAC helpers (Stage 1)
│       ├── nl80211/          # scan, auth_assoc, keys, events, ...
│       ├── crypto/           # sae, handshake4, kdf
│       └── ieee80211/        # auth, eapol, elements
└── shulictl/                 # CLI binary
    └── src/main.rs           # show / apply / scan subcommands
```

- `shuli` (lib): protocol messages, `ShuliClient`, `WifiConfig`/`NetworkState`
  schema, errors — **no root required**, usable by nipart and `shulictl`.
- `shulid`: the Stage 1 connection engine (`client.rs` linear walk,
  `auth.rs`, `scan.rs`, `nl80211/`, `crypto/`, `ieee80211/`) + a tokio
  server task per client connection + a central manager (config,
  interfaces, event bus).
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

### M1b — WPA2-Personal (PSK)

No SAE round-trip — the PMK is derived directly from the
password, so the flow is: scan → associate → 4-way handshake →
keys installed.

- **PMK derivation:** PBKDF2-HMAC-SHA1(password, SSID, 4096,
  256 bits) per 802.11-2020 §12.7.1.2.  Add `pbkdf2` +
  `sha1` (or use `aws-lc-rs` PBKDF2 if available) to the
  crypto stack.
- **AuthMethod extension:** add a `Wpa2Psk` variant to the
  `AuthMethod` trait in `auth.rs`.  `start()` returns
  immediately (no auth frames); the client skips the
  `Authenticating` state and goes straight to `Associating`.
- **RSNE:** emit AKM `00-0F-AC:2` (PSK) instead of
  `00-0F-AC:8` (SAE).  No RSNXE.  Detect the AP's AKM from
  the scan RSNE and select PSK vs SAE accordingly.
- **4-way handshake differences (AKM 00-0F-AC:2):**
  - PTK KDF: PRF-384 (HMAC-SHA1, `label || 0x00 || context ||
    counter` format, single-octet counter from 0) — **not**
    the KDF-Hash-Length used by SAE.  Add a `prf()` function
    to `kdf.rs`.
  - MIC: HMAC-SHA1-128 (first 16 bytes of HMAC-SHA1) for
    descriptor version 1, or AES-CMAC for descriptor version 2.
    Check the key-info descriptor-version bits to select.
  - Key descriptor version 1 uses HMAC-SHA1 MIC; version 2
    uses AES-CMAC.  Most WPA2-PSK APs use version 1.
- **Rekey offload:** pass AKM `0x000FAC02` in
  `NL80211_REKEY_DATA_AKM` when offloading.
- **Tests:** unit tests for PBKDF2 PMK derivation (known
  vectors from 802.11-2020 / wpa_supplicant), PRF-384 PTK
  derivation, HMAC-SHA1 MIC.  Integration test with hostapd
  configured for WPA2-PSK (`wpa=2`, `wpa_key_mgmt=WPA-PSK`).
- **Exit:** `shulid` connects to both WPA3-SAE and WPA2-PSK
  APs, selecting the AKM automatically from the scan RSNE.

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
- `Subscribe` event stream; BSS-loss/roam handling; PMKSA caching
  for fast reconnect; multi-interface.
  *(Auto-reconnect with backoff and GTK rekey offload already done
  in Stage 1 — build on the existing `WpaState` retry logic and
  `keys::set_rekey_offload()`.)*

### M6 — nipart integration
- Land `shuli` backend in nipart behind a switch; port `apply`/`query`/`scan`;
  validate against nipart's existing wifi tests
  (`src/lib/schema/unit_tests/wifi.rs`, integration tests under `tests/`).
- Remove the D-Bus `wifi/` module once parity is proven.

### M7 — Packaging & docs
- systemd unit (`shulid.service`), default `/etc/shuli/` layout, capability
  setup (`CAP_NET_ADMIN`), README, `docs/` for the protocol + client API.
  *(Man page `man/shulid.8` already exists; extend for `shulictl`.)*

---

## 6. Engineering conventions (align with nipart where shared)

- **Edition 2024**; MSRV **1.96** (shuli).  If code/types are shared
  with nipart (MSRV 1.88), either lower shuli's MSRV or keep the
  shared surface in the `shuli` lib crate at nipart's MSRV.
- **SPDX header** on every source file (`// SPDX-License-Identifier:
  Apache-2.0`).
- rustfmt: `max_width=80`, `group_imports=StdExternalCrate`,
  `imports_granularity=Crate` (matches both shuli's `.rustfmt.toml`
  and nipart).
- `cargo clippy -- -D warnings` clean; `cargo fmt --all -- --check`.
- Secrets never logged; hidden in `Debug`/`Display` (copy nipart's
  pattern).
- **Crypto:** `p256` for ECC, `aws-lc-rs` for symmetric/KDF
  primitives (HMAC-SHA256, AES-CMAC, AES Key Wrap, HKDF,
  PBKDF2, HMAC-SHA1 for WPA2-PSK).  Do **not** add RustCrypto
  symmetric crates alongside `aws-lc-rs`.

## 7. Stage 2 exit criteria

1. `shulid` exposes a UNIX abstract-socket control interface; `shulictl show`
   and `shulictl apply` work for WPA3-Personal and WPA2-Personal.
2. `shulid` connects to both WPA3-SAE and WPA2-PSK APs, selecting the
   AKM automatically from the scan RSNE.
3. `shuli` client library is documented and stable enough for nipart to depend
   on.
4. nipart drives WPA3-Personal through shuli (D-Bus/wpa_supplicant path removed
   or switchable-off) and its wifi tests pass.
5. Daily-use robustness: auto-reconnect, PMKSA caching, multi-interface, secret
   hygiene; systemd packaging present.
6. CI green: fmt/clippy/test + integration tests (mac80211_hwsim + hostapd)
   exercising WPA3-SAE, WPA2-PSK, and show/apply/scan through the socket.
