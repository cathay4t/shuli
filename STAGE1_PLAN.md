<!-- SPDX-License-Identifier: Apache-2.0 -->
# 书立 (shuli) — Stage 1 Development Plan

> 书立 / *Book stand* — a pure-Rust Linux WiFi authentication daemon.
> The name is a pun: a book stand resembles the WiFi signal-bar icon.

## 1. Stage 1 Goals

### Primary (from product brief)

1. **WPA3-Personal authentication** working end-to-end on a real STA
   (station/client) interface: scan → SAE authentication → 4-way handshake →
   keys installed → data link up (ready for DHCP by an external tool).
2. **`shulid` daemon** that reads static configuration from
   `/etc/shuli/*.yml` and brings the configured interface(s) onto the
   configured network. Example config:

   ```yaml
   ---
   interfaces:
     - name: wlan0
       type: wifi-phy
       wifi:
         ssid: Test-WIFI
         password: "12345678"
   ```

3. **Crypto crate investigation** — produce a written conclusion (see §6) on
   which Rust crate(s) to use for WiFi authentication crypto, and validate the
   choice with a throw-away SAE proof-of-concept.

### Added goals (initial coding milestone)

4. **nl80211 SME-in-userspace plumbing** over `wl-nl80211`: management-frame
   registration/TX/RX, `ExternalAuth`, `Authenticate`/`Associate`, control
   port over nl80211 (EAPOL over netlink), and `NewKey` key installation.
5. **Project skeleton & engineering baseline**: workspace layout, error type,
   logging, async runtime, CI-able `fmt`/`clippy`/`test`, SPDX headers.
6. **Single-shot, single-interface scope only.** No IPC/CLI, no D-Bus, no
   roaming, no PMKSA caching, no multi-BSS selection logic beyond "best signal
   matching SSID". Those are Stage 2+.

### Explicit non-goals for Stage 1

- WPA2-Personal, 802.1X/EAP, WPA3-Enterprise (Stage 3).
- Control socket, `shulictl`, nipart integration (Stage 2).
- Access-Point / mesh / P2P modes.
- SAE-PK, transition-disable, FT/roaming, OWE, DPP.

---

## 2. Background: how WPA3-Personal authentication works

This is the reference flow the daemon must implement. Spec references are to
`~/Source/wifi_docs/802.11-2020.pdf` and `wpa3_v3.3.pdf`.

1. **Scan** for the target SSID, pick a BSS, read its RSN element to confirm
   AKM = SAE (`00-0F-AC:8`) and pairwise/group cipher (CCMP-128 `00-0F-AC:4`),
   and whether H2E (Hash-to-Element) is required (RSNXE bit).
2. **SAE (Simultaneous Authentication of Equals)** — the Dragonfly handshake
   (802.11-2020 §12.4, RFC 7664). Two round-trips of 802.11 Authentication
   frames:
   - **Commit**: each side derives a password element `PWE` on an ECC group
     (default group 19 = NIST P-256), picks random `rand`/`mask`, sends
     `scalar` and `element`.
   - **Confirm**: each side verifies the peer's commit, derives the shared
     secret `k`, then `KCK`/`PMK`, and exchanges a `confirm` hash.
   - Two PWE methods: legacy *hunting-and-pecking* and the mandatory-for-WPA3
     *Hash-to-Element (H2E)* (802.11-2020 §12.4.4.2.3, uses SSWU /
     RFC 9380 simplified SWU). Stage 1 implements **H2E** (required by WPA3)
     and may add hunt-and-peck only if an AP demands it.
   - Output: a **PMK** (32 bytes) + PMKID.
3. **Association**: send Association Request (with RSNE), receive
   Association Response.
4. **4-Way Handshake (EAPOL-Key)** (802.11-2020 §12.7): authenticator and
   supplicant exchange 4 EAPOL-Key frames carried over the **control port**.
   Derives the **PTK** from PMK + ANonce + SNonce + MACs via the PRF, and
   delivers the **GTK** (AES-Key-Wrapped). Uses AKM-specific KDF/MIC
   (AES-CMAC / HMAC-SHA-256 for SAE).
5. **Key installation**: install PTK (pairwise) and GTK (group) into the kernel
   via `NL80211_CMD_NEW_KEY`. From here the **kernel/hardware performs CCMP**
   data-frame encryption — the daemon does *not* encrypt data frames itself.
6. Link is "connected"; an external DHCP client can run.

**Division of labour (critical):** shuli does the *authentication* crypto in
userspace (SAE + 4-way handshake KDF/MIC/key-wrap). The kernel does the
*data-plane* crypto (CCMP/GCMP) once keys are installed. This keeps the
userspace crypto surface small and avoids reimplementing a cipher datapath.

### SME-in-userspace / external auth

shuli registers for mgmt frames, runs SAE in userspace, and uses
`NL80211_CMD_EXTERNAL_AUTH` + `NL80211_CMD_FRAME`. This is the *general* path
and the Stage 1 target (matches what wpa_supplicant does for mac80211).
`wl-nl80211` exposes the required attributes/commands (`ExternalAuth`,
`Frame`/`ControlPortFrame`, `Authenticate`, `Associate`, `Connect`,
`AkmSuites`, `CipherSuites`, `Pmk`/`Pmksa`, `NewKey`).

---

## 3. Architecture / module layout

Single binary `shulid` for Stage 1 (workspace can be split later).

```
shuli/
├── Cargo.toml                 # workspace
├── src/
│   ├── main.rs                # shulid entry: arg parse, load config, run
│   ├── lib.rs                 # re-exports, error, prelude
│   ├── error.rs               # ShuliError + ErrorKind
│   ├── config/                # /etc/shuli/*.yml loader + schema (serde)
│   │   ├── mod.rs
│   │   └── schema.rs          # Config, InterfaceConfig, WifiConfig
│   ├── nl80211/               # thin async wrappers over wl-nl80211
│   │   ├── mod.rs
│   │   ├── scan.rs            # trigger + dump + BSS/RSNE parse
│   │   ├── connect.rs         # external-auth connect (path A)
│   │   ├── mgmt.rs            # frame registration, TX/RX (path A)
│   │   ├── ctrl_port.rs       # EAPOL over nl80211
│   │   └── keys.rs            # NEW_KEY install (PTK/GTK)
│   ├── crypto/                # userspace auth crypto (see §6)
│   │   ├── mod.rs
│   │   ├── sae.rs             # Dragonfly: PWE(H2E), commit, confirm, PMK
│   │   ├── kdf.rs             # PRF / HKDF / AES-CMAC KDF
│   │   └── handshake4.rs      # EAPOL-Key 4-way: PTK derive, MIC, GTK unwrap
│   ├── ieee80211/             # minimal 802.11 frame + IE build/parse
│   │   ├── mod.rs
│   │   ├── elements.rs        # RSNE, RSNXE, SSID, etc.
│   │   ├── auth.rs            # Authentication frame (SAE commit/confirm)
│   │   ├── assoc.rs           # (Re)Association req/resp
│   │   └── eapol.rs           # EAPOL-Key frame parse/build
│   └── sm/                    # connection state machine
│       ├── mod.rs
│       └── connection.rs      # scan→auth→assoc→4way→keyed
└── STAGE{1,2,3}_PLAN.md
```

State machine (per interface):

```
Idle → Scanning → Authenticating(SAE) → Associating
     → FourWayHandshake → Connected
                 └────── any failure ──────► Failed → (retry/backoff)
```

---

## 4. Dependencies (proposed)

| Purpose                | Crate(s)                                            |
|------------------------|-----------------------------------------------------|
| nl80211 netlink        | `wl-nl80211` (local, `~/Source/netlink/wl-nl80211`) |
| async runtime          | `tokio` (rt-multi-thread, net, macros, signal)      |
| netlink glue           | `futures`, `netlink-packet-core`, `netlink-sys`     |
| config / serde         | `serde`, `serde_yaml` (or `serde_yml`)              |
| logging                | `log` + `env_logger` (swap for `tracing` later)     |
| errors                 | `thiserror`                                         |
| crypto                 | RustCrypto suite — see §6                            |
| randomness             | `rand_core` + `getrandom`                            |

Pin exact versions in `Cargo.toml`; `wl-nl80211` via `path =`. Keep MSRV aligned
with nipart-compatible toolchain (nipart MSRV is 1.88; shuli currently declares
1.96 — confirm we don't need to lower for shared-crate reuse later).

---

## 5. Work breakdown / milestones

### M1 — Skeleton & config (no radio)
- Workspace, `error.rs`, logging, `--config` flag, signal handling.
- YAML schema + loader for `/etc/shuli/*.yml`; unit tests with example config.
- `fmt`/`clippy -D warnings`/`test` all green. SPDX headers everywhere.
- **Exit:** `shulid --config examples/test.yml` parses and logs the desired
  state (no radio actions yet).

### M2 — nl80211 read path
- Enumerate phys/interfaces; ensure `wlan0` exists and is a managed STA.
- Trigger scan, dump results, parse RSNE/RSNXE, select best BSS for SSID,
  detect SAE support + H2E requirement.
- **Exit:** `shulid` prints the matching BSS + its security capabilities.

### M3 — External-auth connect & event loop (path A)
- `NL80211_CMD_CONNECT` with external-auth support, control-port-over-nl80211.
- Subscribe to connect/disconnect/external-auth events on the nl80211 multicast
  socket; drive the event loop.
- **Exit:** `shulid` sends the `CONNECT` command, receives `EXTERNAL_AUTH`
  events from the kernel, and surfaces auth-request details.

### M4 — Userspace SAE crypto (path A core) — *PoC first (§6)*
- Implement `crypto::sae` for group 19 + H2E: PWE, commit, confirm, PMK/PMKID.
- Vectors: cross-check against hostapd/wpa_supplicant test vectors and
  802.11-2020 examples; unit tests with known-answer vectors.
- **Exit:** SAE produces a PMK that matches a reference implementation for a
  fixed password/MAC/group test vector.

### M5 — Userspace SME wiring (path A)
- Register for mgmt frames; build/parse SAE Authentication frames
  (`ieee80211::auth`); drive `ExternalAuth` + `Frame` TX/RX.
- Build/parse Association req/resp with RSNE.
- **Exit:** full SAE exchange completes in userspace against the test AP and
  the kernel reports "authenticated/associated".

### M6 — 4-way handshake & key install
- EAPOL-Key over control-port-over-nl80211; PTK derivation, MIC verify (AES-CMAC
  / HMAC-SHA-256 for SAE AKM), GTK AES-Key-Unwrap.
- Install PTK + GTK via `NL80211_CMD_NEW_KEY`.
- **Exit:** reaches `Connected`; data flows; DHCP works.

### M7 — Daemon loop, robustness, docs
- Per-interface state machine, retry/backoff, clean teardown on SIGTERM,
  disconnect handling.
- Integration test harness (mac80211_hwsim + hostapd WPA3 AP) — automatable in
  CI as a root test.
- README + man page stub; record the §6 conclusion as `docs/crypto.md`.

---

## 6. Crypto crate investigation & conclusion

**Question:** which Rust crate(s) for WiFi authentication crypto?

**Key insight (scope):** for a *station* doing WPA3-Personal, userspace needs
only **authentication** crypto. Data-frame CCMP/GCMP is done by the kernel after
`NEW_KEY`, so we do **not** need a software cipher datapath. This dramatically
shrinks the crypto surface and means **no single "wifi crypto" crate is
needed** — the right answer is a curated set of **RustCrypto** primitives.

### Required primitives and recommended crates

| Need | Used by | Recommended crate |
|------|---------|-------------------|
| ECC group ops (groups 19/20/21 = P-256/384/521): scalar mul, point add | SAE | `p256`, `p384`, `p521` (RustCrypto) |
| Hash-to-curve / Hash-to-Element (SSWU, RFC 9380) | SAE H2E PWE | `elliptic-curve` w/ **`hash2curve`** feature (impl'd by the p* curves) |
| Big-int / constant-time field math (and FFC groups if ever needed) | SAE | `crypto-bigint`, `ff`, `group` (pulled in by above) |
| HMAC | PRF, MIC, KDF | `hmac` |
| SHA-2 (256/384/512) | SAE/KDF/MIC | `sha2` |
| SHA-1 | legacy PRF (WPA2, Stage 3) | `sha1` |
| AES-CMAC | SAE KDF + EAPOL MIC for SAE AKM | `cmac` + `aes` |
| AES Key Wrap (NIST SP800-38F) | GTK unwrap in 4-way handshake | `aes-kw` |
| HKDF | misc KDF | `hkdf` |
| PBKDF2 | WPA2-PSK (Stage 3) | `pbkdf2` |
| CSPRNG | SAE rand/mask, nonces | `rand_core` + `getrandom` |
| (optional) software CCMP/GCMP fallback | only if ever needing SW datapath | `ccm`, `aes-gcm` — **not needed Stage 1** |

### 802.11 frame parsing/building

Evaluated `ieee80211` (0.5.x) and `libwifi` (0.5.x). Both parse 802.11 frames,
but we need precise *building* of SAE Authentication frames, RSNE/RSNXE, and
EAPOL-Key, plus tight control over byte layout. **Conclusion:** keep a small
in-tree `ieee80211/` module for the handful of frames/elements we emit, and
optionally use one of those crates for *parsing* scan/mgmt frames if it reduces
work. Do not take a heavy dependency for the few frames we construct.

### Conclusion (the deliverable)

> **Adopt the RustCrypto ecosystem** (`p256`/`p384`/`p521` + `elliptic-curve`
> `hash2curve`, `hmac`, `sha2`, `sha1`, `cmac`, `aes`, `aes-kw`, `hkdf`,
> `pbkdf2`, `rand_core`/`getrandom`) for all authentication crypto. Implement
> the SAE Dragonfly handshake and the EAPOL-Key 4-way handshake on top of these
> primitives in-tree (`crypto/`). Do **not** rely on `ccm`/`aes-gcm` for the
> data plane — the kernel handles CCMP after key installation. Keep 802.11
> frame construction in a minimal in-tree module.

**Risks / validations to do in M4:**
- Confirm `hash2curve` provides the SSWU map for P-256/384/521 matching the
  802.11 H2E construction; if any gap, we control `wl-nl80211` and can also
  contribute upstream to RustCrypto, or vendor a small SSWU impl.
- Validate constant-time behaviour of SAE (Dragonfly is sensitive to timing
  side-channels in PWE derivation — H2E largely mitigates this vs hunt-and-peck).
- Lock crate versions; record exact KATs (known-answer tests) in CI.

---

## 7. Testing strategy

- **Unit:** SAE KATs, KDF/PRF vectors, EAPOL MIC vectors, RSNE/RSNXE
  parse/serialize round-trips, YAML config parsing.
- **Integration (root, CI-able):** `mac80211_hwsim` virtual radios + `hostapd`
  configured for WPA3-SAE; assert shuli reaches `Connected` and a DHCP lease is
  obtained.
- **Interop:** test against at least one real WPA3 AP before declaring Stage 1
  done.

## 8. Stage 1 exit criteria

1. `shulid` reads `/etc/shuli/*.yml` and connects `wlan0` to a WPA3-Personal
   network, with keys installed and data path working (DHCP succeeds).
2. WPA3-Personal works via **userspace SAE** (path A).
3. `crypto.md` records the §6 conclusion, validated by passing SAE/handshake
   KATs.
4. `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` all green;
   integration test passes under `mac80211_hwsim`.
