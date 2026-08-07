<!-- SPDX-License-Identifier: Apache-2.0 -->
# 书立 (shuli) - Stage 2 Development Plan

> Stage 2 hardens shuli for daily-driver use.  This plan was rebased in
> 2026-08 after an audit of shuli against iwd and wpa_supplicant; it
> replaces the original Stage 2 plan whose primary goal (a UNIX-socket
> control interface with `shulictl`) was **dropped** - see §1.

## 0. Current state (v0.1.0, 2026-08)

Delivered since Stage 1 (some of it already listed in the original plan
as Stage 2 work):

* **Auth methods:** WPA3-Personal (SAE, Hash-to-Element, group 19),
  WPA2-PSK (AKM `00-0F-AC:2`, commit `9f20a6b`), OWE (AKM
  `00-0F-AC:18`), open.  The AKM is selected automatically from the
  scan RSNE; mixed WPA2/WPA3 RSNEs prefer SAE.
* **4-way handshake:** AKM-specific KDF/MIC (SAE: KDF-Hash-Length +
  AES-CMAC; OWE: KDF + HMAC-SHA256; PSK: PRF-384 + HMAC-SHA1-128),
  replay-counter validation, GTK unwrap (NIST AES Key Wrap), userspace
  GTK rekey with driver offload fallback (`SET_REKEY_OFFLOAD`).
* **Scan:** on-demand scan plus firmware scheduled scan (PNO) probing
  for every configured SSID in one schedule, with host-side
  exponential backoff (10 s -> 300 s) when PNO is unsupported.
* **Daemon (`shulid`):** reads `/etc/shuli/config.yml` (or `$1`),
  resolves the interface (`"any"` -> first wifi NIC via nispor),
  auto-reconnect with backoff (10 s general / 10 min auth-failure),
  SIGINT/SIGTERM teardown; after connect applies per-network IP config
  (DHCPv4 via mozim, IPv6 RA, static addresses/routes/DNS via
  rtnetlink).  L3 lives here because `shulid` targets environments
  where a full nipart is not wanted.
* **Library (`shuli` crate):** `WifiClient`/`WifiState` connection
  engine plus a standalone scan API (`scan_wifi_with_ies`).  The
  crate does **no IP work** - its scope ends at keys installed + link
  up; all layer 3+ is left to the caller (e.g. nipart).
* **Crypto stack:** `p256` (ECC group 19, SSWU hash-to-curve) +
  `aws-lc-rs` (HMAC-SHA1/256, AES-CMAC, AES Key Wrap, HKDF, PBKDF2).
* **Tests:** SAE/KDF/EAPOL unit tests + `mac80211_hwsim` + hostapd
  integration tests (open, WPA3-SAE H2E, scheduled-scan wake-up).

## 1. Design decision: no IPC

The original Stage 2 primary goals - a UNIX abstract-socket control
interface with `shulictl` (`show` / `apply` / `scan`), an event /
subscribe stream, and runtime config apply - are **dropped**.
`shulid` provides no IPC interface for live configuration:

* Configuration is file-driven - a single YAML file
  (`/etc/shuli/config.yml` or `$1`); shulid does not support multiple
  config files or a config directory.  Changes take effect on daemon
  restart.
* There is no control protocol, no `shulictl`, no event subscription.
* Consumers that need programmatic WiFi control embed the `shuli`
  **library crate** and drive `WifiClient` / the scan API in-process
  (§3).
* The YAML file is the only configuration interface, so **every
  option of the lib's `WifiConfig`/`NetworkConfig` must be
  configurable through shulid's YAML schema** (`ShuliConfig` + the
  `to_wifi_config` conversion).  Any feature that adds a knob - e.g.
  G1d PMF policy, G2b per-network SAE mode, G8 roaming policy - must
  extend the daemon YAML schema alongside the lib config.

Everything else from the original plan is re-scoped below around
feature and robustness gaps found in the 2026-08 audit against iwd and
wpa_supplicant (§5 is the full comparison table).

## 2. Goals

Scope principle: gaps are prioritized by importance to shuli's
deployment, not by parity with the reference daemons - a feature is
planned when it matters here, even if neither iwd nor wpa_supplicant
implements it (examples below: BIGTK install, WoWLAN).

### G1 - PMF key handling and handshake validation (correctness)

Found by the audit; G1(a) is a functional defect, not just a missing
feature:

a. **Install IGTK / BIGTK from 4-way Message 3.**  Today only the GTK
   KDE (type 1) is parsed; the IGTK KDE (type 9) and BIGTK KDE
   (type 10) carried by every PMF AP are discarded.  mac80211 drops
   any robust management action frame received without a BIP key
   (`net/mac80211/rx.c`, `RX_DROP_U_UNPROT_ACTION`), and the
   in-kernel SA Query responder only sees requests that pass that
   check - so without the IGTK, protected action frames (SA Query,
   BSS Transition Management, WNM notifications, channel-switch
   announcements) are silently dropped and the AP may disassociate an
   "unresponsive" STA.  Work: parse IGTK/BIGTK KDEs from the decrypted
   key data; install via `NL80211_CMD_NEW_KEY` with the RSNE
   group-management cipher (BIP-CMAC-128 today; advertise more BIP
   ciphers later), key index from the KDE, RX sequence from the KDE's
   IPN, and the `NL80211_KEY_DEFAULT_MGMT` flag for the IGTK; in the
   same pass install the BIGTK when the AP delivers it (RX-only,
   beacon protection).  iwd does not implement beacon protection, but
   the install cost is negligible once IGTK KDE parsing exists, so it
   stays in scope.
b. **RSNE downgrade validation:** verify the RSNE in Message 3 against
   the one from the beacon/probe response (both iwd and wpa_supplicant
   do this); fail the handshake on mismatch.
c. **PTK rekey handling:** AP-initiated pairwise rekey arrives as a
   fresh Message 1 (new ANonce) mid-connection; the current code path
   already re-derives the PTK and answers Message 2, but this is
   untested - add coverage.  EAPOL-Key frames with the Request bit
   must be dropped explicitly (both reference supplicants drop them -
   wpa_supplicant `src/rsn_supp/wpa.c`: "EAPOL-Key with Request bit -
   dropped"); today they are mis-routed to the Message-3 branch or
   fall through as unhandled.  (Stretch: a supplicant-initiated rekey
   timer, like wpa_supplicant's `wpa_ptk_rekey`.)
d. **Optional PMF for WPA2-PSK:** shuli advertises no MFP capability
   bits in the PSK RSNE, so PMF-capable WPA2 APs connect unprotected.
   iwd negotiates PMF optional by default on WPA2 (its
   `ManagementFrameProtection` default is 1) and wpa_supplicant has
   `ieee80211w=0/1/2`; add MFPC to the PSK RSNE (depends on (a) for
   the IGTK).

### G2 - SAE interop

a. **Anti-clogging token (status 76):** a loaded AP answers the commit
   with status 76 + a token; shuli currently treats this as auth
   failure and backs off for **10 minutes**.  Re-send the commit with
   the token (for H2E the token arrives in the Anti-Clogging Token
   Container element).  Both reference supplicants implement this.
b. **Hunting-and-pecking fallback:** H2E-only SAE cannot connect to
   HnP-only APs.  Add HnP PWE derivation (group 19) as a fallback when
   the H2E commit is rejected, selectable per network.  (Stretch:
   groups 20/21, plus AP group-rejection negotiation - status 77 /
   Rejected-Groups element - which both reference supplicants do.)
c. **Retransmit/timeout policy:** a lost commit/confirm currently
   costs the full 15 s event timeout + a rescan cycle.  iwd
   retransmits with a Sync counter (max 3) plus association retries;
   wpa_supplicant restarts after a 5 s auth timeout.  Tighten the SAE
   timers so one lost frame does not cost a full scan round.

### G3 - WPA2-PSK test closure

WPA2-PSK shipped without its planned test coverage (the original M1b
exit criteria are unmet):

* Unit KATs: PBKDF2-HMAC-SHA1 PMK derivation (published vectors),
  PRF-384 PTK derivation, HMAC-SHA1-128 EAPOL MIC.
* Integration test: hostapd with `wpa=2`, `wpa_key_mgmt=WPA-PSK`,
  full 4-way + data path (mirrors the existing SAE test).

### G4 - PMKSA caching

wpa_supplicant keeps a userspace PMKSA cache (PMK lifetime 43200 s,
reauth threshold at 70 %) and advertises the cached PMKID in the
(Re)Association RSNE, so reconnects skip SAE/4-way when the AP accepts
the PMKID.  iwd does **not** cache PMKSAs - every reconnect runs full
SAE; it speeds reconnects with a cached H2E password element in the
profile and firmware SAE/PSK offload instead.  shuli follows the
wpa_supplicant model:

* Userspace PMKSA cache keyed by (SSID, BSSID/PMKID) with PMK lifetime
  handling; include the cached PMKID in the (Re)Association RSNE.
* Cache-miss fallback: if the AP starts a full 4-way despite the
  PMKID, proceed with the fresh handshake.
* Driver/firmware caching: `SET_PMKSA`/`DEL_PMKSA` + `SET_PMK`/
  `DEL_PMK` - requires adding `NL80211_ATTR_PMK` to `wl-nl80211`
  (still stubbed out there; the `SetPmksa`/`DelPmksa`/`FlushPmksa`
  commands already exist).

Status (2026-08-06): done - userspace cache with the cached PMKID in
the (Re)Association RSNE and full-auth fallback; driver cache fed via
`SET_PMKSA`/`DEL_PMKSA` best-effort (`wl-nl80211` gained
`NL80211_ATTR_PMK`/`NL80211_ATTR_PMKID` and request builders; the
shipped kernel's `SET_PMK`/`DEL_PMK` are unused since mac80211 returns
EOPNOTSUPP for both paths anyway).

### G5 - Robustness

* **Security classification:** BSSes whose RSNE carries only
  unsupported AKMs (PSK-SHA256, FT variants, WPA1/TKIP) are currently
  classified `Open` and produce a confusing association rejection.
  Add an `Unsupported` security type and skip such BSSes with a clear
  log.
* **Multi-interface:** the daemon currently drives one interface
  (first `wifis` entry / first wifi NIC).  Run one `WifiClient` per
  interface for distinct configured interfaces.
* **Disconnect handling:** surface deauth/disassoc reason codes and
  use reason-aware retry behaviour instead of one generic backoff.
  iwd's policy (`station_retry_with_reason`) is a good model: reasons
  2 (`PREV_AUTH_NOT_VALID`) and 16 (`802.1X_FAILED`) abort retries
  (wrong-passphrase protection), other reasons blacklist the BSS and
  try the next candidate.  shuli's single 10-minute auth backoff
  conflates all causes today.

### G6 - Packaging

systemd unit (`shulid.service`), default `/etc/shuli/` layout,
`CAP_NET_ADMIN` setup notes, README/man updates.

### G7 - nipart integration (TBD)

With the control socket gone, how nipart consumes shuli needs a fresh
decision: (a) embed the `shuli` crate in-process (drive `WifiClient`,
use `scan_wifi_with_ies` for scanning), or (b) nipart stays on
wpa_supplicant.  Either way nipart keeps doing its own layer 3+ work -
the `shuli` crate does no IP configuration by design.  Decide and
record here before starting this work; whichever way, secrets hygiene
(no passwords in logs/Debug output) must hold.

### G8 - Roaming: 802.11r fast transition and 802.11v

Moved forward from Stage 3 (2026-08): roaming is needed in the home
WiFi environment shuli runs in.

* **Fast BSS Transition (802.11r):** FT-PSK (AKM `00-0F-AC:4`) and
  FT-SAE (AKM `00-0F-AC:9`).  PMK-R0/R1 key hierarchy from the PMK
  (PSK = XXKey for FT-PSK, SAE PMK for FT-SAE); over-the-Air first
  (`Nl80211AuthType::Ft` already exists in `wl-nl80211`), over-the-DS
  as stretch.  Reassociation carries the FTIE; MDIE / FT capability
  detection from scan results.
* **802.11v BSS Transition Management:** handle BTM Requests and send
  BTM Responses; candidate list from Neighbor Report elements
  (802.11k).  WNM/RRM action frames are protected management frames
  (needs the G1a IGTK) and need `NL80211_CMD_REGISTER_FRAME`
  registration (`wl-nl80211` already exposes `register_frame()`).
* **Roam decision:** signal-threshold triggered scan while connected,
  candidate scoring (signal + security match), PMKSA/OKC-assisted
  reassociation before falling back to full auth.  OKC = cloning the
  PMKSA to sibling BSSes of the same ESS (wpa_supplicant's `okc`
  option; iwd does not do it - planned anyway, it makes non-FT roams
  cheap).

Dependencies: G1a (BTM/WNM frames are protected) and G4 (PMKSA as the
roaming currency).  References: 802.11-2020 §12.8 (FT), §11.24
(WNM/BTM); wpa_supplicant `src/rsn_supp/wpa_ft.c` + `wnm_sta.c`, iwd
`src/ft.c` + `src/station.c`.

Status (2026-08-06): implemented over-the-Air FT-PSK/FT-SAE (PMK-R0/R1
hierarchy, FTIE MIC validation, PTK/GTK/IGTK install from the
Reassociation Response), 802.11v BTM Request handling with Neighbor
Report candidate parsing and BTM Response, and signal-threshold roam
scans with a post-roam cooldown; non-FT roams fall back to PMKSA/OKC
then full authentication.  Over-the-DS remains stretch.

### G9 - Suspend / WoWLAN

GTK rekey offload (Stage 1) was built as this feature's prerequisite;
WoWLAN is the motivating use case.  Planned because it matters here,
not for parity with the reference daemons.

* On suspend: configure WoWLAN triggers via `NL80211_CMD_SET_WOWLAN`,
  including `NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE`.
* On resume: handle wake notifications; on a GTK-rekey-failure wake,
  disconnect and reconnect (not a userspace-rekey fallback on the old
  association).
* Optionally track driver rekey notification events to keep the
  userspace replay counter in sync.
* Requires adding `NL80211_ATTR_WOWLAN_TRIGGERS` to `wl-nl80211`
  (the `SetWowlan`/`GetWowlan` commands and the trigger-support
  capability attribute already exist).

### Non-goals for Stage 2

* 802.1X / WPA3-Enterprise (Stage 3).
* SAE-PK, OCV, Transition Disable (Stage 3).
* AP mode, mesh, P2P, DPP, FILS.
* TKIP / WPA1 support (reject as unsupported, never implement).

## 3. Workspace layout

Unchanged from the flattened v0.1.0 layout:

```
shuli/
├── Cargo.toml                # [workspace] members: src/lib, src/daemon
├── src/lib/                  # `shuli` crate: WifiClient engine + scan API
│   └── src/{lib,client,auth,scan,config,error,mac}.rs
│       src/lib/nl80211/      # scan, connect helpers
│       src/lib/crypto/       # sae, handshake4, kdf, owe
│       src/lib/ieee80211/    # auth, eapol, elements
└── src/daemon/               # `shulid` binary
    └── src/{main,config,dhcp,ip}.rs
```

Stage 2 touches mostly `src/lib` (handshake/KDE parsing in
`crypto/handshake4.rs`, SAE in `crypto/sae.rs`, event handling in
`client.rs`, AKM detection in `scan.rs`) plus the daemon for
multi-interface and packaging.

## 4. Work breakdown / milestones

* **M1** PMF & handshake correctness (G1): IGTK installed from a
  hostapd `ieee80211w=2` Message 3 (test asserts key install);
  protected action frames reach the kernel (SA Query round-trip or
  equivalent); RSNE-mismatch and Request-bit cases covered by unit
  tests.  **Done 2026-08-06** (IGTK/BIGTK install + SA Query survival
  test; msg3 RSNE/RSNXE downgrade checks; Request-bit drop; PTK rekey
  coverage; optional PMF on WPA2-PSK).
* **M2** WPA2-PSK test closure (G3): PBKDF2/PRF-384/HMAC-SHA1 KATs
  plus a WPA2-PSK integration test, all green.
* **M3** SAE interop (G2): connects to hostapd `sae_pwe=0/1` (HnP)
  and survives an anti-clogging token exchange.
* **M4** PMKSA caching (G4): reconnect to the same AP completes
  without a fresh SAE exchange (cache hit observable in logs/AP);
  driver offload path exercised when the wiphy supports it.
  **Done 2026-08-06** (userspace cache keyed by (SSID, BSSID), 43200 s
  lifetime, cached PMKID in (Re)Assoc RSNE with fallback; SET_PMKSA /
  DEL_PMKSA best-effort - mac80211 answers EOPNOTSUPP).
* **M5** Roaming (G8): in a two-BSS test netns, an FT-PSK or FT-SAE
  over-the-Air transition and a BTM-directed roam both complete;
  PMKSA/OKC-assisted reassociation verified before full-auth
  fallback.  (Requires M1 and M4.)  **Done 2026-08-06** (FT-PSK +
  FT-SAE over-the-Air with PMK-R0/R1 hierarchy; BTM Request/Response
  with Neighbor Report candidates; signal-threshold roam scan with
  cooldown; OKC PMKID cloning attempted before full-auth fallback).
* **M6** Suspend / WoWLAN (G9): WoWLAN triggers armed on suspend;
  wake path (GTK-rekey failure -> disconnect + reconnect) covered
  where the driver supports it.
* **M7** Robustness (G5): unsupported-AKM BSS skipped (unit test),
  two interfaces connected concurrently (integration), reason-code
  aware retry.
* **M8** Packaging (G6): systemd unit + docs; daemon runs from the
  unit with `CAP_NET_ADMIN`.
* **M9** nipart decision (G7): decision recorded; if (a), nipart
  drives `shuli` in its wifi flow.

## 5. Feature comparison: shuli vs iwd vs wpa_supplicant

Audited 2026-08: shuli v0.1.0 against iwd 3.0
(`src/{sae,eapol,eapolutil,handshake,ft,station,wiphy,netdev}.c`) and
wpa_supplicant 2.11 (`src/rsn_supp/wpa*.c`, `src/common/sae*.c`,
`wpa_supplicant/sme.c`, `src/rsn_supp/pmksa_cache.c`).  This is what
the Stage 2/3 scope is derived from.

| Feature area | shuli | iwd | wpa_supplicant |
|---|---|---|---|
| SAE H2E (group 19) | ✓ | ✓ | ✓ |
| SAE hunting-and-pecking | ✗ (G2b) | ✓ | ✓ |
| SAE anti-clogging token | ✗ (G2a) | ✓ | ✓ |
| SAE groups 20/21 / FFC | ✗ | ✓ (ECC only) | ✓ (ECC+FFC) |
| SAE retry / retransmit | coarse (G2c) | ✓ (Sync=3) | ✓ (5 s restart) |
| SAE-PK | ✗ (Stage 3) | ✗ | ✓ |
| WPA2-PSK (AKM 2) | ✓ | ✓ | ✓ |
| PSK-SHA256 (AKM 6) | ✗ (Stage 3) | ✓ | ✓ |
| FT-PSK / FT-SAE (802.11r) | ✓ (over-the-Air) | ✓ | ✓ |
| 4-way GTK delivery + rekey | ✓ | ✓ | ✓ |
| GTK rekey offload | ✓ | ✓ | ✓ |
| IGTK (PMF mgmt key) | ✓ | ✓ | ✓ |
| BIGTK (beacon protection) | ✓ (when AP sends it) | ✗ | ✓ |
| AP-initiated PTK rekey | ✓ | ✓ | ✓ |
| RSNE validation in msg3 | ✓ | ✓ | ✓ |
| PMKSA cache (userspace) | ✓ | ✗ | ✓ |
| PMKSA cache (driver) | ✓ (best-effort) | ✗ | ✓ |
| OKC (proactive key caching) | ✓ (attempt + fallback) | ✗ | ✓ |
| Optional PMF on WPA2-PSK | ✓ | ✓ (default) | ✓ (config) |
| 802.11v BTM / neighbor rpt | ✓ | ✓ | ✓ |
| Signal-triggered roaming | ✓ | ✓ | ✓ |
| OCV | ✗ (Stage 3) | ✓ (non-FT) | ✓ |
| Extended key ID | ✗ (Stage 3) | ✓ | ✓ |
| Transition Disable KDE | ✗ (Stage 3) | ✓ | ✓ |
| Multi-network scan | ✓ (PNO) | ✓ | ✓ |
| WPA1 / TKIP | ✗ (reject) | ✓ | ✓ |

Notes from the deep-dive:

* EAPOL-Key frames with the Request bit are dropped by both reference
  supplicants; pairwise rekey is AP-driven (fresh Message 1) or
  supplicant-driven by timer (wpa_supplicant `wpa_ptk_rekey` only).
* RSN pre-authentication is 802.1X-only in both daemons, never
  PSK/SAE - it is not a PSK-family feature.
* wpa_supplicant's STA has no SAE Sync-based confirm retry (5 s auth
  timeout + restart); iwd retries with Sync=3 and 3 association
  attempts.
* iwd has no userspace PMKSA cache and never issues
  SET_PMKSA/DEL_PMKSA; its reconnect speed-ups are the cached H2E
  password element (profile) and firmware SAE/PSK offload.
* PSK-SHA384 AKMs exist as selector constants only in wpa_supplicant
  (unusable); FILS has no PSK variant in either daemon.

## 6. Engineering conventions

* **Edition 2024**; MSRV **1.96**.
* **SPDX header** on every source file (`// SPDX-License-Identifier:
  Apache-2.0`).
* rustfmt: `max_width=80`, `group_imports=StdExternalCrate`,
  `imports_granularity=Crate`.
* `cargo clippy -- -D warnings` clean; `cargo fmt --all -- --check`.
* Secrets never logged; hidden in `Debug`/`Display`.
* **Crypto:** `p256` for ECC, `aws-lc-rs` for symmetric/KDF
  primitives.  Do not add RustCrypto symmetric crates alongside
  `aws-lc-rs`.
* New nl80211 attributes/commands land in `wl-nl80211` first (e.g.
  `NL80211_ATTR_PMK` for G4).

## 7. Stage 2 exit criteria

1. All G1 correctness fixes landed and covered by tests (unit +
   hostapd `ieee80211w=2`).
2. WPA2-PSK has KAT unit tests and an integration test; SAE interop
   (HnP fallback, anti-clogging) demonstrated against hostapd.
3. PMKSA caching works for reconnects on both WPA2-PSK and WPA3-SAE.
4. Roaming works in a two-BSS test netns: FT transition and
   BTM-directed roam both land (G8).
5. WoWLAN triggers armed on suspend; wake path handled (G9).
6. Unsupported-AKM BSSes are skipped cleanly; multi-interface works.
7. systemd unit shipped; fmt/clippy/test + integration suite green.
8. nipart decision (G7) recorded.
