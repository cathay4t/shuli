<!-- SPDX-License-Identifier: Apache-2.0 -->
# 书立 (shuli) — Stage 3 Goals (notes only)

> **Status: NOT STARTED (2026-08-09).** Stage 2 has since completed
> (all exit criteria met, M1-M8; M9 removed). Stage 3 has no plan
> yet: this document records goals, protocol names, and
> authentication workflows in enough detail to produce a good plan.
> Spec references are to `~/Source/wifi_docs/` (`802.11-2020.pdf`,
> `802.11-2024.pdf`, `wpa2.pdf`, `wpa3_v3.3.pdf`).
>
> **Design note (2026-08):** `shulid` provides no IPC interface for
> live configuration; Stage 3 features land as engine work +
> config-schema fields activated by daemon restart.  Goals 1-3 below
> were updated in the 2026-08 iwd/wpa_supplicant audit; Goal 4 was
> added by it and later **moved to Stage 2** (roaming is needed in
> the home WiFi environment); Goal 5 was added by the audit; Goal 6
> (wired 802.1X) was added 2026-08-13.

## Goal 1 - WPA2-Personal: PSK-SHA256

**Status:** plain WPA2-PSK (AKM `00-0F-AC:2`) was pulled forward from
this goal and **already shipped in v0.1.0** (originally planned as the
old Stage 2 M1b; commit `9f20a6b`: PBKDF2-HMAC-SHA1 PMK, PRF-384 PTK,
HMAC-SHA1-128 MIC; auto-selected from the scan RSNE, SAE preferred in
mixed WPA2/WPA3 transition-mode RSNEs).  Remaining for this goal:

**AKM:** `00-0F-AC:6` (PSK-SHA256).  Both iwd and wpa_supplicant
support it; it is common on enterprise-managed APs running
WPA2-Personal.

**Differences vs AKM 2 (already implemented):**
* PTK via **KDF-Hash-Length with HMAC-SHA256** (384-bit output), not
  PRF-384/HMAC-SHA1.
* EAPOL-Key MIC = **AES-CMAC** (Key Descriptor Version 3), not
  HMAC-SHA1-128.  The 4-way handler must honour the descriptor version
  from the AP instead of hardcoding it per AKM.
* Optional PMF (`ieee80211w=1`) is typically negotiated with this AKM.

**Cipher:** CCMP-128 (`00-0F-AC:4`); TKIP-only legacy APs must be
classified as *unsupported* (see the Stage 2 security-classification
work) rather than attempted as open networks.

**Notes / scope:**
* Mostly a KDF/MIC-selection extension of `crypto::handshake4` and an
  AKM-list extension in `scan.rs` / `ieee80211::elements`.
* Config: per-network auth-type override (e.g. force PSK over SAE on a
  transition-mode AP); autodetection stays the default.
* Policy on **TKIP** and **WPA1** is settled: reject as unsupported,
  never implement.

## Goal 2 — Initial 802.1X support (the EAP transport layer)

**What it is:** IEEE **802.1X** is port-based network access control; on WiFi it
carries **EAP** (Extensible Authentication Protocol, RFC 3748) between the
supplicant (STA) and an **Authentication Server** (RADIUS) via the AP
(authenticator). This is the foundation for WPA-Enterprise (Goal 3).

**AKM:** `00-0F-AC:1` (802.1X) / `00-0F-AC:5` (802.1X-SHA256) for WPA2-Ent;
`00-0F-AC:3` (FT-802.1X) for fast transition (later).

**Workflow (high level):**
1. Associate (open/RSN) → controlled port blocked.
2. **EAP exchange over EAPOL** (EAPOL-Start, EAP-Request/Identity,
   EAP-Response, method-specific frames, EAP-Success/Failure). These EAPOL
   frames travel over the **control port** — same nl80211 control-port-over-
   netlink path used for EAPOL-Key in Stage 1.
3. On EAP-Success, an **MSK** is exported by the EAP method; the top 256 bits
   become the **PMK**.
4. Then the normal **4-Way Handshake** (reuse Stage 1) installs PTK/GTK.

**"Initial" scope means:** build the EAP state machine + EAPOL/EAP framing and
the plumbing to feed the resulting PMK into the 4-way handshake, with at least
one simple EAP method wired up end-to-end (candidate: **EAP-TLS**, since it is
certificate-based, standard, and central to enterprise).

**Workflow components to design:**
- EAP peer state machine (RFC 4137).
- EAPOL/EAP frame build/parse (extend `ieee80211::eapol`).
- TLS stack choice for EAP-TLS/TTLS/PEAP — **evaluate `rustls`** (pure Rust,
  fits the project ethos) incl. how to drive it over EAP (it is not a normal
  TCP TLS session; needs EAP-TLS fragmentation/record handling).
- Credential/config model: CA cert, client cert+key, identity, anonymous
  identity, server-name validation.

## Goal 3 — WPA3-Enterprise

**Builds on Goal 2** (802.1X/EAP) plus WPA3's stronger requirements.

**Two tiers (per `wpa3_v3.3.pdf`):**
- **WPA3-Enterprise (baseline):** 802.1X/EAP with **mandatory PMF**
  (Protected Management Frames, 802.11w) and SHA-256-based AKM
  (`00-0F-AC:5`).
- **WPA3-Enterprise 192-bit (CNSA / Suite-B):** AKM `00-0F-AC:12`
  (Suite-B-192), cipher **GCMP-256**, **HMAC-SHA-384** KDF/MIC, group mgmt
  cipher **BIP-GMAC-256**, and EAP-TLS restricted to **P-384 + SHA-384** (or
  RSA-3072) cipher suites.

**Workflow:** identical structure to Goal 2 (EAP → MSK → PMK → 4-way
handshake), but with:
- **GCMP-256** pairwise/group cipher (kernel does the datapath via `NEW_KEY`;
  ensure we negotiate `00-0F-AC:9` GCMP-256 and `00-0F-AC:12` AKM correctly).
- **SHA-384** KDF + KCK-256/KEK-256 in the 4-way handshake (extend
  `crypto::handshake4` to the 192-bit AKM variant; `aws-lc-rs` covers
  HMAC-SHA384 and AES Key Wrap with a 256-bit KEK).
- **PMF mandatory:** BIP (BIP-CMAC-128 / BIP-GMAC-256) for protected
  management frames.  **Resolved (2026-08, kernel check):** mac80211
  does BIP in software for keys installed via `NL80211_CMD_NEW_KEY`
  (cipher = group-mgmt cipher, `NL80211_KEY_DEFAULT_MGMT` flag);
  userspace never computes MMIE itself, but *must* install the
  IGTK/BIGTK - the Stage 2 G1 work delivers exactly that.
- **Certificate policy:** enforce the 192-bit suite's allowed EAP-TLS cipher
  suites and curve (P-384).

**Open questions to resolve before planning:**
- Which EAP methods to support first (EAP-TLS vs PEAP/MSCHAPv2 vs EAP-TTLS) —
  enterprise deployments vary; EAP-TLS is the cleanest pure-Rust target.
- `rustls` suitability for EAP-TLS framing and for the 192-bit cipher
  constraints; fallback if gaps exist.
- RADIUS-side test rig (hostapd + FreeRADIUS, or hostapd internal EAP server)
  for integration testing.

## Goal 4 - Roaming: moved to Stage 2

**Moved (2026-08):** FT (802.11r) + 802.11v BTM + roam decision are
now planned as Stage 2 G8 / milestone M5, because roaming is needed
in the home WiFi environment shuli runs in.  See
`STAGE2_PLAN.md` §G8 for the full scope (over-the-Air FT first,
over-the-DS as stretch, BTM, neighbor reports, PMKSA/OKC-assisted
roaming).

## Goal 5 - Hardening items from the audit

Smaller WPA2/3-Personal features present in the reference supplicants;
pick per deployment need:

* **SAE-PK** (Simultaneous Authentication of Equals with Public Key):
  not an AKM - RSNXE capability bit + auth status 127, EC public key
  embedded in the password.  wpa_supplicant implements it in
  `src/common/sae_pk.c`; iwd does not.  Niche; low priority.
* **SAE-EXT-KEY** (AKM `00-0F-AC:24` / FT variant `:25`, 384/512-bit
  PMK with AKM-defined KDFs): complete in wpa_supplicant; niche.
* **SAE password identifiers** (H2E-only; both daemons support them,
  status 123 handling included).
* **Transition Disable** (KDE in 4-way Message 3 / group 1-of-2 plus
  MBO WNM-Notification telling the STA to drop legacy AKMs and
  require PMF; both daemons persist it per network - in shuli's
  file-config model this maps to a profile update or log-only).
* **OCV** (Operating Channel Validation, defends against
  multi-channel/downgrade attacks; wpa_supplicant `ocv=1`, iwd full
  for non-FT AKMs).  Requires storing the operating class/channel
  from the handshake and validating it in rekeys/FT.
* **Extended Key ID** (pairwise key id 0/1 rotation for lossless PTK
  rekey, 802.11-2020; both daemons gate it on driver support and
  AES-CC ciphers, with two-phase RX-then-TX install).
* **More BIP ciphers in the RSNE** (BIP-GMAC-128/256, BIP-CMAC-256)
  once IGTK installation (Stage 2 G1) is in; iwd advertises all four
  and prefers GMAC-256 > CMAC-256 > GMAC-128 > CMAC-128.

## Goal 6 - Wired 802.1X (EAPOL over Ethernet)

**Added 2026-08-13.** IEEE 802.1X port-based access control on wired
NICs.  Unlike the WiFi enterprise goals (Goal 2/3), there is **no
association, no 4-way handshake, and no key installation**: the
supplicant runs EAP over EAPOL directly on the Ethernet link, and on
EAP-Success the switch/authenticator opens the port.  No PMK/PTK
exists on wired 802.1X - the output of authentication is port
authorization (plus optionally MACsec later, which is out of scope).

**Workflow (high level):**
1. Bring the NIC up; the controlled port is blocked.
2. Optionally send EAPOL-Start; exchange EAPOL frames
   (EAP-Request/Identity, EAP-Response, method frames,
   EAP-Success/Failure) on ethertype `0x888E`.
3. On EAP-Success the port is authorized; shulid then applies the
   existing static / DHCPv4 / IPv6 config (reuse
   `src/daemon/{dhcp,ip}.rs`).
4. On EAP-Failure or timeout, retry with backoff (reuse the daemon's
   retry-loop pattern).

**Transport differences vs WiFi (important):**
* No nl80211: EAPOL TX/RX is fully in userspace over a raw
  AF_PACKET socket (nix + tokio `AsyncFd`, same approach as mozim's
  DHCPv4 socket) with a BPF filter for ethertype `0x888E`.
* No kernel key install and no control-port-over-netlink.
* Wired EAPOL is addressed to the PAE group address
  `01:80:c2:00:00:03` or the authenticator's MAC.

**Reuse from Goal 2:**
* The EAP peer state machine (RFC 4137) and EAP method stack
  (EAP-TLS first) are shared; Goal 2 should land the common `eap`
  module before this goal starts.
* EAPOL framing: extend `ieee80211::eapol` with EAPOL type 0 (EAP)
  frames - today only EAPOL-Key is parsed.
* The credential model (identity, CA cert, client cert/key,
  server-name validation) is shared.

**Scope:**
* Initial: EAP-TLS end-to-end on one wired NIC (matches Goal 2's
  method choice).
* Config: a new top-level daemon section (e.g. `ethernets:` with a
  per-NIC `eap:` block), distinct from `wifis:`; every field maps
  through the lib config.
* `shulid` runs wired and WiFi clients concurrently (one task per
  interface, mirroring the Stage 2 M7 multi-interface pattern).
* Out of scope: MACsec, MAC Authentication Bypass (MAB), and 802.1X
  over WiFi (that is Goal 2/3); PEAP/TTLS follow Goal 2's method
  order.

**Open questions before planning:**
* Test rig for a wired authenticator: hostapd `driver=wired` +
  FreeRADIUS, or a minimal in-test EAP server (hostapd wired support
  needs checking).
* Whether the library gets a `WiredClient` parallel to `WifiClient`
  or a unified EAP client - decide after Goal 2's EAP module shape.
* Raw-socket helper placement (a small `afpacket` module in shuli vs
  reusing mozim-style code).

## Cross-cutting notes for the future Stage 3 plan

* All **WiFi** goals **reuse the existing 4-Way Handshake and
  key-install path**; the new work is (a) PMK *sources* (EAP/MSK for
  Enterprise, PMKSA cache for FT) and (b) AKM-specific KDF/MIC/cipher
  variants (SHA-1 vs SHA-256 vs SHA-384, CCMP vs GCMP-256).
  PBKDF2/PRF for WPA2-PSK is done.  Wired 802.1X (Goal 6) is the
  exception: it stops at EAP-Success / port authorization and never
  enters the 4-way handshake.
* Crypto stays on the actual stack - **`p256` + `aws-lc-rs`** (the
  RustCrypto suite originally proposed in Stage 1 was replaced); the
  only expected addition is a TLS stack (`rustls`) for EAP-TLS.  New
  nl80211 attributes/commands land in `wl-nl80211` first.
* With no IPC control interface, new auth types are **config-schema
  fields activated by daemon restart**; the schema mirrors nipart's
  `WifiAuthType` (`Wpa2Personal`, `Enterprise`, `Wpa3Personal`, ...)
  and gains enterprise credential fields (certs/identity).  Every
  `WifiConfig`/`NetworkConfig` option must stay configurable through
  shulid's YAML file - extend the daemon schema whenever the lib
  config grows.
* Expand the integration harness to cover WPA2-PSK (Stage 2),
  WPA3-Ent, 192-bit suites, and FT (two hostapd BSSs in one netns)
  with hostapd/FreeRADIUS.
