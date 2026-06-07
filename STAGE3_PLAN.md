<!-- SPDX-License-Identifier: Apache-2.0 -->
# 书立 (shuli) — Stage 3 Goals (notes only)

> Stage 3 extends shuli beyond WPA3-Personal. **No development plan yet** — this
> document records goals, protocol names, and authentication workflows in
> enough detail to produce a good plan after Stage 1 lands. Spec references are
> to `~/Source/wifi_docs/` (`802.11-2020.pdf`, `802.11-2024.pdf`,
> `wpa2.pdf`, `wpa3_v3.3.pdf`).

## Goal 1 — WPA2-Personal (WPA2-PSK)

**AKM:** `00-0F-AC:2` (PSK) and `00-0F-AC:6` (PSK-SHA256).
**Cipher:** CCMP-128 (`00-0F-AC:4`); must also gracefully handle TKIP-only
legacy APs as *unsupported/deprecated* rather than crashing.

**Key difference vs WPA3-Personal:** **no SAE**. The PMK is derived directly
from the passphrase, then the same **4-Way Handshake** (already built in
Stage 1) installs PTK/GTK.

**Workflow:**
1. Scan, select BSS, confirm AKM=PSK in RSNE.
2. **PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096 iters, 256 bits)**
   (802.11-2020 §J.4 / `wpa2.pdf`). Crate: `pbkdf2` + `hmac` + `sha1`
   (already in the Stage 1 RustCrypto set).
3. 4-Way Handshake (reuse Stage 1 `crypto::handshake4`), but with the
   **PSK AKM PRF/MIC** variant:
   - PTK via PRF-512/PRF-384 using **HMAC-SHA1** (AKM 2) or **HMAC-SHA256**
     (AKM 6); EAPOL-Key MIC = HMAC-SHA1-128 / HMAC-SHA256-128 accordingly.
4. Install keys via `NL80211_CMD_NEW_KEY`; kernel does CCMP.

**Notes / scope:**
- This is mostly a *configuration + KDF-selection* extension of the existing
  4-way handshake; relatively low effort once Stage 1 exists.
- Add **WPA2/WPA3 transition mode** handling (AP advertises both PSK and SAE):
  prefer SAE when available, fall back to PSK.
- Consider exposing `auth_types` selection / autodetect in config & schema
  (nipart already models `Wpa2Personal` and `Wpa3Personal`).
- Decide policy on **TKIP** and **WPA1** — almost certainly reject as insecure.

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
- **SHA-384** PRF + KCK-256/KEK-256 in the 4-way handshake (extend
  `crypto::handshake4` to the 192-bit AKM variant; `sha2` already covers
  SHA-384; AES Key Wrap with 256-bit KEK via `aes-kw`).
- **PMF mandatory:** BIP (BIP-CMAC-128 / BIP-GMAC-256) for protected
  management frames — confirm whether kernel/driver handles BIP after key
  install or whether userspace must compute MMIE; design accordingly.
- **Certificate policy:** enforce the 192-bit suite's allowed EAP-TLS cipher
  suites and curve (P-384).

**Open questions to resolve before planning:**
- Which EAP methods to support first (EAP-TLS vs PEAP/MSCHAPv2 vs EAP-TTLS) —
  enterprise deployments vary; EAP-TLS is the cleanest pure-Rust target.
- `rustls` suitability for EAP-TLS framing and for the 192-bit cipher
  constraints; fallback if gaps exist.
- BIP / PMF responsibilities split between shuli and the kernel.
- RADIUS-side test rig (hostapd + FreeRADIUS, or hostapd internal EAP server)
  for integration testing.

## Cross-cutting notes for the future Stage 3 plan

- All three goals **reuse the Stage 1 4-Way Handshake and key-install path**;
  the new work is (a) PMK *sources* (PBKDF2 for WPA2, EAP/MSK for Enterprise)
  and (b) AKM-specific KDF/MIC/cipher variants (SHA-1 vs SHA-256 vs SHA-384,
  CCMP vs GCMP-256).
- Crypto stays within the **RustCrypto** set chosen in Stage 1; additions are
  `pbkdf2` (already listed) and a TLS stack (`rustls`) for EAP.
- Schema already anticipates these via nipart's `WifiAuthType`
  (`Wpa2Personal`, `Enterprise`, `Wpa3Personal`, …) — extend shuli's schema to
  match, adding enterprise credential fields (certs/identity).
- Expand the integration harness to cover WPA2-PSK, WPA3-Ent, and 192-bit
  suites with hostapd/FreeRADIUS.
