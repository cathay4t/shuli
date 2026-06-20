<!-- SPDX-License-Identifier: Apache-2.0 -->

# Crypto crate investigation — conclusion

**Date:** 2026-06-20
**Status:** validated for Stage 1 (WPA3-Personal SAE + 4-way handshake)

## Recommendation

Adopt the **RustCrypto ecosystem** for all WiFi authentication crypto:

| Need | Crate |
|------|-------|
| ECC group ops (P-256) | `p256` (features: `arithmetic`, `hash2curve`, `expose-field`) |
| Hash-to-Curve (SSWU) | `elliptic-curve` (feature: `hash2curve`) |
| HMAC | `hmac` |
| SHA-256 | `sha2` |
| AES-CMAC | `cmac` + `aes` |
| AES Key Wrap (RFC 3394) | `aes-kw` |
| IEEE 802.11 KDF | in-tree `crypto::kdf` using `hmac` + `sha2` |
| CSPRNG | `rand_core` + `getrandom` |
| IEEE 802.11 frame construction | in-tree `ieee80211/` module |

No single "WiFi crypto" crate is needed — the dataplane (CCMP/GCMP) is handled by
the kernel after `NL80211_CMD_NEW_KEY`, keeping the userspace crypto surface
small.

## Validation

- **End-to-end interop (live):** validated against `hostapd` (WPA3-SAE,
  `sae_pwe=2`, CCMP-128, MFP) over `mac80211_hwsim`. `shulid` completes SAE
  (H2E), associates, runs the 4-way handshake, installs PTK/GTK, and successfully
  pings the AP's IP. See `tests/integration.sh`.
- **SAE (H2E, group 19 / P-256):** round-trip tests in `crypto::sae::tests`
  confirm mutual authentication with matching PMK for same password, mismatched
  PMK for different passwords. PWE derivation follows the PT-based H2E
  construction (RFC 9380 SSWU via `hash2curve`, salt = SSID), `keyseed`/`KCK`/
  `PMK` via the IEEE 802.11 KDF, and the `CN` confirm via HMAC-SHA256.
- **4-Way Handshake:** tests in `crypto::handshake4::tests` verify PTK
  derivation, AES-CMAC MIC, AES Key Wrap/Unwrap, and GTK-KDE parsing. The MIC is
  computed over the raw EAPOL-Key PDU (no Ethernet header) using key descriptor
  version 0 (AES-CMAC) as required by the SAE AKM.
- **EAPOL-Key framing:** round-trip tests in `ieee80211::eapol::tests`.
- **SAE auth frame framing:** round-trip tests in `ieee80211::auth::tests`.

## Implementation notes (nl80211 / wl-nl80211)

- SAE runs in userspace via the mac80211 SME path: `NL80211_CMD_AUTHENTICATE`
  with `NL80211_ATTR_AUTH_DATA` (`transaction || status || group || scalar ||
  element`; status 126 = `SAE_HASH_TO_ELEMENT` for H2E), followed by
  `NL80211_CMD_ASSOCIATE` with the RSNE + RSNXE. The kernel delivers the AP's
  commit/confirm as `NL80211_CMD_AUTHENTICATE` events.
- The 4-way handshake uses control-port-over-nl80211: EAPOL PDUs arrive as
  `NL80211_CMD_CONTROL_PORT_FRAME` events and are sent with `NL80211_ATTR_FRAME`
  (raw PDU) + `NL80211_ATTR_MAC` (AP) + `NL80211_ATTR_CONTROL_PORT_ETHERTYPE`.
- 802.11 fixed fields in Authentication frames are little-endian.
- `NL80211_ATTR_KEY_CIPHER` uses the kernel-native suite value (CCMP =
  `0x000FAC04`), not the OUI-first wire encoding; `NL80211_ATTR_KEY_TYPE` is a
  `u32`; group keys must not carry a MAC address.

## Risks and mitigations

1. **`hash2curve` feature on `elliptic-curve`:** confirmed to provide the SSWU
   map for P-256 needed by 802.11 H2E. No gaps found.
2. **Constant-time:** H2E largely mitigates the timing side-channel risk that
   exists in legacy hunt-and-peck. The `hash2curve` implementation in RustCrypto
   uses constant-time field operations.
3. **`wl-nl80211` key attributes:** key-related `Nl80211Attr` variants are not
   yet modeled in `wl-nl80211`. Key installation uses raw `NL80211_CMD_NEW_KEY`
   messages via `Nl80211Attr::Other(DefaultNla)`. This can be refactored when
   upstream support is added.

