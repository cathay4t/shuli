# SoftMAC/FullMAC WiFi connection support plan

Status: reduced scope implemented (M1-M3)  
Last updated: 2026-10-30

Implementation note: the capability probe, FullMAC
`NL80211_CMD_CONNECT` path, raw EAPOL transport and userspace 4-way +
`SET_STATION` authorization for open, WPA2-PSK/PSK-SHA256 and
WPA2/WPA3-Enterprise are implemented. OWE, firmware 4-way offload and
firmware roaming remain deferred; a FullMAC OWE/SAE/FT BSS is rejected
with `NoSupport`.

## 1. Objective

Make `shuli-wifi` select the correct Linux MLME path per wiphy:

1. **SoftMAC / userspace SME** (existing path, must not regress): a driver
   that advertises `NL80211_CMD_AUTHENTICATE` and
   `NL80211_CMD_ASSOCIATE`, as mac80211 does. shuli drives the pre-
   association exchange, association and 4-way handshake in userspace.
2. **FullMAC / driver SME** (new path): a driver that only advertises
   `NL80211_CMD_CONNECT` and performs authentication/association in
   firmware. shuli issues `NL80211_CMD_CONNECT`, then runs whatever part
   of the 4-way handshake the firmware does not offload.

FullMAC coverage is limited to the security modes listed in section 3.3:
open, WPA2-PSK, PSK-SHA256, WPA2-Enterprise, WPA3-Enterprise baseline and
OWE. SAE and FT remain SoftMAC-only, as already documented in README.

The capability must be queried from the wiphy (`NL80211_ATTR_SUPPORTED_COMMANDS`)
and stored, not guessed from the driver name or the presence of a
`connect` command alone: the kernel advertises `NL80211_CMD_CONNECT`
for drivers that only implement `.auth`/`.assoc` as well.

Decision summary:

* SoftMAC detection: `AUTHENTICATE` + `ASSOCIATE` present; keep the
  existing `AUTH`/`ASSOC` flow.
* FullMAC detection: only `CONNECT` present; add a
  `NL80211_CMD_CONNECT` flow.
* EAPOL transport: nl80211 control port when advertised, otherwise a
  raw AF_PACKET socket (all in-tree FullMAC drivers need the latter).
* FullMAC 4-way: userspace over that transport, or firmware offload via
  `NL80211_ATTR_PMK` / `NL80211_ATTR_WANT_1X_4WAY_HS`, completed by
  `NL80211_CMD_PORT_AUTHORIZED`.
* FullMAC security scope: open, WPA2-PSK/PSK-SHA256,
  WPA2/WPA3-Enterprise, OWE. SAE and FT are rejected with `NoSupport`.

```
SoftMAC (mac80211):
  scan -> CMD_AUTHENTICATE -> CMD_ASSOCIATE
       -> 4-way handshake (EAPOL over nl80211)
       -> SET_STATION authorized

FullMAC (CONNECT-only):
  scan -> CMD_CONNECT (SSID/BSSID/freq/RSNE/AKM/ciphers/CONTROL_PORT,
                       PMK or WANT_1X when offloaded)
       -> CONNECT result (status/BSSID/REQ_IE/RESP_IE)
       -> firmware 4-way when offloaded -> PORT_AUTHORIZED
       -> userspace 4-way over raw EAPOL -> SET_STATION authorized
```

## 2. Investigation findings

### 2.1 Kernel model

* `NL80211_CMD_AUTHENTICATE` requires `rdev->ops->auth`
  (`net/wireless/nl80211.c`, `nl80211_authenticate`); `NL80211_CMD_ASSOCIATE`
  requires `rdev->ops->assoc` (`nl80211_associate`).
* mac80211 registers `.auth = ieee80211_auth` and
  `.assoc = ieee80211_assoc`, and no `.connect`
  (`net/mac80211/cfg.c:6361`). It is therefore a userspace-SME/SoftMAC
  driver.
* `NL80211_CMD_CONNECT` is advertised when `rdev->ops->connect ||
  rdev->ops->auth` (`net/wireless/nl80211.c`, `nl80211_add_commands_unsplit`).
  Consequently a SoftMAC wiphy advertises both `CONNECT` and
  `AUTHENTICATE`/`ASSOCIATE`. The authoritative discriminator is
  `AUTHENTICATE` (+ `ASSOCIATE`), not `CONNECT`.
* `cfg80211_connect()` uses the cfg80211 SME (`cfg80211_sme_connect()`)
  when the driver has no `.connect`; that SME itself requires `.auth`
  and `.assoc` (`net/wireless/sme.c`). This is why forced `CONNECT` on
  mac80211 is usable for testing the new code path.
* `NL80211_ATTR_CONTROL_PORT_OVER_NL80211` is accepted only when the
  driver implements `.tx_control_port` and advertises
  `NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211`
  (`net/wireless/nl80211.c`, `validate_pae_over_nl80211`). In-tree,
  only mac80211 sets that feature (`net/mac80211/main.c`). FullMAC
  drivers do not, so on FullMAC EAPOL must use a raw AF_PACKET socket.
* DRIVER-SME 4-way offload capabilities are per-wiphy extension features:
  * `NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK`: pass the PMK in
    `NL80211_CMD_CONNECT` via `NL80211_ATTR_PMK`
    (`net/wireless/nl80211.c`, `nl80211_connect` does not accept it
    without this feature).
  * `NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X`: ask the driver to run
    the 4-way handshake after EAP with `NL80211_ATTR_WANT_1X_4WAY_HS`,
    then hand the PMK over with `NL80211_CMD_SET_PMK`.
  * `NL80211_EXT_FEATURE_SAE_OFFLOAD`: firmware SAE (out of scope).
* The CONNECT result event carries status, `NL80211_ATTR_MAC` (BSSID),
  `NL80211_ATTR_REQ_IE` and `NL80211_ATTR_RESP_IE`
  (`nl80211_send_connect_result`). The driver may rewrite the request
  IEs, so the RSNE used in the 4-way handshake must come from `REQ_IE`
  when present.
* `NL80211_CMD_PORT_AUTHORIZED` carries the peer MAC and an optional
  Transition Disable bitmap; it is the completion signal for offloaded
  4-way handshakes.
* `NL80211_CMD_ROAM` is used by firmware-roaming FullMAC drivers
  (`nl80211_send_roamed`), advertised as `NL80211_ATTR_ROAM_SUPPORT`.
* `NL80211_CMD_SET_STATION` with `NL80211_ATTR_STA_FLAGS2` +
  `NL80211_STA_FLAG_AUTHORIZED` is how userspace opens the data port
  after a host-side 4-way handshake. brcmfmac implements
  `change_station` for exactly this.

A concrete FullMAC example in-tree is brcmfmac
(`drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c`): it sets
`WIPHY_FLAG_SUPPORTS_FW_ROAM`, conditionally advertises
`4WAY_HANDSHAKE_STA_PSK`, `4WAY_HANDSHAKE_STA_1X`, `SAE_OFFLOAD` and
`FAST_ROAM_OFFLOAD`, consumes `sme->crypto.psk` (PSK offload),
`sme->want_1x` (1X offload), and implements `change_station()`
authorization.

### 2.2 wpa_supplicant model

* Capability detection: `NL80211_CMD_AUTHENTICATE` in
  `NL80211_ATTR_SUPPORTED_COMMANDS` sets `WPA_DRIVER_FLAGS_SME`
  (`src/drivers/driver_nl80211_capa.c`); without it, `CONNECT` is
  required. This is exactly the TODO item in `TODO.md`.
* Both SME and driver-SME use one `nl80211_connect_common()` builder,
  but choose `NL80211_CMD_ASSOCIATE` for SME and
  `NL80211_CMD_CONNECT` otherwise (`wpa_driver_nl80211_associate`).
* `nl80211_put_control_port()` always sets `NL80211_ATTR_CONTROL_PORT`
  for RSN/802.1X, and adds `NL80211_ATTR_CONTROL_PORT_OVER_NL80211`
  only when the driver advertises the ext feature. Otherwise EAPOL is
  moved over `l2_packet` (raw AF_PACKET).
* PSK 4-way offload: pass `NL80211_ATTR_PMK`; completion is reported by
  `NL80211_CMD_PORT_AUTHORIZED`.
* 1X 4-way offload: set `NL80211_ATTR_WANT_1X_4WAY_HS` in CONNECT;
  after EAP-Success, call `NL80211_CMD_SET_PMK` and let the driver run
  the 4-way.
* `mlme_event_connect()` ignores CONNECT events when the userspace SME
  flag is set (`src/drivers/driver_nl80211_event.c`). In driver-SME
  mode the CONNECT event is treated as `EVENT_ASSOC`.
* After a host-side 4-way handshake, `wpa_driver_nl80211_set_supp_port()`
  sends `NL80211_CMD_SET_STATION` with the `AUTHORIZED` flag.
* `wpa_supplicant_use_own_rsne_params()` re-reads the RSNE from the
  association request IEs reported by the driver before the 4-way
  handshake.
* `EVENT_PORT_AUTHORIZED` completes the connection when the driver did
  the 4-way handshake.

### 2.3 iwd model

* `wiphy.c` parses `NL80211_ATTR_SUPPORTED_COMMANDS` and sets
  `support_cmds_auth_assoc` only when both AUTHENTICATE and ASSOCIATE
  are present.
* `wiphy_control_port_enabled()` falls back to a raw PAE socket when
  `NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211` is absent.
* `netdev.c` distinguishes `CONNECTION_TYPE_SOFTMAC`, `FULLMAC`,
  `SAE_OFFLOAD`, `PSK_OFFLOAD` and `8021X_OFFLOAD`; the selection is
  driven by the ext features described above.
* OWE always uses `NL80211_CMD_CONNECT` (DH element in the request IE,
  AP DH element parsed from the CONNECT response IEs).
* The CONNECT request always includes SSID, frequency, MAC, auth type,
  RSN ciphers/AKMs/WPA version, privacy, MFP, the RSNE, the optional
  `CONTROL_PORT`/`CONTROL_PORT_OVER_NL80211` flags, and
  `SOCKET_OWNER`.
* `netdev_connect_event()` parses `REQ_IE`/`RESP_IE`, handles OWE DH,
  parses the FTE for initial FT association, then starts EAPOL.

### 2.4 shuli today

* All connection attempts unconditionally use
  `NL80211_CMD_AUTHENTICATE`/`NL80211_CMD_ASSOCIATE`
  (`src/wifi/auth.rs`, `src/wifi/client/associate.rs`).
* EAPOL is always sent/received over
  `NL80211_CMD_CONTROL_PORT_FRAME` (`src/wifi/nl80211.rs`,
  `src/wifi/client/events.rs`). This only works on wiphys advertising
  `CONTROL_PORT_OVER_NL80211` (in-tree: mac80211).
* The wiphy probe only fetches scheduled-scan caps and WoWLAN triggers
  (`src/wifi/client/wiphy.rs`); supported commands and ext features are
  not queried, so the client cannot tell SoftMAC from FullMAC.
* `WifiCaps` (`src/wifi/client/state.rs`) has no connection-mode,
  control-port or handshake-offload fields.
* On a FullMAC wiphy, `CMD_AUTHENTICATE` returns `-EOPNOTSUPP` and the
  client retries forever on the scan/authenticate cadence.

## 3. Scope

### 3.1 In scope

* Capability detection and storage per wiphy.
* FullMAC connection path via `NL80211_CMD_CONNECT` for:
  * open,
  * WPA2-PSK (AKM 2) and PSK-SHA256 (AKM 6),
  * WPA2-Enterprise (AKM 1) and WPA3-Enterprise baseline (AKM 5),
  * OWE (AKM 18).
* Raw AF_PACKET EAPOL transport when nl80211 control port is not
  available (mandatory for in-tree FullMAC drivers).
* Userspace 4-way handshake on top of CONNECT, including port
  authorization via `NL80211_CMD_SET_STATION`.
* Driver/firmware 4-way offload for PSK and 1X.
* PMKSA fallback, rekey offload, WoWLAN and resume behavior on the new
  path where applicable.
* Firmware `NL80211_CMD_ROAM` event handling that does not corrupt the
  userspace state.
* Tests on `mac80211_hwsim` with a test-only mode override, plus unit
  tests for all attribute construction and state decisions.
* Documentation, CHANGELOG and TODO cleanup.

### 3.2 Out of scope

* SAE / SAE-EXT-KEY / FT-SAE on FullMAC via external auth or SAE
  offload. Already a documented limitation; keep it.
* FT-PSK and FT roaming on FullMAC. The initial mobility-domain
  association is technically possible through CONNECT, but roaming
  afterwards needs FT authentication frames that CONNECT cannot carry.
* Host-initiated roaming on FullMAC, including
  `NL80211_ATTR_PREV_BSSID` reassociation. Use firmware roaming.
* FILS, DPP, SAE-PK, OWE group retry.
* WPA1/TKIP/WEP (unsupported everywhere).
* A user-facing configuration knob to force SoftMAC/FullMAC. Detection
  is automatic; only an in-crate test override is added.

### 3.3 Connection support matrix

| Security | SoftMAC | FullMAC | FullMAC 4-way |
|---|---|---|---|
| Open | AUTH+ASSOC | CONNECT | none |
| WPA2-PSK (AKM 2) | AUTH+ASSOC | CONNECT | userspace, or firmware if `4WAY_HANDSHAKE_STA_PSK` |
| PSK-SHA256 (AKM 6) | AUTH+ASSOC | CONNECT | same as WPA2-PSK |
| WPA2-Enterprise (AKM 1) | AUTH+ASSOC | CONNECT | userspace EAP + userspace/firmware 4-way |
| WPA3-Enterprise (AKM 5) | AUTH+ASSOC | CONNECT, MFPR | userspace EAP + userspace/firmware 4-way |
| OWE (AKM 18) | AUTH+ASSOC | CONNECT + DH IE (driver must accept AKM 18) | userspace |
| SAE (AKM 8), SAE-EXT (24/25) | AUTH+ASSOC, userspace SAE | reject with `NoSupport` | n/a |
| FT-PSK (AKM 4), FT-SAE (9/9+EXT) | AUTH+ASSOC | reject with `NoSupport` | n/a |
| WPA1/TKIP/WEP | reject | reject | n/a |

"userspace/firmware 4-way": use firmware offload when the wiphy
advertises the matching feature, otherwise run the existing userspace
4-way over the available control-port transport.

OWE is only as good as the FullMAC driver's AKM handling: some drivers
pass AKM 18 through to firmware, others reject it. brcmfmac's
`brcmf_set_key_mgmt()` currently has no OWE case and returns `-EINVAL`,
so OWE on brcmfmac must be validated before it is claimed as supported.
The forced-CONNECT hwsim test still exercises shuli's OWE code because
cfg80211 SME is AKM-agnostic.

## 4. Design

### 4.1 Capability model

Probe the wiphy once in `WifiIface::init()` and extend `WiphyCaps` with:

```rust
pub(crate) enum MlmeMode {
    /// AUTHENTICATE + ASSOCIATE: userspace SME (mac80211/SoftMAC).
    SoftMac,
    /// CONNECT without AUTHENTICATE/ASSOCIATE: driver SME (FullMAC).
    FullMac,
}

pub(crate) enum ControlPortMode {
    /// NL80211_CMD_CONTROL_PORT_FRAME (mac80211).
    Nl80211,
    /// AF_PACKET / ETH_P_PAE (in-tree FullMAC).
    RawEapol,
}

pub(crate) struct WiphyCaps {
    // existing fields ...
    pub(crate) mlme: MlmeMode,
    pub(crate) control_port: ControlPortMode,
    pub(crate) fourway_psk_offload: bool,
    pub(crate) fourway_1x_offload: bool,
    pub(crate) sae_offload: bool,      // logged / error text only
    pub(crate) roam_support: bool,     // NL80211_ATTR_ROAM_SUPPORT
    pub(crate) ext_key_id: bool,       // gate EKID on FullMAC
    pub(crate) ocv: bool,              // gate OCV on FullMAC
}
```

Selection rules:

* `mlme = SoftMac` when both `AUTHENTICATE` and `ASSOCIATE` are in
  `NL80211_ATTR_SUPPORTED_COMMANDS`; `CONNECT` may also be present.
* else `mlme = FullMac` when `CONNECT` is present.
* else fail `WifiIface::init()` with `ErrorKind::NoSupport` when networks
  are configured (a pure scan client uses the separate
  `WifiClient::scan()` API and is unaffected).
* `control_port = Nl80211` when
  `NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211` is advertised, else
  `RawEapol`.
* `fourway_psk_offload = ExtFeature::FourWayHandshakeStaPsk`.
* `fourway_1x_offload = ExtFeature::FourWayHandshakeSta1X`.
* `roam_support = NL80211_ATTR_ROAM_SUPPORT`.

The raw command list is logged once (`SoftMAC (userspace SME)` /
`FullMAC (driver SME)` plus the relevant features), so field reports show
which path was chosen.

Safety net: if the command list is unavailable or incomplete, record an
"auto" state. If the selected path returns `-EOPNOTSUPP`, flip to the
other path once for that attempt and retry (guarded by a per-attempt
set of tried modes). `is_eopnotsupp()` already exists in
`src/wifi/client/wiphy.rs`.

### 4.2 CONNECT request

Add a new `src/wifi/client/connect.rs` with
`send_out_connect_request()` and `build_connect_attrs()`.

Common attributes:

* `NL80211_ATTR_IFINDEX`
* `NL80211_ATTR_SSID`
* `NL80211_ATTR_MAC` (the exact BSS selected by the scan; shuli pins a
  BSS deliberately)
* `NL80211_ATTR_WIPHY_FREQ`
* `NL80211_ATTR_SOCKET_OWNER`
* `NL80211_ATTR_AUTH_TYPE = OPEN_SYSTEM` (OWE included; SAE never
  reaches this path)
* `NL80211_ATTR_IE` with the RSNE (plus the OWE DH element for OWE)
* `NL80211_ATTR_WPA_VERSIONS = WPA_VERSION_2` for every RSN mode
  (SAE is never sent through CONNECT)
* pairwise/group ciphers: CCMP-128 (matching the existing RSNE builders)
* `NL80211_ATTR_AKM_SUITES` with the single AKM of the selected security
* `NL80211_ATTR_PRIVACY` for all RSN modes (including OWE)
* `NL80211_ATTR_USE_MFP = REQUIRED` for OWE and WPA3-Enterprise, or for
  WPA2 modes when the AP advertises MFPC (same policy as the current
  association path)
* `NL80211_ATTR_CONTROL_PORT` and
  `NL80211_ATTR_CONTROL_PORT_ETHERTYPE = ETH_P_PAE` whenever the
  connection has a 4-way handshake (open has none)
* `NL80211_ATTR_CONTROL_PORT_OVER_NL80211` only when
  `control_port == Nl80211`

For PSK when `fourway_psk_offload` is set:

* derive the PBKDF2 PMK before CONNECT and add `NL80211_ATTR_PMK`
  (32 bytes).

For Enterprise when `fourway_1x_offload` is set:

* add `NL80211_ATTR_WANT_1X_4WAY_HS`.

For OWE:

* create `OweAuth` before CONNECT, append the OWE DH element to the IE
  attribute (RSNE first, DH element second), and on success parse the
  AP DH element from the CONNECT response IEs.

`NL80211_ATTR_EXTERNAL_AUTH_SUPPORT` is not used: SAE is rejected on
FullMAC and no other supported mode needs external auth.

`ShuliNl80211Connection::connect()` is added with the same
`-EALREADY` recovery as `authenticate()`: if cfg80211 still holds the
old connection, send `CMD_DISCONNECT` and retry once.

### 4.3 Control port transport

Add `src/wifi/control_port.rs`:

```rust
pub(crate) enum ControlPort {
    Nl80211,
    Raw {
        async_fd: AsyncFd<OwnedFd>,
        if_index: u32,
        local_mac: [u8; ETH_ADDR_LEN],
    },
}

impl ControlPort {
    fn send(&self, dst: [u8; 6], eapol: &[u8]) -> Result<(), WifiError>;
}
```

Raw socket details (mirroring iwd):

* `socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
  htons(ETH_P_PAE))`
* bind to `sockaddr_ll { sll_ifindex, sll_protocol = ETH_P_PAE }`
* send with `sendto()`, `sll_addr = BSSID` (EAPOL on WiFi is addressed
  to the AP, not the wired PAE group address)
* receive gives the EAPOL payload and the source MAC in `sockaddr_ll`.

The existing `shuli-wired` helper cannot be reused directly: it sends
Ethernet frames with the PAE group destination on a `SOCK_RAW` socket.
Either extract a shared helper with a destination parameter or keep a
WiFi-local copy; the plan assumes a WiFi-local module to avoid changing
the wired code path in this milestone.

Raw mode is opened lazily, before sending CONNECT/AUTH for a connection
that needs userspace EAPOL/4-way. This keeps open and PSK-offload-only
connections usable without `CAP_NET_RAW`, and the daemon already has
that capability.

### 4.4 Unified event source

The raw socket needs to feed the same state machine as nl80211 events.
Introduce a per-interface event enum:

```rust
enum WifiEvent {
    Kernel(Nl80211EventMsg),
    Eapol { src: [u8; ETH_ADDR_LEN], payload: Vec<u8> },
}
```

A small reader task owns the `AsyncFd`, reads frames and forwards
`Eapol` events to the interface queue created in `WifiClient`. The
kernel dispatcher wraps its messages in `Kernel`. All existing wait
loops (`Run`, `wait_scan_finish`, neighbor-report wait, retry backoff)
consume `WifiEvent`; kernel variants keep the current
`disconnect_info()` + `Nl80211Event::parse()` path, EAPOL variants feed
`handle_control_port_frame()`.

Ordering guarantees:

* nl80211 events are ordered among themselves.
* EAPOL frames are ordered among themselves.
* Cross-source ordering is inherently racy (already true for
  CONTROL_PORT_FRAME vs ASSOCIATE); the existing buffering
  (`pending_ft_msg1`) and state checks remain responsible for that.

The EAPOL handler verifies `src == link.bss_info.bssid` and ignores
frames in states without a live attempt/association. The reader task is
stopped when the interface is removed/shut down (drop the queue sender
or abort the task).

### 4.5 CONNECT result and shared association success

`Nl80211Event::ConnectResult` must be extended (in wl-nl80211) with the
BSSID from `NL80211_ATTR_MAC`, and optionally the `TIMED_OUT` flag and
timeout reason for better error text.

Extract the association-success logic currently in the
`Associated` handler into a shared `on_association_success(ies, rsne)`:

* Open: mark connected immediately.
* OWE: derive PMK/PMKID from the response DH element; wait for the
  4-way handshake.
* RSN: record the RSNE used by the driver (from `REQ_IE`) in
  `Link::assoc_rsne`; wait for EAPOL.
* PMKID-bearing association: same as today.

`Associated`/`Authenticated` continue to drive SoftMAC. In FullMac mode
they are logged and ignored (the kernel should not send them; treating
them as authoritative would duplicate CONNECT handling). Conversely,
`ConnectResult` success stays informational in SoftMAC mode, as today.

On CONNECT failure:

* if a cached PMKSA was in use, run `pmksa_fallback()` (drop the entry
  and retry without PMKID) instead of blacklisting the BSS;
* otherwise set `WifiState::Failed`.

### 4.6 4-way handshake changes

* `Link::assoc_rsne` stores the RSNE actually sent in the
  association/connect request (extracted from `REQ_IE` for FullMac;
  built by `associate()` for SoftMAC). `handle_control_port_frame()`
  uses it for Message 2 instead of rebuilding the RSNE, so a driver
  rewrite cannot break the handshake. The FT path keeps its special
  PMK-R1-based RSNE construction.
* After Message 3/4 and key installation, send
  `NL80211_CMD_SET_STATION` with `STA_FLAGS2 = { mask: AUTHORIZED,
  set: AUTHORIZED }` for the BSSID. This is required when
  `NL80211_ATTR_CONTROL_PORT` was set in CONNECT; it is harmless
  (best effort, logged) elsewhere. Add the wl-nl80211 attribute and
  request.
* `try_offload_rekey()` remains the only source of
  `ConnectedWithOffloadRekey` for host-side handshakes.

### 4.7 Driver 4-way offload

Add a per-attempt `HandshakeMode`:

```rust
enum HandshakeMode {
    None,            // open
    Userspace,       // userspace 4-way over ControlPort
    PskOffload,      // PMK passed in CONNECT, firmware runs 4-way
    Eapol1xOffload,  // EAP in userspace, SET_PMK, firmware runs 4-way
}
```

Selection happens in `send_out_connect_request()`:

* Open -> `None`.
* PSK/PSK-SHA256 + `fourway_psk_offload` -> `PskOffload`.
* WPA2/WPA3-Enterprise + `fourway_1x_offload` -> `Eapol1xOffload`.
* everything else -> `Userspace` (requires control port transport).

Behavior:

* `PskOffload`: `ConnectResult` success leaves the client in
  `Authenticating`; `PORT_AUTHORIZED` completes it as
  `ConnectedWithOffloadRekey`. No EAPOL state is created and no
  `SET_REKEY_OFFLOAD` is attempted.
* `Eapol1xOffload`: EAP runs in userspace exactly as today. On
  EAP-Success, call `NL80211_CMD_SET_PMK` with `MAC = BSSID` and the
  first 32 MSK bytes, then wait for `PORT_AUTHORIZED`. EAP-Failure and
  SET_PMK errors enter the normal failure path.
* `Userspace` on FullMac: 4-way over the selected control port; finish
  with `SET_STATION` authorization.
* Timeout classification:
  * PSK userspace handshake timeout -> `WrongPassword` (existing).
  * PSK-offload timeout -> transient `Failed`, not `WrongPassword`.
  * 1X-offload timeout -> transient `Failed` (EAP-Failure is the
    credential error).

`NL80211_CMD_PORT_AUTHORIZED` must be extended to expose the peer MAC
(and optionally the Transition Disable bitmap). Compare it with
`link.bss_info.bssid` before completing, and only accept it in
`Authenticating` for the current attempt. This also closes the
long-standing stale `PORT_AUTHORIZED` risk noted in `TODO.md`.

### 4.8 Scanning and candidate selection

`collect_scan_candidates()` must filter by connection mode, not only by
credentials:

* FullMac: `Sae`, `SaeExtKey`, `FtSae`, `FtSaeExtKey`, `FtPsk` are not
  connectable. Skip them and record a mode-specific
  `unsupported_security` reason, e.g.
  `"WPA3-SAE requires a SoftMAC driver (NL80211_CMD_AUTHENTICATE)"`.
* SoftMAC: current behavior unchanged.
* The scan-free hint path (`scan_free_target()` /
  `NetworkConfigHints::bss_info()`) applies the same filter, otherwise
  a persisted hint could bypass the scan-time check.

Existing scan/PNO/WoWLAN behavior is mode-independent and stays as is.
`NL80211_ATTR_MAX_NUM_SCAN_SSIDS` etc. are already probed; the
capability query should reuse one wiphy dump instead of issuing several.

### 4.9 Roaming

FullMAC firmware owns roaming. To avoid the userspace roam engine
calling `CMD_AUTHENTICATE`/`CMD_ASSOCIATE` on a CONNECT-only driver:

* Gate CQM-based roaming, background scans, post-connect best-BSS scan
  and BTM-triggered FT on `mlme == SoftMac`.
* Continue to register for action frames only where supported, but in
  FullMac mode log/ignore BTM requests (the firmware decides).
* Extend wl-nl80211 with `Nl80211Event::Roamed` (same payload as
  CONNECT). On `ROAM`:
  * verify the new BSSID against the current link;
  * update `link.bss_info` from the event/scan cache (BSSID, frequency,
    signal, IEs) so hints and logs stay accurate;
  * if the connection uses firmware 4-way offload, stay connected;
  * otherwise mark the link lost and let the normal retry path reconnect
    (a firmware roam without offload leaves userspace keys invalid).
* `NL80211_ATTR_ROAM_SUPPORT` is probed and logged. Firmware roaming is
  not otherwise driven by shuli in this milestone.

### 4.10 Public API

Implemented scope: `WifiState` is unchanged and the detected mode is
logged at client init. The read-only accessor below is deferred until
nipart needs it:

```rust
#[non_exhaustive]
pub enum WifiMlmeMode {
    SoftMac,
    FullMac,
}

impl WifiClient {
    pub fn mlme_mode(&self, iface_name: &str) -> Option<WifiMlmeMode>;
}
```

No production config knob is added. For tests, add a `#[cfg(test)]`
override on `WifiConfig`:

```rust
#[cfg(test)]
pub(crate) struct TestModeOverride {
    pub mlme: Option<MlmeMode>,
    pub control_port: Option<ControlPortMode>,
    pub fourway_psk_offload: Option<bool>,
    pub fourway_1x_offload: Option<bool>,
}
```

This lets the hwsim integration tests force CONNECT, raw EAPOL and
offload decisions deterministically, while release builds contain none
of it.

### 4.11 Error handling

* `NoSupport` with an actionable message when:
  * the wiphy advertises neither AUTHENTICATE+ASSOCIATE nor CONNECT;
  * a selected BSS requires SAE/FT on a FullMAC wiphy;
  * EAPOL transport cannot be established for a connection that needs
    it.
* `ConnectFailed`/`AuthFailed`/`WrongPassword` keep their current
  meanings. Do not report `WrongPassword` from an offload timeout or a
  CONNECT failure before the 4-way handshake has started.
* `-EALREADY` on CONNECT: disconnect and retry once (same policy as
  AUTHENTICATE today).
* `-EOPNOTSUPP` on AUTHENTICATE/ASSOCIATE: flip the MLME mode once and
  retry with CONNECT.
* Log one line per interface at init and per attempt with the chosen
  mode, control-port transport and handshake mode.

## 5. wl-nl80211 dependency work

Implemented scope: **no wl-nl80211 changes were needed.** The reduced
path builds the extra `NL80211_ATTR_CONTROL_PORT` flag and the
`NL80211_CMD_SET_STATION` `STA_FLAGS2` attribute with `DefaultNla`
through the crate's public generic `Nl80211Handle::request()` API.
The items below remain the clean upstream follow-up (especially BSSID
and ROAM-event modelling):

1. `Nl80211Attr`:
   * `ControlPort` flag (`NL80211_ATTR_CONTROL_PORT`)
   * `Want1X4WayHs` flag (`NL80211_ATTR_WANT_1X_4WAY_HS`)
   * `StaFlags2` (`NL80211_ATTR_STA_FLAGS2`, mask + set bitfields)
2. `Nl80211Connect` builder:
   * `.control_port()`, `.want_1x_4way_hs()`, `.pmk(Vec<u8>)`,
     `.prev_bssid([u8; 6])` (the last one for future reassociation)
3. `Nl80211Pmk` builder: `.mac([u8; 6])` (required by `CMD_SET_PMK`).
4. A `Nl80211SetStation` builder or a `Nl80211ConnectionHandle::set_station()`
   request using the new `StaFlags2` attribute.
5. `Nl80211EventConnectResult`: add `bssid: Option<[u8; 6]>`, plus
   `timed_out`/`timeout_reason` for diagnostics.
6. `Nl80211Event::Roamed` parsed from `NL80211_CMD_ROAM` with the same
   payload as CONNECT.
7. `Nl80211Event::PortAuthorized`: add `bssid: Option<[u8; 6]>` and the
   optional Transition Disable bitmap.
8. Extend `Nl80211ExtFeature` if a kernel feature needed by the
   implementation is newer than the crate's enum (currently the needed
   ones - `FourWayHandshakeStaPsk`, `FourWayHandshakeSta1X`,
   `ControlPortOverNl80211`, `ExtKeyId`, `OperatingChannelValidation`,
   `SaeOffload` - are already modelled).

Decision required: upstream these changes and bump the crate, or switch
the workspace to the git dependency until a release is cut. Do not
vendor a patched copy inside shuli.

## 6. Code changes by file

| File | Change |
|---|---|
| `src/wifi/client/wiphy.rs` | One wiphy dump; parse supported commands/ext features/roam support; compute `MlmeMode`, `ControlPortMode` and offload flags; keep WoWLAN/sched-scan caps |
| `src/wifi/client/state.rs` | Extend `WiphyCaps`; add `HandshakeMode` and `assoc_rsne` to `Link`; add control-port state; add `MlmeMode` re-export |
| `src/wifi/client/connect.rs` (new) | CONNECT attribute builder, `send_out_connect_request()`, `SET_PMK`, `SET_STATION` authorization, handshake-mode selection |
| `src/wifi/control_port.rs` (new) | `ControlPort` enum, raw AF_PACKET EAPOL send/receive, reader task |
| `src/wifi/auth.rs` | Dispatch to SoftMAC (current code) or CONNECT; keep EAP/PSK preparation shared |
| `src/wifi/client/associate.rs` | Record `assoc_rsne` for the SoftMAC path; PMKSA fallback unchanged |
| `src/wifi/client/events.rs` | Shared association-success handler; CONNECT result; ignore cross-mode events; `PORT_AUTHORIZED` BSSID checks/offload completion; `ROAM`; raw EAPOL; mode-aware timeouts |
| `src/wifi/scan.rs` | Mode-aware candidate and hint filtering; mode-specific `NoSupport` reasons |
| `src/wifi/roam.rs` | Disable host-driven roaming on FullMAC; add firmware-roam state update |
| `src/wifi/client/wifi_client.rs` | Unified `WifiEvent` queue, raw EAPOL reader registration, `mlme_mode()` accessor |
| `src/wifi/nl80211.rs` | `connect()` (with `-EALREADY` retry), `set_pmk()`, `set_station_authorized()` |
| `src/wifi/lib.rs` | Export `WifiMlmeMode` and the accessor |
| `src/wifi/tests/*` | Unit tests for caps/attrs/state; forced-CONNECT integration tests |
| `README.md`, `CHANGELOG`, `TODO.md` | Document FullMAC support and remove the two completed TODO items |

No `shulid` YAML or nipart API changes are required. Existing callers
keep using `WifiClient` unchanged.

## 7. Milestones

### M1 - Capability detection and model (no behavior change)

* Single wiphy capability query.
* `MlmeMode`, `ControlPortMode`, offload flags, `WifiClient::mlme_mode()`.
* Log the selected mode and features.
* Unit tests for the selection table.
* Existing test suite must pass unchanged; hwsim logs `SoftMAC`.

Acceptance: on mac80211/hwsim the mode is SoftMAC and every existing
test still passes; on a FullMAC wiphy the log shows FullMAC and the
required features.

### M2 - CONNECT path for open, WPA2-PSK and OWE

* CONNECT attribute builder and request wrapper.
* Shared association-success handling and CONNECT result parsing.
* RSNE from `REQ_IE`; OWE DH handling.
* `SET_STATION` authorization after userspace 4-way.
* Forced-FullMAC integration tests on hwsim using the nl80211 control
  port (hwsim advertises it).
* Wrong password still reported as `WrongPassword`.

Acceptance: forced-FullMAC tests for open, PSK, PSK-SHA256 and OWE
connect, rekey and reconnect; SoftMAC tests unchanged.

### M3 - Raw EAPOL and 4-way offload

* `ControlPort::RawEapol`, reader task and unified event queue.
* PSK offload (`NL80211_ATTR_PMK`, `PORT_AUTHORIZED`).
* 1X offload (`WANT_1X_4WAY_HS`, `SET_PMK` after EAP).
* Mode-aware timeouts and `PORT_AUTHORIZED` BSSID checks.
* Forced-FullMAC + forced-raw tests on hwsim for PSK and Enterprise.
* Hardware validation on brcmfmac (offload and host-supplicant paths
  if both can be selected).

Acceptance: enterprise EAP-TLS connects with raw EAPOL; PSK/1X offload
completes via `PORT_AUTHORIZED`; data path works after authorization;
wrong credentials fail cleanly.

### M4 - Enterprise/OWE hardening, rekey, WoWLAN, resume

* PMKSA fallback on CONNECT failure.
* Rekey offload on host-side 4-way; no rekey offload on firmware
  4-way.
* WoWLAN arm/disarm and resume behavior on FullMAC.
* Hidden SSID, scan-free hints, fast reconnect and PNO tests in forced
  FullMAC mode.
* SAE/FT on FullMAC surfaces `NoSupport` once instead of a retry loop.

Acceptance: full forced-FullMAC matrix passes; existing SoftMAC matrix
passes; Resume/WoWLAN tests behave as on SoftMAC.

### M5 - Firmware roaming, docs and release

* Parse `NL80211_CMD_ROAM` and update the link without corrupting
  userspace state.
* Gate host roaming in FullMAC mode.
* README/CHANGELOG/TODO updates and a hardware validation note.
* Run the whole workspace test suite and formatting/lints.

Acceptance: a firmware roam keeps the connection usable when 4-way is
offloaded; otherwise the client reconnects cleanly; documentation
matches behavior.

## 8. Test plan

### 8.1 Unit tests

* Capability table:
  * AUTH+ASSOC (with or without CONNECT) -> SoftMAC.
  * CONNECT only -> FullMac.
  * neither -> NoSupport.
  * `CONTROL_PORT_OVER_NL80211` -> nl80211 transport, otherwise raw.
  * 4-way PSK/1X flags -> offload decisions.
* CONNECT attribute construction per `SecurityType`:
  * SSID/MAC/freq/auth type/privacy/WPA version/ciphers/AKM/MFP;
  * IE contains the expected RSNE (and OWE DH element only for OWE);
  * `CONTROL_PORT` and over-nl80211 flags;
  * `PMK` only for PSK offload, `WANT_1X` only for 1X offload.
* RSNE extraction from `REQ_IE` and fallback to the locally built RSNE.
* Handshake-mode selection and timeout classification.
* Candidate filtering: SAE/FT rejected in FullMac mode with the exact
  reason; scan-free hints filtered identically.
* `PORT_AUTHORIZED` and `ROAM` BSSID validation.

### 8.2 Integration tests (root, mac80211_hwsim, hostapd)

The test override forces FullMac and/or raw EAPOL while keeping the real
mac80211/hostapd stack. This exercises CONNECT through cfg80211 SME and
both EAPOL transports, but not a real FullMAC driver's `.connect`
implementation.

| Test | SoftMAC default | FullMac + nl80211 CP | FullMac + raw PAE |
|---|---|---|---|
| Open | existing | new | new |
| WPA2-PSK | existing | new | new |
| PSK-SHA256 | existing | new | new |
| WPA2-Enterprise (EAP-TLS) | existing | new | new |
| WPA3-Enterprise (AKM 5) | existing | new | new |
| OWE | existing | new | new |
| Wrong password -> `WrongPassword` | existing | new | new |
| Hidden SSID | existing | new | new |
| Group rekey | existing | new | new |
| Reconnect/fast retry | existing | new | new |
| Scan-free hints | existing | new | new |
| SAE/FT | existing | `NoSupport` | `NoSupport` |

Not testable on hwsim (unit tests + hardware validation):

* `4WAY_HANDSHAKE_STA_PSK`/`_1X` offload and `PORT_AUTHORIZED`.
* `NL80211_CMD_SET_PMK`.
* Firmware `NL80211_CMD_ROAM`.
* A real driver where `CONTROL_PORT_OVER_NL80211` is absent.

### 8.3 Hardware validation

The host used for planning has no FullMAC radio (the MT7925 is
mac80211/SoftMAC), so hardware must be added. Two practical options:

* Raspberry Pi 3/4/5/Zero 2 W: built-in brcmfmac SDIO (BCM43430/43455),
  a true `NL80211_CMD_CONNECT` FullMAC. Default boot exercises firmware
  4-way offload (FWSUP). Reload with
  `modprobe brcmfmac feature_disable=8192` (`BIT(13)` = `FWSUP`) to
  force host 4-way over raw EAPOL on the same device.
* USB brcmfmac dongles (verify the ID against `modinfo brcmfmac`
  aliases first): `0a5c:bd17` BCM43236, `0a5c:bd1e` BCM43143,
  `0a5c:bd1f` / `043e:3101` BCM43242, `13b1:0039` Linksys AE1200
  (BCM43235). FWSUP availability depends on the firmware.

Validation matrix:

* PSK with firmware 4-way offload and, with `feature_disable=8192`, host
  4-way over raw EAPOL.
* Enterprise (EAP-TLS) with 1X offload and host 4-way.
* WPA3-Enterprise baseline if the firmware/AP support MFPR/AKM 5.
* OWE only on a driver that accepts AKM 18; brcmfmac currently does
  not, so OWE remains covered by the forced-CONNECT hwsim test until a
  supporting driver is available.
* Confirm:
  * the init log reports FullMac and the offload flags,
  * DHCP/data path works after authorization,
  * group rekey and suspend/resume keep working,
  * a wrong PSK reports `WrongPassword` without a retry storm,
  * a firmware roam does not leave stale userspace state.
* If another FullMAC driver is available (mwifiex, wilc1000, ...), run
  the same matrix and record which features it advertises.
* Avoid Realtek RTL8188/8192/8812 and MediaTek MT7601/MT76 USB parts:
  they are mac80211 SoftMAC and do not exercise the FullMAC path.

## 9. Risks and open questions

### Risks

* FullMAC driver behavior varies widely: IE rewriting, missing
  `PORT_AUTHORIZED`, authorization via `SET_STATION` not supported, and
  different offload combinations.
* The raw EAPOL path is only fully exercised on real hardware; hwsim can
  only validate the transport mechanics.
* Firmware roaming can desynchronize the userspace BSS/key state. The
  first implementation deliberately reconnects when 4-way is not
  offloaded.
* `wl-nl80211` changes must be released or consumed via git; leaving a
  private patch in shuli would be a maintenance trap.
* OWE on FullMAC depends on the driver accepting AKM 18; brcmfmac
  currently rejects it. Do not claim FullMAC OWE support until a
  supporting driver is validated.
* OWE group retry is still missing (pre-existing limitation), so some
  APs may not connect.
* Treating CONNECT success as connected for offloaded PSK (iwd behavior)
  versus waiting for `PORT_AUTHORIZED` (wpa_supplicant behavior) needs a
  hardware decision.

### Open questions

1. Should `WifiMlmeMode` be public API now, or only logged internally
   until nipart asks for it? (Recommended: public read-only accessor.)
2. Firmware roaming policy: keep the connection with offload and update
   hints (recommended), or force a reconnect on every `ROAM` event?
3. Offload completion: wait for `PORT_AUTHORIZED` (wpa_supplicant
   parity) or mark connected on CONNECT success (iwd parity)? Confirm
   on brcmfmac.
4. Dependency workflow for the wl-nl80211 additions: upstream release
   versus git dependency until the next release.
5. Should initial FT-PSK association on FullMAC be added later
   (CONNECT can carry the FT RSNE/MDIE and the AP returns the FTE), or
   keep all FT on SoftMAC? Recommended: keep it out until firmware
   roaming is validated.
6. The SAE/WPA3-on-FullMAC limitation stays as documented; confirm no
   user request justifies external-auth SAE work in this cycle.

## 10. References

Kernel (`~/Source/linux`):

* `net/wireless/nl80211.c`
  * supported-command advertisement: `nl80211_add_commands_unsplit`
  * `nl80211_authenticate`, `nl80211_associate`
  * `nl80211_connect`, `nl80211_valid_auth_type`
  * `nl80211_crypto_settings`, `validate_pae_over_nl80211`
  * `nl80211_set_pmk`
  * `nl80211_send_connect_result`, `nl80211_send_roamed`,
    `nl80211_send_port_authorized`
* `net/wireless/sme.c`: `cfg80211_sme_connect`, `cfg80211_connect`,
  `cfg80211_conn_do_work`
* `net/mac80211/cfg.c`: `ieee80211_auth`, `ieee80211_assoc`
* `net/mac80211/main.c`: `CONTROL_PORT_OVER_NL80211` ext features
* `net/mac80211/mlme.c`: automatic station authorization when no
  control port is requested
* `include/uapi/linux/nl80211.h`: `4WAY_HANDSHAKE_STA_*`,
  `CONTROL_PORT_OVER_NL80211`, `EXTERNAL_AUTH_SUPPORT`, `ROAM_SUPPORT`,
  `WANT_1X_4WAY_HS`
* `drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c`:
  FullMAC feature advertisement, PSK/1X offload, `change_station`
  authorization, and the lack of an OWE case in `brcmf_set_key_mgmt()`
* `drivers/net/wireless/broadcom/brcm80211/brcmfmac/common.c` /
  `feature.c`: `feature_disable` module parameter and the `FWSUP`
  feature bit (`BIT(13)`, decimal 8192)

wpa_supplicant (`~/Public_Sources/wpa_supplicant-2.11`):

* `src/drivers/driver_nl80211_capa.c`: SME detection, ext features
* `src/drivers/driver_nl80211.c`: `nl80211_connect_common`,
  CONNECT vs ASSOCIATE, control port, PMK/1X attributes,
  `set_supp_port`, `set_pmk`
* `src/drivers/driver_nl80211_event.c`: CONNECT/ROAM event handling,
  userspace-SME filtering
* `wpa_supplicant/events.c`: association success, own-RSNE update,
  offload completion, `PORT_AUTHORIZED`
* `wpa_supplicant/wpas_glue.c`: EAPOL transport, 1X offload PMK

iwd (`~/Public_Sources/iwd`):

* `src/wiphy.c`: supported commands, control-port feature, SAE modes
* `src/netdev.c`: connection types, CONNECT/ASSOCIATE builders, CONNECT
  event parsing (OWE/FTE/REQ_IE), raw PAE socket, driver-offload paths
* `src/nl80211util.c`: RSN attribute construction

shuli:

* `src/wifi/auth.rs`: current userspace-SME authentication
* `src/wifi/client/associate.rs`: ASSOCIATE and PMKSA
* `src/wifi/client/events.rs`: event/state machine, 4-way, EAP
* `src/wifi/client/wiphy.rs`: current wiphy probes
* `src/wifi/client/state.rs`: `WiphyCaps`, `Link`, `AuthSession`
* `src/wifi/nl80211.rs`: nl80211 request wrappers
* `src/wifi/scan.rs`: candidate selection and security classification
* `src/wired/eap.rs`: existing raw EAPOL socket pattern
* `TODO.md`: the two items this plan implements
