# IPsec support roadmap

Status: implemented (M0-M6 core; M7 interoperability and hardening ongoing)  
Last updated: 2026-10-19

## 1. Objective

Add native IPsec support to shuli as a new workspace crate, `shuli-ipsec`,
implemented in Rust on top of Linux XFRM. The crate must be usable by:

1. **`nipart-plugin-ipsec`** (to be created in the nipart repository) as
   the IKE/IPsec engine. The plugin owns the XFRM interface and XFRM
   rules, obtains and refreshes Child SA keys, applies them in the
   kernel, and reports tunnel information back to the nipart daemon.
   Address, route, and DNS configuration remain nipart daemon work.
2. **`shulid`** for systems that do not run nipart. `shulid` uses the
   same library and applies address, route, and DNS configuration with
   its existing IP/DHCP code.
3. Third-party Rust applications that need an async IKEv2/XFRM client
   without nipart or shulid.

The supported topologies are:

- point-to-point,
- ad-hoc,
- site-to-site.

## 2. Design principles

- Use `local` and `remote` throughout public APIs, YAML, documentation,
  logs, and tests. Do not expose libreswan endpoint naming.
  Alias handling belongs to nipart; shuli consumes concrete endpoints.
- Keep the IPsec library independent of nipart, DHCP, addresses,
  routes, and DNS. `shuli-ipsec` may create/delete XFRM links and
  XFRM state/policies; it must not assign IP addresses or install
  ordinary routes and DNS records.
- Implement IKEv2 natively. Do not shell out to libreswan, strongSwan,
  or another keying daemon, and do not make them runtime dependencies.
- Reuse `shuli-core` for transport-neutral EAP/EAP-TLS. Keep
  `shuli-core` free of IKE, XFRM, and nipart dependencies.
- Support initiator and responder roles. Role is an internal protocol
  property; public configuration uses local/remote endpoints.
- Prefer route-based IPsec using XFRM interfaces. Every tunnel-mode
  connection gets an XFRM interface with an `if_id`; the interface is
  the integration point for address, route, firewall, and DHCP-style
  lease reporting. Transport-mode host-to-host may use the same model
  if the milestone-0 kernel validation confirms it is reliable;
  otherwise policy-based transport is a documented exception.
- One `IpsecClient` per network namespace manages all configured
  connections and peers, with one nl/xfrm socket and one IKE socket
  set per namespace.
- Use only Apache-2.0-compatible code. libreswan and swanny are
  references for behavior and interoperability, not code to copy.

## 3. Non-goals for the first release

- IKEv1 and its authentication methods.
- Opportunistic/unauthenticated IPsec and peer discovery.
- EAP-TLS server/responder support. `shuli-core` currently provides
  the EAP-TLS client method only.
- IKEv2 reauthentication with EAP re-authentication extensions.
- IPsec transport for arbitrary non-IP protocols beyond what Linux XFRM
  already supports.
- Replacing a full routing suite. nipart or shulid owns routing.
- VTI, IPTFS, labeled IPsec, PPK, and post-quantum key exchange in the
  first milestone series.

## 4. Terminology and topology model

### 4.1 Endpoint model

Every connection has exactly one local endpoint and one or more remote
peers. Each endpoint has:

- underlay address or interface reference,
- IKE identity,
- optional protected subnet selectors,
- IKE port and NAT-T state,
- authentication material.

`initiator` and `responder` are protocol roles, not configuration
names. A connection may be configured to initiate, accept inbound IKE,
or both.

### 4.2 Point-to-point

- One local endpoint, one remote endpoint.
- Host-to-host with transport or tunnel mode, or host-to-subnet with
  tunnel mode.
- Remote address may be static or learned from the peer identity.
- Road-warrior mode is a point-to-point variant: the remote underlay
  address may change and the peer may receive an inner address and DNS
  settings through IKEv2 Configuration Payload.
- Both local and remote may initiate when configured.

### 4.3 Ad-hoc

- A static set of two or more peers with no central gateway.
- Each pair of nodes has an independent IKE SA and one or more Child
  SAs. A full mesh of N nodes has O(N^2) SAs.
- A local node may initiate to any configured peer and respond to any
  authenticated peer.
- Initial scope: statically configured peer list; optional dynamic
  remote underlay address learned after authenticated exchange.
- No multicast discovery, DNS-based opportunistic discovery, or
  unauthenticated peer acceptance in the first release.
- Each peer gets its own XFRM interface and `if_id` unless an explicit
  shared-interface policy is configured later.

If "ad-hoc" is intended to mean opportunistic encryption rather than a
static mesh, it must be split into a separate feature: it changes the
trust model, policy installation, and acquire handling.

### 4.4 Site-to-site

- Gateway-to-gateway tunnel connecting local and remote protected
  subnets.
- Traffic selectors are subnet ranges, not just host addresses.
- Multiple Child SAs or multiple traffic selectors per peer are allowed.
- Hub-and-spoke is site-to-site with multiple remote peers.
- Forwarding and routes to remote subnets are external (nipart or
  shulid), not part of `shuli-ipsec` itself.
- One XFRM interface per remote gateway/tunnel by default.

### 4.5 XFRM interface ownership

- The XFRM interface is the route-based VPN device. It is created with
  `if_id` and an underlay link using rtnetlink (`LinkXfrm`).
- `if_id` identifies the tunnel in XFRM SAs, policies, and templates.
- `reqid` identifies the SA bundle associated with policies.
- Both values must be unique within a network namespace. They may be
  explicitly configured or allocated by `shuli-ipsec`.
- The default interface name is configurable. An automatically allocated
  name must be stable for the lifetime of the connection and must not
  collide with existing links.
- The library creates/deletes only the XFRM link. Address, MTU policy,
  routes, and DNS are applied by nipart or shulid.
- Cleanup is ownership-scoped: only SAs, policies, and interfaces
  created by this client instance are removed. Never flush all XFRM
  state.

## 5. Architecture

```
nipart daemon
    |
    v
nipart-plugin-ipsec (separate repository)
    |
    +--> shuli-ipsec::IpsecClient  ---- UDP 500/4500 ----> remote peer
    |
    +--> shuli-ipsec::XfrmManager  ---- XFRM netlink ----> kernel
    |
    +--> IpsecLease (inner selectors, addresses, DNS, state)
             |
             v
        nipart daemon: address / route / DNS

shulid
    |
    +--> shuli-ipsec (same client and XFRM manager)
    |
    +--> existing ip.rs / dhcp.rs: address / route / DNS
```

### 5.1 Crates

| Crate | Responsibility |
| --- | --- |
| `shuli-core` | Shared EAP/EAP-TLS, EAPOL, common errors. No IPsec dependency. |
| `shuli-ipsec` | New crate: IKEv2 engine, XFRM manager, public client API, public config/event/lease types. |
| `shulid` | YAML config, connection lifecycle, address/route/DNS, systemd integration. |
| `nipart-plugin-ipsec` | Nipart-facing schema and plugin lifecycle; lives in the nipart repository. |

Proposed crate location and package metadata:

```text
src/ipsec/Cargo.toml       package = "shuli-ipsec", lib = "shuli_ipsec"
```

Add it to the workspace `members` and `workspace.dependencies` lists.

### 5.2 Internal module layout

```text
src/ipsec/
  lib.rs
  config.rs          public configuration types
  error.rs           IpsecError and IpsecErrorKind
  client.rs          IpsecClient, event stream, connection lifecycle
  identity.rs        IKE identities and certificate identity matching
  ikev2/
    codec.rs         IKE header and payload encode/decode
    crypto.rs        crypto primitives and key derivation
    proposal.rs      proposals, transforms, negotiation
    sa.rs            IKE SA and Child SA state
    state.rs         IKE_SA_INIT / IKE_AUTH / CREATE_CHILD_SA / INFORMATIONAL
    auth/            PSK, certificate, EAP-TLS client
    transport.rs     UDP 500/4500, retransmission, NAT-T
  xfrm/
    mod.rs           XfrmManager
    interface.rs     LinkXfrm create/delete/query
    state.rs         XFRM SAs
    policy.rs        XFRM policies and templates
    monitor.rs       acquire/expire event subscription
  tests/
```

### 5.3 Dependencies

- XFRM wire format: `netlink-packet-xfrm` 0.5 from
  `/home/fge/Source/netlink/netlink-packet-xfrm`.
- Netlink transport: `netlink-packet-core`, `netlink-proto`,
  `netlink-sys`.
- Link management: `rtnetlink`, using `LinkXfrm` and `InfoXfrm::IfId`.
- Async runtime and utilities: `tokio`, `futures`, `log`.
- Crypto: `aws-lc-rs`, `getrandom`, `zeroize`, and `rustls` through
  `shuli-core` for EAP-TLS.
- X.509 parsing and verification: choose in milestone 0, preferably
  RustCrypto or rustls-webpki pieces rather than OpenSSL/NSS.
- Serde support for public config/event types is optional behind a
  feature so library users are not forced to depend on serde.

Start with a thin async XFRM handle over `netlink-packet-xfrm`; do not
take a hard dependency on `xfrmnetlink`'s higher-level API. Re-evaluate
after milestone 1 if it materially reduces lifecycle code.

### 5.4 Runtime model

- One `IpsecClient` per network namespace, similar to `WifiClient`.
- Each connection has one or more independent IKE SAs.
- A worker task owns IKE sockets, retransmission timers, XFRM event
  monitoring, and rekey timers.
- Public operations are async and cancellation-safe.
- `run()`/`next_event()` returns one event at a time so a plugin worker
  can serialize slow work without blocking the nipart daemon.
- `shutdown()` sends delete notifications where possible and removes
  owned XFRM state/interfaces.

## 6. Public API target

The API must be sufficient for `nipart-plugin-ipsec` without exposing
internal modules or requiring a shulid dependency. The API has two
layers:

### 6.1 IKE engine — `IpsecClient`

The engine negotiates IKE and Child SAs and exposes opaquely held key
material. It does not install SAs or policies.

```rust
pub struct IpsecConfig {
    pub name: String,
    pub topology: Topology,
    pub local: LocalConfig,
    pub peers: Vec<PeerConfig>,
    pub ike: IkeConfig,
    pub child: ChildConfig,
    pub xfrm: XfrmConfig,
    pub rekey: RekeyConfig,
    pub dpd: DpdConfig,
}

pub struct PeerConfig {
    pub remote: RemoteConfig,
    pub selectors: TrafficSelectorPair,
    /// Per-peer authentication; ad-hoc peers may use different
    /// credentials while sharing one connection configuration.
    pub auth: AuthConfig,
}

pub enum Topology {
    PointToPoint,
    AdHoc,
    SiteToSite,
}

pub enum AuthConfig {
    Psk(Secret),
    Certificate(CertificateConfig),
    EapTls(EapConfig),
}

pub struct IpsecLease {
    pub connection: String,
    pub peer_index: usize,
    pub xfrm_interface: Option<String>,
    pub if_id: u32,
    pub reqid: u32,
    pub local_selectors: Vec<TrafficSelector>,
    pub remote_selectors: Vec<TrafficSelector>,
    pub local_inner_addresses: Vec<IpNet>,
    pub remote_inner_addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub expires_at: Option<SystemTime>,
}

pub enum IpsecEvent {
    State { connection: String, state: IpsecState },
    ChildSaReady {
        connection: String,
        peer_index: usize,
        child: ChildSaHandle,
        lease: IpsecLease,
    },
    ChildSaRefreshed {
        connection: String,
        peer_index: usize,
        child: ChildSaHandle,
        lease: IpsecLease,
    },
    ChildSaRemoved {
        connection: String,
        peer_index: usize,
        reason: ChildSaRemovalReason,
    },
    Error { connection: String, error: IpsecError },
}

impl IpsecClient {
    pub async fn init(configs: Vec<IpsecConfig>) -> Result<Self, IpsecError>;
    pub async fn run(&mut self) -> Result<IpsecEvent, IpsecError>;
    pub async fn update(&mut self, configs: Vec<IpsecConfig>) -> Result<(), IpsecError>;
    pub async fn shutdown(&mut self);
    pub fn state_of(&self, connection: &str) -> Option<IpsecState>;
}
```

`ChildSaHandle` is an opaque, non-`Debug` handle containing the Child SA
selectors, SPIs, algorithms, and keys. Keys are zeroized on drop. The
handle is passed to `XfrmManager::install()`; callers cannot read raw
keys through the public API. A rekey produces a new handle and the old
one is released after the old kernel state is removed.

### 6.2 Kernel layer — `XfrmManager`

`XfrmManager` is the only public API that writes XFRM state. Both nipart
and shulid use it.

```rust
pub struct XfrmManager { /* private */ }

impl XfrmManager {
    pub async fn new() -> Result<Self, IpsecError>;

    pub async fn ensure_interface(
        &mut self,
        spec: &XfrmInterfaceSpec,
    ) -> Result<XfrmInterface, IpsecError>;

    pub async fn install(
        &mut self,
        child: &ChildSaHandle,
        spec: &InstallSpec,
    ) -> Result<InstalledChildSa, IpsecError>;

    pub async fn remove(
        &mut self,
        installed: &InstalledChildSa,
    ) -> Result<(), IpsecError>;

    pub async fn remove_interface(
        &mut self,
        interface: &XfrmInterface,
    ) -> Result<(), IpsecError>;

    pub async fn cleanup_owned(&mut self) -> Result<(), IpsecError>;
}
```

`InstallSpec` includes XFRM interface name/`if_id`, `reqid`, mode
(transport/tunnel), optional marks, lifetimes, replay/ESN, and policy
priority. `InstalledChildSa` records enough identity to remove exactly
the installed SAs and policies later.

### 6.3 Convenience layer for shulid

`shulid` may use a small orchestration helper on top of `IpsecClient`
and `XfrmManager`, for example `IpsecConnection`, which:

1. starts the IKE engine,
2. ensures the XFRM interface,
3. installs the Child SA,
4. exposes the lease to the daemon's IP layer,
5. refreshes/removes state on rekey and teardown.

This helper must remain a thin composition; the two lower layers stay
public and usable by the nipart plugin.

## 7. Nipart plugin contract

The nipart plugin is responsible for the IPsec service lifecycle and
XFRM kernel state. The shuli library must make the following flow
possible using public APIs only:

1. **Apply**: nipart sends desired `ipsec`/`xfrm` state. The plugin maps
   it to `IpsecConfig` and enqueues work on a dedicated worker. The
   nipart apply call returns without blocking.
2. **IKE**: the worker creates/updates `IpsecClient`. Authentication is
   PSK, certificate, or EAP-TLS client.
3. **XFRM**: on `ChildSaReady`/`ChildSaRefreshed`, the plugin creates or
   reuses the XFRM interface via `XfrmManager::ensure_interface()`,
   installs SAs and policies with `XfrmManager::install()`, and records
   the resulting lease.
4. **Lease reporting**: the plugin publishes the lease in its live
   state. `query_network_state()` returns it without blocking. The
   nipart daemon uses the lease (selectors, inner addresses, DNS, XFRM
   interface) to apply address, route, and DNS configuration.
5. **Rekey/refresh**: a new Child SA is installed before the old one is
   removed. The plugin updates the live lease after the new SA is
   active, then removes the old state after a short grace period.
6. **Teardown**: delete XFRM policies/SAs/interface owned by the
   connection and remove the lease.
7. **Resume**: on system resume, re-check XFRM state and IKE liveness;
   re-establish missing SAs and cancel pre-suspend retry backoff.
8. **Errors**: map `IpsecErrorKind` to nipart error kinds. Authentication
   failures and unsupported proposals must be reported promptly instead
   of waiting for the nipart verification timeout.

API properties required by nipart:

- no dependency on `shulid`, CLI code, or global singletons;
- async, `Send`, cancellation-safe operations;
- one engine per network namespace, multiple connections per engine;
- no IP/route/DNS mutation by the library;
- precise ownership of kernel objects for safe cleanup;
- no secrets in `Debug` output or logs;
- public types documented and versioned for cross-repository use.

A standalone example under `examples/` must implement this flow using
only public APIs. That example is the acceptance test for "sufficient
API for nipart-plugin-ipsec".

## 8. Protocol and kernel scope

### 8.1 IKEv2

First release:

- IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL.
- Proposal negotiation for IKE and ESP.
- PSK authentication (RFC 7296).
- Certificate authentication with X.509, certificate requests, and
  identity validation.
- EAP-TLS client authentication over IKE_AUTH using `shuli-core`
  EAP/EAP-TLS and the EAP MSK.
- Traffic selector negotiation and narrowing.
- Multiple Child SAs and rekeying; IKE SA rekeying.
- Delete notifications, DPD/liveness checks, retransmission, request
  queueing, and message-ID handling.
- IKEv2 fragmentation (RFC 7383).
- NAT detection, UDP 4500 encapsulation, and keepalives.
- IPv4 and IPv6 underlay and inner traffic.
- IKEv2 Configuration Payload for inner address and DNS reporting in
  point-to-point/road-warrior deployments.

Later or explicitly deferred:

- MOBIKE (RFC 4555).
- IKEv2 redirect, PPK, post-quantum groups, IPTFS, labeled IPsec.
- Additional EAP methods and EAP-TLS server/responder support.
- AH; ESP is the default and first protocol.

Proposal defaults should be conservative and interoperable, with
explicit overrides:

- IKE: AES-GCM-16 or AES-CBC with HMAC-SHA2-256, PRF HMAC-SHA2-256,
  DH ECP-256/X25519/MODP-2048.
- ESP: AES-GCM-16-256 or AES-CBC-128 with HMAC-SHA2-256, optional ESN.
- PFS enabled for Child SA rekey where the peer supports it.

### 8.2 XFRM

Use `netlink-packet-xfrm` message types and attributes directly:

- XFRM SAs: source/destination, SPI, protocol, mode, algorithms,
  replay window/ESN, lifetimes, `if_id`, `reqid`, optional marks.
- XFRM policies: direction, action, selector, priority, lifetime,
  `if_id`, `reqid`, and templates for outbound SAs.
- XFRM interfaces: create/delete with underlay link and `if_id` via
  rtnetlink; support IPv4 and IPv6 underlay.
- Monitor `XFRM_MSG_ACQUIRE`, `XFRM_MSG_EXPIRE`, and policy expiry
  events. Use them for diagnostics and fallback rekey behavior; do not
  rely on acquire alone to establish traffic-driven SAs.
- Dump and remove only state/policies/links owned by this client.
- Support both transport and tunnel modes; route-based XFRM interfaces
  are the default for tunnel connections, including point-to-point.
  Transport-mode host-to-host uses the same interface model when the
  milestone-0 validation proves it reliable; otherwise it uses
  policy-based XFRM as a documented exception.
- Never install ordinary routes, addresses, DNS, or firewall rules.

### 8.3 Topology mapping

| Topology | Peers | Child SA mode | Selectors | XFRM interface |
| --- | --- | --- | --- | --- |
| Point-to-point | 1 | transport or tunnel | host or host-to-subnet | One per connection; route-based by default |
| Ad-hoc | N static peers | transport or tunnel | per-peer host/subnet | One per peer |
| Site-to-site | 1 gateway per tunnel, or many | tunnel | local/remote subnets | One per gateway/tunnel |

Road-warrior is point-to-point with dynamic remote underlay and optional
Configuration Payload.

## 9. Milestones

Sizes are engineering estimates, not release commitments. A milestone
is complete only when its exit criteria pass in CI and, where required,
on a root-capable test host.

### M0 — Architecture decisions and feasibility spike

Size: 1 week. Depends on: none.

Tasks:

- Confirm the ad-hoc definition (static mesh vs. opportunistic IPsec).
- Decide whether the first release includes MOBIKE and EAP-TLS server.
- Choose the X.509 parsing/verification stack and confirm license
  compatibility.
- Decide how MODP DH groups are implemented with the chosen crypto
  library.
- Prototype XFRM interface creation and static SA/policy installation
  with `netlink-packet-xfrm` in a network namespace.
- Write the public API sketch and review it against the nipart plugin
  flow in section 7.
- Confirm root test strategy using the existing cargo runner.

Exit criteria:

- Decisions recorded in this document.
- A static XFRM tunnel passes traffic between two namespaces.
- Static SA/policy state is removed cleanly by ownership, not by flush.
- No unresolved blocker for the IKEv2 implementation.

### M1 — Workspace skeleton and XFRM foundation

Size: 2-3 weeks. Depends on: M0.

Tasks:

- Add `src/ipsec` as workspace member `shuli-ipsec`.
- Add `IpsecError`/`IpsecErrorKind`, config validation, and secret
  wrappers with zeroization.
- Implement the async XFRM manager:
  - XFRM interface create/delete/query with rtnetlink;
  - SA add/update/delete/dump;
  - policy add/update/delete/dump;
  - `if_id`, `reqid`, templates, marks, lifetimes, replay/ESN;
  - acquire/expire monitoring;
  - ownership-scoped cleanup;
  - netlink error mapping.
- Add root integration tests with network namespaces and veth pairs.
- Add codec/unit tests for XFRM message construction.

Exit criteria:

- `XfrmManager` can create an XFRM interface, install a pair of SAs and
  matching policies, pass traffic, and remove exactly those objects.
- Stale-state cleanup removes only owned objects.
- Tests run as root and skip safely when XFRM or netns support is
  unavailable.

### M2 — IKEv2 core and PSK authentication

Size: 4-6 weeks. Depends on: M1.

Tasks:

- Implement IKEv2 header and payload codecs.
- Implement crypto primitives and key derivation with the selected
  library.
- Implement proposal/transform parsing, selection, and rejection.
- Implement IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, and INFORMATIONAL
  state machines.
- Implement PSK authentication and identity handling.
- Implement message retransmission, request/response matching, error
  notifications, and basic DPD.
- Implement Child SA creation, rekey, and deletion with ESP.
- Add a test peer runner and self-connection tests.
- Interoperate with swanny for basic PSK transport/tunnel cases and
  with libreswan for PSK tunnel/transport.
- Add negative tests for malformed payloads, bad MACs, bad proposals,
  and replayed messages.

Exit criteria:

- PSK point-to-point works as initiator and responder.
- Rekey and delete complete without traffic interruption beyond the
  expected SA transition.
- Interoperates with libreswan in both directions for PSK.
- No plaintext leak during Child SA installation.

### M3 — Certificate and EAP-TLS client authentication

Size: 4-6 weeks. Depends on: M2.

Tasks:

- X.509 parsing, chain construction, validity checks, and signature
  verification.
- Identity matching for IPv4, IPv6, FQDN, RFC 822, and DER names.
- Certificate request handling and selection of local credentials.
- RSA, ECDSA, and EdDSA authentication where the crypto library
  supports them.
- Adapt `shuli_core::eap::{EapPeer, EapPacket}` and
  `shuli_core::eap_tls::EapTlsMethod` to IKEv2 EAP-AUTH payloads.
- Implement EAP identity exchange, fragmentation, and MSK handoff to
  IKE_AUTH.
- Evaluate whether IKEv2 deployments still require TLS 1.2; extend the
  EAP-TLS client if required for interoperability.
- Add certificate failure tests: wrong CA, expired certificate, wrong
  identity, missing client key, untrusted chain.
- Interoperate with libreswan and, where available, strongSwan for
  certificate and EAP-TLS client cases.

Exit criteria:

- Certificate authentication works as initiator and responder.
- EAP-TLS client authentication works with libreswan.
- The negotiated MSK is used for the IKE_AUTH authentication payload.
- Authentication failures are reported with precise error kinds.
- EAP-TLS server/responder remains explicitly unsupported unless a
  separate milestone is approved.

### M4 — NAT-T, robustness, and protocol completeness

Size: 3-4 weeks. Depends on: M3.

Tasks:

- NAT detection and UDP 4500 encapsulation/decapsulation.
- NAT keepalives and path failure detection.
- IKEv2 fragmentation for large certificate chains.
- Cookie challenges and basic anti-DoS behavior.
- Replay window and ESN handling.
- Lifetimes, soft/hard expiry, rekey fuzzing, and simultaneous rekey
  handling.
- Traffic selector narrowing and multi-selector Child SAs.
- IPv4/IPv6 combinations, including 4-in-6 and 6-in-4 where practical.
- Configuration Payload handling for inner address and DNS lease data.
- Soak tests and parser fuzz targets.

Exit criteria:

- Point-to-point works through NAT as initiator and responder.
- Long-running soak test (rekey, delete, reconnect, network flap) has no
  leaks or stuck states.
- Fuzz targets run without panics or unbounded allocations.
- Interop matrix for NAT-T and IPv6 passes.

### M5 — Public client API, topologies, and XFRM lifecycle

Size: 3-4 weeks. Depends on: M4.

Tasks:

- Implement the public `IpsecClient`, event, lease, and `ChildSaHandle`
  APIs.
- Implement the public `XfrmManager` API and ownership model.
- Implement point-to-point, site-to-site, and static ad-hoc topologies.
- Implement responder peer matching by identity for ad-hoc and
  site-to-site.
- Implement XFRM interface/`if_id`/`reqid` allocation and collision
  handling.
- Implement atomic rekey: install new Child SA, switch policies, remove
  old Child SA after grace.
- Implement event reporting for state changes, rekey, removal, and
  errors.
- Add a standalone example consumer that performs the nipart-like flow.
- Add API documentation and an API review with the nipart plugin
  author.

Exit criteria:

- Example consumer uses only public APIs to create an XFRM interface,
  install SAs/policies, refresh on rekey, and clean up on exit.
- Point-to-point, site-to-site, and three-node ad-hoc tests pass.
- API review confirms no shulid/nipart concepts leak into the library.
- API is frozen for shulid and nipart plugin integration (changes after
  this point require a compatibility review).

### M6 — shulid integration

Size: 2-3 weeks. Depends on: M5.

Tasks:

- Extend `ShuliConfig` with an `ipsecs` list using local/remote naming.
- Map YAML credentials, identities, selectors, topology, and XFRM
  settings to `IpsecConfig`.
- Start/stop `IpsecClient` connections alongside WiFi and Ethernet
  tasks.
- On lease/state events, create the XFRM interface and apply IP/DNS
  configuration with the existing `ip.rs`/`dhcp.rs` code.
- Install routes to remote selectors through the XFRM interface where
  configured.
- Handle retries, rekey refresh, shutdown cleanup, and system resume.
- Add an example YAML file, man page updates, and systemd notes.
- Ensure shulid works without nipart for point-to-point and
  site-to-site; ad-hoc support follows the configured peer list.

Exit criteria:

- shulid brings up each supported topology from YAML.
- IPv4/IPv6 addresses, routes, and DNS are applied by shulid, not by
  `shuli-ipsec`.
- Restart and shutdown leave no owned XFRM state.
- Existing WiFi/Ethernet behavior is unchanged.

### M7 — Interoperability, hardening, and release

Size: 4+ weeks. Depends on: M6.

Tasks:

- Build a repeatable libreswan interoperability matrix:
  - PSK, certificate, and EAP-TLS client.
  - point-to-point, site-to-site, and road-warrior.
  - transport and tunnel modes.
  - IPv4 and IPv6.
  - NAT-T and rekey.
- Optionally add strongSwan coverage for the same matrix.
- Review certificate validation, key handling, secret zeroization, and
  logging.
- Run fuzzing continuously on IKE payload and XFRM attribute parsers.
- Add documentation, changelog entries, packaging updates, and release
  notes.
- Audit that no GPL/LGPL implementation code was copied.

Exit criteria:

- Interop matrix passes or has documented, accepted exceptions.
- Security review finds no unresolved critical or high issues.
- Fuzz targets have a clean baseline.
- Release documentation covers topology configuration, DNS/IP
  responsibilities, and cleanup semantics.

### M8 — Future work (not committed)

- EAP-TLS server/responder support and additional EAP methods.
- MOBIKE for mobile point-to-point/road-warrior.
- IKEv2 redirect, PPK, post-quantum key exchange (ML-KEM), IPTFS, and
  labeled IPsec.
- Opportunistic IPsec, if it becomes a requirement.
- Policy-based IPsec without XFRM interfaces.
- AH support.
- High-availability/failover and multi-path IPsec.

### Milestone summary

| Milestone | Main result | Depends on |
| --- | --- | --- |
| M0 | Decisions and XFRM feasibility | - |
| M1 | `shuli-ipsec` crate and XFRM manager | M0 |
| M2 | IKEv2 core with PSK | M1 |
| M3 | Certificate and EAP-TLS client auth | M2 |
| M4 | NAT-T, robustness, protocol completeness | M3 |
| M5 | Public API, topologies, XFRM lifecycle | M4 |
| M6 | shulid integration | M5 |
| M7 | Interop, hardening, release | M6 |
| M8 | Future features | M7 |

## 10. Test plan

### 10.1 Unit tests

- IKE header/payload encode/decode round trips and malformed inputs.
- Proposal selection and transform matching.
- Key derivation and PRF test vectors.
- Authentication payload/signature verification.
- XFRM message encode/decode, selectors, templates, `if_id`, and
  `reqid`.
- Ownership and cleanup decision logic.

### 10.2 Integration tests

Use network namespaces and veth pairs. The existing cargo runner executes
tests as root, so integration tests can self-provision namespaces and
XFRM state. Skip cleanly when kernel XFRM interface support or required
capabilities are missing.

Scenarios:

- Self-to-self PSK, certificate, and EAP-TLS client.
- Point-to-point host-to-host transport and tunnel.
- Point-to-point host-to-subnet.
- Site-to-site subnet-to-subnet, including multiple selectors.
- Three-node ad-hoc mesh.
- Rekey, delete, reconnect, peer restart, local restart.
- Soft/hard lifetime expiry and XFRM expire handling.
- NAT-T through a namespace NAT.
- IPv4, IPv6, and mixed inner/outer families.
- Ownership cleanup with unrelated XFRM state present.

### 10.3 Interoperability tests

Use libreswan from `/home/fge/Public_Sources/libreswan` as the primary
oracle. Useful reference suites include:

- `testing/pluto/ikev2-hostpair-01`
- `testing/pluto/ikev2-systemrole-02-net-to-net`
- `testing/pluto/ikev2-xfrmi-02`
- `testing/pluto/ikev2-25-rw-nat`
- EAP-TLS client tests under `testing/pluto/` matching `eaptls`.

Treat these as behavior references and configuration inputs only. Do not
copy libreswan code or mirror its endpoint naming.

Use swanny from `/home/fge/Public_Sources/swanny` for early PSK
transport/tunnel interoperability. Swanny is explicitly experimental
and incomplete (no certificate, EAP, or NAT-T coverage); it is not the
final conformance reference.

### 10.4 Soak and fuzz testing

- Long-running rekey/delete loops with state dumps and leak checks.
- Random malformed IKE messages and XFRM attributes.
- Certificate-chain stress cases.
- Network flap, NAT rebinding, and duplicate/out-of-order packets.
- Verify that shutdown always removes owned XFRM state.

## 11. Security requirements

- Zeroize PSK, private keys, IKE/Child SA keys, nonces, and derived
  secrets on drop.
- Never print secrets or raw key material in `Debug`, logs, or errors.
- Validate certificate chains, validity periods, key usage, and
  identity binding.
- Validate peer identities before accepting responder or ad-hoc peers.
- Implement replay protection and reject invalid message IDs.
- Bound all parser allocations and fragment reassembly buffers.
- Apply NAT-T and IKE fragmentation limits defensively.
- Avoid full XFRM flushes; always scope cleanup to owned objects.
- Keep privileged operations limited to netlink/XFRM and UDP sockets.
  The library itself does not require root; `shulid` does.
- Document the trust model for PSK, certificate, EAP-TLS, and ad-hoc
  peer sets.
- Respect upstream licenses: shuli is Apache-2.0; do not copy GPL or
  LGPL implementation code from libreswan or swanny.

## 12. Risks and open questions

### Risks

- IKEv2 is a large protocol surface; NAT-T, fragmentation, rekey, and
  authentication edge cases can consume most of the schedule.
- Implementing certificate validation and DH groups with a non-OpenSSL
  crypto stack may require additional crates or custom constant-time
  code.
- XFRM policy/template lifecycle and atomic rekey are easy to get subtly
  wrong; they need dedicated integration tests.
- Cleanup bugs can leave persistent kernel state after crashes or
  restarts.
- The nipart plugin API may evolve while the library is being built; the
  M5 API review and standalone consumer are the mitigation.
- EAP-TLS client reuse may need TLS 1.2 support or EAP server work for
  full interop.
- libreswan behavior is broad; the test matrix must be prioritized to
  avoid an open-ended interoperability effort.

### Open questions

1. Does "ad-hoc" mean a statically configured mesh, or opportunistic
   IPsec with peer discovery? This plan assumes a static mesh for the
   first release.
2. Is EAP-TLS responder/server support required for site-to-site or
   ad-hoc gateways? `shuli-core` currently has client-side EAP-TLS only.
3. Is MOBIKE required in the first release for point-to-point and
   road-warrior?
4. Should the default XFRM interface name be `xfrmN`, `ipsecN`, or
   derived from the connection name? Explicit naming always wins.
5. Are policy-based tunnels without XFRM interfaces required, or is
   route-based XFRM the only supported deployment?
6. Which DH groups and ESP algorithms must be enabled by default for
   the target deployments?
7. Should `shuli-ipsec` expose serde support directly, or leave YAML
   mapping entirely to shulid and the nipart plugin?

## 13. M0 decisions

The feasibility decisions are now recorded here:

- **Ad-hoc** means a statically configured mesh.  Opportunistic IPsec and
  peer discovery remain out of scope.
- **MOBIKE** and **EAP-TLS server/responder** are deferred.  The first
  release supports the EAP-TLS client only.
- **X.509** parsing and path validation use `rustls-webpki`
  (Apache-2.0-compatible); signatures, ECDH, AEAD, HMAC, and AES-CBC use
  `aws-lc-rs`.
- **MODP-2048** is implemented with `num-bigint` constant-length modular
  exponentiation; ECP-256, ECP-384, and X25519 use `aws-lc-rs`.
- The XFRM layer talks to the kernel through `netlink-packet-xfrm` and
  `netlink-proto` directly; no `xfrmnetlink` high-level dependency is
  used.
- Root integration tests use the existing cargo `sudo` runner and skip
  cleanly when XFRM interfaces or capabilities are unavailable.
- Route-based XFRM interfaces are the default for tunnel mode.  Transport
  mode uses policy-based XFRM, which is the documented exception in the
  plan.

### Implemented scope

- `shuli-ipsec` workspace crate with public config, event, lease,
  `IpsecClient`, `ChildSaHandle`, `XfrmManager`, `InstallSpec`, and
  ownership-scoped cleanup APIs.
- IKEv2 codec, PRF/PRF+, AEAD and AES-CBC/HMAC, DH (ECP/X25519/MODP),
  proposal negotiation, PSK and X.509 authentication, EAP-TLS client
  authentication through `shuli-core`, NAT-T, DPD, Delete notifications,
  and Child SA rekeying.
- XFRM interface, SA, policy, mark, lifetime, replay/ESN, acquire/expire
  monitor, and exact-ownership removal.
- `shulid` `ipsecs` YAML, IKE/XFRM lifecycle, host address assignment,
  routes to remote selectors, DNS application, and shutdown cleanup.
- Unit, self-connection, certificate, rekey, and root XFRM tests, plus the
  `examples/nipart_flow` public-API consumer.

### Remaining interoperability work (M7)

- IKE SA rekeying and IKEv2 fragmentation on the wire.
- Full Configuration Payload lease reporting for road-warrior mode.
- Multi-peer ad-hoc/one-runner-per-namespace socket sharing.
- libreswan/strongSwan interoperability matrix, soak, and fuzz runs.

## 14. References

- RFC 7296 — Internet Key Exchange Protocol Version 2 (IKEv2).
- RFC 7383 — IKEv2 Fragmentation.
- RFC 4555 — IKEv2 Mobility and Multihoming (MOBIKE).
- RFC 3948 — UDP Encapsulation of IPsec ESP Packets.
- RFC 5216 — EAP-TLS.
- RFC 9190 — EAP-TLS 1.3.
- Linux XFRM UAPI: `/home/fge/Source/linux/include/uapi/linux/xfrm.h`.
- `netlink-packet-xfrm`:
  `/home/fge/Source/netlink/netlink-packet-xfrm`.
- rtnetlink XFRM link support:
  `/home/fge/Source/netlink/rtnetlink/src/link/xfrm.rs`.
- libreswan reference implementation:
  `/home/fge/Public_Sources/libreswan`.
- swanny experimental Rust IKEv2 implementation:
  `/home/fge/Public_Sources/swanny`.
- Existing shuli EAP core: `src/core/eap.rs`, `src/core/eap_tls.rs`.
- Existing shulid IP handling: `src/daemon/ip.rs`, `src/daemon/dhcp.rs`.
- nipart plugin architecture:
  `/home/fge/Source/nipart/src/lib/plugin/plugin_trait.rs` and
  `/home/fge/Source/nipart/src/plugin-wifi/`.
