## Design decisions (need a policy/API decision before fixing)

- WiFi multi-interface `WifiClient::run()`: every call builds fresh
  per-interface futures and drops the others when one returns; the
  handlers are not cancellation-safe across awaits. Choose persistent
  per-interface tasks, a fan-in event API, or make each handler
  cancellation-safe.
- WiFi link cleanup on SSID switch/roam: addresses, routes, and
  `/etc/resolv.conf` from the previous network are never removed, and
  `add_default_route` deliberately uses a growing metric, so a stale
  default route can stay preferred. Decide what shuli owns and when to
  delete it.
- WiFi stale `ASSOCIATED` / `CONNECT` results are still applied without
  checking the attempt generation (only `PORT_AUTHORIZED` is gated now);
  a generation counter shared with the kernel events would be the clean
  fix.
- WiFi group rekey drops IGTK/BIGTK from the returned KDEs; installing
  them needs an API change so `process_group_rekey` can return the new
  management keys to the caller.
- Wired MKA: expired peers and retired SAKs are not removed from the
  kernel; duplicate SCIs are not rejected and Key Server election uses
  only the SCI. Decide the ownership/removal rules and how to detect a
  duplicate SCI safely.
- Wired MACsec netdev reuse accepts any interface with the configured
  name without checking that it is a SecY with matching base/SCI/encrypt
  settings. Decide whether to reject, rename, or verify/recreate.
- Wired EAP mode never transitions to MACsec/MKA even though the
  EAP-derived CAK/CKN helpers exist. Decide whether `WiredAuth::Eap`
  should start MKA after authorization (and support 256-bit CAKs) or
  document PSK-only MACsec.
- Wired 802.1X stops reading EAPOL after the first EAP-Success; switch
  reauthentication and link-down/up recovery need a reauth state machine.
- IPsec: IKE SA rekey/deletion, the `ike.lifetime`/`ike_margin_percent`
  knobs, multi-peer connections, COOKIE/INVALID_KE_PAYLOAD handling,
  and transport-mode `USE_TRANSPORT_MODE` negotiation are not
  implemented.
- IPsec XFRM ownership: policies and interfaces are adopted by
  selector/name and deleted by selector, so a rekey can delete the
  replacement policy and another manager's objects can be stolen.
  Child rekey also omits `REKEY_SA` and never deletes the replaced SA,
  and the daemon's route EEXIST handling drops live routes on rekey.
  A unique owner token/index and a rekey handover policy are needed.
- IPsec certificate identities: only IP/FQDN are bound to the
  certificate; Email/DER-DN/KeyId identities accept any certificate
  signed by the configured CA. Decide the SAN/DN matching rules.
- IPsec config knobs without effect: `XfrmConfig.esn`,
  `RekeyConfig.grace`, `LocalConfig.interface`, `IpsecClient.configs`;
  `mark_mask` defaults to 0 and silently disables a configured mark.
  Decide which to implement and which to remove/validate.
- Daemon DHCPv4 only applies the first lease (no T1/T2 renewal,
  rebinding, or release) and IP configuration is not retried after a
  failure. Decide the renewal/retry policy and whether failed configs
  should keep the connection up.
- Core EAP: `EapPeer` keeps no last identifier/response, so
  retransmitted EAP-Requests are reprocessed instead of replaying the
  cached response; RFC 9190 protected success indication is not
  required before accepting EAP-Success. Both need a session-state
  design decision.
