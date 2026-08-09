# wl-nl80211 change plan (for shuli Stage 2 M6 / M7)

This plan documents the `wl-nl80211` changes needed by the `shuli` project
(`/home/fge/Source/shuli`, `STAGE2_PLAN.md`). Work is done in
`/home/fge/Source/netlink/wl-nl80211` and should be a *separate* commit(s)
in that repo; afterwards shuli must consume the new API (see
["shuli side"](#shuli-side-after-wl-nl80211-is-pushed)).

Status: **partially applied** — the edits below were applied by a previous
session and are **uncommitted** in the wl-nl80211 working tree, but the
crate does **not** compile yet (2 errors, fix described in
[Remaining code fixes](#remaining-code-fixes)). Run `git status` /
`git diff` there to see exactly what exists before continuing.

---

## 1. Why

Two Stage-2 milestones need new `wl-nl80211` surface:

- **M6 (G9, Suspend/WoWLAN)** — the STA must arm WoWLAN triggers
  (`NL80211_CMD_SET_WOWLAN` with `NL80211_ATTR_WOWLAN_TRIGGERS`,
  including `NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE`) so the device can
  wake a suspended host, and must react to the wake notification the
  kernel sends after resume (`cfg80211_report_wowlan_wakeup()` emits a
  `NL80211_CMD_SET_WOWLAN` event carrying `NL80211_ATTR_WOWLAN_WAKEUP`).
- **M7 (G5, reason-aware retry)** — the client must see the reason code
  of AP-initiated `deauth`/`disassoc` so it can distinguish "wrong
  passphrase / fatal" (reason 2 = `PREV_AUTH_NOT_VALID`, reason 23 =
  `IEEE_802_1X_AUTH_FAILED`) from transient failures.

The `SetWowlan`/`GetWowlan` commands and the *capability* attribute
(`NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED`) already exist in wl-nl80211;
the set-side attribute, the wake-report attribute, the request builder and
the reason-carrying events are missing.

---

## 2. Target API (what shuli will call)

```rust
// M6: arm triggers
let attrs = Nl80211Wowlan::new(if_index)
    .triggers(vec![
        Nl80211WowlanTriggersSupport::Disconnect,      // kind 2
        Nl80211WowlanTriggersSupport::GtkRekeyFailure, // kind 6
    ])
    .build(); // vec![IfIndex, WowlanTriggers(...)]
conn_handle.set_wowlan(attrs).execute().await;

// M6: wake notification
match event {
    Nl80211Event::WowlanWakeup { reasons } => {
        if reasons.contains(&Nl80211WowlanWakeup::GtkRekeyFailure) { ... }
    }
    ...
}

// M7: reason codes
match event {
    Nl80211Event::Deauthenticated { reason } | Nl80211Event::Disassociated { reason } => ...
}
```

`Nl80211WowlanWakeup` mirrors kernel `enum nl80211_wowlan_wakeup`
(**note:** its numbering differs from the trigger kinds):
`Any=1, Disconnect=2, MagicPkt=3, PktPattern=4, GtkRekeyFailure=5,
EapIdentRequest=6, FourWayHandshake=7, RfkillRelease=8, TcpWakeup=9`.

---

## 3. Already applied (uncommitted)

All edits live in `/home/fge/Source/netlink/wl-nl80211/src/`.

| File | Change |
|------|--------|
| `attr.rs` | consts `NL80211_ATTR_WOWLAN_TRIGGERS=117`, `NL80211_ATTR_WOWLAN_WAKEUP=127`; variants `WowlanTriggers(Vec<Nl80211WowlanTriggersSupport>)` and `WowlanWakeup(Vec<Nl80211WowlanWakeup>)`; `kind()`/parse arms; import of `Nl80211WowlanWakeup`. ⚠️ 2 compile errors remain (see below). |
| `wiphy/wowlan.rs` | wake-up kind consts + `Nl80211WowlanWakeup` enum (implements `Nla`, `Parseable`; empty values for flag kinds). |
| `wiphy/mod.rs` | re-export `Nl80211WowlanWakeup`. |
| `wowlan_request.rs` | **new file**: `Nl80211Wowlan` (builder entry), `Nl80211WowlanRequestBuilder` (`.triggers()`, `.build()`), `Nl80211WowlanRequest` (`async fn execute(...) -> impl TryStream<...>`; mirrors `src/rekey_request.rs`). |
| `connect/handle.rs` | `Nl80211ConnectionHandle::set_wowlan(Vec<Nl80211Attr>) -> Nl80211WowlanRequest` + import. |
| `event.rs` | `Nl80211Event::WowlanWakeup { reasons: Vec<Nl80211WowlanWakeup> }`; parse arm for `Nl80211Command::SetWowlan` (with `WOWLAN_WAKEUP` attr → `WowlanWakeup`, else falls back to `Unknown`); `attr_wowlan_wakeup()` helper. |
| `lib.rs` | `mod wowlan_request;`; crate-root exports `Nl80211Wowlan`, `Nl80211WowlanRequest`, `Nl80211WowlanWakeup`. |

### Remaining code fixes

`cargo check` currently fails with two `E0308` in `src/attr.rs`:
the combined match arm `Self::WowlanTriggers(nlas) |
Self::WowlanWakeup(nlas)` does not type-check because the variants hold
different `Vec` element types. **Split each arm in two:**

- in `value_len()` (~line 898):
  ```rust
  Self::WowlanTriggers(nlas) => nlas.as_slice().buffer_len(),
  Self::WowlanWakeup(nlas) => nlas.as_slice().buffer_len(),
  ```
- in `emit_value()` (~line 1229):
  ```rust
  Self::WowlanTriggers(nlas) => nlas.as_slice().emit(buffer),
  Self::WowlanWakeup(nlas) => nlas.as_slice().emit(buffer),
  ```

After the fix, `cargo check` must be clean.

---

## 4. Remaining work

### 4.1 Fix the two `attr.rs` arms (above) — required

### 4.2 Add `src/tests/wowlan.rs` (round-trip tests, like `src/tests/disconnect.rs`)

Follow the existing style: hand-built raw NLA bytes (len u16 LE, kind
u16 LE, value, padded to 4 bytes), assert `Nl80211Attr::parse` equals the
expected value and `emit` reproduces the raw bytes.

- `NL80211_ATTR_WOWLAN_TRIGGERS` = 117, nested value with two empty
  trigger NLAs: `Disconnect` (kind 2) then `GtkRekeyFailure` (kind 6).
  Each empty NLA is exactly 4 bytes: `04 00 <kind-le16>` (no padding
  needed, already aligned).
- `NL80211_ATTR_WOWLAN_WAKEUP` = 127, nested value with one empty
  wakeup NLA: `GtkRekeyFailure` (kind **5**).
- Also assert the `Nl80211Wowlan` request builder produces
  `vec![IfIndex(if_index), WowlanTriggers([Disconnect, GtkRekeyFailure])]`.

Register with `mod wowlan;` in `src/tests/mod.rs`.

### 4.3 M7: `Deauthenticated`/`Disassociated` reason events (still TODO)

Currently `NL80211_CMD_DEAUTHENTICATE` / `NL80211_CMD_DISASSOCIATE`
events fall through to `Nl80211Event::Unknown`, dropping
`NL80211_ATTR_REASON_CODE` (=3, parsed by the existing
`Nl80211EventReason`). Add:

- variants on `Nl80211Event`:
  `Deauthenticated { reason: Nl80211EventReason }`,
  `Disassociated { reason: Nl80211EventReason }`; and
- parse arms in `event.rs` for `Nl80211Command::Deauthenticate` /
  `Nl80211Command::Disassociate` that extract `Nl80211Attr::ReasonCode`
  (fall back to `Unknown { cmd }` when the attribute is absent).
- A unit test can reuse the captured reason-code bytes already in
  `src/tests/disconnect.rs` (`06 00 36 00 03 00 00 00` = REASON_CODE 3),
  wrapped in a `CMD_DEAUTHENTICATE` message.

Reason semantics (for shuli, documented here so the enum docs stay
accurate): reason 2 `PrevAuthNotValid` and reason 23 `Ieee8021xFailed`
indicate a fatal/credential problem; everything else is transient.

### 4.4 Format, lint, test, commit

```
cd /home/fge/Source/netlink/wl-nl80211
cargo fmt --all
cargo clippy --all-targets
cargo test
git add -A && git commit
```

Suggested commit message:
`wowlan: SET_WOWLAN triggers + wake notification, deauth/disassoc reasons`
(one commit is fine; two are also OK if preferred).

---

## 5. shuli side (after wl-nl80211 is pushed)

`/home/fge/Source/shuli` currently pins wl-nl80211 by git rev in
`Cargo.lock`. To use the local work before pushing, add to shuli's
`Cargo.toml`:

```toml
[patch."https://github.com/rust-netlink/wl-nl80211"]
wl-nl80211 = { path = "../netlink/wl-nl80211" }
```

(remove the patch and bump the rev once pushed). Then in shuli:

- `WifiClient::arm_wowlan()`: build the `Nl80211Wowlan` request
  (Disconnect + GtkRekeyFailure), send via `set_wowlan()`, treat a
  netlink `EOPNOTSUPP` as success-by-skip (mac80211_hwsim has no
  WoWLAN). Arm automatically when a connection is established.
- Handle `Nl80211Event::WowlanWakeup`: on `GtkRekeyFailure` wake, log,
  disconnect and reconnect (the reconnect loop already exists).
- Reason-aware retry: match the new `Deauthenticated { reason }` /
  `Disassociated { reason }` events (they will no longer arrive as
  `Unknown { cmd: ... }` — update the existing `Unknown` arm
  accordingly); reason 2 / 23 → `WifiState::FailedAuthentication`
  (long backoff), other reasons → `WifiState::Failed`.

## 6. Verification checklist

- [ ] `cargo check` clean in wl-nl80211 (attr.rs arms split)
- [ ] `cargo test` green incl. new `src/tests/wowlan.rs` (+ M7 event tests)
- [ ] fmt + clippy clean
- [ ] commit in `/home/fge/Source/netlink/wl-nl80211`
- [ ] shuli consumes the new API (patch or bumped rev) and its
      WoWLAN/wake + reason-aware integration tests pass
