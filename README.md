<!-- SPDX-License-Identifier: Apache-2.0 -->
# 书立 (shuli)

**A pure-Rust Linux WiFi authentication daemon.**

`shuli` authenticates a Linux station (client) to modern WiFi networks entirely
in Rust, talking directly to the kernel's [nl80211] netlink interface via
[`wl-nl80211`] — no `wpa_supplicant`, no C dependencies. Authentication crypto
(SAE, the EAPOL 4-way handshake) runs in userspace; data-frame encryption stays
in the kernel/hardware after keys are installed.

[nl80211]: https://wireless.wiki.kernel.org/en/developers/documentation/nl80211
[`wl-nl80211`]: https://github.com/rust-netlink/wl-nl80211

## ⚠️ Work in progress

This project is in **early development and is not yet usable**. APIs, config
schema, and on-disk formats will change without notice. Do not use it in
production. There is no stable release.

## Goals

The project is built in stages (see the `STAGE*_PLAN.md` documents):

- **Stage 1** — WPA3-Personal (SAE) authentication; `shulid` daemon driven by
  static config in `/etc/shuli/*.yml`. *(in progress)*
- **Stage 2** — UNIX-socket control interface with a `shulictl show` / `apply`
  CLI, plus a client library for [nipart] to consume — replacing nipart's
  `wpa_supplicant` control code. Ready for daily WPA3-Personal use.
- **Stage 3** — WPA2-Personal, 802.1X/EAP, and WPA3-Enterprise (incl. the
  192-bit Suite-B profile).

[nipart]: https://github.com/nispor/nipart

## Configuration (planned)

`shulid` reads YAML from `/etc/shuli/`:

```yaml
---
interfaces:
  - name: wlan0
    type: wifi-phy
    wifi:
      ssid: Test-WIFI
      password: "12345678"
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
