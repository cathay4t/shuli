<!-- SPDX-License-Identifier: Apache-2.0 -->
# 书立 (shuli)

**A pure-Rust Linux WiFi authentication library and daemon.**

The `shuli` crate authenticates a Linux station (client) to modern WiFi
networks entirely in Rust, talking directly to the kernel's [nl80211] netlink
interface via [`wl-nl80211`] - no `wpa_supplicant`, no C dependencies.
Authentication crypto (SAE, the EAPOL 4-way handshake) runs in userspace;
data-frame encryption stays in the kernel/hardware after keys are installed.
A bundled `shulid` daemon drives the crate from a YAML config file.

[nl80211]: https://wireless.wiki.kernel.org/en/developers/documentation/nl80211
[`wl-nl80211`]: https://github.com/rust-netlink/wl-nl80211

## ⚠️ Work in progress

This project is in **early development and is not yet usable**. APIs, config
schema, and on-disk formats will change without notice. Do not use it in
production. There is no stable release.

## Using the daemon for simple WiFi configuration

`shulid` reads YAML from `/etc/shuli/config.yml` (or a path given on the
command line).  It targets small systems that don't run nipart: each WiFi
entry is configured either fully static or fully dynamic (DHCP):

```yaml
---
version: 1
wifis:
  - ssid: Test-WIFI
    password: "12345678"
    dns:
      nameservers:
        - 2001:db8:1::254
        - 192.0.2.1
      searches:
        - example.org
    ipv4:
      auto: false # full static configuration
      address:
        - ip: 192.0.2.251
          prefix-length: 24
      gateway: 192.0.2.1
    ipv6:
      auto: false
      address:
        - ip: 2001:db8:1::1
          prefix-length: 64
      gateway: 2001:db8:1::254
  - ssid: Test-WIFI-OPEN
    interface: any
    ipv4:
      auto: true
    ipv6:
      auto: true
```

With `auto: true` the IPv4 address comes from DHCP (and IPv6 from router
solicitation), with DNS taken from the lease when not set in the config.
`interface: any` (or absent) picks the first available WiFi interface.

A ready-to-use example lives in [`examples/config.yml`](examples/config.yml).

## Using the `shuli` crate

Add these lines to your Cargo.toml:

```toml
[dependencies.shuli]
package = "shuli"
version = "0.1.0"
git = "https://github.com/cathay4t/shuli"

[dependencies.tokio]
version = "1"
features = ["rt-multi-thread", "macros"]
```

The crate exposes a `WifiClient` that drives the whole connection flow -
scan, authentication, association, and the 4-way handshake - one step per
call to `run()`:

```rust
use shuli::{WifiClient, WifiConfig, WifiState};

#[tokio::main]
async fn main() -> Result<(), shuli::WifiError> {
    let mut config = WifiConfig::new("wlan0", "Test-WIFI");
    config.set_password("12345678");

    let mut client = WifiClient::init(config).await?;

    // Drive the connection: scan -> authenticate -> 4-way handshake.
    // Failed states retry on the next call; errors are logged and retried.
    loop {
        match client.run().await {
            Ok(WifiState::ConnectedWithoutOffloadRekey)
            | Ok(WifiState::ConnectedWithOffloadRekey) => break,
            Ok(_) => {}
            Err(e) => eprintln!("{e}"),
        }
    }
    println!("connected to Test-WIFI");

    // Keep the client alive to drain events (group rekeys, disconnects).
    loop {
        if let Err(e) = client.run().await {
            eprintln!("{e}");
        }
    }
}
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
