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
    # wowlan: true # arm WoWLAN triggers (disconnect, GTK rekey
    #              # failure) while connected; off by default
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
`wowlan: true` enables Wake-on-WLAN for that network (opt-in; the
default is off): while connected, shuli arms the wiphy's supported
disconnect and GTK-rekey-failure triggers so the device can wake the
host on suspend, and it reconnects after a GTK-rekey-failure wake.

A ready-to-use example lives in [`examples/config.yml`](examples/config.yml).

## Installing and running shulid

Build and install the daemon, the systemd unit, and the default config:

```sh
cargo build --release
sudo install -Dm755 target/release/shulid /usr/bin/shulid
sudo install -Dm644 packaging/shulid.service /etc/systemd/system/shulid.service
sudo install -Dm644 examples/config.yml /etc/shuli/config.yml
sudo systemctl daemon-reload
sudo systemctl enable --now shulid
```

`shulid` must run with root privileges (or equivalent capabilities):
it configures the WiFi interface over nl80211/rtnetlink (`CAP_NET_ADMIN`),
runs DHCPv4 on a raw packet socket (`CAP_NET_RAW`), writes IPv6 sysctls,
and updates `/etc/resolv.conf`. The packaged
[`shulid.service`](packaging/shulid.service) therefore runs as root and
reads `/etc/shuli/config.yml` by default. Change that file and
`systemctl restart shulid` to apply new networks.

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
    let mut config = WifiConfig::new("wlan0");
    config.add_network("Test-WIFI", Some("12345678"));

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

To scan for and connect to several networks, add them to the config - a
single scan schedule probes for all of them and the strongest matching
BSS wins:

```rust
let mut config = WifiConfig::new("wlan0");
config
    .add_network("Home-WIFI", Some("home-secret"))
    .add_network("Office-WIFI", Some("office-secret"))
    .add_network("Guest-Open", None);
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
