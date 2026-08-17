# 书立 (shuli)

**Linux WiFi authentication library and daemon in Rust**

The `shuli` crate and `shulid` daemon authenticates a Linux station (client) to
modern WiFi networks written entirely in Rust.

## Features

* **WPA3-Personal** - SAE with hash-to-element and hunting-and-pecking
  fallback, anti-clogging tokens, and optional SAE password identifiers.
* **WPA2-Personal** - PSK (AKM 2) and PSK-SHA256 (AKM 6).
* **WPA3-OWE** - WPA3 open networks.
* **WPA2-Enterprise and WPA3-Enterprise** - 802.1X / EAP-TLS (rustls,
  TLS 1.3, RFC 9190 MSK), mandatory PMF for WPA3.
* **Roaming** - 802.11r fast BSS transition (FT-PSK / FT-SAE), 802.11v
  BTM, 802.11k Neighbor Reports before quick roam scans, and
  signal-triggered roam scans; PMKSA caching and OKC.
* **Wired 802.1X** - EAP-TLS over Ethernet (raw AF_PACKET EAPOL).
* **Hardening** - WoWLAN (opt-in), OCV, Extended Key ID, Transition
  Disable, and BIP cipher negotiation (GMAC-256/CMAC-256/GMAC-128/
  CMAC-128).
* **Rust crate** - Async crate for WIFI authentication.
* **shulid daemon** - YAML configuration, one client per network
  namespace, systemd unit, handling both WIFI and IP config.

## Using the daemon for simple WiFi configuration

Full configuration document are stored in
[`examples/config.yml`](examples/config.yml).

`shulid` reads YAML from `/etc/shuli/config.yml` (or a path given on the
command line).  It targets small systems that don't run nipart: each WiFi
entry is configured either fully static or fully dynamic (DHCP):

```yaml
---
version: 1
wifis:
  - ssid: Test-WIFI-OPEN
    interface: any
    ipv4:
      # automatically set IP, route and DNS
      auto: true
    ipv6:
      auto: true
  - ssid: Test-WIFI
    password: "12345678"
    # hidden: true # AP hides its SSID; probe for it by name
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
```

Wired 802.1X authentication:

```yaml
ethernets:
  - name: eth0
    eap:
      identity: user@example.org
      ca_cert: /etc/shuli/ca.pem
      client_cert: /etc/shuli/client.pem
      client_key: /etc/shuli/client.key
      server_name: radius.example.org
    ipv4:
      auto: true
```

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

`shulid` must run with root privileges (`CAP_NET_ADMIN` and `CAP_NET_RAW`)
to start WIFI and DHCP, writes IPv6 sysctls, and updates `/etc/resolv.conf`.

## Using the `shuli` crate

Add these lines to your Cargo.toml:

```toml
[dependencies.shuli]
package = "shuli"
version = "0.2.0"
```

A `WifiClient` manages one or more wifi-phy interfaces with a single
nl80211 socket and a single multicast event subscription. Run **one**
`WifiClient` per network namespace: creating multiple clients in the
same namespace would make every client receive the same kernel
multicast events (scan, MLME and config groups), and the client has no
way to know an event belongs to another interface.

Single interface:

```rust
use shuli::{WifiClient, WifiConfig, WifiState};

#[tokio::main]
async fn main() -> Result<(), shuli::WifiError> {
    let mut config = WifiConfig::new("wlan0");
    config.add_network("Test-WIFI", Some("12345678"))
        .add_network("Office-WIFI", Some("office-secret"))
        .add_network("Guest-Open", None);

    let mut client = WifiClient::init(config).await?;

    // Drive the connection: scan -> authenticate -> 4-way handshake.
    // Failed states retry on the next call; errors are logged and retried.
    // A wrong password is returned as `ErrorKind::WrongPassword`.
    loop {
        match client.run().await {
            Ok(WifiState::ConnectedWithoutOffloadRekey) |
            Ok(WifiState::ConnectedWithOffloadRekey) => {
                println!("WIFI connected");
            }
            Ok(s) => println!("WIFI state {s}"),
            Err(e) => eprintln!("{e}"),
        }
    }
}
```

Multiple interfaces with one client:

```rust
use shuli::{WifiClient, WifiConfig};

#[tokio::main]
async fn main() -> Result<(), shuli::WifiError> {
    let mut wlan0 = WifiConfig::new("wlan0");
    wlan0.add_network("Home", Some("home-secret"));
    let mut wlan1 = WifiConfig::new("wlan1");
    wlan1.add_network("Office", Some("office-secret"));

    let mut client = WifiClient::init_multi(vec![wlan0, wlan1]).await?;

    loop {
        // Returns the first interface that changed state.
        let result = client.run_multi().await?;
        if let Some(e) = result.error {
            eprintln!("{}: {e}", result.iface_name);
        }
        if let Some(ssid) = client.current_ssid_of(&result.iface_name) {
            println!("{}: {}", result.iface_name, ssid);
        }
    }
}
```

`WifiRunResult` carries the interface name, so callers can tell which
interface changed. Use `update_networks_of()`, `current_ssid_of()` and
`current_bssid_of()` when more than one interface is managed.

## Contact

 * Crate github issue
 * Use Matrix room: [`#rust-netlink:fedora.im`][matrix_room_url]

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

[matrix_room_url]: https://app.element.io/#/room/#rust-netlink:fedora.im
