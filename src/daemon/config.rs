// SPDX-License-Identifier: Apache-2.0

//! Daemon-level configuration with serde support.
//!
//! `ShuliConfig` is deserialized from the YAML config file
//! (`/etc/shuli/config.yml` or `$1`).  It targets small systems
//! that don't run nipart: full static or full dynamic (DHCP).

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use shuli::{ErrorKind, WifiError};

/// Top-level daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ShuliConfig {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub wifis: Vec<WifiEntry>,
}

/// SAE PWE derivation mode as configured in the YAML file. Kept as its
/// own serde type (the `shuli` library does not depend on serde); maps
/// onto `shuli::SaePwe`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SaePweConfig {
    /// H2E first, hunting-and-pecking fallback when the AP rejects it.
    #[default]
    Auto,
    /// Hash-to-element only.
    H2e,
    /// Hunting-and-pecking only (RFC 7664).
    Hnp,
}

impl SaePweConfig {
    fn to_lib(self) -> shuli::SaePwe {
        match self {
            SaePweConfig::Auto => shuli::SaePwe::Auto,
            SaePweConfig::H2e => shuli::SaePwe::H2E,
            SaePweConfig::Hnp => shuli::SaePwe::HnP,
        }
    }
}

/// A single WiFi network entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WifiEntry {
    pub ssid: String,
    #[serde(default)]
    pub password: Option<String>,
    /// Signal-triggered roaming while connected to this SSID: `false`
    /// disables it (BTM / 802.11v Requests are still honoured).
    /// Defaults to `true`.
    #[serde(default = "default_roaming")]
    pub roaming: bool,
    /// Signal level (dBm) below which the client scans for roam
    /// candidates while connected. Defaults to -70 (iwd's
    /// `RoamThreshold`).
    #[serde(default = "default_roam_threshold")]
    pub roaming_threshold: i32,
    /// Wake-on-WLAN (WoWLAN): arm the wiphy's Disconnect / GTK-rekey
    /// failure triggers while connected, so the device can wake the
    /// host on suspend. Defaults to `false` (opt-in, like
    /// wpa_supplicant's `wowlan_triggers` config).
    #[serde(default)]
    pub wowlan: bool,
    /// EAP credentials for WPA2-Enterprise / 802.1X networks
    /// (EAP-TLS).  `None` for PSK/SAE/open networks.
    #[serde(default)]
    pub eap: Option<EapEntry>,
    /// SAE PWE derivation for WPA3-Personal networks: `auto` (default,
    /// H2E with hunting-and-pecking fallback), `h2e`, or `hnp`.
    #[serde(default)]
    pub sae_pwe: SaePweConfig,
    /// Interface name to bind to.  `"any"` (or absent) picks the
    /// first available wifi interface.
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    #[serde(default)]
    pub ipv4: Option<IpConfig>,
    #[serde(default)]
    pub ipv6: Option<IpConfig>,
}

/// EAP credential settings as configured in the YAML file; mapped onto
/// `shuli::EapConfig`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct EapEntry {
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub ca_cert: Option<String>,
    #[serde(default)]
    pub client_cert: Option<String>,
    #[serde(default)]
    pub client_key: Option<String>,
    #[serde(default)]
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct DnsConfig {
    #[serde(default)]
    pub nameservers: Vec<String>,
    #[serde(default)]
    pub searches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IpConfig {
    /// `true` = DHCP / auto-config, `false` = full static.
    #[serde(default)]
    pub auto: bool,
    #[serde(default)]
    pub address: Vec<IpAddress>,
    #[serde(default)]
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IpAddress {
    pub ip: String,
    #[serde(rename = "prefix-length")]
    pub prefix_length: u8,
}

impl ShuliConfig {
    pub(crate) fn load(path: &Path) -> Result<Self, WifiError> {
        if !path.exists() {
            return Err(WifiError::new(
                ErrorKind::ConfigNotFound,
                path.display().to_string(),
            ));
        }
        let content = fs::read_to_string(path)?;
        let config: ShuliConfig =
            rmsd_yaml::from_str(&content).map_err(|e| {
                WifiError::new(ErrorKind::InvalidConfig, e.to_string())
            })?;
        Ok(config)
    }

    /// Convert `entries` - the configured networks bound to
    /// `iface_name` (M7: one interface can carry several SSIDs) - into
    /// the lib's `WifiConfig`. Each entry keeps its own roaming policy.
    pub(crate) fn wifi_config_for_entries(
        iface_name: &str,
        entries: &[WifiEntry],
    ) -> shuli::WifiConfig {
        let mut config = shuli::WifiConfig::new(iface_name);
        for entry in entries {
            let mut network = shuli::NetworkConfig::new(&entry.ssid);
            if let Some(password) = entry.password.as_deref() {
                network.set_password(password);
            }
            network.roaming = entry.roaming;
            network.roaming_threshold = entry.roaming_threshold;
            network.wowlan = entry.wowlan;
            if let Some(eap) = entry.eap.as_ref() {
                network.eap = Some(shuli::EapConfig {
                    identity: eap.identity.clone(),
                    ca_cert: eap.ca_cert.as_ref().map(PathBuf::from),
                    client_cert: eap.client_cert.as_ref().map(PathBuf::from),
                    client_key: eap.client_key.as_ref().map(PathBuf::from),
                    server_name: eap.server_name.clone(),
                });
            }
            network.sae_pwe = entry.sae_pwe.to_lib();
            config.networks.push(network);
        }
        config
    }
}

fn default_roaming() -> bool {
    true
}

fn default_roam_threshold() -> i32 {
    shuli::DEFAULT_ROAM_THRESHOLD_DBM
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_YAML: &str = "\
---
version: 1
wifis:
  - ssid: Home
    password: secret
";

    fn parse(yaml: &str) -> ShuliConfig {
        rmsd_yaml::from_str(yaml).expect("valid YAML")
    }

    #[test]
    fn roaming_defaults_to_enabled_with_default_threshold() {
        let config = parse(MINIMAL_YAML);
        let entry = &config.wifis[0];
        assert!(entry.roaming);
        assert_eq!(entry.roaming_threshold, -70);

        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        let network = &wifi.networks[0];
        assert!(network.roaming);
        assert_eq!(network.roaming_threshold, -70);
    }

    #[test]
    fn roaming_false_disables_signal_roam() {
        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Home
    roaming: false
",
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert!(!wifi.networks[0].roaming);
    }

    #[test]
    fn roaming_threshold_override() {
        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Home
    roaming_threshold: -80
",
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        let network = &wifi.networks[0];
        assert!(network.roaming);
        assert_eq!(network.roaming_threshold, -80);
    }

    #[test]
    fn wowlan_defaults_to_disabled_and_maps_true() {
        let config = parse(MINIMAL_YAML);
        assert!(!config.wifis[0].wowlan);

        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert!(!wifi.networks[0].wowlan);

        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Home
    wowlan: true
",
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert!(wifi.networks[0].wowlan);
    }

    #[test]
    fn eap_entry_maps_to_eap_config() {
        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Corp
    eap:
      identity: user@example.org
      ca_cert: /etc/shuli/ca.pem
      client_cert: /etc/shuli/client.pem
      client_key: /etc/shuli/client.key
      server_name: radius.example.org
",
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        let eap = wifi.networks[0].eap.as_ref().expect("EAP config");
        assert_eq!(eap.identity, "user@example.org");
        assert_eq!(
            eap.ca_cert.as_deref(),
            Some(std::path::Path::new("/etc/shuli/ca.pem"))
        );
        assert_eq!(eap.server_name.as_deref(), Some("radius.example.org"));
    }
}
