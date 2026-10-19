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
use shuli_core::{ErrorKind, WifiError};

/// Top-level daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ShuliConfig {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub wifis: Vec<WifiEntry>,
    /// Wired 802.1X ports: each entry authenticates one
    /// Ethernet interface with EAP and then applies its IP config.
    #[serde(default)]
    pub ethernets: Vec<EthernetEntry>,
}

/// SAE PWE derivation mode as configured in the YAML file. Kept as its
/// own serde type (the `shuli-wifi` library does not depend on serde); maps
/// onto `shuli_wifi::SaePwe`.
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
    fn to_lib(self) -> shuli_wifi::SaePwe {
        match self {
            SaePweConfig::Auto => shuli_wifi::SaePwe::Auto,
            SaePweConfig::H2e => shuli_wifi::SaePwe::H2E,
            SaePweConfig::Hnp => shuli_wifi::SaePwe::HnP,
        }
    }
}

/// A single WiFi network entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WifiEntry {
    pub ssid: String,
    #[serde(default)]
    pub password: Option<String>,
    /// BSSID (AP MAC address) this network is pinned to. When set, the
    /// client only connects to that AP: it never fails over to another
    /// BSS of the same SSID and never roams to one. Absent (the
    /// default) allows any BSS of the SSID.
    #[serde(default, deserialize_with = "deserialize_bssid")]
    pub bssid: Option<[u8; 6]>,
    /// Hidden SSID: probe for this network with an SSID-specific probe
    /// request (wpa_supplicant's `scan_ssid=1`). Visible networks
    /// (default) are found by the wildcard probe every scan carries.
    #[serde(default)]
    pub hidden: bool,
    /// Preferred SSID for scan-result selection: when found with a signal
    /// at or above `shuli_wifi::DEFAULT_SWITCH_SSID_LOWER_THAN_DBM`, this
    /// network is chosen before a stronger BSS of another configured
    /// SSID. Defaults to `false`.
    #[serde(default)]
    pub prefered: bool,
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
    /// Signal level (dBm) below which the current link is critical and
    /// may be abandoned for a well-signalled BSS of another configured
    /// SSID (terminating the current session). Defaults to -80 (iwd's
    /// `CriticalRoamThreshold`).
    #[serde(default = "default_roam_critical_threshold")]
    pub switch_ssid_lower_than_dbm: i32,
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
    /// Optional SAE password identifier (WPA3-Personal, H2E-only).
    #[serde(default)]
    pub sae_password_id: Option<String>,
    /// Operating Channel Validation (OCV) for this network.
    #[serde(default)]
    pub ocv: bool,
    /// Extended Key ID (pairwise key id 0/1 rotation) for this
    /// network.  Requires driver support.
    #[serde(default)]
    pub ext_key_id: bool,
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
/// `shuli_core::EapConfig`.
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

impl EapEntry {
    pub(crate) fn to_lib(&self) -> shuli_core::EapConfig {
        let mut eap = shuli_core::EapConfig::default();
        eap.identity = self.identity.clone();
        eap.ca_cert = self.ca_cert.as_ref().map(PathBuf::from);
        eap.client_cert = self.client_cert.as_ref().map(PathBuf::from);
        eap.client_key = self.client_key.as_ref().map(PathBuf::from);
        eap.server_name = self.server_name.clone();
        eap
    }
}

/// MACsec/MKA settings as configured in the YAML file; mapped onto
/// `shuli_wired::MacsecConfig`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MacsecEntry {
    /// Connectivity Association Key, hex encoded (16 or 32 octets).
    pub cak: String,
    /// Connectivity Association Key Name, hex encoded (1..=32 octets).
    pub ckn: String,
    /// Key Server Priority: lower wins. Defaults to 255 (never).
    #[serde(default = "default_mka_priority")]
    pub key_server_priority: u8,
    /// Whether this participant may be elected Key Server.
    #[serde(default)]
    pub can_be_key_server: bool,
    /// MACsec netdev name. Defaults to `macsec0`.
    #[serde(default)]
    pub macsec_iface: Option<String>,
    /// Replay protection window; 0 disables replay protection.
    #[serde(default)]
    pub replay_window: u32,
    /// Encrypt frames (false = integrity-only MACsec).
    #[serde(default = "default_true")]
    pub encrypt: bool,
}

fn default_mka_priority() -> u8 {
    0xff
}

fn default_true() -> bool {
    true
}

fn parse_hex(field: &str, value: &str) -> Result<Vec<u8>, WifiError> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(WifiError::new(
            ErrorKind::InvalidConfig,
            format!("{field} must contain an even number of hex digits"),
        ));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|e| {
                WifiError::new(
                    ErrorKind::InvalidConfig,
                    format!("invalid hex in {field}: {e}"),
                )
            })
        })
        .collect()
}

impl MacsecEntry {
    pub(crate) fn to_lib(
        &self,
    ) -> Result<shuli_wired::MacsecConfig, WifiError> {
        let mut config = shuli_wired::MacsecConfig::new(
            parse_hex("macsec.cak", &self.cak)?,
            parse_hex("macsec.ckn", &self.ckn)?,
        );
        config.key_server_priority = self.key_server_priority;
        config.can_be_key_server = self.can_be_key_server;
        config.macsec_iface = self.macsec_iface.clone();
        config.replay_window = self.replay_window;
        config.encrypt = self.encrypt;
        Ok(config)
    }
}

/// A wired 802.1X or MACsec port entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EthernetEntry {
    pub name: String,
    #[serde(default)]
    pub eap: Option<EapEntry>,
    #[serde(default)]
    pub macsec: Option<MacsecEntry>,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    #[serde(default)]
    pub ipv4: Option<IpConfig>,
    #[serde(default)]
    pub ipv6: Option<IpConfig>,
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
    /// `iface_name` (one interface can carry several SSIDs) - into
    /// the lib's `WifiConfig`. Each entry keeps its own roaming policy.
    pub(crate) fn wifi_config_for_entries(
        iface_name: &str,
        entries: &[WifiEntry],
    ) -> shuli_wifi::WifiConfig {
        let mut config = shuli_wifi::WifiConfig::new(iface_name);
        for entry in entries {
            let mut network = shuli_wifi::NetworkConfig::new(&entry.ssid);
            if let Some(password) = entry.password.as_deref() {
                network.set_password(password);
            }
            network.bssid = entry.bssid;
            network.hidden = entry.hidden;
            network.prefered = entry.prefered;
            network.roaming = entry.roaming;
            network.roaming_threshold = entry.roaming_threshold;
            network.switch_ssid_lower_than_dbm =
                entry.switch_ssid_lower_than_dbm;
            network.wowlan = entry.wowlan;
            network.sae_password_id = entry.sae_password_id.clone();
            network.ocv = entry.ocv;
            network.ext_key_id = entry.ext_key_id;
            if let Some(eap) = entry.eap.as_ref() {
                network.eap = Some(eap.to_lib());
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
    shuli_wifi::DEFAULT_ROAM_THRESHOLD_DBM
}

fn default_roam_critical_threshold() -> i32 {
    shuli_wifi::DEFAULT_SWITCH_SSID_LOWER_THAN_DBM
}

/// Deserialize an optional colon-separated MAC address
/// (`aa:bb:cc:dd:ee:ff`), rejecting malformed values at config-load time.
fn deserialize_bssid<'de, D>(
    deserializer: D,
) -> Result<Option<[u8; 6]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|value| parse_mac(&value).map_err(serde::de::Error::custom))
        .transpose()
}

/// Parse a colon-separated MAC address into its six octets. Each octet
/// must be exactly two hex digits so a truncated value (e.g.
/// `aa:bb:cc:dd:ee:0`) cannot accidentally match.
fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = value.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(format!(
            "invalid BSSID {value:?}: expected six colon-separated octets"
        ));
    }
    let mut mac = [0u8; 6];
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(format!(
                "invalid BSSID octet {part:?} in {value:?}: expected exactly \
                 two hex digits"
            ));
        }
        mac[index] = u8::from_str_radix(part, 16)
            .map_err(|e| format!("invalid BSSID octet {part:?}: {e}"))?;
    }
    Ok(mac)
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
        // The critical threshold keeps its -80 default unless set.
        assert_eq!(
            network.switch_ssid_lower_than_dbm,
            shuli_wifi::DEFAULT_SWITCH_SSID_LOWER_THAN_DBM
        );
    }

    #[test]
    fn switch_ssid_lower_than_dbm_override() {
        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Home
    switch_ssid_lower_than_dbm: -85
",
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert_eq!(wifi.networks[0].switch_ssid_lower_than_dbm, -85);
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
    fn hidden_defaults_to_false_and_maps_true() {
        let config = parse(MINIMAL_YAML);
        assert!(!config.wifis[0].hidden);

        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert!(!wifi.networks[0].hidden);

        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Home
    hidden: true
",
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert!(wifi.networks[0].hidden);
    }

    #[test]
    fn prefered_defaults_to_false_and_maps_true() {
        let config = parse(MINIMAL_YAML);
        assert!(!config.wifis[0].prefered);

        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert!(!wifi.networks[0].prefered);

        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Home
    prefered: true
",
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert!(wifi.networks[0].prefered);
    }

    #[test]
    fn bssid_pin_parses_and_maps_to_network() {
        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Home
    bssid: 02:00:00:00:00:01
",
        );
        assert_eq!(
            config.wifis[0].bssid,
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert_eq!(
            wifi.networks[0].bssid,
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
    }

    #[test]
    fn absent_bssid_means_no_pin() {
        let config = parse(MINIMAL_YAML);
        assert_eq!(config.wifis[0].bssid, None);
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert_eq!(wifi.networks[0].bssid, None);
    }

    #[test]
    fn malformed_bssid_is_rejected() {
        for bad in [
            "not-a-mac",
            "02:00:00:00:00",
            "02:00:00:00:00:0",
            "02:00:00:00:00:0g",
            "02:00:00:00:00:00:01",
        ] {
            let yaml = format!(
                "---\nversion: 1\nwifis:\n  - ssid: Home\n    bssid: {bad}\n"
            );
            assert!(
                rmsd_yaml::from_str::<ShuliConfig>(&yaml).is_err(),
                "{bad:?} must be rejected"
            );
        }
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

    #[test]
    fn ethernet_entry_defaults_and_eap_parse() {
        let config = parse(
            "\
---
version: 1
ethernets:
  - name: eth0
    eap:
      identity: user@example.org
      server_name: radius.example.org
",
        );
        let entry = &config.ethernets[0];
        assert_eq!(entry.name, "eth0");
        assert_eq!(entry.eap.as_ref().unwrap().identity, "user@example.org");
        assert!(entry.dns.is_none());
    }

    #[test]
    fn macsec_entry_parses_and_maps() {
        let config = parse(
            "\
---
version: 1
ethernets:
  - name: eth0
    macsec:
      cak: \"00112233445566778899aabbccddeeff\"
      ckn: \"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff\"
      key_server_priority: 16
      can_be_key_server: true
      macsec_iface: macsec-test
      replay_window: 32
",
        );
        let entry = &config.ethernets[0];
        let macsec = entry.macsec.as_ref().expect("macsec config");
        let lib = macsec.to_lib().expect("valid macsec config");
        let expected = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        assert_eq!(lib.cak, expected);
        assert_eq!(lib.ckn, expected);
        assert_eq!(lib.key_server_priority, 16);
        assert!(lib.can_be_key_server);
        assert_eq!(lib.macsec_iface.as_deref(), Some("macsec-test"));
        assert_eq!(lib.replay_window, 32);
        assert!(lib.encrypt);
    }

    #[test]
    fn example_configs_parse() {
        for (name, text) in [
            (
                "wifi_config.yml",
                include_str!("../../examples/wifi_config.yml"),
            ),
            (
                "eap_config.yml",
                include_str!("../../examples/eap_config.yml"),
            ),
            (
                "macsec_config.yml",
                include_str!("../../examples/macsec_config.yml"),
            ),
        ] {
            let config = parse(text);
            for entry in &config.ethernets {
                if let Some(macsec) = &entry.macsec {
                    macsec.to_lib().unwrap_or_else(|e| panic!("{name}: {e}"));
                }
            }
        }
    }

    #[test]
    fn macsec_entry_rejects_bad_hex() {
        let config = parse(
            "\
---
version: 1
ethernets:
  - name: eth0
    macsec:
      cak: \"xyz\"
      ckn: \"0011\"
",
        );
        assert!(
            config.ethernets[0]
                .macsec
                .as_ref()
                .unwrap()
                .to_lib()
                .is_err()
        );
    }

    #[test]
    fn sae_password_id_maps_to_network() {
        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Home
    sae_password_id: corp-id
",
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert_eq!(
            wifi.networks[0].sae_password_id.as_deref(),
            Some("corp-id")
        );
    }

    #[test]
    fn ocv_maps_to_network() {
        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Home
    ocv: true
",
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert!(wifi.networks[0].ocv);
    }

    #[test]
    fn ext_key_id_maps_to_network() {
        let config = parse(
            "\
---
version: 1
wifis:
  - ssid: Home
    ext_key_id: true
",
        );
        let wifi = ShuliConfig::wifi_config_for_entries("wlan0", &config.wifis);
        assert!(wifi.networks[0].ext_key_id);
    }
}
