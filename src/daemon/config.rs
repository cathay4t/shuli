// SPDX-License-Identifier: Apache-2.0

//! Daemon-level configuration with serde support.
//!
//! `ShuliConfig` is deserialized from the YAML config file
//! (`/etc/shuli/config.yml` or `$1`).  It targets small systems
//! that don't run nipart: full static or full dynamic (DHCP).

use std::{fs, path::Path};

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

/// A single WiFi network entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WifiEntry {
    pub ssid: String,
    #[serde(default)]
    pub password: Option<String>,
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
            serde_yaml::from_str(&content).map_err(|e| {
                WifiError::new(ErrorKind::InvalidConfig, e.to_string())
            })?;
        Ok(config)
    }

    /// Convert all configured networks into the lib's `WifiConfig`, so
    /// one scan schedule probes for every SSID.
    pub(crate) fn to_wifi_config(&self, iface_name: &str) -> shuli::WifiConfig {
        let mut config = shuli::WifiConfig::new(iface_name);
        for entry in &self.wifis {
            config.add_network(&entry.ssid, entry.password.as_deref());
        }
        config
    }
}
