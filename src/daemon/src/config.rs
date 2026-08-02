// SPDX-License-Identifier: Apache-2.0

//! Daemon-level configuration with serde support.
//!
//! `ShuliConfig` is deserialized from the YAML config file
//! (`/etc/shuli/config.yml` or `$1`).  It is converted into the
//! lib's `WifiConfig` before being passed to `WifiClient`.

use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use shuli::{ErrorKind, WifiConfig, WifiError};

/// Top-level daemon configuration (YAML), compatible with the nipart
/// `wifi-phy` interface schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ShuliConfig {
    #[serde(default)]
    pub interfaces: Vec<InterfaceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct InterfaceConfig {
    pub name: String,
    #[serde(default)]
    pub wifi: Option<WifiSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WifiSection {
    pub ssid: String,
    #[serde(default)]
    pub password: Option<String>,
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

    /// Convert the first interface's wifi section into a lib
    /// `WifiConfig`.
    pub(crate) fn to_wifi_config(&self) -> Result<WifiConfig, WifiError> {
        let iface = self.interfaces.first().ok_or_else(|| {
            WifiError::new(ErrorKind::InvalidConfig, "no interfaces")
        })?;
        let wifi = iface.wifi.as_ref().ok_or_else(|| {
            WifiError::new(ErrorKind::InvalidConfig, "no wifi config")
        })?;
        let mut config = WifiConfig::new(&iface.name, &wifi.ssid);
        if let Some(ref password) = wifi.password {
            config.set_password(password);
        }
        Ok(config)
    }
}
