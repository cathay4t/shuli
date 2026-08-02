// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::{ErrorKind, WpaError};

/// Top-level daemon configuration (YAML), compatible with the nipart
/// `wifi-phy` interface schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub interfaces: Vec<InterfaceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    #[serde(default)]
    pub wifi: Option<WifiConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiConfig {
    pub ssid: String,
    #[serde(default)]
    pub password: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, WpaError> {
        if !path.exists() {
            return Err(WpaError::new(
                ErrorKind::ConfigNotFound,
                path.display().to_string(),
            ));
        }
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content).map_err(|e| {
            WpaError::new(ErrorKind::InvalidConfig, e.to_string())
        })?;
        Ok(config)
    }
}
