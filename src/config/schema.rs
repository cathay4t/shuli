// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub interfaces: Vec<InterfaceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub iface_type: InterfaceType,
    #[serde(default)]
    pub wifi: Option<WifiConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InterfaceType {
    WifiPhy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiConfig {
    pub ssid: String,
    pub password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_example_config() {
        let yaml = r#"
---
interfaces:
  - name: wlan0
    type: wifi-phy
    wifi:
      ssid: Test-WIFI
      password: "12345678"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.interfaces.len(), 1);
        assert_eq!(config.interfaces[0].name, "wlan0");
        assert!(matches!(
            config.interfaces[0].iface_type,
            InterfaceType::WifiPhy
        ));
        let wifi = config.interfaces[0].wifi.as_ref().unwrap();
        assert_eq!(wifi.ssid, "Test-WIFI");
        assert_eq!(wifi.password, "12345678");
    }

    #[test]
    fn parse_empty_config() {
        let yaml = r#"
---
interfaces: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.interfaces.is_empty());
    }

    #[test]
    fn parse_config_without_wifi() {
        let yaml = r#"
---
interfaces:
  - name: wlan0
    type: wifi-phy
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.interfaces.len(), 1);
        assert!(config.interfaces[0].wifi.is_none());
    }
}
