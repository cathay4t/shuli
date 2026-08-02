// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;

#[test]
fn parse_example_config() {
    let yaml = r#"
---
interfaces:
  - name: wlan0
    wifi:
      ssid: Test-WIFI
      password: "12345678"
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.interfaces.len(), 1);
    assert_eq!(config.interfaces[0].name, "wlan0");
    let wifi = config.interfaces[0].wifi.as_ref().unwrap();
    assert_eq!(wifi.ssid, "Test-WIFI");
    assert_eq!(wifi.password, Some("12345678".to_string()));
}

#[test]
fn parse_open_config() {
    let yaml = r#"
---
interfaces:
  - name: wlan0
    wifi:
      ssid: Test-WIFI-NOPASS
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let wifi = config.interfaces[0].wifi.as_ref().unwrap();
    assert_eq!(wifi.ssid, "Test-WIFI-NOPASS");
    assert_eq!(wifi.password, None);
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
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.interfaces.len(), 1);
    assert!(config.interfaces[0].wifi.is_none());
}
