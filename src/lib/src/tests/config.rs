// SPDX-License-Identifier: Apache-2.0

use crate::config::WifiConfig;

#[test]
fn wifi_config_builder() {
    let mut config = WifiConfig::new("wlan0", "Test-WIFI");
    config.set_password("12345678");
    assert_eq!(config.iface_name, "wlan0");
    assert_eq!(config.ssid, "Test-WIFI");
    assert_eq!(config.password, Some("12345678".to_string()));
}

#[test]
fn wifi_config_open() {
    let config = WifiConfig::new("wlan0", "Test-WIFI-NOPASS");
    assert_eq!(config.iface_name, "wlan0");
    assert_eq!(config.ssid, "Test-WIFI-NOPASS");
    assert_eq!(config.password, None);
}
