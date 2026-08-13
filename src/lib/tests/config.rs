// SPDX-License-Identifier: Apache-2.0

use crate::config::{NetworkConfig, WifiConfig};

#[test]
fn wifi_config_requires_networks() {
    let config = WifiConfig::new("wlan0");
    assert_eq!(config.iface_name, "wlan0");
    assert!(config.networks.is_empty());
}

#[test]
fn wifi_config_multiple_networks() {
    let mut config = WifiConfig::new("wlan0");
    config
        .add_network("Home-WIFI", Some("secret"))
        .add_network("Coffee-Shop", None)
        .add_network("Office-WIFI", Some("12345678"));
    assert_eq!(config.networks.len(), 3);
    assert_eq!(config.networks[0].ssid, "Home-WIFI");
    assert_eq!(config.networks[0].password.as_deref(), Some("secret"));
    assert_eq!(config.networks[1].ssid, "Coffee-Shop");
    assert_eq!(config.networks[1].password, None);
    assert_eq!(config.networks[2].ssid, "Office-WIFI");
    assert_eq!(config.networks[2].password.as_deref(), Some("12345678"));
    assert_eq!(
        config.ssids().collect::<Vec<_>>(),
        vec!["Home-WIFI", "Coffee-Shop", "Office-WIFI"]
    );
}

#[test]
fn network_config_builder() {
    let mut network = NetworkConfig::new("Test-WIFI");
    network.set_password("12345678");
    assert_eq!(network.ssid, "Test-WIFI");
    assert_eq!(network.password, Some("12345678".to_string()));
    assert!(!network.wowlan, "WoWLAN must be opt-in (off by default)");
}

#[test]
fn roaming_defaults_to_enabled_with_default_threshold() {
    let mut config = WifiConfig::new("wlan0");
    config.add_network("Home-WIFI", Some("secret"));
    let network = config.networks.first().expect("network");
    assert!(network.roaming, "roaming should be on by default");
    assert_eq!(network.roaming_threshold, -70);
}

#[test]
fn roaming_can_be_disabled_and_threshold_adjusted() {
    let mut network = NetworkConfig::new("Home-WIFI");
    network.roaming_threshold = -80;
    assert_eq!(network.roaming_threshold, -80);
    network.roaming = false;
    assert!(!network.roaming);
}

#[test]
fn wowlan_is_opt_in_and_can_be_enabled() {
    let mut network = NetworkConfig::new("Home-WIFI");
    assert!(!network.wowlan, "WoWLAN must default to disabled");
    network.set_wowlan(true);
    assert!(network.wowlan);
    network.set_wowlan(false);
    assert!(!network.wowlan);
}
