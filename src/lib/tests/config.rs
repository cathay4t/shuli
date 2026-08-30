// SPDX-License-Identifier: Apache-2.0

use crate::{
    Ieee80211CipherSuite, SecurityType,
    config::{EapConfig, NetworkConfig, NetworkConfigHints, WifiConfig},
};

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

#[test]
fn hidden_defaults_to_false_and_can_be_set() {
    let mut network = NetworkConfig::new("Home-WIFI");
    assert!(
        !network.hidden,
        "visible networks are found by the wildcard probe"
    );
    network.set_hidden(true);
    assert!(network.hidden);
    network.set_hidden(false);
    assert!(!network.hidden);
}

#[test]
fn network_hints_default_to_empty_and_can_be_set() {
    let mut network = NetworkConfig::new("Home-WIFI");
    assert!(
        network.hints.frequencies_mhz.is_empty(),
        "frequency hints must be opt-in"
    );

    network.set_hints(
        NetworkConfigHints::new().with_frequencies_mhz(vec![5180, 5765]),
    );
    assert_eq!(network.hints.frequencies_mhz, vec![5180, 5765]);
}

#[test]
fn scan_free_hints_require_complete_bss_info() {
    let mut hints = NetworkConfigHints::default();
    assert!(
        hints.bss_info().is_none(),
        "empty hints must not enable scan-free"
    );

    hints.frequencies_mhz = vec![5765];
    hints.bssid = Some([0x52, 0xc3, 0xa2, 0x3a, 0x61, 0xe4]);
    hints.frequency_mhz = Some(5765);
    hints.security = Some(SecurityType::Wpa2Psk);
    hints.ap_rsne = Some(vec![0x30, 0x02, 0x01, 0x00]);
    hints.ap_rsnxe = Some(Vec::new());
    hints.group_mgmt_cipher = Some(Ieee80211CipherSuite::BipCmac128);
    hints.btm_support = Some(true);
    hints.rm_neighbor_report = Some(false);

    let bss = hints.bss_info().expect("complete hints build BssInfo");
    assert_eq!(bss.bssid, [0x52, 0xc3, 0xa2, 0x3a, 0x61, 0xe4]);
    assert_eq!(bss.freq_mhz, 5765);
    assert_eq!(bss.security, SecurityType::Wpa2Psk);
    assert_eq!(bss.ap_rsne, vec![0x30, 0x02, 0x01, 0x00]);
    assert!(bss.btm_support);
    assert!(!bss.rm_neighbor_report);

    // Dropping any scan-free property disables the direct path.
    hints.ap_rsnxe = None;
    assert!(hints.bss_info().is_none());

    // An unsupported security guess must never be used directly.
    hints.ap_rsnxe = Some(Vec::new());
    hints.security = Some(SecurityType::Unsupported);
    assert!(hints.bss_info().is_none());
}

#[test]
fn eap_config_defaults_to_none_and_can_be_set() {
    let mut network = NetworkConfig::new("Enterprise-WIFI");
    assert!(network.eap.is_none(), "EAP credentials must be opt-in");
    let eap = EapConfig {
        identity: "user@example.org".to_string(),
        ca_cert: Some("/etc/shuli/ca.pem".into()),
        client_cert: Some("/etc/shuli/client.pem".into()),
        client_key: Some("/etc/shuli/client.key".into()),
        server_name: Some("radius.example.org".to_string()),
    };
    network.set_eap(eap);
    let eap = network.eap.as_ref().expect("EAP config set");
    assert_eq!(eap.identity, "user@example.org");
    assert_eq!(
        eap.client_cert.as_deref(),
        Some(std::path::Path::new("/etc/shuli/client.pem"))
    );
}

#[test]
fn sae_password_id_defaults_to_none_and_can_be_set() {
    let mut network = NetworkConfig::new("Home-WIFI");
    assert!(
        network.sae_password_id.is_none(),
        "SAE password identifier must be opt-in"
    );
    network.set_sae_password_id(Some("corp-id"));
    assert_eq!(network.sae_password_id.as_deref(), Some("corp-id"));
    network.set_sae_password_id(None);
    assert!(network.sae_password_id.is_none());
}

#[test]
fn ocv_defaults_to_disabled_and_can_be_enabled() {
    let mut network = NetworkConfig::new("Home-WIFI");
    assert!(!network.ocv, "OCV must be opt-in");
    network.set_ocv(true);
    assert!(network.ocv);
    network.set_ocv(false);
    assert!(!network.ocv);
}

#[test]
fn ext_key_id_defaults_to_disabled_and_can_be_enabled() {
    let mut network = NetworkConfig::new("Home-WIFI");
    assert!(!network.ext_key_id, "Extended Key ID must be opt-in");
    network.set_ext_key_id(true);
    assert!(network.ext_key_id);
    network.set_ext_key_id(false);
    assert!(!network.ext_key_id);
}
