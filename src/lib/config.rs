// SPDX-License-Identifier: Apache-2.0

/// WiFi connection configuration for [`WifiClient`](crate::WifiClient).
///
/// No serde — the daemon layer deserializes its own `ShuliConfig` and
/// converts it into this struct.
#[derive(Debug, Clone)]
pub struct WifiConfig {
    pub iface_name: String,
    /// Networks to scan for and connect to. A single scan schedule
    /// probes for all of them; the strongest matching BSS wins and its
    /// network's passphrase is used for authentication.
    pub networks: Vec<NetworkConfig>,
    /// Signal level (dBm) below which the client scans for roam
    /// candidates while connected. `None` disables signal-triggered
    /// roaming (BTM Requests are still honoured).
    pub roam_threshold_dbm: Option<i32>,
}

/// A single WiFi network: an SSID with an optional passphrase. Open
/// networks carry `password: None`.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub ssid: String,
    pub password: Option<String>,
}

impl NetworkConfig {
    pub fn new(ssid: &str) -> Self {
        Self {
            ssid: ssid.to_string(),
            password: None,
        }
    }

    pub fn set_password(&mut self, password: &str) -> &mut Self {
        self.password = Some(password.to_string());
        self
    }
}

impl WifiConfig {
    /// Create a config with no networks yet on `iface_name`. Add
    /// networks with [`add_network`](Self::add_network) so one scan
    /// schedule checks all of them.
    pub fn new(iface_name: &str) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            networks: Vec::new(),
            roam_threshold_dbm: None,
        }
    }

    /// Enable signal-triggered roaming: while connected, the client
    /// polls the AP's signal level and scans for roam candidates when
    /// it drops below `threshold_dbm`.
    pub fn set_roam_threshold(&mut self, threshold_dbm: i32) -> &mut Self {
        self.roam_threshold_dbm = Some(threshold_dbm);
        self
    }

    /// Add a network to scan for and connect to.
    ///
    /// Note: each network adds one SSID match set to the firmware
    /// scheduled scan (PNO); drivers with a small
    /// `max_sched_scan_match_sets` may reject a long list, in which
    /// case the client falls back to host-side scans.
    pub fn add_network(
        &mut self,
        ssid: &str,
        password: Option<&str>,
    ) -> &mut Self {
        let mut network = NetworkConfig::new(ssid);
        if let Some(password) = password {
            network.set_password(password);
        }
        self.networks.push(network);
        self
    }

    /// All configured SSIDs (for probe requests, PNO match sets, and
    /// logging).
    pub fn ssids(&self) -> impl Iterator<Item = &str> {
        self.networks.iter().map(|network| network.ssid.as_str())
    }
}
