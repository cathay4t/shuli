// SPDX-License-Identifier: Apache-2.0

/// WiFi connection configuration for [`WifiClient`](crate::WifiClient).
///
/// No serde — the daemon layer deserializes its own `ShuliConfig` and
/// converts it into this struct.
#[derive(Debug, Clone)]
pub struct WifiConfig {
    pub iface_name: String,
    pub ssid: String,
    pub password: Option<String>,
}

impl WifiConfig {
    pub fn new(iface_name: &str, ssid: &str) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            ssid: ssid.to_string(),
            password: None,
        }
    }

    pub fn set_password(&mut self, password: &str) -> &mut Self {
        self.password = Some(password.to_string());
        self
    }
}
