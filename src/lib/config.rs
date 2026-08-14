// SPDX-License-Identifier: Apache-2.0

/// Default roam threshold: matches iwd's `RoamThreshold` (-70 dBm).
pub const DEFAULT_ROAM_THRESHOLD_DBM: i32 = -70;

/// SAE PWE derivation mode for a WPA3-Personal network (Stage 2 G2b).
///
/// WPA3 APs derive the SAE password element either with hash-to-element
/// (H2E, RFC 9380) or with hunting-and-pecking (HnP, RFC 7664); an
/// H2E-only STA cannot connect to an HnP-only AP. `Auto` (the default)
/// sends an H2E commit and falls back to HnP when the AP rejects it,
/// which keeps existing H2E APs on the fast path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SaePwe {
    /// Hash-to-element only (the Stage-1 behaviour).
    H2E,
    /// Hunting-and-pecking only (RFC 7664), for HnP-only APs.
    HnP,
    /// Try hash-to-element first, fall back to hunting-and-pecking when
    /// the H2E commit is rejected.
    #[default]
    Auto,
}

impl SaePwe {
    /// Whether the initial commit should use hash-to-element.
    pub(crate) fn starts_h2e(self) -> bool {
        !matches!(self, SaePwe::HnP)
    }

    /// Whether a rejected H2E commit may fall back to hunting-and-pecking.
    pub(crate) fn allows_hnp_fallback(self) -> bool {
        matches!(self, SaePwe::Auto)
    }
}

/// WiFi connection configuration for [`WifiClient`](crate::WifiClient).
///
/// No serde — the daemon layer deserializes its own `ShuliConfig` and
/// converts it into this struct.
#[derive(Debug, Clone)]
pub struct WifiConfig {
    pub iface_name: String,
    /// Networks to scan for and connect to. A single scan schedule
    /// probes for all of them; the strongest matching BSS wins and its
    /// network's passphrase is used for authentication. Roaming is
    /// configured per network (see [`NetworkConfig::roaming`]).
    pub networks: Vec<NetworkConfig>,
}

/// A single WiFi network: an SSID with an optional passphrase and its
/// own roaming settings. Open networks carry `password: None`.
///
/// Signal-triggered roaming is on by default with a -70 dBm threshold
/// (matching iwd's `RoamThreshold`); the IEEE 802.11 standard (BSS
/// transition management, 802.11v §11.21.7) leaves client-side roaming
/// policy to the implementation. The threshold is deliberately
/// band-agnostic: per-band thresholds are added only if users ask for
/// them. BTM (802.11v) Requests are honoured regardless of `roaming`.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub ssid: String,
    pub password: Option<String>,
    /// When `false`, no signal-triggered roam scans are started while
    /// connected to this SSID. Defaults to `true`.
    pub roaming: bool,
    /// Signal level (dBm) below which the client scans for roam
    /// candidates while connected to this SSID. Defaults to
    /// [`DEFAULT_ROAM_THRESHOLD_DBM`].
    pub roaming_threshold: i32,
    /// Wake-on-WLAN (WoWLAN): when `true`, the client arms the
    /// `Disconnect` and `GtkRekeyFailure` triggers (as supported by the
    /// wiphy) while connected, so the device can wake the host on
    /// suspend. Defaults to `false` - opt in per network (matches
    /// wpa_supplicant, where `wowlan_triggers` is unset by default).
    pub wowlan: bool,
    /// EAP credentials for 802.1X networks (WPA-Enterprise / wired
    /// 802.1X). `None` for PSK/SAE/open networks.
    pub eap: Option<EapConfig>,
    /// SAE PWE derivation mode (WPA3-Personal only). Defaults to
    /// [`SaePwe::Auto`]: hash-to-element first, hunting-and-pecking
    /// fallback for HnP-only APs.
    pub sae_pwe: SaePwe,
    /// Optional SAE password identifier (Stage 3 M7).  When set, the
    /// client derives the H2E PWE with the identifier, includes it in
    /// the SAE commit, and never falls back to hunting-and-pecking
    /// (password identifiers are H2E-only).
    pub sae_password_id: Option<String>,
    /// Operating Channel Validation (OCV, Stage 3 M10): when `true`,
    /// the STA advertises the OCVC RSN capability, sends its OCI in
    /// 4-way Message 2, and verifies the AP's OCI in Message 3 and
    /// group rekeys.  Defaults to `false`.
    pub ocv: bool,
}

impl NetworkConfig {
    pub fn new(ssid: &str) -> Self {
        Self {
            ssid: ssid.to_string(),
            password: None,
            roaming: true,
            roaming_threshold: DEFAULT_ROAM_THRESHOLD_DBM,
            wowlan: false,
            eap: None,
            sae_pwe: SaePwe::Auto,
            sae_password_id: None,
            ocv: false,
        }
    }

    pub fn set_password(&mut self, password: &str) -> &mut Self {
        self.password = Some(password.to_string());
        self
    }

    /// Enable (or disable) Wake-on-WLAN for this network. WoWLAN is
    /// off by default; enabling it arms the wiphy's supported
    /// `Disconnect` / `GtkRekeyFailure` triggers while connected.
    pub fn set_wowlan(&mut self, enabled: bool) -> &mut Self {
        self.wowlan = enabled;
        self
    }

    /// Attach EAP credentials to this network (802.1X).
    pub fn set_eap(&mut self, eap: EapConfig) -> &mut Self {
        self.eap = Some(eap);
        self
    }

    /// Set the optional SAE password identifier (WPA3-Personal).
    pub fn set_sae_password_id(&mut self, id: Option<&str>) -> &mut Self {
        self.sae_password_id = id.map(str::to_string);
        self
    }

    /// Enable or disable Operating Channel Validation (OCV).
    pub fn set_ocv(&mut self, enabled: bool) -> &mut Self {
        self.ocv = enabled;
        self
    }
}

/// EAP credential configuration (Stage 3 M3): identity, certificate
/// paths, and the TLS server name used for certificate validation.
#[derive(Debug, Clone, Default)]
pub struct EapConfig {
    /// EAP identity (outer identity) sent in the Identity exchange.
    pub identity: String,
    /// PEM CA certificate used to validate the EAP server.
    pub ca_cert: Option<std::path::PathBuf>,
    /// PEM client certificate (EAP-TLS).
    pub client_cert: Option<std::path::PathBuf>,
    /// PEM client private key (EAP-TLS).
    pub client_key: Option<std::path::PathBuf>,
    /// TLS server name for certificate validation (SNI / SAN match).
    pub server_name: Option<String>,
}

impl WifiConfig {
    /// Create a config with no networks yet on `iface_name`. Add
    /// networks with [`add_network`](Self::add_network) so one scan
    /// schedule checks all of them.
    pub fn new(iface_name: &str) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            networks: Vec::new(),
        }
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
