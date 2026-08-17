// SPDX-License-Identifier: Apache-2.0

use crate::scan::SecurityType;

/// Default roam threshold: matches iwd's `RoamThreshold` (-70 dBm).
pub const DEFAULT_ROAM_THRESHOLD_DBM: i32 = -70;

/// Default signal level (dBm) below which the current link is treated
/// as critical and may be abandoned for a well-signalled BSS of a
/// *different* configured SSID. Matches iwd's `CriticalRoamThreshold`.
pub const DEFAULT_SWITCH_SSID_LOWER_THAN_DBM: i32 = -80;

/// SAE PWE derivation mode for a WPA3-Personal network.
///
/// WPA3 APs derive the SAE password element either with hash-to-element
/// (H2E, RFC 9380) or with hunting-and-pecking (HnP, RFC 7664); an
/// H2E-only STA cannot connect to an HnP-only AP. `Auto` (the default)
/// follows the AP's RSNXE from the scan: H2E when the AP advertises it,
/// hunting-and-pecking otherwise. Either way it still falls back to the
/// other method if the first commit is rejected or silently dropped, so
/// a missing/misleading RSNXE cannot strand the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SaePwe {
    /// Hash-to-element only.
    H2E,
    /// Hunting-and-pecking only (RFC 7664), for HnP-only APs.
    HnP,
    /// Follow the AP's advertised RSNXE Hash-to-Element capability,
    /// falling back to the other method when the first commit fails.
    #[default]
    Auto,
}

impl SaePwe {
    /// Whether the initial commit should use hash-to-element. Explicit
    /// `H2E`/`HnP` override the AP; `Auto` follows `ap_supports_h2e`,
    /// which the caller derives from the selected BSS's RSNXE.
    pub(crate) fn starts_h2e(self, ap_supports_h2e: bool) -> bool {
        match self {
            SaePwe::H2E => true,
            SaePwe::HnP => false,
            SaePwe::Auto => ap_supports_h2e,
        }
    }

    /// Whether a rejected/timed-out commit may fall back to the other
    /// PWE derivation method.
    pub(crate) fn allows_hnp_fallback(self) -> bool {
        matches!(self, SaePwe::Auto)
    }
}

/// WiFi connection configuration for [`WifiClient`](crate::WifiClient).
///
/// Create one `WifiConfig` per wifi-phy interface and pass all of them
/// to [`WifiClient::init_multi`](crate::WifiClient::init_multi) so a
/// single client manages every interface in the network namespace.
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
/// them. The signal is tracked by the kernel's connection quality
/// monitor (`NL80211_CMD_SET_CQM`, beacon-based and power-save stable),
/// polling every few seconds only on drivers without CQM support, and
/// a roam scan is only started against an AP that advertises a
/// managed-roaming capability (802.11v BSS Transition or 802.11k
/// Neighbor Report). BTM (802.11v) Requests are honoured regardless of
/// `roaming`.
#[derive(Debug, Clone, PartialEq)]
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
    /// Signal level (dBm) below which the current link is considered
    /// critical: a roam scan then also considers a well-signalled BSS of
    /// a *different* configured SSID and switches to it, even though
    /// that terminates the current session. Defaults to
    /// [`DEFAULT_SWITCH_SSID_LOWER_THAN_DBM`].
    pub switch_ssid_lower_than_dbm: i32,
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
    /// Optional SAE password identifier.  When set, the
    /// client derives the H2E PWE with the identifier, includes it in
    /// the SAE commit, and never falls back to hunting-and-pecking
    /// (password identifiers are H2E-only).
    pub sae_password_id: Option<String>,
    /// Operating Channel Validation (OCV): when `true`,
    /// the STA advertises the OCVC RSN capability, sends its OCI in
    /// 4-way Message 2, and verifies the AP's OCI in Message 3 and
    /// group rekeys.  Defaults to `false`.
    pub ocv: bool,
    /// Extended Key ID: use pairwise key id 0/1 rotation
    /// for lossless PTK rekeys.  Requires driver support and an
    /// AES-CC pairwise cipher; opt-in per network, defaults to `false`.
    pub ext_key_id: bool,
}

impl NetworkConfig {
    pub fn new(ssid: &str) -> Self {
        Self {
            ssid: ssid.to_string(),
            password: None,
            roaming: true,
            roaming_threshold: DEFAULT_ROAM_THRESHOLD_DBM,
            switch_ssid_lower_than_dbm: DEFAULT_SWITCH_SSID_LOWER_THAN_DBM,
            wowlan: false,
            eap: None,
            sae_pwe: SaePwe::Auto,
            sae_password_id: None,
            ocv: false,
            ext_key_id: false,
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

    /// Enable or disable Extended Key ID.
    pub fn set_ext_key_id(&mut self, enabled: bool) -> &mut Self {
        self.ext_key_id = enabled;
        self
    }

    /// Whether a cross-SSID roam may land on a BSS advertising
    /// `security`.
    pub(crate) fn can_roam_to_security(&self, security: SecurityType) -> bool {
        match security {
            SecurityType::Unsupported => false,
            SecurityType::Open => self.password.is_none() && self.eap.is_none(),
            _ => true,
        }
    }
}

/// EAP credential configuration: identity, certificate
/// paths, and the TLS server name used for certificate validation.
#[derive(Debug, Clone, Default, PartialEq)]
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
