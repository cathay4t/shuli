// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use shuli_core::EapConfig;
use wl_nl80211::{ETH_ALEN, Ieee80211CipherSuite};

use crate::scan::{BssInfo, MdieInfo, SecurityType};

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
#[non_exhaustive]
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

/// A BSS a network has successfully connected to before.
///
/// Part of [`NetworkConfigHints`]: a non-empty known-BSS list makes the
/// hinted quick scan prefer the strongest visible entry over a
/// non-hinted BSS of the same SSID. It carries no security/credential
/// data and does not enable the scan-free path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub struct KnownBss {
    /// BSSID (MAC address) of the BSS.
    pub bssid: [u8; 6],
    /// Frequency (MHz) the BSS was last seen on.
    pub frequency_mhz: u32,
}

impl KnownBss {
    /// Create one known-BSS entry.
    pub fn new(bssid: [u8; 6], frequency_mhz: u32) -> Self {
        Self {
            bssid,
            frequency_mhz,
        }
    }
}

/// Optional user-provided hints that let shuli find a network faster.
///
/// Hints are guesses, not hard constraints: shuli tries them first and
/// falls back to the normal scan flow when they miss.
///
/// When every scan-free field is set (`bssid`, `frequency_mhz`,
/// `security`, `ap_rsne`, `ap_rsnxe` and `group_mgmt_cipher`), shuli
/// skips the scan and authenticates directly. When any of them is
/// `None`, the scan is restricted to `frequencies_mhz` (plus every
/// [`KnownBss::frequency_mhz`]) and the normal scan flow is the
/// fallback. A non-empty `known_bss` list additionally makes the
/// selection prefer the strongest visible BSS the client already knows
/// over a non-hinted BSS of the same SSID.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub struct NetworkConfigHints {
    /// Frequencies (MHz) where the API user expects this network's APs.
    /// The first host scan is restricted to these channels; if no
    /// configured SSID is found, shuli falls back to a full scan.
    pub frequencies_mhz: Vec<u32>,
    /// BSSes this network has successfully connected to before (e.g.
    /// loaded from a quick-boot hint file). The hinted quick scan
    /// restricts the first scan to the known frequencies and connects
    /// to the strongest visible BSS from this list. Does not enable the
    /// scan-free path.
    pub known_bss: Vec<KnownBss>,
    /// BSSID of the AP this hint refers to. Required for the scan-free
    /// path.
    pub bssid: Option<[u8; 6]>,
    /// Frequency (MHz) of `bssid`. Required for the scan-free path.
    pub frequency_mhz: Option<u32>,
    /// Security mode detected on the AP. Required for the scan-free
    /// path.
    pub security: Option<SecurityType>,
    /// The AP's RSNE as a full element (ID 48 + length + body), empty
    /// for open networks. Required for the scan-free path.
    pub ap_rsne: Option<Vec<u8>>,
    /// The AP's RSNXE as a full element (ID 244 + length + body),
    /// `Some(vec![])` when the AP advertises none. Required for the
    /// scan-free path.
    pub ap_rsnxe: Option<Vec<u8>>,
    /// Negotiated group management (BIP) cipher. Required for the
    /// scan-free path.
    #[serde(with = "group_mgmt_cipher_serde")]
    pub group_mgmt_cipher: Option<Ieee80211CipherSuite>,
    /// Mobility Domain ID of an FT-capable AP. Optional; both `mdid`
    /// and `ft_capab` must be set to restore the MDIE.
    pub mdid: Option<[u8; 2]>,
    /// FT capability octet of the AP's MDIE. Optional; both `mdid` and
    /// `ft_capab` must be set to restore the MDIE.
    pub ft_capab: Option<u8>,
    /// Whether the AP advertises BSS Transition Management (802.11v).
    /// Optional; defaults to `false`.
    pub btm_support: Option<bool>,
    /// Whether the AP advertises Neighbor Report (802.11k). Optional;
    /// defaults to `false`.
    pub rm_neighbor_report: Option<bool>,
}

impl NetworkConfigHints {
    /// Create an empty hint set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the frequency hint list.
    pub fn with_frequencies_mhz(mut self, frequencies_mhz: Vec<u32>) -> Self {
        self.frequencies_mhz = frequencies_mhz;
        self
    }

    /// Replace the known-BSS hint list.
    pub fn with_known_bss(mut self, known_bss: Vec<KnownBss>) -> Self {
        self.known_bss = known_bss;
        self
    }

    /// Whether `bssid` is one of the remembered BSSes of this network.
    pub(crate) fn knows_bssid(&self, bssid: &[u8; 6]) -> bool {
        self.known_bss.iter().any(|known| known.bssid == *bssid)
    }

    /// Rebuild the BSS information required by the scan-free path.
    ///
    /// Returns `None` when any scan-free property is missing or the
    /// security type is unsupported; the caller should then fall back
    /// to a normal scan.
    pub(crate) fn bss_info(&self) -> Option<BssInfo> {
        let bssid = self.bssid?;
        if bssid == [0; 6] {
            return None;
        }
        let freq_mhz = self.frequency_mhz?;
        if freq_mhz == 0 {
            return None;
        }
        let security = self.security?;
        if security == SecurityType::Unsupported {
            return None;
        }
        Some(BssInfo {
            bssid,
            freq_mhz,
            // The scan-free path has no signal measurement, and the
            // auth path never reads this field; 0 is only a placeholder.
            signal_dbm: 0,
            security,
            ap_rsne: self.ap_rsne.clone()?,
            ap_rsnxe: self.ap_rsnxe.clone()?,
            group_mgmt_cipher: self.group_mgmt_cipher?,
            mdie: match (self.mdid, self.ft_capab) {
                (Some(mdid), Some(ft_capab)) => {
                    Some(MdieInfo { mdid, ft_capab })
                }
                _ => None,
            },
            hidden: false,
            btm_support: self.btm_support.unwrap_or(false),
            rm_neighbor_report: self.rm_neighbor_report.unwrap_or(false),
        })
    }
}

/// Serialize [`Ieee80211CipherSuite`] as its numeric OUI value so hint
/// files stay self-contained without depending on wl-nl80211's serde
/// support.
mod group_mgmt_cipher_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use wl_nl80211::Ieee80211CipherSuite;

    pub fn serialize<S>(
        cipher: &Option<Ieee80211CipherSuite>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match cipher {
            Some(cipher) => serializer.serialize_some(&u32::from(*cipher)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<Ieee80211CipherSuite>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<u32>::deserialize(deserializer)?;
        Ok(value.map(Ieee80211CipherSuite::from))
    }
}

/// WiFi connection configuration for [`WifiClient`](crate::WifiClient).
///
/// Create one `WifiConfig` per wifi-phy interface and pass all of them
/// to [`WifiClient::init`](crate::WifiClient::init) so a
/// single client manages every interface in the network namespace.
///
/// No serde — the daemon layer deserializes its own `ShuliConfig` and
/// converts it into this struct.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WifiConfig {
    pub iface_name: String,
    /// Networks to scan for and connect to. A single scan schedule
    /// probes for all of them; when no network is marked `prefered`, the
    /// strongest matching BSS wins and its network's passphrase is used
    /// for authentication. Roaming is configured per network (see
    /// [`NetworkConfig::roaming`]).
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
#[non_exhaustive]
pub struct NetworkConfig {
    pub ssid: String,
    pub password: Option<String>,
    /// When set, the network is pinned to this BSSID: only that BSS
    /// may be selected, the failed-BSS retry path never fails over to
    /// another BSS of the SSID, and roaming (802.11v BTM, scan based)
    /// never targets one. `None` (the default) accepts any BSS of
    /// `ssid`. Unlike [`NetworkConfigHints::bssid`], which is only a
    /// speed-up hint, this is a hard constraint.
    pub bssid: Option<[u8; ETH_ALEN]>,
    /// Optional hints that speed up the initial connection attempt.
    /// Complete hints enable a scan-free connect; partial hints (e.g.
    /// frequencies) enable a best-effort quick scan with the normal
    /// scan flow as fallback.
    pub hints: NetworkConfigHints,
    /// When `true`, this SSID is selected ahead of raw signal strength:
    /// as long as any BSS advertising it appears in the scan results,
    /// the strongest BSS of this SSID wins over a stronger BSS of a
    /// non-preferred configured SSID. A preferred SSID is ignored when
    /// its signal is below
    /// [`DEFAULT_SWITCH_SSID_LOWER_THAN_DBM`]: a link that weak does not
    /// deserve preference over a stronger configured SSID. When no
    /// qualifying preferred SSID is found, the strongest BSS among all
    /// configured networks is chosen. Defaults to `false`.
    pub prefered: bool,
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
    /// Hidden network: the AP does not include its SSID in beacons and
    /// only answers directed probe requests that carry its name. Mark
    /// this `true` to probe for the SSID with a specific probe request
    /// (wpa_supplicant's `scan_ssid=1`). Visible networks (the default)
    /// are found by the wildcard SSID entry that every scan carries.
    pub hidden: bool,
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
            bssid: None,
            hints: NetworkConfigHints::default(),
            prefered: false,
            roaming: true,
            roaming_threshold: DEFAULT_ROAM_THRESHOLD_DBM,
            switch_ssid_lower_than_dbm: DEFAULT_SWITCH_SSID_LOWER_THAN_DBM,
            wowlan: false,
            hidden: false,
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

    /// Pin the network to `bssid`, or remove the pin with `None`.
    ///
    /// A pinned network only ever connects to the given BSS, never
    /// fails over to another BSS of the same SSID and never roams to
    /// one. `None` (the default) accepts any BSS of the SSID.
    pub fn set_bssid(&mut self, bssid: Option<[u8; ETH_ALEN]>) -> &mut Self {
        self.bssid = bssid;
        self
    }

    /// Attach user-provided hints (e.g. last-known BSS information or
    /// just frequencies) used to speed up the first connection attempt.
    /// Complete hints enable the scan-free path; partial hints enable a
    /// best-effort quick scan with the normal scan flow as fallback.
    pub fn set_hints(&mut self, hints: NetworkConfigHints) -> &mut Self {
        self.hints = hints;
        self
    }

    /// Mark this SSID as preferred for scan-result selection. When it is
    /// found with a signal at or above
    /// [`DEFAULT_SWITCH_SSID_LOWER_THAN_DBM`], it is chosen before the
    /// strongest BSS of another configured SSID.
    pub fn set_prefered(&mut self, prefered: bool) -> &mut Self {
        self.prefered = prefered;
        self
    }

    /// Enable (or disable) Wake-on-WLAN for this network. WoWLAN is
    /// off by default; enabling it arms the wiphy's supported
    /// `Disconnect` / `GtkRekeyFailure` triggers while connected.
    pub fn set_wowlan(&mut self, enabled: bool) -> &mut Self {
        self.wowlan = enabled;
        self
    }

    /// Mark this network hidden so shuli probes for it with an
    /// SSID-specific probe request (like wpa_supplicant's `scan_ssid=1`).
    pub fn set_hidden(&mut self, hidden: bool) -> &mut Self {
        self.hidden = hidden;
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

    /// Whether a BSS with `bssid` is eligible for this network. A
    /// pinned network only accepts its pinned BSSID; an unpinned one
    /// accepts every BSS of its SSID.
    pub(crate) fn matches_bssid(&self, bssid: &[u8; ETH_ALEN]) -> bool {
        self.bssid.is_none_or(|pin| pin == *bssid)
    }

    /// Rebuild the BSS information for the scan-free path, rejecting
    /// hints that describe another BSS than the pinned one. Returns
    /// `None` when any scan-free property is missing, unsupported, or
    /// conflicts with the pin; the caller then falls back to a normal
    /// scan.
    pub(crate) fn scan_free_bss_info(&self) -> Option<BssInfo> {
        let bss = self.hints.bss_info()?;
        (self.matches_bssid(&bss.bssid) && self.accepts_security(bss.security))
            .then_some(bss)
    }

    /// Whether this network has the credentials required by `security`.
    /// Open and OWE networks need no credentials, PSK/SAE/FT networks
    /// need a password, and enterprise networks need EAP.
    pub(crate) fn accepts_security(&self, security: SecurityType) -> bool {
        match security {
            SecurityType::Unsupported => false,
            SecurityType::Open | SecurityType::Owe => {
                self.password.is_none() && self.eap.is_none()
            }
            SecurityType::Wpa2Psk
            | SecurityType::Wpa2PskSha256
            | SecurityType::Sae
            | SecurityType::SaeExtKey
            | SecurityType::FtPsk
            | SecurityType::FtSae
            | SecurityType::FtSaeExtKey => {
                self.password.is_some() && self.eap.is_none()
            }
            SecurityType::Wpa2Ent | SecurityType::Wpa2EntSha256 => {
                self.eap.is_some() && self.password.is_none()
            }
        }
    }

    /// Whether a cross-SSID roam may land on a BSS advertising
    /// `security`.
    pub(crate) fn can_roam_to_security(&self, security: SecurityType) -> bool {
        self.accepts_security(security)
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

    /// All configured SSIDs (for PNO match sets and logging; probe
    /// requests use [`Self::hidden_ssids`] plus a wildcard entry).
    pub fn ssids(&self) -> impl Iterator<Item = &str> {
        self.networks.iter().map(|network| network.ssid.as_str())
    }

    /// SSIDs of hidden networks, probed with directed probe requests.
    /// Visible networks are discovered by the wildcard scan entry that
    /// every scan carries (wpa_supplicant behaviour).
    pub fn hidden_ssids(&self) -> impl Iterator<Item = &str> {
        self.networks
            .iter()
            .filter(|network| network.hidden)
            .map(|network| network.ssid.as_str())
    }
}
