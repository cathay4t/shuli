// SPDX-License-Identifier: Apache-2.0

//! Public configuration types.
//!
//! Configuration uses `local` and `remote` endpoints throughout.  IKE
//! initiator/responder roles are protocol properties and are not part of
//! the configuration schema.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use zeroize::Zeroizing;

use crate::{error::IpsecError, identity::Identity};

/// Network topology of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum Topology {
    /// One local endpoint and one remote endpoint.
    #[default]
    PointToPoint,
    /// A statically configured mesh of peers.
    AdHoc,
    /// Gateway-to-gateway tunnel between protected subnets.
    SiteToSite,
}

impl fmt::Display for Topology {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PointToPoint => f.write_str("point-to-point"),
            Self::AdHoc => f.write_str("ad-hoc"),
            Self::SiteToSite => f.write_str("site-to-site"),
        }
    }
}

/// Child SA packet mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum ChildMode {
    /// ESP transport mode (host-to-host only).
    Transport,
    /// ESP tunnel mode, normally used with an XFRM interface.
    #[default]
    Tunnel,
}

/// IKE encryption transforms supported by this implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum EncryptionAlgorithm {
    AesCbc128,
    AesCbc192,
    AesCbc256,
    AesGcm16_128,
    AesGcm16_256,
}

impl EncryptionAlgorithm {
    /// IKEv2 transform ID (RFC 7296 and the IANA registry).
    pub fn transform_id(self) -> u16 {
        match self {
            Self::AesCbc128 | Self::AesCbc192 | Self::AesCbc256 => 12,
            Self::AesGcm16_128 | Self::AesGcm16_256 => 20,
        }
    }

    /// Encryption key length in octets.
    pub fn key_len(self) -> usize {
        match self {
            Self::AesCbc128 | Self::AesGcm16_128 => 16,
            Self::AesCbc192 => 24,
            Self::AesCbc256 | Self::AesGcm16_256 => 32,
        }
    }

    /// Key length attribute for transforms that carry one.
    pub fn key_len_bits(self) -> Option<u16> {
        match self {
            Self::AesCbc128 | Self::AesGcm16_128 => Some(128),
            Self::AesCbc192 => Some(192),
            Self::AesCbc256 | Self::AesGcm16_256 => Some(256),
        }
    }

    /// Whether this is a combined-mode (AEAD) cipher.
    pub fn is_aead(self) -> bool {
        matches!(self, Self::AesGcm16_128 | Self::AesGcm16_256)
    }

    /// Size in octets of the explicit IV/nonce prefix carried in the SK
    /// payload.
    pub fn iv_len(self) -> usize {
        if self.is_aead() { 8 } else { 16 }
    }

    /// AES-GCM salt length appended to the encryption key in SK_e.
    pub fn salt_len(self) -> usize {
        if self.is_aead() { 4 } else { 0 }
    }

    /// Size in octets of the padding block.
    pub fn block_len(self) -> usize {
        16
    }
}

/// PRF transforms supported by this implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum PrfAlgorithm {
    HmacSha1,
    HmacSha2_256,
}

impl PrfAlgorithm {
    pub fn transform_id(self) -> u16 {
        match self {
            Self::HmacSha1 => 2,
            Self::HmacSha2_256 => 5,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha2_256 => 32,
        }
    }
}

/// Integrity transforms supported by this implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum IntegrityAlgorithm {
    None,
    HmacSha1_96,
    HmacSha2_256_128,
}

impl IntegrityAlgorithm {
    pub fn transform_id(self) -> u16 {
        match self {
            Self::None => 0,
            Self::HmacSha1_96 => 2,
            Self::HmacSha2_256_128 => 12,
        }
    }

    /// Length of the truncated ICV in octets.
    pub fn output_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::HmacSha1_96 => 12,
            Self::HmacSha2_256_128 => 16,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::HmacSha1_96 => 20,
            Self::HmacSha2_256_128 => 32,
        }
    }
}

/// Diffie-Hellman groups supported by this implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum DhGroup {
    None,
    Modp2048,
    Ecp256,
    Ecp384,
    X25519,
}

impl DhGroup {
    pub fn transform_id(self) -> u16 {
        match self {
            Self::None => 0,
            Self::Modp2048 => 14,
            Self::Ecp256 => 19,
            Self::Ecp384 => 20,
            Self::X25519 => 31,
        }
    }

    pub fn from_transform_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(Self::None),
            14 => Some(Self::Modp2048),
            19 => Some(Self::Ecp256),
            20 => Some(Self::Ecp384),
            31 => Some(Self::X25519),
            _ => None,
        }
    }
}

/// One complete IKE proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct IkeProposal {
    pub encryption: EncryptionAlgorithm,
    pub prf: PrfAlgorithm,
    pub integrity: IntegrityAlgorithm,
    pub dh: DhGroup,
}

impl IkeProposal {
    /// Whether the transform combination is valid: AEAD ciphers carry
    /// their own integrity protection.
    pub fn is_valid(&self) -> bool {
        !(self.encryption.is_aead()
            && self.integrity != IntegrityAlgorithm::None)
    }
}

/// One complete ESP proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct ChildProposal {
    pub encryption: EncryptionAlgorithm,
    pub integrity: IntegrityAlgorithm,
    /// Extended sequence numbers.
    pub esn: bool,
    /// Optional PFS group for CREATE_CHILD_SA rekey.
    pub dh: DhGroup,
}

impl ChildProposal {
    pub fn is_valid(&self) -> bool {
        !(self.encryption.is_aead()
            && self.integrity != IntegrityAlgorithm::None)
    }
}

/// The proposal list used while negotiating one protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct ProposalSet<T> {
    pub proposals: Vec<T>,
}

impl<T> ProposalSet<T> {
    pub fn new(proposals: Vec<T>) -> Self {
        Self { proposals }
    }
}

impl<T: Copy> From<&[T]> for ProposalSet<T> {
    fn from(value: &[T]) -> Self {
        Self {
            proposals: value.to_vec(),
        }
    }
}

/// IKE SA negotiation and lifetime settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct IkeConfig {
    pub proposals: ProposalSet<IkeProposal>,
    pub lifetime: Duration,
}

impl Default for IkeConfig {
    fn default() -> Self {
        Self {
            proposals: ProposalSet::new(vec![
                IkeProposal {
                    encryption: EncryptionAlgorithm::AesGcm16_256,
                    prf: PrfAlgorithm::HmacSha2_256,
                    integrity: IntegrityAlgorithm::None,
                    dh: DhGroup::Ecp256,
                },
                IkeProposal {
                    encryption: EncryptionAlgorithm::AesGcm16_128,
                    prf: PrfAlgorithm::HmacSha2_256,
                    integrity: IntegrityAlgorithm::None,
                    dh: DhGroup::X25519,
                },
                IkeProposal {
                    encryption: EncryptionAlgorithm::AesCbc256,
                    prf: PrfAlgorithm::HmacSha2_256,
                    integrity: IntegrityAlgorithm::HmacSha2_256_128,
                    dh: DhGroup::Modp2048,
                },
                IkeProposal {
                    encryption: EncryptionAlgorithm::AesCbc128,
                    prf: PrfAlgorithm::HmacSha2_256,
                    integrity: IntegrityAlgorithm::HmacSha2_256_128,
                    dh: DhGroup::Ecp256,
                },
            ]),
            lifetime: Duration::from_secs(8 * 60 * 60),
        }
    }
}

/// Child SA negotiation and lifetime settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct ChildConfig {
    pub proposals: ProposalSet<ChildProposal>,
    pub mode: ChildMode,
    pub lifetime: Duration,
    /// Replay window size in packets.
    pub replay_window: u32,
}

impl Default for ChildConfig {
    fn default() -> Self {
        Self {
            proposals: ProposalSet::new(vec![
                ChildProposal {
                    encryption: EncryptionAlgorithm::AesGcm16_256,
                    integrity: IntegrityAlgorithm::None,
                    esn: false,
                    dh: DhGroup::Ecp256,
                },
                ChildProposal {
                    encryption: EncryptionAlgorithm::AesGcm16_128,
                    integrity: IntegrityAlgorithm::None,
                    esn: false,
                    dh: DhGroup::X25519,
                },
                ChildProposal {
                    encryption: EncryptionAlgorithm::AesCbc256,
                    integrity: IntegrityAlgorithm::HmacSha2_256_128,
                    esn: false,
                    dh: DhGroup::Modp2048,
                },
                ChildProposal {
                    encryption: EncryptionAlgorithm::AesCbc128,
                    integrity: IntegrityAlgorithm::HmacSha2_256_128,
                    esn: true,
                    dh: DhGroup::Ecp256,
                },
            ]),
            mode: ChildMode::Tunnel,
            lifetime: Duration::from_secs(60 * 60),
            replay_window: 512,
        }
    }
}

/// Rekey timers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct RekeyConfig {
    /// Start IKE SA rekey after this fraction of the negotiated
    /// lifetime has elapsed, in percent.
    pub ike_margin_percent: u8,
    /// Start Child SA rekey after this fraction of the negotiated
    /// lifetime has elapsed, in percent.
    pub child_margin_percent: u8,
    /// Delay between installing a replacement Child SA and removing the
    /// old one.
    pub grace: Duration,
}

impl Default for RekeyConfig {
    fn default() -> Self {
        Self {
            ike_margin_percent: 90,
            child_margin_percent: 90,
            grace: Duration::from_secs(10),
        }
    }
}

/// Dead Peer Detection settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct DpdConfig {
    /// Idle interval between liveness checks.
    pub interval: Duration,
    /// Time to wait for the response.
    pub timeout: Duration,
    /// Number of failed checks before the SA is declared dead.
    pub retries: u8,
    /// Whether DPD is enabled at all.
    pub enabled: bool,
}

impl Default for DpdConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            retries: 3,
            enabled: true,
        }
    }
}

/// XFRM interface and state settings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct XfrmConfig {
    /// Explicit XFRM interface name.  When absent, a stable name is
    /// derived from the connection name.
    pub interface: Option<String>,
    /// Explicit `if_id`.  When absent, an unused value is allocated.
    pub if_id: Option<u32>,
    /// Explicit `reqid`.  When absent, an unused value is allocated.
    pub reqid: Option<u32>,
    /// Policy priority.
    pub priority: u32,
    /// Optional XFRM mark value and mask.
    pub mark: Option<u32>,
    pub mark_mask: u32,
    /// Underlay interface used as the XFRM link base.
    pub underlay_interface: Option<String>,
    /// Whether to use ESN on the installed SAs.
    pub esn: bool,
}

/// Authentication material for one peer.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum AuthConfig {
    /// Pre-shared key, used with RFC 7296 PSK authentication.
    Psk(Secret),
    /// X.509 certificate authentication.
    Certificate(CertificateConfig),
    /// EAP-TLS client authentication.
    EapTls(EapTlsConfig),
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Psk(_) => f.write_str("Psk(<redacted>)"),
            Self::Certificate(config) => {
                f.debug_tuple("Certificate").field(config).finish()
            }
            Self::EapTls(config) => {
                f.debug_tuple("EapTls").field(config).finish()
            }
        }
    }
}

/// X.509 credentials, encoded as PEM or DER.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct CertificateConfig {
    /// Trust anchors used to validate the peer certificate.
    pub ca_certificates: Vec<Vec<u8>>,
    /// Local certificate chain, leaf first.
    pub certificates: Vec<Vec<u8>>,
    /// Local PKCS#8 or SEC1 private key.
    pub private_key: Secret,
    /// Optional list of CA distinguished names acceptable to the peer.
    pub certificate_requests: Vec<Vec<u8>>,
}

impl fmt::Debug for CertificateConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateConfig")
            .field("ca_certificates", &self.ca_certificates.len())
            .field("certificates", &self.certificates.len())
            .field("private_key", &"<redacted>")
            .field("certificate_requests", &self.certificate_requests.len())
            .finish()
    }
}

impl CertificateConfig {
    pub fn new(
        ca_certificates: Vec<Vec<u8>>,
        certificates: Vec<Vec<u8>>,
        private_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            ca_certificates,
            certificates,
            private_key: Secret::new(private_key),
            certificate_requests: Vec::new(),
        }
    }
}

/// EAP-TLS client configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct EapTlsConfig {
    /// Outer EAP identity.
    pub identity: String,
    /// PEM CA certificate used to validate the EAP server.
    pub ca_cert: Option<PathBuf>,
    /// PEM client certificate.
    pub client_cert: Option<PathBuf>,
    /// PEM client private key.
    pub client_key: Option<PathBuf>,
    /// TLS server name used for certificate validation.
    pub server_name: Option<String>,
}

impl EapTlsConfig {
    /// Validate required EAP-TLS fields.
    pub fn validate(&self) -> Result<(), IpsecError> {
        if self.identity.is_empty() {
            return Err(IpsecError::config("EAP-TLS identity is required"));
        }
        for (field, value) in [
            ("ca_cert", &self.ca_cert),
            ("client_cert", &self.client_cert),
            ("client_key", &self.client_key),
        ] {
            if value.is_none() {
                return Err(IpsecError::config(format!(
                    "EAP-TLS {field} is required"
                )));
            }
        }
        if self.server_name.as_deref().is_none_or(str::is_empty) {
            return Err(IpsecError::config("EAP-TLS server_name is required"));
        }
        Ok(())
    }

    /// Convert to the transport-neutral EAP core configuration.
    pub fn to_core(&self) -> shuli_core::EapConfig {
        let mut config = shuli_core::EapConfig::default();
        config.identity = self.identity.clone();
        config.ca_cert = self.ca_cert.clone();
        config.client_cert = self.client_cert.clone();
        config.client_key = self.client_key.clone();
        config.server_name = self.server_name.clone();
        config
    }
}

impl From<&EapTlsConfig> for shuli_core::EapConfig {
    fn from(value: &EapTlsConfig) -> Self {
        value.to_core()
    }
}

/// Local endpoint configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct LocalConfig {
    /// Local underlay address.  When absent, the kernel selects the
    /// source address for the outgoing IKE socket.
    pub address: Option<IpAddr>,
    /// Underlay interface reference.
    pub interface: Option<String>,
    /// IKE identity.
    pub identity: Identity,
    /// Local UDP port.  Defaults to 500.
    pub port: u16,
    /// Enable NAT-T (UDP 4500 encapsulation) when the peer supports it.
    pub nat_t: bool,
    /// Request an inner address through the IKEv2 Configuration
    /// Payload (road-warrior mode).
    pub request_inner_address: bool,
    /// Request DNS servers through the Configuration Payload.
    pub request_dns: bool,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            address: None,
            interface: None,
            identity: Identity::Fqdn("localhost".to_string()),
            port: 500,
            nat_t: true,
            request_inner_address: false,
            request_dns: false,
        }
    }
}

/// Remote endpoint configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct RemoteConfig {
    /// Remote underlay address.  `None` for a responder that learns the
    /// address from the peer identity, or for a peer that only
    /// initiates.
    pub address: Option<IpAddr>,
    /// Remote IKE identity.
    pub identity: Identity,
    /// Remote UDP port.  Defaults to 500.
    pub port: u16,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            address: None,
            identity: Identity::Fqdn("remote.example.org".to_string()),
            port: 500,
        }
    }
}

/// One peer in a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct PeerConfig {
    pub remote: RemoteConfig,
    pub selectors: TrafficSelectorPair,
    pub auth: AuthConfig,
}

/// A pair of local and remote traffic selectors.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct TrafficSelectorPair {
    pub local: Vec<TrafficSelector>,
    pub remote: Vec<TrafficSelector>,
}

impl TrafficSelectorPair {
    pub fn new(
        local: Vec<TrafficSelector>,
        remote: Vec<TrafficSelector>,
    ) -> Self {
        Self { local, remote }
    }

    /// Host-to-host selector pair for `local` and `remote`.
    pub fn hosts(local: IpAddr, remote: IpAddr) -> Self {
        Self {
            local: vec![TrafficSelector::host(local)],
            remote: vec![TrafficSelector::host(remote)],
        }
    }

    pub(crate) fn validate(&self) -> Result<(), IpsecError> {
        if self.local.is_empty() || self.remote.is_empty() {
            return Err(IpsecError::config(
                "traffic selectors must contain at least one local and one \
                 remote prefix",
            ));
        }
        for selector in self.local.iter().chain(self.remote.iter()) {
            selector.validate()?;
        }
        let local_family = self.local[0].start;
        if self
            .local
            .iter()
            .any(|s| s.family() != family(local_family))
        {
            return Err(IpsecError::config(
                "local traffic selectors mix address families",
            ));
        }
        if self
            .remote
            .iter()
            .any(|s| s.family() != family(local_family))
        {
            return Err(IpsecError::config(
                "local and remote traffic selectors must use the same address \
                 family",
            ));
        }
        Ok(())
    }
}

fn family(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 4 } else { 6 }
}

/// One IKEv2 traffic selector (RFC 7296 section 3.13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct TrafficSelector {
    pub start: IpAddr,
    pub end: IpAddr,
    pub protocol: u8,
    pub start_port: u16,
    pub end_port: u16,
}

impl TrafficSelector {
    /// A single host with any protocol and port.
    pub fn host(address: IpAddr) -> Self {
        Self {
            start: address,
            end: address,
            protocol: 0,
            start_port: 0,
            end_port: u16::MAX,
        }
    }

    /// A subnet with any protocol and port.
    pub fn net(network: IpNet) -> Self {
        Self {
            start: network.first(),
            end: network.last(),
            protocol: 0,
            start_port: 0,
            end_port: u16::MAX,
        }
    }

    pub fn family(&self) -> u8 {
        family(self.start)
    }

    fn validate(&self) -> Result<(), IpsecError> {
        if family(self.start) != family(self.end) {
            return Err(IpsecError::config(
                "traffic selector start and end use different address families",
            ));
        }
        if self.start > self.end {
            return Err(IpsecError::config(
                "traffic selector start is greater than its end",
            ));
        }
        if self.start_port > self.end_port {
            return Err(IpsecError::config(
                "traffic selector start port is greater than its end port",
            ));
        }
        Ok(())
    }

    /// Whether `address` falls inside this selector.
    pub fn contains(&self, address: IpAddr) -> bool {
        family(address) == family(self.start)
            && address >= self.start
            && address <= self.end
    }

    /// Intersect two selectors, if their protocol/port ranges overlap.
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        if self.family() != other.family() || self.protocol != other.protocol {
            return None;
        }
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        if start > end {
            return None;
        }
        let start_port = self.start_port.max(other.start_port);
        let end_port = self.end_port.min(other.end_port);
        if start_port > end_port {
            return None;
        }
        Some(Self {
            start,
            end,
            protocol: self.protocol,
            start_port,
            end_port,
        })
    }

    /// Whether `self` is fully contained in `other`.
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.family() == other.family()
            && self.protocol == other.protocol
            && self.start >= other.start
            && self.end <= other.end
            && self.start_port >= other.start_port
            && self.end_port <= other.end_port
    }
}

/// An IP address with a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl IpNet {
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, IpsecError> {
        let max = if address.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(IpsecError::config(format!(
                "prefix length {prefix_len} is invalid for {address}"
            )));
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    pub fn first(&self) -> IpAddr {
        match self.address {
            IpAddr::V4(address) => {
                let value = if self.prefix_len == 0 {
                    0
                } else {
                    u32::from(address) & (!0u32 << (32 - self.prefix_len))
                };
                IpAddr::V4(Ipv4Addr::from(value))
            }
            IpAddr::V6(address) => {
                let value = if self.prefix_len == 0 {
                    0
                } else {
                    u128::from(address) & (!0u128 << (128 - self.prefix_len))
                };
                IpAddr::V6(Ipv6Addr::from(value))
            }
        }
    }

    pub fn last(&self) -> IpAddr {
        match self.address {
            IpAddr::V4(address) => {
                let host = if self.prefix_len == 0 {
                    u32::MAX
                } else {
                    (1u32 << (32 - self.prefix_len)) - 1
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(address) | host))
            }
            IpAddr::V6(address) => {
                let host = if self.prefix_len == 0 {
                    u128::MAX
                } else {
                    (1u128 << (128 - self.prefix_len)) - 1
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(address) | host))
            }
        }
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

impl FromStr for IpNet {
    type Err = IpsecError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value.split_once('/').ok_or_else(|| {
            IpsecError::config(format!("invalid prefix {value}"))
        })?;
        let address = address.parse().map_err(|_| {
            IpsecError::config(format!("invalid address {address}"))
        })?;
        let prefix_len = prefix.parse().map_err(|_| {
            IpsecError::config(format!("invalid prefix length {prefix}"))
        })?;
        Self::new(address, prefix_len)
    }
}

impl From<TrafficSelector> for IpNet {
    fn from(value: TrafficSelector) -> Self {
        let prefix_len = common_prefix_len(&value.start, &value.end);
        Self {
            address: value.start,
            prefix_len,
        }
    }
}

fn common_prefix_len(start: &IpAddr, end: &IpAddr) -> u8 {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            let xor = u32::from(*start) ^ u32::from(*end);
            xor.leading_zeros() as u8
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            let xor = u128::from(*start) ^ u128::from(*end);
            xor.leading_zeros() as u8
        }
        _ => 0,
    }
}

/// A zeroizing secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Expose the raw secret to the IKE implementation.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes().to_vec())
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

impl From<&[u8]> for Secret {
    fn from(value: &[u8]) -> Self {
        Self::new(value.to_vec())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Secret {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("<redacted>")
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from(value))
    }
}

/// One configured IPsec connection.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub struct IpsecConfig {
    pub name: String,
    pub topology: Topology,
    pub local: LocalConfig,
    pub peers: Vec<PeerConfig>,
    pub ike: IkeConfig,
    pub child: ChildConfig,
    pub xfrm: XfrmConfig,
    pub rekey: RekeyConfig,
    pub dpd: DpdConfig,
}

impl IpsecConfig {
    /// Validate structural configuration.  Kernel-dependent checks
    /// (`if_id` collisions, interface existence) belong to
    /// [`crate::XfrmManager`].
    pub fn validate(&self) -> Result<(), IpsecError> {
        if self.name.trim().is_empty() {
            return Err(IpsecError::config("connection name is required"));
        }
        if self.peers.is_empty() {
            return Err(IpsecError::config(format!(
                "connection {} has no peers",
                self.name
            )));
        }
        if self.topology == Topology::PointToPoint && self.peers.len() != 1 {
            return Err(IpsecError::config(
                "point-to-point connections require exactly one peer",
            ));
        }
        if self.ike.proposals.proposals.is_empty() {
            return Err(IpsecError::config(
                "at least one IKE proposal is required",
            ));
        }
        if self.child.proposals.proposals.is_empty() {
            return Err(IpsecError::config(
                "at least one Child SA proposal is required",
            ));
        }
        for proposal in &self.ike.proposals.proposals {
            if !proposal.is_valid() {
                return Err(IpsecError::config(
                    "AEAD IKE proposals must not specify an integrity \
                     transform",
                ));
            }
        }
        for proposal in &self.child.proposals.proposals {
            if !proposal.is_valid() {
                return Err(IpsecError::config(
                    "AEAD ESP proposals must not specify an integrity \
                     transform",
                ));
            }
        }
        if self.child.mode == ChildMode::Transport
            && self.peers.iter().any(|peer| {
                peer.selectors.local.iter().any(|s| s.start != s.end)
            })
        {
            return Err(IpsecError::config(
                "transport mode requires host traffic selectors",
            ));
        }
        for peer in &self.peers {
            peer.selectors.validate()?;
            match &peer.auth {
                AuthConfig::Psk(secret) if secret.is_empty() => {
                    return Err(IpsecError::config("PSK must not be empty"));
                }
                AuthConfig::Certificate(cert) => {
                    if cert.ca_certificates.is_empty() {
                        return Err(IpsecError::config(
                            "certificate authentication requires a CA \
                             certificate",
                        ));
                    }
                    if cert.certificates.is_empty() {
                        return Err(IpsecError::config(
                            "certificate authentication requires a local \
                             certificate",
                        ));
                    }
                    if cert.private_key.is_empty() {
                        return Err(IpsecError::config(
                            "certificate authentication requires a private key",
                        ));
                    }
                }
                AuthConfig::EapTls(eap) => eap.validate()?,
                AuthConfig::Psk(_) => {}
            }
        }
        Ok(())
    }
}
