// SPDX-License-Identifier: Apache-2.0

/// EAP credential configuration: identity, certificate
/// paths, and the TLS server name used for certificate validation.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
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
