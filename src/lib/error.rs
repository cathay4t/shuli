// SPDX-License-Identifier: Apache-2.0

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    Config,
    Nl80211,
    Io,
    InterfaceNotFound,
    ScanFailed,
    ConnectFailed,
    AuthFailed,
    WrongPassword,
    KeyInstallFailed,
    SaeFailed,
    HandshakeFailed,
    SsidNotFound,
    ConfigNotFound,
    InvalidConfig,
    NetlinkDecode,
    Deprecated,
    Roaming,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ErrorKind::Config => "config",
            ErrorKind::Nl80211 => "nl80211",
            ErrorKind::Io => "io",
            ErrorKind::InterfaceNotFound => "interface-not-found",
            ErrorKind::ScanFailed => "scan-failed",
            ErrorKind::ConnectFailed => "connect-failed",
            ErrorKind::AuthFailed => "auth-failed",
            ErrorKind::WrongPassword => "wrong-password",
            ErrorKind::KeyInstallFailed => "key-install-failed",
            ErrorKind::SaeFailed => "sae-failed",
            ErrorKind::HandshakeFailed => "handshake-failed",
            ErrorKind::SsidNotFound => "ssid-not-found",
            ErrorKind::ConfigNotFound => "config-not-found",
            ErrorKind::InvalidConfig => "invalid-config",
            ErrorKind::NetlinkDecode => "netlink-decode",
            ErrorKind::Deprecated => "deprecated",
            ErrorKind::Roaming => "roaming",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WifiError {
    pub kind: ErrorKind,
    pub msg: String,
    pub iface_name: Option<String>,
}

impl WifiError {
    pub fn new(kind: ErrorKind, msg: impl Into<String>) -> Self {
        WifiError {
            kind,
            msg: msg.into(),
            iface_name: None,
        }
    }

    /// Attach the interface the error belongs to.
    pub fn with_iface_name(mut self, iface_name: impl Into<String>) -> Self {
        self.iface_name = Some(iface_name.into());
        self
    }

    /// A credential failure against a password-protected network.
    pub fn wrong_password(ssid: &str) -> Self {
        WifiError::new(
            ErrorKind::WrongPassword,
            format!("wrong password for SSID '{ssid}'"),
        )
    }
}

impl fmt::Display for WifiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.iface_name {
            Some(iface_name) => {
                write!(f, "[{iface_name}] {}: {}", self.kind, self.msg)
            }
            None => write!(f, "{}: {}", self.kind, self.msg),
        }
    }
}

impl std::error::Error for WifiError {}

impl From<wl_nl80211::Nl80211Error> for WifiError {
    fn from(e: wl_nl80211::Nl80211Error) -> Self {
        WifiError::new(ErrorKind::Nl80211, e.to_string())
    }
}

impl From<std::io::Error> for WifiError {
    fn from(e: std::io::Error) -> Self {
        WifiError::new(ErrorKind::Io, e.to_string())
    }
}

impl From<netlink_packet_core::DecodeError> for WifiError {
    fn from(e: netlink_packet_core::DecodeError) -> Self {
        WifiError::new(ErrorKind::NetlinkDecode, e.to_string())
    }
}
