// SPDX-License-Identifier: Apache-2.0

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    Config,
    Nl80211,
    Io,
    InterfaceNotFound,
    ScanFailed,
    ConnectFailed,
    AuthFailed,
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

#[derive(Debug)]
pub struct WifiError {
    pub kind: ErrorKind,
    pub msg: String,
}

impl WifiError {
    pub fn new(kind: ErrorKind, msg: impl Into<String>) -> Self {
        WifiError {
            kind,
            msg: msg.into(),
        }
    }
}

impl fmt::Display for WifiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
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
