// SPDX-License-Identifier: Apache-2.0

use std::fmt;

#[derive(Debug)]
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
        };
        write!(f, "{s}")
    }
}

#[derive(Debug)]
pub struct WpaError {
    pub kind: ErrorKind,
    pub msg: String,
}

impl WpaError {
    pub fn new(kind: ErrorKind, msg: impl Into<String>) -> Self {
        WpaError {
            kind,
            msg: msg.into(),
        }
    }
}

impl fmt::Display for WpaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
    }
}

impl std::error::Error for WpaError {}

impl From<wl_nl80211::Nl80211Error> for WpaError {
    fn from(e: wl_nl80211::Nl80211Error) -> Self {
        WpaError::new(ErrorKind::Nl80211, e.to_string())
    }
}

impl From<std::io::Error> for WpaError {
    fn from(e: std::io::Error) -> Self {
        WpaError::new(ErrorKind::Io, e.to_string())
    }
}

impl From<netlink_packet_core::DecodeError> for WpaError {
    fn from(e: netlink_packet_core::DecodeError) -> Self {
        WpaError::new(ErrorKind::NetlinkDecode, e.to_string())
    }
}
