// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use netlink_packet_core::DecodeError;

#[derive(thiserror::Error, Debug)]
pub enum ShuliError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("nl80211 error: {0}")]
    Nl80211(#[from] wl_nl80211::Nl80211Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Scan failed: {0}")]
    ScanFailed(String),

    #[error("Connect failed: {0}")]
    ConnectFailed(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Key installation failed: {0}")]
    KeyInstallFailed(String),

    #[error("SAE authentication failed: {0}")]
    SaeFailed(String),

    #[error("4-way handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("No matching BSS found for SSID {ssid}")]
    NoMatchingBss { ssid: String },

    #[error("Config file not found: {0}")]
    ConfigNotFound(PathBuf),

    #[error("Invalid config: {0}")]
    InvalidConfig(String),

    #[error("Netlink decode error: {0}")]
    NetlinkDecode(#[from] DecodeError),
}

pub type ShuliResult<T> = Result<T, ShuliError>;
