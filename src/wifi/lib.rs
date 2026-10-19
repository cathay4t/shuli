// SPDX-License-Identifier: Apache-2.0

//! WiFi (WPA) authentication library.

mod auth;
mod client;
mod config;
mod crypto;
mod nl80211;
mod pmksa;
mod roam;
mod scan;

#[cfg(test)]
mod tests;

pub use shuli_core::{EapConfig, ErrorKind, WifiError};
pub(crate) use shuli_core::{eap, eap_tls};
pub(crate) use wl_nl80211::ETH_ALEN;
pub use wl_nl80211::Ieee80211CipherSuite;

pub(crate) use self::{client::WifiIface, nl80211::ShuliNl80211Connection};
pub use self::{
    client::{WifiClient, WifiIfaceState, WifiState},
    config::{
        DEFAULT_ROAM_THRESHOLD_DBM, DEFAULT_SWITCH_SSID_LOWER_THAN_DBM,
        KnownBss, NetworkConfig, NetworkConfigHints, SaePwe, WifiConfig,
    },
    scan::{BssInfo, SecurityType},
};
