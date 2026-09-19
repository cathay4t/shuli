// SPDX-License-Identifier: Apache-2.0

mod auth;
mod client;
mod config;
mod crypto;
mod eap;
mod eap_tls;
mod error;
mod nl80211;
mod pmksa;
mod roam;
mod scan;
mod wired;

#[cfg(test)]
mod tests;

pub(crate) use wl_nl80211::ETH_ALEN;
pub use wl_nl80211::Ieee80211CipherSuite;

pub(crate) use self::{client::WifiIface, nl80211::ShuliNl80211Connection};
pub use self::{
    client::{WifiClient, WifiIfaceState, WifiState},
    config::{
        DEFAULT_ROAM_THRESHOLD_DBM, DEFAULT_SWITCH_SSID_LOWER_THAN_DBM,
        EapConfig, NetworkConfig, NetworkConfigHints, SaePwe, WifiConfig,
    },
    error::{ErrorKind, WifiError},
    scan::{BssInfo, SecurityType},
    wired::{WiredClient, WiredState},
};
