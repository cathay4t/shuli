// SPDX-License-Identifier: Apache-2.0

mod auth;
mod client;
mod config;
mod crypto;
mod eap;
mod eap_tls;
mod error;
mod ieee80211;
mod mac;
mod nl80211;
mod pmksa;
mod roam;
mod scan;
mod wired;

#[cfg(test)]
mod tests;

pub(crate) use self::{
    client::WifiIface, mac::ETH_ALEN, nl80211::ShuliNl80211Connection,
};
pub use self::{
    client::{WifiClient, WifiIfaceState, WifiState},
    config::{
        DEFAULT_ROAM_THRESHOLD_DBM, DEFAULT_SWITCH_SSID_LOWER_THAN_DBM,
        EapConfig, NetworkConfig, SaePwe, WifiConfig,
    },
    error::{ErrorKind, WifiError},
    scan::{BssInfo, SecurityType},
    wired::{WiredClient, WiredState},
};
