// SPDX-License-Identifier: Apache-2.0

mod auth;
mod client;
mod config;
mod crypto;
#[allow(dead_code)] // EAP transport API: wired into WiFi 802.1X in M4
mod eap;
#[allow(dead_code)] // EAP-TLS method: wired into 802.1X in M4
mod eap_tls;
mod error;
mod ieee80211;
mod mac;
pub mod nl80211;
mod pmksa;
mod roam;
pub mod scan;
#[cfg(test)]
mod tests;

pub(crate) use self::mac::ETH_ALEN;
pub use self::{
    client::{WifiClient, WifiState},
    config::{
        DEFAULT_ROAM_THRESHOLD_DBM, EapConfig, NetworkConfig, SaePwe,
        WifiConfig,
    },
    error::{ErrorKind, WifiError},
    scan::{BssInfo, SecurityType},
};
