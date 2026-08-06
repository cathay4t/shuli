// SPDX-License-Identifier: Apache-2.0

mod auth;
mod client;
mod config;
mod crypto;
mod error;
mod ieee80211;
mod mac;
pub mod nl80211;
pub mod scan;
#[cfg(test)]
mod tests;

pub(crate) use self::mac::ETH_ALEN;
pub use self::{
    client::{WifiClient, WifiState},
    config::{NetworkConfig, WifiConfig},
    error::{ErrorKind, WifiError},
    scan::{BssInfo, SecurityType},
};
