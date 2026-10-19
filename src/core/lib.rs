// SPDX-License-Identifier: Apache-2.0

//! Shared 802.1X/EAP core: error types, EAP framing and peer state
//! machine, EAP-TLS, and the common EAPOL-EAP frame codec used by both
//! the WiFi and wired crates.

mod config;
pub mod eap;
pub mod eap_tls;
pub mod eapol;
mod error;

#[cfg(test)]
mod tests;

pub use self::{
    config::EapConfig,
    eap_tls::EapTlsMethod,
    error::{ErrorKind, WifiError},
};

/// Alias for callers that prefer a transport-neutral error name.
pub type Error = WifiError;
