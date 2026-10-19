// SPDX-License-Identifier: Apache-2.0

//! Wired authentication: 802.1X/EAP and MACsec/MKA.

mod client;
mod eap;
mod macsec;
mod mka;

#[cfg(test)]
mod tests;

pub use shuli_core::EapConfig;

pub use self::{
    client::{WiredAuth, WiredClient, WiredState},
    mka::{DEFAULT_MACSEC_IFACE, MacsecConfig},
};
