// SPDX-License-Identifier: Apache-2.0

//! Wired authentication: 802.1X/EAP today, MACsec/MKA in the future.

mod eap;

#[cfg(test)]
mod tests;

pub use shuli_core::EapConfig;

pub use self::eap::{WiredClient, WiredState};
