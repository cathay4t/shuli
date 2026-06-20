// SPDX-License-Identifier: Apache-2.0

/// Minimal IEEE 802.11 element IDs and element builders.
pub mod element_id {
    pub const SSID: u8 = 0;
    pub const RSN: u8 = 48;
    pub const RSNXE: u8 = 244;
}

/// Canonical RSNE for WPA3-Personal (SAE / CCMP-128) with management frame
/// protection required. These exact bytes are used both in the Association
/// Request and in 4-way handshake Message 2; the AP verifies they match.
pub fn sae_rsne() -> Vec<u8> {
    vec![
        element_id::RSN,
        0x1a, // length = 26
        0x01,
        0x00, // version 1
        0x00,
        0x0f,
        0xac,
        0x04, // group cipher CCMP-128
        0x01,
        0x00, // pairwise count 1
        0x00,
        0x0f,
        0xac,
        0x04, // pairwise CCMP-128
        0x01,
        0x00, // AKM count 1
        0x00,
        0x0f,
        0xac,
        0x08, // AKM SAE
        0xc0,
        0x00, // RSN capabilities: MFPC | MFPR
        0x00,
        0x00, // PMKID count 0
        0x00,
        0x0f,
        0xac,
        0x06, // group mgmt cipher BIP-CMAC-128
    ]
}

/// RSNXE advertising SAE Hash-to-Element support (bit 5).
pub fn rsnxe_h2e() -> Vec<u8> {
    vec![element_id::RSNXE, 0x01, 0x20]
}
