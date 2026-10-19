// SPDX-License-Identifier: Apache-2.0

//! Authentication payload helpers.

pub(crate) mod cert;
pub(crate) mod eap;
pub(crate) mod psk;

use crate::{config::PrfAlgorithm, ikev2::crypto};

pub const AUTH_RSA: u8 = 1;
pub const AUTH_PSK: u8 = 2;
pub const AUTH_ECDSA_P256_SHA256: u8 = 9;
pub const AUTH_ECDSA_P384_SHA384: u8 = 10;

/// Build the signed-octets input for an AUTH payload.
pub(crate) fn signed_octets(
    real_message1: &[u8],
    nonce_r: &[u8],
    prf: PrfAlgorithm,
    sk_p: &[u8],
    id: &[u8],
) -> Vec<u8> {
    let id_hash = crypto::prf(prf, sk_p, id);
    let mut signed =
        Vec::with_capacity(real_message1.len() + nonce_r.len() + id_hash.len());
    signed.extend_from_slice(real_message1);
    signed.extend_from_slice(nonce_r);
    signed.extend_from_slice(&id_hash);
    signed
}
