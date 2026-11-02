// SPDX-License-Identifier: Apache-2.0

//! RFC 7296 pre-shared-key authentication.

use subtle::ConstantTimeEq;

use crate::{config::PrfAlgorithm, error::IpsecError, ikev2::crypto};

pub(crate) fn compute(psk: &[u8], prf: PrfAlgorithm, signed: &[u8]) -> Vec<u8> {
    let key = crypto::prf(prf, psk, b"Key Pad for IKEv2");
    crypto::prf(prf, &key, signed)
}

pub(crate) fn verify(
    psk: &[u8],
    prf: PrfAlgorithm,
    signed: &[u8],
    auth: &[u8],
) -> Result<(), IpsecError> {
    let expected = compute(psk, prf, signed);
    if expected.len() == auth.len() && bool::from(expected.ct_eq(auth)) {
        Ok(())
    } else {
        Err(IpsecError::authentication(
            "pre-shared key authentication failed",
        ))
    }
}
