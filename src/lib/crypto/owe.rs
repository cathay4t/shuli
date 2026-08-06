// SPDX-License-Identifier: Apache-2.0

//! OWE (Opportunistic Wireless Encryption) — RFC 8110.
//!
//! Implements the Diffie-Hellman exchange carried in the 802.11
//! Association Request/Response and the PMK/PMKID derivation from
//! the shared secret.  Only ECC group 19 (NIST P-256) is supported
//! (mandatory per RFC 8110 §4.3).

use aws_lc_rs::digest;
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};

use crate::{ErrorKind, WifiError, crypto::kdf};

const GROUP_19: u16 = 19;
const P256_COORD_LEN: usize = 32;
/// Compact public key: x-coordinate only (RFC 8110 §4.3 / RFC 6090
/// §4.3.1), 32 bytes for P-256.
const P256_PUBKEY_LEN: usize = P256_COORD_LEN;
const PMK_LEN: usize = 32;

/// OWE Diffie-Hellman state for a single association attempt.
pub(crate) struct OweAuth {
    secret: SecretKey,
    /// Our public key as raw x||y (64 bytes for P-256).
    our_pubkey_raw: Vec<u8>,
    /// PMK derived after processing the AP's DH element.
    pmk: Option<[u8; PMK_LEN]>,
    pmkid: Option<[u8; 16]>,
}

impl OweAuth {
    pub fn new() -> Self {
        let secret = SecretKey::generate();
        let pubkey = secret.public_key();
        let encoded = pubkey.to_sec1_point(false);
        // Compact representation: x-coordinate only (skip 0x04 tag
        // and y-coordinate).  RFC 8110 §4.3, RFC 6090 §4.3.1.
        let our_pubkey_raw = encoded.as_bytes()[1..1 + P256_COORD_LEN].to_vec();
        Self {
            secret,
            our_pubkey_raw,
            pmk: None,
            pmkid: None,
        }
    }

    /// Build the OWE Diffie-Hellman Parameter Element
    /// (RFC 8110 §4.3, Figure 1):
    ///   Element ID (255) | Length | Ext (32) | Group (LE) | PubKey
    pub fn build_dh_element(&self) -> Vec<u8> {
        let body_len = 1 + 2 + self.our_pubkey_raw.len();
        let mut elem = Vec::with_capacity(2 + body_len);
        elem.push(255); // Element ID (Extension)
        elem.push(body_len as u8);
        elem.push(32); // Element ID Extension: OWE DH Param
        elem.extend_from_slice(&GROUP_19.to_le_bytes());
        elem.extend_from_slice(&self.our_pubkey_raw);
        elem
    }

    /// Process the AP's OWE DH Parameter Element from the
    /// Association Response.  Derives PMK and PMKID per
    /// RFC 8110 §4.4.
    ///
    /// `dh_data` starts at the Group field (after Element ID,
    /// Length, and Extension octets have been stripped).
    pub fn process_ap_dh_element(
        &mut self,
        dh_data: &[u8],
    ) -> Result<(), WifiError> {
        if dh_data.len() < 2 + P256_PUBKEY_LEN {
            return Err(WifiError::new(
                ErrorKind::AuthFailed,
                format!("OWE DH element too short: {} bytes", dh_data.len()),
            ));
        }
        let group = u16::from_le_bytes([dh_data[0], dh_data[1]]);
        if group != GROUP_19 {
            return Err(WifiError::new(
                ErrorKind::AuthFailed,
                format!("unsupported OWE group {group}"),
            ));
        }
        let ap_pubkey_raw = &dh_data[2..2 + P256_PUBKEY_LEN];

        // Reconstruct the SEC1 point from the compact x-coordinate.
        // Use compressed form (0x02 || x); either y parity yields the
        // same ECDH shared-secret x-coordinate.
        let mut sec1 = vec![0x02u8];
        sec1.extend_from_slice(ap_pubkey_raw);
        let ap_pubkey = PublicKey::from_sec1_bytes(&sec1).map_err(|e| {
            WifiError::new(
                ErrorKind::AuthFailed,
                format!("invalid OWE AP public key: {e}"),
            )
        })?;

        // z = F(DH(x, Y)) — x-coordinate of the shared secret.
        let shared = diffie_hellman(
            self.secret.to_nonzero_scalar(),
            ap_pubkey.as_affine(),
        );
        let z = shared.raw_secret_bytes();

        // prk = HKDF-Extract(salt = C | A | group, IKM = z)
        // PMK = HKDF-Expand(prk, "OWE Key Generation", n)
        let mut salt = Vec::with_capacity(
            self.our_pubkey_raw.len() + ap_pubkey_raw.len() + 2,
        );
        salt.extend_from_slice(&self.our_pubkey_raw); // C
        salt.extend_from_slice(ap_pubkey_raw); // A
        salt.extend_from_slice(&GROUP_19.to_le_bytes());

        let prk = kdf::hkdf_extract_sha256(&salt, z.as_ref());
        let mut pmk = [0u8; PMK_LEN];
        kdf::hkdf_expand(&prk, b"OWE Key Generation", &mut pmk);
        self.pmk = Some(pmk);

        // PMKID = Truncate-128(Hash(C | A))
        let mut hash_data =
            Vec::with_capacity(self.our_pubkey_raw.len() + ap_pubkey_raw.len());
        hash_data.extend_from_slice(&self.our_pubkey_raw);
        hash_data.extend_from_slice(ap_pubkey_raw);
        let hash = digest::digest(&digest::SHA256, &hash_data);
        let mut pmkid = [0u8; 16];
        pmkid.copy_from_slice(&hash.as_ref()[..16]);
        self.pmkid = Some(pmkid);

        Ok(())
    }

    pub fn pmk(&self) -> Option<[u8; PMK_LEN]> {
        self.pmk
    }

    /// PMKID of the completed OWE exchange; consumed by the PMKSA cache
    /// (Stage 2 G4).
    #[allow(dead_code)]
    pub fn pmkid(&self) -> Option<[u8; 16]> {
        self.pmkid
    }
}

/// Find the OWE DH Parameter Element in an IE buffer and return
/// the data after Element ID + Length + Extension (i.e. starting
/// at the Group field).
pub(crate) fn find_owe_dh_element(ies: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;
    while pos + 2 <= ies.len() {
        let id = ies[pos];
        let len = ies[pos + 1] as usize;
        let body_start = pos + 2;
        let body_end = body_start + len;
        if body_end > ies.len() {
            break;
        }
        // Element ID 255 (Extension) with Extension ID 32 (OWE DH).
        if id == 255 && len >= 1 && ies[body_start] == 32 {
            // Return everything after the extension octet.
            return Some(&ies[body_start + 1..body_end]);
        }
        pos = body_end;
    }
    None
}
