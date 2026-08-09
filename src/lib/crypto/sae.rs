// SPDX-License-Identifier: Apache-2.0

// Simultaneous Authentication of Equals (SAE) / Dragonfly handshake.
// Implements H2E (Hash-to-Element) for group 19 (P-256) with a
// hunting-and-pecking (HnP) fallback for HnP-only APs.
//
// Reference: IEEE 802.11-2020 §12.4, RFC 7664, RFC 9380 (SSWU), and the
// wpa_supplicant / iwd reference implementations (src/common/sae.c).

use core::ops::Neg;

use p256::{
    self, AffinePoint, NistP256, ProjectivePoint, Scalar,
    elliptic_curve::{
        Curve, Field, Group, PrimeField,
        array::Array,
        bigint::NonZero,
        hazmat::FieldArithmetic,
        ops::Reduce,
        point::AffineCoordinates,
        rand_core::TryRng,
        sec1::{FromSec1Point, ToSec1Point},
    },
    hash2curve::MapToCurve,
};

use crate::{
    ErrorKind, WifiError,
    crypto::kdf::{hkdf_expand, hkdf_extract_sha256, kdf, sae_confirm},
};

const SAE_GROUP19_ID: u16 = 19;
const SAE_FIELD_LEN: usize = 32;
const SAE_KCK_LEN: usize = 32;
const SAE_PMK_LEN: usize = 32;
/// IEEE 802.11 status code for an H2E SAE commit (802.11-2020 §12.4.4.4).
const SAE_STATUS_H2E: u16 = 126;
/// IEEE 802.11 status code 76: anti-clogging token required.
pub(crate) const SAE_STATUS_ANTI_CLOGGING: u16 = 76;
/// Element ID extension of the Anti-Clogging Token Container element
/// (inside the `WLAN_EID_EXTENSION` = 255 element, 802.11-2020 §9.4.2.47.4).
const EXT_ANTI_CLOGGING_TOKEN: u8 = 93;
/// Number of hunting-and-pecking iterations before giving up (both
/// reference implementations cap at 200; the PWE is found within a few).
const HNP_MAX_ITER: u16 = 200;

/// Base-field element of P-256 (values mod the curve prime `p`).
type FieldElement = <NistP256 as FieldArithmetic>::FieldElement;

/// SAE handshake
/// Hash-to-Element group 19(NIST P-256 elliptic curve)
#[derive(Clone, Debug)]
pub(crate) struct SaeAuth {
    pub(crate) pwe: ProjectivePoint,
    rand: Scalar,
    scalar: Scalar,
    elem: ProjectivePoint,
    peer_scalar: Option<Scalar>,
    peer_elem: Option<ProjectivePoint>,
    kck: Option<[u8; SAE_KCK_LEN]>,
    pmk: Option<[u8; SAE_PMK_LEN]>,
    pmkid: Option<[u8; 16]>,
    confirmed: bool,
    /// PWE was derived with hash-to-element (true) or hunting-and-pecking
    /// (false); decides the commit's status code and the anti-clogging
    /// token framing.
    h2e: bool,
    /// When an H2E commit is rejected (e.g. by an HnP-only AP), fall back
    /// to hunting-and-pecking instead of failing the authentication.
    hnp_fallback: bool,
    own_scalar_bytes: [u8; 32],
    own_elem_bytes: [u8; 64], // x || y uncompressed
}

impl SaeAuth {
    pub(crate) fn new(
        password: &str,
        ssid: &str,
        mac_sta: [u8; 6],
        mac_ap: [u8; 6],
        h2e: bool,
        hnp_fallback: bool,
    ) -> Result<Self, WifiError> {
        let pwe = if h2e {
            compute_pwe_h2e(password, ssid, &mac_sta, &mac_ap)?
        } else {
            compute_pwe_hnp(password, ssid, &mac_sta, &mac_ap)?
        };
        Ok(Self {
            pwe,
            rand: Scalar::ZERO,
            scalar: Scalar::ZERO,
            elem: ProjectivePoint::IDENTITY,
            peer_scalar: None,
            peer_elem: None,
            kck: None,
            pmk: None,
            pmkid: None,
            confirmed: false,
            h2e,
            hnp_fallback,
            own_scalar_bytes: [0u8; 32],
            own_elem_bytes: [0u8; 64],
        })
    }

    /// SAE group identifier (19 = P-256).
    pub(crate) fn group_id(&self) -> u16 {
        SAE_GROUP19_ID
    }

    /// Whether the PWE was derived with hash-to-element.
    pub(crate) fn is_h2e(&self) -> bool {
        self.h2e
    }

    /// Whether a rejected H2E commit may fall back to hunting-and-pecking.
    pub(crate) fn hnp_fallback_allowed(&self) -> bool {
        self.hnp_fallback
    }

    /// Generate our commit (scalar + element) using the given RNG.
    pub(crate) fn build_commit(
        &mut self,
        rng: &mut impl TryRng,
    ) -> Result<(Vec<u8>, Vec<u8>), WifiError> {
        let mut rand = Scalar::try_random(&mut *rng).map_err(|e| {
            WifiError::new(ErrorKind::SaeFailed, format!("rng failure: {e}"))
        })?;
        while bool::from(rand.is_zero()) {
            rand = Scalar::try_random(&mut *rng).map_err(|e| {
                WifiError::new(
                    ErrorKind::SaeFailed,
                    format!("rng failure: {e}"),
                )
            })?;
        }
        let mut mask = Scalar::try_random(&mut *rng).map_err(|e| {
            WifiError::new(ErrorKind::SaeFailed, format!("rng failure: {e}"))
        })?;
        while bool::from(mask.is_zero()) {
            mask = Scalar::try_random(&mut *rng).map_err(|e| {
                WifiError::new(
                    ErrorKind::SaeFailed,
                    format!("rng failure: {e}"),
                )
            })?;
        }

        // scalar = (rand + mask) mod r
        let scalar = rand + mask;

        // COMMIT-ELEMENT = inverse(scalar-op(mask, PWE)) = -(mask * PWE)
        let elem = (self.pwe * mask).neg();
        let scalar_bytes: [u8; 32] = scalar.to_bytes().into();
        let mut elem_bytes = [0u8; 64];
        point_to_x_y(&elem, &mut elem_bytes);

        self.rand = rand;
        self.scalar = scalar;
        self.elem = elem;
        self.own_scalar_bytes = scalar_bytes;
        self.own_elem_bytes = elem_bytes;

        Ok((scalar_bytes.to_vec(), elem_bytes.to_vec()))
    }

    /// Process peer's commit (scalar + element). Derives KCK/PMK/PMKID and
    /// returns our confirm value (32-byte CN output).
    pub(crate) fn process_commit(
        &mut self,
        peer_scalar_bytes: &[u8],
        peer_elem_bytes: &[u8],
    ) -> Result<Vec<u8>, WifiError> {
        let peer_scalar = scalar_from_bytes(peer_scalar_bytes)?;
        let peer_elem = projective_from_elem(peer_elem_bytes);

        if bool::from(peer_elem.is_identity()) {
            return Err(WifiError::new(
                ErrorKind::SaeFailed,
                "failed to reconstruct peer element",
            ));
        }

        // K = rand * (peer_scalar * PWE + peer_elem); k = K.x
        let k_point = (self.pwe * peer_scalar + peer_elem) * self.rand;
        if bool::from(k_point.is_identity()) {
            return Err(WifiError::new(
                ErrorKind::SaeFailed,
                "shared secret is identity",
            ));
        }
        let k_affine = k_point.to_affine();

        // keyseed = HKDF-Extract(0^32, k)
        let keyseed = hkdf_extract_sha256(&[0u8; 32], k_affine.x().as_ref());

        // val = (own_scalar + peer_scalar) mod r, encoded big-endian (32 B)
        let scalar_sum = self.scalar + peer_scalar;
        let val_bytes: [u8; 32] = scalar_sum.to_bytes().into();

        // KCK || PMK = KDF-Hash-256(keyseed, "SAE KCK and PMK", val)
        let keys = kdf(
            &keyseed,
            "SAE KCK and PMK",
            &val_bytes,
            SAE_KCK_LEN + SAE_PMK_LEN,
        );

        let mut kck = [0u8; SAE_KCK_LEN];
        kck.copy_from_slice(&keys[..SAE_KCK_LEN]);
        let mut pmk = [0u8; SAE_PMK_LEN];
        pmk.copy_from_slice(&keys[SAE_KCK_LEN..]);

        // PMKID = L(val, 0, 128) = first 16 bytes of val
        let mut pmkid = [0u8; 16];
        pmkid.copy_from_slice(&val_bytes[..16]);

        self.peer_scalar = Some(peer_scalar);
        self.peer_elem = Some(peer_elem);
        self.kck = Some(kck);
        self.pmk = Some(pmk);
        self.pmkid = Some(pmkid);

        // Confirm = CN(KCK, send_confirm=1, own_scalar, own_elem,
        //              peer_scalar, peer_elem)
        let confirm = sae_confirm(
            &kck,
            1,
            &self.own_scalar_bytes,
            &self.own_elem_bytes,
            peer_scalar_bytes,
            peer_elem_bytes,
        );
        Ok(confirm)
    }

    /// Process peer's confirm message body: `send_confirm(2 LE) || CN(32)`.
    pub(crate) fn process_confirm(
        &mut self,
        peer_confirm_body: &[u8],
    ) -> Result<[u8; 32], WifiError> {
        let kck = self.kck.ok_or_else(|| {
            WifiError::new(
                ErrorKind::SaeFailed,
                "no KCK derived - process commit first",
            )
        })?;
        let peer_scalar = self.peer_scalar.ok_or_else(|| {
            WifiError::new(ErrorKind::SaeFailed, "no peer commit processed")
        })?;
        let peer_elem = self.peer_elem.ok_or_else(|| {
            WifiError::new(ErrorKind::SaeFailed, "no peer commit processed")
        })?;

        if peer_confirm_body.len() < 2 + 32 {
            return Err(WifiError::new(
                ErrorKind::SaeFailed,
                "confirm too short",
            ));
        }
        let peer_send_confirm =
            u16::from_le_bytes([peer_confirm_body[0], peer_confirm_body[1]]);
        let peer_hash = &peer_confirm_body[2..34];

        let peer_scalar_bytes = scalar_to_array(&peer_scalar);
        let mut peer_elem_bytes = [0u8; 64];
        point_to_x_y(&peer_elem, &mut peer_elem_bytes);

        // verifier = CN(KCK, peer_send_confirm, peer_scalar, peer_elem,
        //               own_scalar, own_elem)
        let expected = sae_confirm(
            &kck,
            peer_send_confirm,
            &peer_scalar_bytes,
            &peer_elem_bytes,
            &self.own_scalar_bytes,
            &self.own_elem_bytes,
        );

        if aws_lc_rs::constant_time::verify_slices_are_equal(
            &expected, peer_hash,
        )
        .is_err()
        {
            return Err(WifiError::new(
                ErrorKind::SaeFailed,
                "confirm mismatch",
            ));
        }

        let pmk = self.pmk.ok_or_else(|| {
            WifiError::new(ErrorKind::SaeFailed, "no PMK derived")
        })?;
        self.confirmed = true;
        Ok(pmk)
    }

    pub(crate) fn pmk(&self) -> Option<[u8; 32]> {
        self.pmk
    }

    pub(crate) fn pmkid(&self) -> Option<[u8; 16]> {
        self.pmkid
    }

    /// Whether the peer's confirm has been validated (SAE completed).
    pub(crate) fn confirmed(&self) -> bool {
        self.confirmed
    }

    /// Build the initial SAE commit auth_data for `NL80211_ATTR_AUTH_DATA`.
    /// The kernel reads the first 4 bytes as transaction(2 LE) and
    /// status(2 LE); the remaining bytes become the authentication frame
    /// body. The status is `SAE_HASH_TO_ELEMENT` (126) for H2E and 0
    /// (success) for hunting-and-pecking, and the body is:
    ///   group(2 LE) || scalar(32) || element(64)
    pub(crate) fn build_init_auth_msg(&mut self) -> Vec<u8> {
        let (scalar, element) = self
            .build_commit(&mut getrandom::SysRng)
            .expect("OS random number generator failure");
        build_commit_auth_data(
            self.h2e,
            self.group_id(),
            &scalar,
            &element,
            None,
        )
    }

    /// Re-run the commit and return the auth_data for a retry that must
    /// echo the AP's anti-clogging token (status 76 response). Only valid
    /// before any peer commit was processed: a fresh scalar/element pair
    /// is generated and the token is appended after the element - inside
    /// the Anti-Clogging Token Container element for H2E (802.11-2020
    /// §9.4.2.47.4), raw for hunting-and-pecking.
    pub(crate) fn build_commit_with_token(
        &mut self,
        token: &[u8],
    ) -> Result<Vec<u8>, WifiError> {
        if self.peer_scalar.is_some() || self.confirmed {
            return Err(WifiError::new(
                ErrorKind::SaeFailed,
                "cannot retry commit with token after processing the peer",
            ));
        }
        let (scalar, element) = self.build_commit(&mut getrandom::SysRng)?;
        Ok(build_commit_auth_data(
            self.h2e,
            self.group_id(),
            &scalar,
            &element,
            Some(token),
        ))
    }
}

/// Serialize a SAE commit as auth_data: transaction(2 LE) || status(2 LE)
/// || group(2 LE) || scalar || element [|| anti-clogging token].
fn build_commit_auth_data(
    h2e: bool,
    group: u16,
    scalar: &[u8],
    element: &[u8],
    token: Option<&[u8]>,
) -> Vec<u8> {
    let token_len = token.map_or(0, |t| t.len());
    let mut auth_data =
        Vec::with_capacity(6 + scalar.len() + element.len() + token_len + 3);
    auth_data.extend_from_slice(&1u16.to_le_bytes()); // transaction = commit
    // status: SAE_HASH_TO_ELEMENT for H2E, 0 for hunting-and-pecking
    auth_data.extend_from_slice(
        &(if h2e { SAE_STATUS_H2E } else { 0 }).to_le_bytes(),
    );
    auth_data.extend_from_slice(&group.to_le_bytes());
    auth_data.extend_from_slice(scalar);
    auth_data.extend_from_slice(element);
    if let Some(token) = token {
        if h2e {
            // Anti-Clogging Token Container: extended element
            // (ID 255, extension 93 = EXT_ANTI_CLOGGING_TOKEN).
            auth_data.push(255);
            auth_data.push(1 + token.len() as u8);
            auth_data.push(EXT_ANTI_CLOGGING_TOKEN);
        }
        auth_data.extend_from_slice(token);
    }
    auth_data
}

/// Parse the anti-clogging token from a status-76 commit response.
/// Payload layout: group(2 LE) || token, where the token is wrapped in
/// the Anti-Clogging Token Container element for H2E and raw for HnP
/// (802.11-2020 §12.4.4.2.1, matching wpa_supplicant `sae_parse_commit` /
/// `sme_sae_auth`).
pub(crate) fn parse_anti_clogging_token(
    h2e: bool,
    payload: &[u8],
) -> Result<Vec<u8>, WifiError> {
    if payload.len() < 2 {
        return Err(WifiError::new(
            ErrorKind::SaeFailed,
            "anti-clogging response too short",
        ));
    }
    let rest = &payload[2..];
    if h2e {
        // FF || elen || EXT_ANTI_CLOGGING_TOKEN || token...
        if rest.len() < 3
            || rest[0] != 255
            || rest[2] != EXT_ANTI_CLOGGING_TOKEN
        {
            return Err(WifiError::new(
                ErrorKind::SaeFailed,
                "malformed anti-clogging token container",
            ));
        }
        let elen = rest[1] as usize;
        if elen == 0 || elen > rest.len() - 2 {
            return Err(WifiError::new(
                ErrorKind::SaeFailed,
                "bad anti-clogging token container length",
            ));
        }
        Ok(rest[3..3 + elen - 1].to_vec())
    } else {
        Ok(rest.to_vec())
    }
}

// ---- PWE derivation: H2E for group 19 (RFC 9380 SSWU, hostapd-compatible) --

pub(crate) fn compute_pwe_h2e(
    password: &str,
    ssid: &str,
    mac_sta: &[u8; 6],
    mac_ap: &[u8; 6],
) -> Result<ProjectivePoint, WifiError> {
    let pt = derive_pt_ecc(ssid.as_bytes(), password.as_bytes())?;
    derive_pwe_from_pt(&pt, mac_sta, mac_ap)
}

// ---- PWE derivation: hunting-and-pecking for group 19 (RFC 7664) ----

/// P-256 field prime `p` (big-endian), the KDF context of the
/// hunting-and-pecking pwd-value derivation (RFC 7664 §3.2.1).
const P256_PRIME: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// P-256 curve constant `b` (big-endian).
const P256_B: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55,
    0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
    0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];

/// Hunting-and-pecking PWE derivation for group 19 (RFC 7664 §3.2.1,
/// 802.11-2020 §12.4.5.1). Ported from wpa_supplicant's
/// `sae_derive_pwe_ecc` (without its constant-time blinding: the first
/// valid candidate is functionally identical, since the reference keeps
/// the first found x/pwd-seed parity through its const-time selection).
///
/// For each counter (starting at 1):
///   pwd-seed = HMAC-SHA256(MAX(mac)||MIN(mac), password || counter)
///   pwd-value = KDF(pwd-seed, "SAE Hunting and Pecking", p, 256)
///   x = pwd-value, if x < p and y_sqr = x^3 - 3x + b is a quadratic
///       residue: PWE = (x, y) with y = sqrt(y_sqr) chosen by the LSB of
///       the pwd-seed (802.11-2020 §12.4.5.1.3).
pub(crate) fn compute_pwe_hnp(
    password: &str,
    _ssid: &str,
    mac_sta: &[u8; 6],
    mac_ap: &[u8; 6],
) -> Result<ProjectivePoint, WifiError> {
    let (max_mac, min_mac) = if u64_from_mac(mac_sta) > u64_from_mac(mac_ap) {
        (mac_sta, mac_ap)
    } else {
        (mac_ap, mac_sta)
    };
    let mut addrs = [0u8; 12];
    addrs[..6].copy_from_slice(max_mac);
    addrs[6..].copy_from_slice(min_mac);

    // p is the KDF context of the pwd-value derivation, and the P-256
    // curve constant b is the y^2 = x^3 - 3x + b offset.
    let b = FieldElement::from_repr(
        Array::try_from(&P256_B[..]).expect("32-byte curve constant"),
    )
    .expect("curve constant b < p");

    let password_bytes = password.as_bytes();
    for counter in 1..=HNP_MAX_ITER {
        let mut ikm = Vec::with_capacity(password_bytes.len() + 1);
        ikm.extend_from_slice(password_bytes);
        ikm.push(counter as u8);

        // pwd-seed = HMAC-SHA256(addrs, password || counter)
        let pwd_seed = hkdf_extract_sha256(&addrs, &ikm);

        // pwd-value = KDF-256(pwd-seed, "SAE Hunting and Pecking", p);
        // x = pwd-value when pwd-value < p, otherwise this iteration
        // fails (the in-range check is the from_repr reduction).
        let pwd_value = kdf(
            &pwd_seed,
            "SAE Hunting and Pecking",
            &P256_PRIME,
            SAE_FIELD_LEN,
        );
        let x_cand = FieldElement::from_repr(
            Array::try_from(&pwd_value[..]).expect("32-byte pwd-value"),
        );
        let Some(x) = Option::<FieldElement>::from(x_cand) else {
            continue; // pwd-value >= p
        };

        // y^2 = x^3 - 3x + b mod p; a quadratic residue means the
        // candidate x is on the curve.
        let y_sqr = x.cube() - (x * FieldElement::from_u64(3)) + b;
        let Some(y0) = Option::<FieldElement>::from(y_sqr.sqrt()) else {
            continue; // not a quadratic residue
        };

        // The spec requires the point be solved unambiguously: pick the
        // y whose LSB matches the LSB of the pwd-seed
        // (802.11-2020 §12.4.5.1.3); `-y0` is `p - y0` mod p.
        let y = if y0.to_bytes()[31] & 1 == pwd_seed[31] & 1 {
            y0
        } else {
            -y0
        };

        let x_bytes = x.to_bytes();
        let y_bytes = y.to_bytes();
        let mut elem = [0u8; 64];
        elem[..32].copy_from_slice(&x_bytes);
        elem[32..].copy_from_slice(&y_bytes);
        let pwe = projective_from_elem(&elem);
        if bool::from(pwe.is_identity()) {
            return Err(WifiError::new(
                ErrorKind::SaeFailed,
                "PWE derivation produced the identity",
            ));
        }
        log::debug!("SAE HnP: PWE found at counter {counter}");
        return Ok(pwe);
    }
    Err(WifiError::new(
        ErrorKind::SaeFailed,
        format!("could not derive PWE within {HNP_MAX_ITER} iterations"),
    ))
}

/// Derive the password token PT (group 19), per sae_derive_pt_ecc.
fn derive_pt_ecc(
    ssid: &[u8],
    password: &[u8],
) -> Result<ProjectivePoint, WifiError> {
    // pwd-seed = HKDF-Extract(ssid, password)
    let pwd_seed = hkdf_extract_sha256(ssid, password);

    let p1 = sswu_from_label(&pwd_seed, b"SAE Hash to Element u1 P1")?;
    let p2 = sswu_from_label(&pwd_seed, b"SAE Hash to Element u2 P2")?;

    let pt = p1 + p2;
    if bool::from(pt.is_identity()) {
        return Err(WifiError::new(ErrorKind::SaeFailed, "PT is identity"));
    }
    Ok(pt)
}

fn sswu_from_label(
    pwd_seed: &[u8; 32],
    label: &[u8],
) -> Result<ProjectivePoint, WifiError> {
    // pwd-value = HKDF-Expand(pwd-seed, label, len); len = prime+ceil(prime/2)
    let mut okm = [0u8; SAE_FIELD_LEN + SAE_FIELD_LEN.div_ceil(2)]; // 48
    hkdf_expand(pwd_seed, label, &mut okm);

    // u = OS2IP(pwd-value) mod p ; P = SSWU(u)
    let u = <NistP256 as MapToCurve>::FieldElement::reduce(
        &Array::try_from(&okm[..]).expect("SSWU okm is 48 bytes"),
    );
    Ok(<NistP256 as MapToCurve>::map_to_curve(u))
}

/// PWE = val * PT, where val = H(0^n, MAX(mac)||MIN(mac)) mod (q-1) + 1.
fn derive_pwe_from_pt(
    pt: &ProjectivePoint,
    mac_sta: &[u8; 6],
    mac_ap: &[u8; 6],
) -> Result<ProjectivePoint, WifiError> {
    let (max_mac, min_mac) = if u64_from_mac(mac_sta) > u64_from_mac(mac_ap) {
        (mac_sta, mac_ap)
    } else {
        (mac_ap, mac_sta)
    };
    let mut ikm = [0u8; 12];
    ikm[..6].copy_from_slice(max_mac);
    ikm[6..].copy_from_slice(min_mac);

    // val = HKDF-Extract(0^32, MAX||MIN)
    let val_hash = hkdf_extract_sha256(&[0u8; 32], &ikm);

    // val = (OS2IP(val) mod (q - 1)) + 1
    let order = NistP256::ORDER.as_ref();
    let order_m1 = order.wrapping_sub(&p256::U256::ONE);
    let nz = NonZero::new(order_m1).unwrap();
    let val_int = p256::U256::from_be_slice(&val_hash) % nz;
    let val_int = val_int.wrapping_add(&p256::U256::ONE);
    let val_bytes = val_int.to_be_bytes();
    let val_scalar = Scalar::from_repr(val_bytes.into());
    if bool::from(val_scalar.is_none()) {
        return Err(WifiError::new(ErrorKind::SaeFailed, "val out of range"));
    }
    let val_scalar = val_scalar.unwrap();

    let pwe = *pt * val_scalar;
    if bool::from(pwe.is_identity()) {
        return Err(WifiError::new(ErrorKind::SaeFailed, "PWE is identity"));
    }
    Ok(pwe)
}

// ---- Helpers ----

fn scalar_to_array(s: &Scalar) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(s.to_bytes().as_ref());
    arr
}

/// Decode a peer scalar, rejecting values outside [1, r-1]
/// (802.11-2020 §12.4.5.3).
fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar, WifiError> {
    if bytes.len() < 32 {
        return Err(WifiError::new(
            ErrorKind::SaeFailed,
            format!("peer scalar too short: {} bytes", bytes.len()),
        ));
    }
    let opt = Scalar::from_repr(
        Array::try_from(&bytes[..32]).expect("32-byte scalar"),
    );
    if bool::from(opt.is_none()) {
        return Err(WifiError::new(
            ErrorKind::SaeFailed,
            "peer scalar out of range",
        ));
    }
    let scalar = opt.unwrap();
    if bool::from(scalar.is_zero()) {
        return Err(WifiError::new(
            ErrorKind::SaeFailed,
            "peer scalar is zero",
        ));
    }
    Ok(scalar)
}

/// Reconstruct a curve point from a 64-byte x||y encoding.
fn projective_from_elem(elem_bytes: &[u8]) -> ProjectivePoint {
    if elem_bytes.len() < 64 {
        return ProjectivePoint::IDENTITY;
    }
    let ep = p256::Sec1Point::from_affine_coordinates(
        &Array::try_from(&elem_bytes[..32]).expect("32-byte x"),
        &Array::try_from(&elem_bytes[32..64]).expect("32-byte y"),
        false,
    );
    let affine = AffinePoint::from_sec1_point(&ep);
    if bool::from(affine.is_some()) {
        let affine = affine.unwrap();
        if bool::from(!affine.is_identity()) {
            return ProjectivePoint::from(&affine);
        }
    }
    ProjectivePoint::IDENTITY
}

/// Encode a point as 64-byte x||y (uncompressed without prefix).
fn point_to_x_y(point: &ProjectivePoint, out: &mut [u8; 64]) {
    let affine = point.to_affine();
    let encoded = affine.to_sec1_point(false);
    if let (Some(x), Some(y)) = (encoded.x(), encoded.y()) {
        out[..32].copy_from_slice(x.as_ref());
        out[32..64].copy_from_slice(y.as_ref());
    }
}

fn u64_from_mac(mac: &[u8; 6]) -> u64 {
    let mut buf = [0u8; 8];
    buf[2..8].copy_from_slice(mac);
    u64::from_be_bytes(buf)
}
