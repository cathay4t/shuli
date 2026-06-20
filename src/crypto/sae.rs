// SPDX-License-Identifier: Apache-2.0

// Simultaneous Authentication of Equals (SAE) / Dragonfly handshake.
// Implements H2E (Hash-to-Element) for group 19 (P-256).
//
// Reference: IEEE 802.11-2020 §12.4, RFC 7664, RFC 9380 (SSWU), and the
// wpa_supplicant reference implementation (src/common/sae.c).

use core::ops::Neg;

use p256::{
    self, AffinePoint, EncodedPoint, FieldElement, NistP256, ProjectivePoint,
    Scalar,
    elliptic_curve::{
        Curve, Field, Group, PrimeField,
        bigint::{Encoding, NonZero},
        generic_array::GenericArray,
        hash2curve::{FromOkm, MapToCurve},
        point::AffineCoordinates,
        rand_core::CryptoRngCore,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};

use crate::{
    ShuliResult,
    crypto::kdf::{hkdf_expand, hkdf_extract_sha256, kdf, sae_confirm},
};

const SAE_GROUP19_ID: u16 = 19;
const SAE_FIELD_LEN: usize = 32;
const SAE_KCK_LEN: usize = 32;
const SAE_PMK_LEN: usize = 32;

/// SAE handshake state machine (supplicant side, H2E group 19).
#[derive(Clone, Debug)]
pub struct SaeState {
    pwe: ProjectivePoint,
    rand: Scalar,
    scalar: Scalar,
    elem: ProjectivePoint,
    peer_scalar: Option<Scalar>,
    peer_elem: Option<ProjectivePoint>,
    kck: Option<[u8; SAE_KCK_LEN]>,
    pmk: Option<[u8; SAE_PMK_LEN]>,
    pmkid: Option<[u8; 16]>,
    own_scalar_bytes: [u8; 32],
    own_elem_bytes: [u8; 64], // x || y uncompressed
}

impl SaeState {
    /// Create a new SAE state. The PWE is derived immediately via H2E.
    pub fn new(
        password: &str,
        ssid: &str,
        mac_sta: [u8; 6],
        mac_ap: [u8; 6],
    ) -> ShuliResult<Self> {
        let pwe = compute_pwe_h2e(password, ssid, &mac_sta, &mac_ap)?;
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
            own_scalar_bytes: [0u8; 32],
            own_elem_bytes: [0u8; 64],
        })
    }

    /// SAE group identifier (19 = P-256).
    pub fn group_id(&self) -> u16 {
        SAE_GROUP19_ID
    }

    /// Generate our commit (scalar + element) using the given RNG.
    pub fn build_commit(
        &mut self,
        rng: &mut impl CryptoRngCore,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut rand = Scalar::random(&mut *rng);
        while bool::from(rand.is_zero()) {
            rand = Scalar::random(&mut *rng);
        }
        let mut mask = Scalar::random(&mut *rng);
        while bool::from(mask.is_zero()) {
            mask = Scalar::random(&mut *rng);
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

        (scalar_bytes.to_vec(), elem_bytes.to_vec())
    }

    /// Process peer's commit (scalar + element). Derives KCK/PMK/PMKID and
    /// returns our confirm value (32-byte CN output).
    pub fn process_commit(
        &mut self,
        peer_scalar_bytes: &[u8],
        peer_elem_bytes: &[u8],
    ) -> ShuliResult<Vec<u8>> {
        let peer_scalar = scalar_from_bytes(peer_scalar_bytes);
        let peer_elem = projective_from_elem(peer_elem_bytes);

        if bool::from(peer_elem.is_identity()) {
            return Err(crate::ShuliError::SaeFailed(
                "failed to reconstruct peer element".into(),
            ));
        }

        // K = rand * (peer_scalar * PWE + peer_elem); k = K.x
        let k_point = (self.pwe * peer_scalar + peer_elem) * self.rand;
        if bool::from(k_point.is_identity()) {
            return Err(crate::ShuliError::SaeFailed(
                "shared secret is identity".into(),
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
    pub fn process_confirm(
        &self,
        peer_confirm_body: &[u8],
    ) -> ShuliResult<[u8; 32]> {
        let kck = self.kck.ok_or_else(|| {
            crate::ShuliError::SaeFailed(
                "no KCK derived - process commit first".into(),
            )
        })?;
        let peer_scalar = self.peer_scalar.ok_or_else(|| {
            crate::ShuliError::SaeFailed("no peer commit processed".into())
        })?;
        let peer_elem = self.peer_elem.ok_or_else(|| {
            crate::ShuliError::SaeFailed("no peer commit processed".into())
        })?;

        if peer_confirm_body.len() < 2 + 32 {
            return Err(crate::ShuliError::SaeFailed(
                "confirm too short".into(),
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

        if expected.as_slice() != peer_hash {
            return Err(crate::ShuliError::SaeFailed(
                "confirm mismatch".into(),
            ));
        }

        Ok(self.pmk.unwrap())
    }

    pub fn pmk(&self) -> Option<[u8; 32]> {
        self.pmk
    }

    pub fn pmkid(&self) -> Option<[u8; 16]> {
        self.pmkid
    }
}

// ---- PWE derivation: H2E for group 19 (RFC 9380 SSWU, hostapd-compatible) --

fn compute_pwe_h2e(
    password: &str,
    ssid: &str,
    mac_sta: &[u8; 6],
    mac_ap: &[u8; 6],
) -> ShuliResult<ProjectivePoint> {
    let pt = derive_pt_ecc(ssid.as_bytes(), password.as_bytes())?;
    derive_pwe_from_pt(&pt, mac_sta, mac_ap)
}

/// Derive the password token PT (group 19), per sae_derive_pt_ecc.
fn derive_pt_ecc(ssid: &[u8], password: &[u8]) -> ShuliResult<ProjectivePoint> {
    // pwd-seed = HKDF-Extract(ssid, password)
    let pwd_seed = hkdf_extract_sha256(ssid, password);

    let p1 = sswu_from_label(&pwd_seed, b"SAE Hash to Element u1 P1")?;
    let p2 = sswu_from_label(&pwd_seed, b"SAE Hash to Element u2 P2")?;

    let pt = p1 + p2;
    if bool::from(pt.is_identity()) {
        return Err(crate::ShuliError::SaeFailed("PT is identity".into()));
    }
    Ok(pt)
}

fn sswu_from_label(
    pwd_seed: &[u8; 32],
    label: &[u8],
) -> ShuliResult<ProjectivePoint> {
    // pwd-value = HKDF-Expand(pwd-seed, label, len); len = prime+ceil(prime/2)
    let mut okm = [0u8; SAE_FIELD_LEN + SAE_FIELD_LEN.div_ceil(2)]; // 48
    hkdf_expand(pwd_seed, label, &mut okm);

    // u = OS2IP(pwd-value) mod p ; P = SSWU(u)
    let u = FieldElement::from_okm(GenericArray::from_slice(&okm));
    Ok(u.map_to_curve())
}

/// PWE = val * PT, where val = H(0^n, MAX(mac)||MIN(mac)) mod (q-1) + 1.
fn derive_pwe_from_pt(
    pt: &ProjectivePoint,
    mac_sta: &[u8; 6],
    mac_ap: &[u8; 6],
) -> ShuliResult<ProjectivePoint> {
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
    let order = NistP256::ORDER;
    let order_m1 = order.wrapping_sub(&p256::U256::ONE);
    let nz = NonZero::new(order_m1).unwrap();
    let val_int = p256::U256::from_be_slice(&val_hash) % nz;
    let val_int = val_int.wrapping_add(&p256::U256::ONE);
    let val_bytes = val_int.to_be_bytes();
    let val_scalar = Scalar::from_repr(val_bytes.into());
    if bool::from(val_scalar.is_none()) {
        return Err(crate::ShuliError::SaeFailed("val out of range".into()));
    }
    let val_scalar = val_scalar.unwrap();

    let pwe = *pt * val_scalar;
    if bool::from(pwe.is_identity()) {
        return Err(crate::ShuliError::SaeFailed("PWE is identity".into()));
    }
    Ok(pwe)
}

// ---- Helpers ----

#[cfg(test)]
fn affine_x_bytes(point: &AffinePoint) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(point.x().as_ref());
    bytes
}

fn scalar_to_array(s: &Scalar) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(s.to_bytes().as_ref());
    arr
}

fn scalar_from_bytes(bytes: &[u8]) -> Scalar {
    let mut arr = [0u8; 32];
    let len = bytes.len().min(32);
    arr[..len].copy_from_slice(&bytes[..len]);
    Scalar::from_repr(arr.into()).unwrap_or(Scalar::ZERO)
}

/// Reconstruct a curve point from a 64-byte x||y encoding.
fn projective_from_elem(elem_bytes: &[u8]) -> ProjectivePoint {
    if elem_bytes.len() < 64 {
        return ProjectivePoint::IDENTITY;
    }
    let ep = EncodedPoint::from_affine_coordinates(
        GenericArray::from_slice(&elem_bytes[..32]),
        GenericArray::from_slice(&elem_bytes[32..64]),
        false,
    );
    let affine = AffinePoint::from_encoded_point(&ep);
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
    let encoded = affine.to_encoded_point(false);
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

// ---- Tests ----

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::rand_core::OsRng;

    use super::*;

    #[test]
    fn test_pwe_derivation() {
        let mac_sta = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mac_ap = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
        let pwe = compute_pwe_h2e("12345678", "Test-WIFI", &mac_sta, &mac_ap);
        assert!(pwe.is_ok());
        assert!(!bool::from(pwe.unwrap().is_identity()));
    }

    #[test]
    fn test_full_sae_exchange() {
        let mut rng = OsRng;
        let mac_sta = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mac_ap = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
        let password = "12345678";
        let ssid = "Test-WIFI";

        let mut supp = SaeState::new(password, ssid, mac_sta, mac_ap).unwrap();
        let (supp_scalar, supp_elem) = supp.build_commit(&mut rng);

        let mut ap = SaeState::new(password, ssid, mac_ap, mac_sta).unwrap();
        let (ap_scalar, ap_elem) = ap.build_commit(&mut rng);

        // PWE must match on both sides (symmetric in MAC ordering).
        let supp_pwe_x = affine_x_bytes(&supp.pwe.to_affine());
        let ap_pwe_x = affine_x_bytes(&ap.pwe.to_affine());
        assert_eq!(supp_pwe_x, ap_pwe_x, "PWE x must match");

        let supp_confirm = supp.process_commit(&ap_scalar, &ap_elem).unwrap();
        let ap_confirm = ap.process_commit(&supp_scalar, &supp_elem).unwrap();

        assert_eq!(supp.pmk(), ap.pmk(), "PMK must match");
        assert_eq!(supp.pmkid(), ap.pmkid(), "PMKID must match");

        // Each side verifies the other's confirm. Confirm body = send_confirm
        // (1, LE) || hash.
        let mut ap_confirm_body = vec![1u8, 0u8];
        ap_confirm_body.extend_from_slice(&ap_confirm);
        supp.process_confirm(&ap_confirm_body).unwrap();

        let mut supp_confirm_body = vec![1u8, 0u8];
        supp_confirm_body.extend_from_slice(&supp_confirm);
        ap.process_confirm(&supp_confirm_body).unwrap();
    }

    #[test]
    fn test_sae_different_passwords() {
        let mut rng = OsRng;
        let mac_sta = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mac_ap = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
        let ssid = "Test-WIFI";

        let mut supp =
            SaeState::new("12345678", ssid, mac_sta, mac_ap).unwrap();
        let (supp_scalar, supp_elem) = supp.build_commit(&mut rng);

        let mut ap =
            SaeState::new("wrong_password", ssid, mac_ap, mac_sta).unwrap();
        let (ap_scalar, ap_elem) = ap.build_commit(&mut rng);

        supp.process_commit(&ap_scalar, &ap_elem).unwrap();
        ap.process_commit(&supp_scalar, &supp_elem).unwrap();

        assert_ne!(supp.pmk(), ap.pmk(), "PMK must differ");
    }
}
