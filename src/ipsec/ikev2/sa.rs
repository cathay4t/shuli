// SPDX-License-Identifier: Apache-2.0

//! IKE SA keys, key derivation, and encrypt/decrypt helpers.

use zeroize::{Zeroize, Zeroizing};

use crate::{
    client::ChildSaHandle,
    config::{
        ChildMode, EncryptionAlgorithm, IntegrityAlgorithm, PrfAlgorithm,
        TrafficSelector,
    },
    error::IpsecError,
    ikev2::{
        codec::{self, IKE_HEADER_LEN, IkeHeader, Payload},
        crypto,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

impl Role {
    pub(crate) fn is_initiator(self) -> bool {
        self == Self::Initiator
    }
}

/// Long-term IKE SA key material (RFC 7296 section 2.14).
pub(crate) struct IkeKeys {
    pub sk_d: Zeroizing<Vec<u8>>,
    pub sk_ai: Zeroizing<Vec<u8>>,
    pub sk_ar: Zeroizing<Vec<u8>>,
    pub sk_ei: Zeroizing<Vec<u8>>,
    pub sk_er: Zeroizing<Vec<u8>>,
    pub sk_pi: Zeroizing<Vec<u8>>,
    pub sk_pr: Zeroizing<Vec<u8>>,
}

impl IkeKeys {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn derive(
        prf: PrfAlgorithm,
        shared_secret: &[u8],
        nonce_i: &[u8],
        nonce_r: &[u8],
        spi_i: u64,
        spi_r: u64,
        encryption: EncryptionAlgorithm,
        integrity: IntegrityAlgorithm,
    ) -> Self {
        let mut seed = Vec::new();
        seed.extend_from_slice(nonce_i);
        seed.extend_from_slice(nonce_r);
        seed.extend_from_slice(&spi_i.to_be_bytes());
        seed.extend_from_slice(&spi_r.to_be_bytes());
        let mut seed = Zeroizing::new(seed);

        let skeyseed = Zeroizing::new(crypto::prf(
            prf,
            &[nonce_i, nonce_r].concat(),
            shared_secret,
        ));

        let prf_len = prf.key_len();
        let enc_len = encryption.key_len() + encryption.salt_len();
        let integ_len = integrity.key_len();
        let total = prf_len * 3 + enc_len * 2 + integ_len * 2;
        let material =
            Zeroizing::new(crypto::prf_plus(prf, &skeyseed, &seed, total));
        let mut offset = 0;
        let mut take = |length: usize| {
            let value =
                Zeroizing::new(material[offset..offset + length].to_vec());
            offset += length;
            value
        };
        let keys = Self {
            sk_d: take(prf_len),
            sk_ai: take(integ_len),
            sk_ar: take(integ_len),
            sk_ei: take(enc_len),
            sk_er: take(enc_len),
            sk_pi: take(prf_len),
            sk_pr: take(prf_len),
        };
        seed.zeroize();
        keys
    }

    pub(crate) fn outbound_encryption(&self, role: Role) -> &[u8] {
        if role.is_initiator() {
            &self.sk_ei
        } else {
            &self.sk_er
        }
    }

    pub(crate) fn inbound_encryption(&self, role: Role) -> &[u8] {
        if role.is_initiator() {
            &self.sk_er
        } else {
            &self.sk_ei
        }
    }

    pub(crate) fn outbound_integrity(&self, role: Role) -> &[u8] {
        if role.is_initiator() {
            &self.sk_ai
        } else {
            &self.sk_ar
        }
    }

    pub(crate) fn inbound_integrity(&self, role: Role) -> &[u8] {
        if role.is_initiator() {
            &self.sk_ar
        } else {
            &self.sk_ai
        }
    }
}

/// Derive the Child SA keys from SK_d and the exchange nonces.
#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_child_keys(
    prf: PrfAlgorithm,
    sk_d: &[u8],
    nonce_i: &[u8],
    nonce_r: &[u8],
    dh_shared: Option<&[u8]>,
    role: Role,
    encryption: EncryptionAlgorithm,
    integrity: IntegrityAlgorithm,
    local_spi: u32,
    remote_spi: u32,
    mode: ChildMode,
    local_selectors: Vec<TrafficSelector>,
    remote_selectors: Vec<TrafficSelector>,
    esn: bool,
) -> ChildSaHandle {
    let mut seed = Vec::new();
    if let Some(shared) = dh_shared {
        seed.extend_from_slice(shared);
    }
    seed.extend_from_slice(nonce_i);
    seed.extend_from_slice(nonce_r);
    let enc_len = encryption.key_len() + encryption.salt_len();
    let integ_len = integrity.key_len();
    let total = enc_len * 2 + integ_len * 2;
    let material = Zeroizing::new(crypto::prf_plus(prf, sk_d, &seed, total));

    let encryption_i = Zeroizing::new(material[..enc_len].to_vec());
    let encryption_r = Zeroizing::new(material[enc_len..enc_len * 2].to_vec());
    let integrity_i =
        Zeroizing::new(material[enc_len * 2..enc_len * 2 + integ_len].to_vec());
    let integrity_r = Zeroizing::new(
        material[enc_len * 2 + integ_len..enc_len * 2 + integ_len * 2].to_vec(),
    );

    let (
        outbound_key,
        inbound_key,
        outbound_integrity_key,
        inbound_integrity_key,
    ) = if role.is_initiator() {
        (encryption_i, encryption_r, integrity_i, integrity_r)
    } else {
        (encryption_r, encryption_i, integrity_r, integrity_i)
    };

    ChildSaHandle {
        local_spi,
        remote_spi,
        encryption,
        integrity: if integrity == IntegrityAlgorithm::None {
            None
        } else {
            Some(integrity)
        },
        esn,
        mode,
        local_selectors,
        remote_selectors,
        outbound_key,
        outbound_integrity_key: (integrity != IntegrityAlgorithm::None)
            .then_some(outbound_integrity_key),
        inbound_key,
        inbound_integrity_key: (integrity != IntegrityAlgorithm::None)
            .then_some(inbound_integrity_key),
    }
}

/// Encrypt an IKE message's payload chain and return the complete wire
/// message.
pub(crate) fn seal_message(
    header: &IkeHeader,
    payloads: &[Payload],
    encryption: EncryptionAlgorithm,
    integrity: IntegrityAlgorithm,
    key_e: &[u8],
    key_a: &[u8],
) -> Result<Vec<u8>, IpsecError> {
    let plaintext = codec::encode_chain(payloads)?;
    let iv_len = encryption.iv_len();
    let block = encryption.block_len();
    let ciphertext_len = if encryption.is_aead() {
        plaintext.len() + 16
    } else {
        (plaintext.len() / block + 1) * block
    };
    let icv_len = integrity.output_len();
    let total = IKE_HEADER_LEN + 4 + iv_len + ciphertext_len + icv_len;

    let mut header = header.clone();
    header.next_payload = codec::payload_type::SK;
    header.length = total as u32;
    let aad = header.encode();

    let mut iv = vec![0u8; iv_len];
    crypto::random_bytes(&mut iv)?;
    let ciphertext = crypto::encrypt(encryption, key_e, &iv, &plaintext, &aad)?;
    let mut body = iv;
    body.extend_from_slice(&ciphertext);
    if integrity != IntegrityAlgorithm::None {
        let mut signed = Vec::with_capacity(aad.len() + body.len());
        signed.extend_from_slice(&aad);
        signed.extend_from_slice(&body);
        let icv = crypto::integrity(integrity, key_a, &signed)?;
        body.extend_from_slice(&icv);
    }

    let mut message = aad;
    message.push(payloads.first().map(Payload::payload_type).unwrap_or(0));
    message.push(0);
    message.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    message.extend_from_slice(&body);
    if message.len() != total {
        return Err(IpsecError::internal(
            "IKE encrypted message length mismatch",
        ));
    }
    Ok(message)
}

/// Verify and decrypt the encrypted payload of an IKE message.
pub(crate) fn open_message(
    header: &IkeHeader,
    encrypted: &Payload,
    encryption: EncryptionAlgorithm,
    integrity: IntegrityAlgorithm,
    key_e: &[u8],
    key_a: &[u8],
) -> Result<Vec<Payload>, IpsecError> {
    let Payload::Encrypted { next, data } = encrypted else {
        return Err(IpsecError::ike("expected an encrypted IKE payload"));
    };
    let iv_len = encryption.iv_len();
    let icv_len = integrity.output_len();
    if data.len() < iv_len + icv_len {
        return Err(IpsecError::ike("truncated encrypted IKE payload"));
    }
    if integrity != IntegrityAlgorithm::None {
        let split = data.len() - icv_len;
        let mut signed = header.encode();
        signed.push(*next);
        signed.push(0);
        signed.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
        signed.extend_from_slice(&data[..split]);
        crypto::verify_integrity(integrity, key_a, &signed, &data[split..])?;
    }
    let (iv, rest) = data.split_at(iv_len);
    let ciphertext = &rest[..rest.len() - icv_len];
    let plaintext =
        crypto::decrypt(encryption, key_e, iv, ciphertext, &header.encode())?;
    codec::decode_chain(*next, &plaintext)
}
