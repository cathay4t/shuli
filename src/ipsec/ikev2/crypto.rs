// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives used by IKEv2.
//!
//! All secret material is held in ordinary vectors only for the duration of
//! a primitive call; callers wrap long-lived material in `zeroize` types.

use aws_lc_rs::{
    aead,
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey},
    cipher::{
        AES_128, AES_256, DecryptingKey, DecryptionContext, EncryptingKey,
        EncryptionContext, UnboundCipherKey,
    },
    hmac,
    iv::{FixedLength, IV_LEN_128_BIT},
};
use num_bigint::BigUint;
use zeroize::Zeroizing;

use crate::{
    config::{DhGroup, EncryptionAlgorithm, IntegrityAlgorithm, PrfAlgorithm},
    error::{IpsecError, IpsecErrorKind},
};

/// Fill `output` with cryptographically secure random bytes.
pub fn random_bytes(output: &mut [u8]) -> Result<(), IpsecError> {
    getrandom::fill(output).map_err(|e| {
        IpsecError::new(IpsecErrorKind::Internal, format!("random: {e}"))
    })
}

pub fn random_u64() -> Result<u64, IpsecError> {
    let mut bytes = [0u8; 8];
    random_bytes(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

pub fn random_u32() -> Result<u32, IpsecError> {
    let mut bytes = [0u8; 4];
    random_bytes(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn hmac_algorithm(prf: PrfAlgorithm) -> hmac::Algorithm {
    match prf {
        PrfAlgorithm::HmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        PrfAlgorithm::HmacSha2_256 => hmac::HMAC_SHA256,
    }
}

/// The negotiated PRF.
pub fn prf(algorithm: PrfAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac_algorithm(algorithm), key);
    hmac::sign(&key, data).as_ref().to_vec()
}

/// IKEv2 prf+ (RFC 7296 section 2.13).
pub fn prf_plus(
    algorithm: PrfAlgorithm,
    key: &[u8],
    seed: &[u8],
    output_len: usize,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut previous = Vec::new();
    let mut counter: u8 = 1;
    while output.len() < output_len {
        let mut input = Vec::with_capacity(previous.len() + seed.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(seed);
        input.push(counter);
        let block = prf(algorithm, key, &input);
        let take = (output_len - output.len()).min(block.len());
        output.extend_from_slice(&block[..take]);
        previous = block;
        counter = counter.wrapping_add(1);
    }
    output
}

/// Compute the truncated ICV for an integrity algorithm.
pub fn integrity(
    algorithm: IntegrityAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, IpsecError> {
    let algorithm = match algorithm {
        IntegrityAlgorithm::HmacSha1_96 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        IntegrityAlgorithm::HmacSha2_256_128 => hmac::HMAC_SHA256,
        IntegrityAlgorithm::None => {
            return Err(IpsecError::internal(
                "cannot compute integrity with the NONE algorithm",
            ));
        }
    };
    let key = hmac::Key::new(algorithm, key);
    let tag = hmac::sign(&key, data);
    let length = match algorithm.digest_algorithm().output_len {
        20 => 12,
        _ => 16,
    };
    Ok(tag.as_ref()[..length.min(tag.as_ref().len())].to_vec())
}

/// Verify a truncated ICV in constant time.
pub fn verify_integrity(
    algorithm: IntegrityAlgorithm,
    key: &[u8],
    data: &[u8],
    expected: &[u8],
) -> Result<(), IpsecError> {
    let actual = integrity(algorithm, key, data)?;
    if actual.len() == expected.len()
        && aws_lc_rs::constant_time::verify_slices_are_equal(&actual, expected)
            .is_ok()
    {
        Ok(())
    } else {
        Err(IpsecError::authentication("IKE integrity check failed"))
    }
}

/// Encrypt a plaintext, returning ciphertext followed by the ICV tag.
/// The IV is supplied by the caller and is not included in the result.
pub fn encrypt(
    algorithm: EncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, IpsecError> {
    if algorithm.is_aead() {
        encrypt_gcm(algorithm, key, iv, plaintext, aad)
    } else {
        encrypt_cbc(algorithm, key, iv, plaintext)
    }
}

/// Decrypt ciphertext (with trailing ICV tag for AEAD).
pub fn decrypt(
    algorithm: EncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, IpsecError> {
    if algorithm.is_aead() {
        decrypt_gcm(algorithm, key, iv, ciphertext, aad)
    } else {
        decrypt_cbc(algorithm, key, iv, ciphertext)
    }
}

fn encrypt_gcm(
    algorithm: EncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, IpsecError> {
    let (key, salt) = key.split_at(algorithm.key_len());
    if salt.len() != 4 || iv.len() != 8 {
        return Err(IpsecError::internal("invalid IKE AEAD key or IV length"));
    }
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(salt);
    nonce[4..].copy_from_slice(iv);
    let algorithm = match algorithm {
        EncryptionAlgorithm::AesGcm16_128 => &aead::AES_128_GCM,
        EncryptionAlgorithm::AesGcm16_256 => &aead::AES_256_GCM,
        _ => return Err(IpsecError::internal("not an AEAD algorithm")),
    };
    let unbound = aead::UnboundKey::new(algorithm, key)
        .map_err(|_| IpsecError::internal("invalid AEAD key"))?;
    let key = aead::LessSafeKey::new(unbound);
    let mut output = plaintext.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad),
        &mut output,
    )
    .map_err(|_| IpsecError::internal("AEAD encryption failed"))?;
    Ok(output)
}

fn decrypt_gcm(
    algorithm: EncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, IpsecError> {
    let (key, salt) = key.split_at(algorithm.key_len());
    if salt.len() != 4 || iv.len() != 8 {
        return Err(IpsecError::internal("invalid IKE AEAD key or IV length"));
    }
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(salt);
    nonce[4..].copy_from_slice(iv);
    let algorithm = match algorithm {
        EncryptionAlgorithm::AesGcm16_128 => &aead::AES_128_GCM,
        EncryptionAlgorithm::AesGcm16_256 => &aead::AES_256_GCM,
        _ => return Err(IpsecError::internal("not an AEAD algorithm")),
    };
    let unbound = aead::UnboundKey::new(algorithm, key)
        .map_err(|_| IpsecError::internal("invalid AEAD key"))?;
    let key = aead::LessSafeKey::new(unbound);
    let mut output = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut output,
        )
        .map_err(|_| {
            IpsecError::authentication("IKE AEAD authentication failed")
        })?;
    Ok(plaintext.to_vec())
}

fn cipher_algorithm(
    algorithm: EncryptionAlgorithm,
) -> &'static aws_lc_rs::cipher::Algorithm {
    match algorithm {
        EncryptionAlgorithm::AesCbc128 => &AES_128,
        EncryptionAlgorithm::AesCbc192 => &aws_lc_rs::cipher::AES_192,
        EncryptionAlgorithm::AesCbc256 => &AES_256,
        _ => &AES_128,
    }
}

fn encrypt_cbc(
    algorithm: EncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, IpsecError> {
    if !plaintext.len().is_multiple_of(16) {
        return Err(IpsecError::internal(
            "AES-CBC plaintext is not block aligned",
        ));
    }
    let iv: [u8; 16] = iv
        .try_into()
        .map_err(|_| IpsecError::internal("invalid AES-CBC IV length"))?;
    let mut output = plaintext.to_vec();
    let unbound = UnboundCipherKey::new(cipher_algorithm(algorithm), key)
        .map_err(|_| IpsecError::internal("invalid AES key"))?;
    let cipher = EncryptingKey::cbc(unbound)
        .map_err(|_| IpsecError::internal("AES-CBC init failed"))?;
    cipher
        .less_safe_encrypt(
            &mut output,
            EncryptionContext::Iv128(FixedLength::<IV_LEN_128_BIT>::from(iv)),
        )
        .map_err(|_| IpsecError::internal("AES-CBC encryption failed"))?;
    Ok(output)
}

fn decrypt_cbc(
    algorithm: EncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, IpsecError> {
    if !ciphertext.len().is_multiple_of(16) || ciphertext.is_empty() {
        return Err(IpsecError::ike("invalid AES-CBC ciphertext length"));
    }
    let iv: [u8; 16] = iv
        .try_into()
        .map_err(|_| IpsecError::internal("invalid AES-CBC IV length"))?;
    let mut output = ciphertext.to_vec();
    let unbound = UnboundCipherKey::new(cipher_algorithm(algorithm), key)
        .map_err(|_| IpsecError::internal("invalid AES key"))?;
    let cipher = DecryptingKey::cbc(unbound)
        .map_err(|_| IpsecError::internal("AES-CBC init failed"))?;
    let plaintext = cipher
        .decrypt(
            &mut output,
            DecryptionContext::Iv128(FixedLength::<IV_LEN_128_BIT>::from(iv)),
        )
        .map_err(|_| IpsecError::authentication("AES-CBC decryption failed"))?;
    Ok(plaintext.to_vec())
}

/// A Diffie-Hellman private/public key pair.
pub struct DhKeyPair {
    group: DhGroup,
    public: Vec<u8>,
    private: DhPrivate,
}

enum DhPrivate {
    Ephemeral(EphemeralPrivateKey),
    Modp(Zeroizing<Vec<u8>>),
}

impl DhKeyPair {
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    pub fn agree(
        self,
        peer_public: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, IpsecError> {
        match self.private {
            DhPrivate::Ephemeral(private) => {
                let algorithm = agreement_algorithm(self.group)?;
                let peer = UnparsedPublicKey::new(algorithm, peer_public);
                let shared = agreement::agree_ephemeral(
                    private,
                    peer,
                    aws_lc_rs::error::Unspecified,
                    |secret| Ok(secret.to_vec()),
                )
                .map_err(|_| {
                    IpsecError::ike("Diffie-Hellman key agreement failed")
                })?;
                Ok(Zeroizing::new(shared))
            }
            DhPrivate::Modp(private) => {
                let prime = modp_prime();
                let peer = BigUint::from_bytes_be(peer_public);
                if peer <= BigUint::from(1u8)
                    || peer >= &prime - BigUint::from(1u8)
                {
                    return Err(IpsecError::ike(
                        "peer MODP public value is out of range",
                    ));
                }
                let exponent = BigUint::from_bytes_be(&private);
                let shared = peer.modpow(&exponent, &prime);
                Ok(Zeroizing::new(pad_left(&shared.to_bytes_be(), 256)))
            }
        }
    }

    pub fn generate(group: DhGroup) -> Result<Self, IpsecError> {
        match group {
            DhGroup::Ecp256 | DhGroup::Ecp384 | DhGroup::X25519 => {
                let algorithm = agreement_algorithm(group)?;
                let private = EphemeralPrivateKey::generate(
                    algorithm,
                    &aws_lc_rs::rand::SystemRandom::new(),
                )
                .map_err(|_| {
                    IpsecError::internal("DH key generation failed")
                })?;
                let public = private
                    .compute_public_key()
                    .map_err(|_| {
                        IpsecError::internal("DH public key generation failed")
                    })?
                    .as_ref()
                    .to_vec();
                Ok(Self {
                    group,
                    public,
                    private: DhPrivate::Ephemeral(private),
                })
            }
            DhGroup::Modp2048 => {
                let prime = modp_prime();
                let mut exponent = Zeroizing::new(vec![0u8; 256]);
                random_bytes(&mut exponent)?;
                let exponent = BigUint::from_bytes_be(&exponent)
                    % (&prime - BigUint::from(2u8))
                    + BigUint::from(2u8);
                let public = BigUint::from(2u8).modpow(&exponent, &prime);
                let public = pad_left(&public.to_bytes_be(), 256);
                let exponent = Zeroizing::new(exponent.to_bytes_be());
                Ok(Self {
                    group,
                    public,
                    private: DhPrivate::Modp(exponent),
                })
            }
            DhGroup::None => Err(IpsecError::ike(
                "cannot generate a key pair for DH group NONE",
            )),
        }
    }
}

fn agreement_algorithm(
    group: DhGroup,
) -> Result<&'static agreement::Algorithm, IpsecError> {
    match group {
        DhGroup::Ecp256 => Ok(&agreement::ECDH_P256),
        DhGroup::Ecp384 => Ok(&agreement::ECDH_P384),
        DhGroup::X25519 => Ok(&agreement::X25519),
        _ => Err(IpsecError::new(
            IpsecErrorKind::NoSupport,
            format!("unsupported DH group {group:?}"),
        )),
    }
}

fn pad_left(value: &[u8], length: usize) -> Vec<u8> {
    if value.len() >= length {
        value[value.len() - length..].to_vec()
    } else {
        let mut padded = vec![0u8; length - value.len()];
        padded.extend_from_slice(value);
        padded
    }
}

/// RFC 3526 group 14 (2048-bit MODP) prime.
fn modp_prime() -> BigUint {
    const PRIME_HEX: &str = concat!(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
    );
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("valid MODP prime")
}

/// RFC 7383 fragment payload body.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub fragment_number: u16,
    pub total_fragments: u16,
    pub data: Vec<u8>,
}

#[allow(dead_code)]
pub fn encode_fragment(fragment: &Fragment) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + fragment.data.len());
    body.extend_from_slice(&fragment.fragment_number.to_be_bytes());
    body.extend_from_slice(&fragment.total_fragments.to_be_bytes());
    body.extend_from_slice(&fragment.data);
    body
}

#[allow(dead_code)]
pub fn decode_fragment(body: &[u8]) -> Result<Fragment, IpsecError> {
    if body.len() < 4 {
        return Err(IpsecError::ike("truncated IKE fragment payload"));
    }
    Ok(Fragment {
        fragment_number: u16::from_be_bytes([body[0], body[1]]),
        total_fragments: u16::from_be_bytes([body[2], body[3]]),
        data: body[4..].to_vec(),
    })
}
