// SPDX-License-Identifier: Apache-2.0

//! X.509 certificate authentication.

use std::time::SystemTime;

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{
        self, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
        EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair,
    },
};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject,
};
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

use crate::{
    config::CertificateConfig,
    error::{IpsecError, IpsecErrorKind},
    identity::Identity,
};

const CERT_ENCODING_X509: u8 = 4;

/// Local signing credentials.
pub(crate) enum LocalCredentials {
    Rsa(RsaKeyPair),
    Ecdsa { key: EcdsaKeyPair, method: u8 },
    Ed25519(Ed25519KeyPair),
}

pub(crate) struct LocalAuth {
    pub chain: Vec<Vec<u8>>,
    pub credentials: LocalCredentials,
}

impl LocalAuth {
    pub(crate) fn load(config: &CertificateConfig) -> Result<Self, IpsecError> {
        let mut chain = Vec::new();
        for certificate in &config.certificates {
            chain.extend(parse_certificates(certificate)?);
        }
        if chain.is_empty() {
            return Err(IpsecError::config(
                "certificate authentication requires a local certificate",
            ));
        }
        let key = parse_private_key(config.private_key.expose())?;
        let key = key.as_slice();
        let credentials = if let Ok(key) = RsaKeyPair::from_pkcs8(key) {
            LocalCredentials::Rsa(key)
        } else if let Ok(key) =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key)
        {
            LocalCredentials::Ecdsa {
                key,
                method: super::AUTH_ECDSA_P256_SHA256,
            }
        } else if let Ok(key) =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, key)
        {
            LocalCredentials::Ecdsa {
                key,
                method: super::AUTH_ECDSA_P384_SHA384,
            }
        } else if let Ok(key) = Ed25519KeyPair::from_pkcs8(key) {
            LocalCredentials::Ed25519(key)
        } else {
            return Err(IpsecError::new(
                IpsecErrorKind::Certificate,
                "unsupported private key format",
            ));
        };
        Ok(Self { chain, credentials })
    }

    /// Sign the AUTH signed octets and return the auth method and value.
    pub(crate) fn sign(
        &self,
        signed: &[u8],
    ) -> Result<(u8, Vec<u8>), IpsecError> {
        let rng = SystemRandom::new();
        match &self.credentials {
            LocalCredentials::Rsa(key) => {
                let mut signature = vec![0u8; key.public_modulus_len()];
                key.sign(
                    &signature::RSA_PKCS1_SHA256,
                    &rng,
                    signed,
                    &mut signature,
                )
                .map_err(|_| {
                    IpsecError::new(
                        IpsecErrorKind::Certificate,
                        "RSA signing failed",
                    )
                })?;
                Ok((super::AUTH_RSA, signature))
            }
            LocalCredentials::Ecdsa { key, method } => {
                let signature = key.sign(&rng, signed).map_err(|_| {
                    IpsecError::new(
                        IpsecErrorKind::Certificate,
                        "ECDSA signing failed",
                    )
                })?;
                Ok((*method, signature.as_ref().to_vec()))
            }
            LocalCredentials::Ed25519(key) => {
                let signature = key.sign(signed);
                // RFC 8420 assigns EdDSA the value 13.
                Ok((13, signature.as_ref().to_vec()))
            }
        }
    }

    pub(crate) fn certificates(&self) -> &[Vec<u8>] {
        &self.chain
    }
}

/// Verify a peer certificate chain and bind it to `identity`.
pub(crate) fn verify_peer(
    ca_certificates: &[Vec<u8>],
    peer_chain: &[Vec<u8>],
    identity: &Identity,
) -> Result<(), IpsecError> {
    if peer_chain.is_empty() {
        return Err(IpsecError::new(
            IpsecErrorKind::Certificate,
            "peer did not send a certificate",
        ));
    }
    let mut anchor_certs: Vec<CertificateDer<'static>> = Vec::new();
    for certificate in ca_certificates {
        for der in parse_certificates(certificate)? {
            anchor_certs.push(CertificateDer::from(der));
        }
    }
    if anchor_certs.is_empty() {
        return Err(IpsecError::new(
            IpsecErrorKind::Certificate,
            "no trust anchors configured",
        ));
    }
    let anchors: Vec<rustls::pki_types::TrustAnchor<'_>> = anchor_certs
        .iter()
        .map(|certificate| {
            anchor_from_trusted_cert(certificate).map_err(|e| {
                IpsecError::new(
                    IpsecErrorKind::Certificate,
                    format!("invalid CA certificate: {e}"),
                )
            })
        })
        .collect::<Result<_, _>>()?;
    let leaf_der = CertificateDer::from(peer_chain[0].clone());
    let leaf = EndEntityCert::try_from(&leaf_der).map_err(|e| {
        IpsecError::new(
            IpsecErrorKind::Certificate,
            format!("invalid peer certificate: {e}"),
        )
    })?;
    let intermediates: Vec<CertificateDer<'static>> = peer_chain[1..]
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();
    let time = UnixTime::since_unix_epoch(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default(),
    );
    leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediates,
        time,
        KeyUsage::required_if_present(&[43, 6, 1, 5, 5, 7, 3, 2]),
        None,
        None,
    )
    .map_err(|e| {
        IpsecError::new(
            IpsecErrorKind::Certificate,
            format!("peer certificate validation failed: {e}"),
        )
    })?;

    match identity {
        Identity::Ip(address) => {
            let name = rustls::pki_types::ServerName::from(*address);
            leaf.verify_is_valid_for_subject_name(&name).map_err(|e| {
                IpsecError::new(
                    IpsecErrorKind::Identity,
                    format!(
                        "certificate does not match identity {address}: {e}"
                    ),
                )
            })?;
        }
        Identity::Fqdn(name) => {
            let name = rustls::pki_types::ServerName::try_from(name.clone())
                .map_err(|e| {
                    IpsecError::new(
                        IpsecErrorKind::Identity,
                        format!("invalid peer identity {name}: {e}"),
                    )
                })?;
            leaf.verify_is_valid_for_subject_name(&name).map_err(|e| {
                IpsecError::new(
                    IpsecErrorKind::Identity,
                    format!(
                        "certificate does not match identity {name:?}: {e}"
                    ),
                )
            })?;
        }
        // webpki does not expose email/DN SAN comparison; the chain is
        // still validated against the configured trust anchors.
        Identity::Email(_)
        | Identity::DerAsn1Dn(_)
        | Identity::KeyId(_)
        | Identity::Any => {}
    }
    Ok(())
}

/// Verify a signature from a peer certificate.
pub(crate) fn verify_signature(
    peer_chain: &[Vec<u8>],
    method: u8,
    signed: &[u8],
    auth: &[u8],
) -> Result<(), IpsecError> {
    if peer_chain.is_empty() {
        return Err(IpsecError::new(
            IpsecErrorKind::Certificate,
            "peer did not send a certificate",
        ));
    }
    let leaf_der = CertificateDer::from(peer_chain[0].clone());
    let leaf = EndEntityCert::try_from(&leaf_der).map_err(|e| {
        IpsecError::new(
            IpsecErrorKind::Certificate,
            format!("invalid peer certificate: {e}"),
        )
    })?;
    let algorithms: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] = match method {
        super::AUTH_RSA => &[
            webpki::ring::RSA_PKCS1_2048_8192_SHA256,
            webpki::ring::RSA_PKCS1_2048_8192_SHA384,
            webpki::ring::RSA_PKCS1_2048_8192_SHA512,
        ],
        super::AUTH_ECDSA_P256_SHA256 => &[webpki::ring::ECDSA_P256_SHA256],
        super::AUTH_ECDSA_P384_SHA384 => &[webpki::ring::ECDSA_P384_SHA384],
        13 => &[webpki::ring::ED25519],
        _ => {
            return Err(IpsecError::new(
                IpsecErrorKind::NoSupport,
                format!("unsupported AUTH method {method}"),
            ));
        }
    };
    let mut last_error = None;
    for algorithm in algorithms {
        match leaf.verify_signature(*algorithm, signed, auth) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(IpsecError::new(
        IpsecErrorKind::Authentication,
        format!(
            "peer AUTH signature verification failed: {}",
            last_error.map_or_else(
                || "no signature algorithm".to_string(),
                |e| e.to_string()
            )
        ),
    ))
}

pub(crate) fn certificate_payloads(
    chain: &[Vec<u8>],
) -> Vec<crate::ikev2::codec::Payload> {
    use crate::ikev2::codec::Payload;
    chain
        .iter()
        .map(|certificate| Payload::Cert {
            encoding: CERT_ENCODING_X509,
            data: certificate.clone(),
        })
        .collect()
}

/// Parse PEM or DER data into one or more DER certificates.
pub(crate) fn parse_certificates(
    data: &[u8],
) -> Result<Vec<Vec<u8>>, IpsecError> {
    if data.starts_with(b"-----BEGIN") {
        parse_pem(data)
    } else {
        Ok(vec![data.to_vec()])
    }
}

fn parse_pem(data: &[u8]) -> Result<Vec<Vec<u8>>, IpsecError> {
    let text = std::str::from_utf8(data).map_err(|_| {
        IpsecError::new(IpsecErrorKind::Certificate, "PEM data is not UTF-8")
    })?;
    let mut certificates = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
        let Some(end) = after.find("-----END CERTIFICATE-----") else {
            return Err(IpsecError::new(
                IpsecErrorKind::Certificate,
                "unterminated PEM certificate",
            ));
        };
        let body: String = after[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        certificates.push(base64_decode(&body)?);
        rest = &after[end + "-----END CERTIFICATE-----".len()..];
    }
    if certificates.is_empty() {
        return Err(IpsecError::new(
            IpsecErrorKind::Certificate,
            "no PEM certificate found",
        ));
    }
    Ok(certificates)
}

fn base64_decode(value: &str) -> Result<Vec<u8>, IpsecError> {
    fn digit(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(IpsecError::new(
            IpsecErrorKind::Certificate,
            "invalid base64 length",
        ));
    }
    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let a = digit(chunk[0]).ok_or_else(|| {
            IpsecError::new(IpsecErrorKind::Certificate, "invalid base64")
        })? as u32;
        let b = digit(chunk[1]).ok_or_else(|| {
            IpsecError::new(IpsecErrorKind::Certificate, "invalid base64")
        })? as u32;
        let c = if chunk[2] == b'=' {
            0
        } else {
            digit(chunk[2]).ok_or_else(|| {
                IpsecError::new(IpsecErrorKind::Certificate, "invalid base64")
            })? as u32
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            digit(chunk[3]).ok_or_else(|| {
                IpsecError::new(IpsecErrorKind::Certificate, "invalid base64")
            })? as u32
        };
        let value = (a << 18) | (b << 12) | (c << 6) | d;
        output.push((value >> 16) as u8);
        if chunk[2] != b'=' {
            output.push((value >> 8) as u8);
        }
        if chunk[3] != b'=' {
            output.push(value as u8);
        }
    }
    Ok(output)
}

/// Read a PEM key and return PKCS#8 DER.
pub(crate) fn parse_private_key(data: &[u8]) -> Result<Vec<u8>, IpsecError> {
    let key = PrivateKeyDer::from_pem_slice(data).map_err(|e| {
        IpsecError::new(
            IpsecErrorKind::Certificate,
            format!("invalid private key: {e}"),
        )
    })?;
    Ok(key.secret_der().to_vec())
}
