// SPDX-License-Identifier: Apache-2.0

//! Proposal construction and selection.

use crate::{
    config::{
        ChildProposal, DhGroup, EncryptionAlgorithm, IkeProposal,
        IntegrityAlgorithm, PrfAlgorithm,
    },
    error::{IpsecError, IpsecErrorKind},
    ikev2::codec::{self, Proposal, Transform, transform_type},
};

pub fn build_ike(proposals: &[IkeProposal]) -> Vec<Proposal> {
    proposals
        .iter()
        .enumerate()
        .map(|(index, proposal)| Proposal {
            number: (index + 1) as u8,
            protocol: codec::protocol_id::IKE,
            spi: Vec::new(),
            transforms: codec::ike_transforms(
                proposal.encryption,
                proposal.prf,
                proposal.integrity,
                proposal.dh,
            ),
        })
        .collect()
}

pub fn build_esp(
    proposals: &[ChildProposal],
    spi: u32,
    include_dh: bool,
) -> Vec<Proposal> {
    proposals
        .iter()
        .enumerate()
        .map(|(index, proposal)| Proposal {
            number: (index + 1) as u8,
            protocol: codec::protocol_id::ESP,
            spi: spi.to_be_bytes().to_vec(),
            transforms: codec::esp_transforms(
                proposal.encryption,
                proposal.integrity,
                proposal.esn,
                if include_dh {
                    proposal.dh
                } else {
                    DhGroup::None
                },
            ),
        })
        .collect()
}

pub fn select_ike(
    configured: &[IkeProposal],
    received: &[Proposal],
) -> Result<(IkeProposal, u8), IpsecError> {
    for offer in received {
        if offer.protocol != codec::protocol_id::IKE {
            continue;
        }
        if let Some(candidate) = configured.iter().find(|candidate| {
            transform_offer_matches(
                &offer.transforms,
                candidate.encryption,
                Some(candidate.prf),
                candidate.integrity,
                candidate.dh,
            )
        }) {
            return Ok((*candidate, offer.number));
        }
    }
    Err(IpsecError::new(
        IpsecErrorKind::Proposal,
        "no mutually supported IKE proposal",
    ))
}

pub fn select_esp(
    configured: &[ChildProposal],
    received: &[Proposal],
) -> Result<(ChildProposal, u8), IpsecError> {
    select_esp_with_dh(configured, received, true)
}

/// Select an ESP proposal for the initial IKE_AUTH exchange, where a
/// DH exchange is not allowed.  The configured PFS group is ignored.
pub fn select_esp_initial(
    configured: &[ChildProposal],
    received: &[Proposal],
) -> Result<(ChildProposal, u8), IpsecError> {
    select_esp_with_dh(configured, received, false)
}

fn select_esp_with_dh(
    configured: &[ChildProposal],
    received: &[Proposal],
    include_dh: bool,
) -> Result<(ChildProposal, u8), IpsecError> {
    for offer in received {
        if offer.protocol != codec::protocol_id::ESP {
            continue;
        }
        if let Some(candidate) = configured.iter().find(|candidate| {
            transform_offer_matches(
                &offer.transforms,
                candidate.encryption,
                None,
                candidate.integrity,
                if include_dh {
                    candidate.dh
                } else {
                    DhGroup::None
                },
            )
        }) {
            let mut candidate = *candidate;
            if !include_dh {
                candidate.dh = DhGroup::None;
            }
            return Ok((candidate, offer.number));
        }
    }
    Err(IpsecError::new(
        IpsecErrorKind::Proposal,
        "no mutually supported ESP proposal",
    ))
}

/// Parse a single selected IKE proposal from a response.
pub fn parse_selected_ike(
    proposals: &[Proposal],
) -> Result<IkeProposal, IpsecError> {
    let offer = proposals
        .iter()
        .find(|proposal| proposal.protocol == codec::protocol_id::IKE)
        .ok_or_else(|| {
            IpsecError::new(
                IpsecErrorKind::Proposal,
                "no IKE proposal in response",
            )
        })?;
    let encryption = select_transform(&offer.transforms, transform_type::ENCR)
        .and_then(parse_encryption)
        .ok_or_else(|| {
            IpsecError::new(
                IpsecErrorKind::Proposal,
                "unsupported IKE encryption",
            )
        })?;
    let prf = select_transform(&offer.transforms, transform_type::PRF)
        .and_then(parse_prf)
        .ok_or_else(|| {
            IpsecError::new(IpsecErrorKind::Proposal, "unsupported IKE PRF")
        })?;
    let integrity = select_transform(&offer.transforms, transform_type::INTEG)
        .and_then(parse_integrity)
        .unwrap_or(IntegrityAlgorithm::None);
    let dh = select_transform(&offer.transforms, transform_type::DH)
        .and_then(parse_dh)
        .ok_or_else(|| {
            IpsecError::new(
                IpsecErrorKind::Proposal,
                "unsupported IKE DH group",
            )
        })?;
    Ok(IkeProposal {
        encryption,
        prf,
        integrity,
        dh,
    })
}

/// Parse a single selected ESP proposal from a response.
pub fn parse_selected_esp(
    proposals: &[Proposal],
) -> Result<ChildProposal, IpsecError> {
    let offer = proposals
        .iter()
        .find(|proposal| proposal.protocol == codec::protocol_id::ESP)
        .ok_or_else(|| {
            IpsecError::new(
                IpsecErrorKind::Proposal,
                "no ESP proposal in response",
            )
        })?;
    let encryption = select_transform(&offer.transforms, transform_type::ENCR)
        .and_then(parse_encryption)
        .ok_or_else(|| {
            IpsecError::new(
                IpsecErrorKind::Proposal,
                "unsupported ESP encryption",
            )
        })?;
    let integrity = select_transform(&offer.transforms, transform_type::INTEG)
        .and_then(parse_integrity)
        .unwrap_or(IntegrityAlgorithm::None);
    let esn = offer
        .transforms
        .iter()
        .find(|transform| transform.transform_type == transform_type::ESN)
        .map(|transform| transform.id == 1)
        .unwrap_or(false);
    let dh = select_transform(&offer.transforms, transform_type::DH)
        .and_then(parse_dh)
        .unwrap_or(DhGroup::None);
    Ok(ChildProposal {
        encryption,
        integrity,
        esn,
        dh,
    })
}

fn select_transform(transforms: &[Transform], kind: u8) -> Option<&Transform> {
    transforms
        .iter()
        .find(|transform| transform.transform_type == kind)
}

fn transform_offer_matches(
    transforms: &[Transform],
    encryption: EncryptionAlgorithm,
    prf: Option<PrfAlgorithm>,
    integrity: IntegrityAlgorithm,
    dh: DhGroup,
) -> bool {
    if !transforms.iter().any(|transform| {
        if transform.transform_type != transform_type::ENCR
            || transform.id != encryption.transform_id()
        {
            return false;
        }
        if encryption.transform_id() == 12 || encryption.transform_id() == 20 {
            transform
                .attributes
                .iter()
                .find_map(|attribute| attribute.key_length_bits())
                == encryption.key_len_bits()
        } else {
            true
        }
    }) {
        return false;
    }
    if let Some(prf) = prf
        && !transforms.iter().any(|transform| {
            transform.transform_type == transform_type::PRF
                && transform.id == prf.transform_id()
        })
    {
        return false;
    }
    if integrity != IntegrityAlgorithm::None
        && !transforms.iter().any(|transform| {
            transform.transform_type == transform_type::INTEG
                && transform.id == integrity.transform_id()
        })
    {
        return false;
    }
    if integrity == IntegrityAlgorithm::None && !encryption.is_aead() {
        return false;
    }
    if dh != DhGroup::None
        && !transforms.iter().any(|transform| {
            transform.transform_type == transform_type::DH
                && transform.id == dh.transform_id()
        })
    {
        return false;
    }
    dh == DhGroup::None
        || transforms.iter().any(|transform| {
            transform.transform_type == transform_type::DH
                && transform.id == dh.transform_id()
        })
}

fn parse_encryption(transform: &Transform) -> Option<EncryptionAlgorithm> {
    match transform.id {
        12 => {
            let bits = transform
                .attributes
                .iter()
                .find_map(|attribute| attribute.key_length_bits())?;
            match bits {
                128 => Some(EncryptionAlgorithm::AesCbc128),
                192 => Some(EncryptionAlgorithm::AesCbc192),
                256 => Some(EncryptionAlgorithm::AesCbc256),
                _ => None,
            }
        }
        20 => match transform
            .attributes
            .iter()
            .find_map(|attribute| attribute.key_length_bits())
        {
            Some(256) => Some(EncryptionAlgorithm::AesGcm16_256),
            Some(128) | None => Some(EncryptionAlgorithm::AesGcm16_128),
            _ => None,
        },
        _ => None,
    }
}

fn parse_prf(transform: &Transform) -> Option<PrfAlgorithm> {
    match transform.id {
        2 => Some(PrfAlgorithm::HmacSha1),
        5 => Some(PrfAlgorithm::HmacSha2_256),
        _ => None,
    }
}

fn parse_integrity(transform: &Transform) -> Option<IntegrityAlgorithm> {
    match transform.id {
        0 => Some(IntegrityAlgorithm::None),
        2 => Some(IntegrityAlgorithm::HmacSha1_96),
        12 => Some(IntegrityAlgorithm::HmacSha2_256_128),
        _ => None,
    }
}

fn parse_dh(transform: &Transform) -> Option<DhGroup> {
    DhGroup::from_transform_id(transform.id)
}
