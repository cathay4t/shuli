// SPDX-License-Identifier: Apache-2.0

//! IKEv2 wire codec (RFC 7296).
//!
//! The codec is deliberately parser-hardened: every nested length is
//! checked against its enclosing buffer before use.

use std::fmt;

use crate::{
    config::{DhGroup, EncryptionAlgorithm, IntegrityAlgorithm, PrfAlgorithm},
    error::{IpsecError, IpsecErrorKind},
};

pub const IKE_HEADER_LEN: usize = 28;
pub const IKE_VERSION_2: u8 = 0x20;

pub const FLAG_INITIATOR: u8 = 0x08;
pub const FLAG_VERSION: u8 = 0x10;
pub const FLAG_RESPONSE: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExchangeType {
    IkeSaInit = 34,
    IkeAuth = 35,
    CreateChildSa = 36,
    Informational = 37,
}

impl ExchangeType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            34 => Some(Self::IkeSaInit),
            35 => Some(Self::IkeAuth),
            36 => Some(Self::CreateChildSa),
            37 => Some(Self::Informational),
            _ => None,
        }
    }
}

/// Payload type numbers.
pub mod payload_type {
    pub const NONE: u8 = 0;
    pub const SA: u8 = 33;
    pub const KE: u8 = 34;
    pub const IDI: u8 = 35;
    pub const IDR: u8 = 36;
    pub const CERT: u8 = 37;
    pub const CERTREQ: u8 = 38;
    pub const AUTH: u8 = 39;
    pub const NONCE: u8 = 40;
    pub const NOTIFY: u8 = 41;
    pub const DELETE: u8 = 42;
    pub const VENDOR_ID: u8 = 43;
    pub const TSI: u8 = 44;
    pub const TSR: u8 = 45;
    pub const SK: u8 = 46;
    pub const CP: u8 = 47;
    pub const EAP: u8 = 48;
    pub const SKF: u8 = 53;
}

/// Protocol IDs.
pub mod protocol_id {
    pub const IKE: u8 = 1;
    pub const AH: u8 = 2;
    pub const ESP: u8 = 3;
}

/// Notify message types used by this implementation.
pub mod notify_type {
    pub const INVALID_KE_PAYLOAD: u16 = 17;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    pub const SINGLE_PAIR_REQUIRED: u16 = 34;
    pub const TS_UNACCEPTABLE: u16 = 38;
    pub const INVALID_SYNTAX: u16 = 7;
    pub const COOKIE: u16 = 16390;
    pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
    pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;
    pub const REKEY_SA: u16 = 16393;
    pub const ESP_TFC_PADDING_NOT_SUPPORTED: u16 = 16394;
    pub const NON_FIRST_FRAGMENTS_ALSO: u16 = 16395;
    pub const MOBIKE_SUPPORTED: u16 = 16396;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IkeHeader {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub next_payload: u8,
    pub version: u8,
    pub exchange: ExchangeType,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

impl IkeHeader {
    pub fn new(
        initiator_spi: u64,
        responder_spi: u64,
        exchange: ExchangeType,
        flags: u8,
        message_id: u32,
    ) -> Self {
        Self {
            initiator_spi,
            responder_spi,
            next_payload: payload_type::NONE,
            version: IKE_VERSION_2,
            exchange,
            flags,
            message_id,
            length: IKE_HEADER_LEN as u32,
        }
    }

    pub fn is_initiator(&self) -> bool {
        self.flags & FLAG_INITIATOR != 0
    }

    pub fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(IKE_HEADER_LEN);
        buffer.extend_from_slice(&self.initiator_spi.to_be_bytes());
        buffer.extend_from_slice(&self.responder_spi.to_be_bytes());
        buffer.push(self.next_payload);
        buffer.push(self.version);
        buffer.push(self.exchange as u8);
        buffer.push(self.flags);
        buffer.extend_from_slice(&self.message_id.to_be_bytes());
        buffer.extend_from_slice(&self.length.to_be_bytes());
        buffer
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, IpsecError> {
        if buffer.len() < IKE_HEADER_LEN {
            return Err(IpsecError::ike(
                "IKE message is shorter than its header",
            ));
        }
        let initiator_spi =
            u64::from_be_bytes(buffer[0..8].try_into().unwrap());
        let responder_spi =
            u64::from_be_bytes(buffer[8..16].try_into().unwrap());
        let next_payload = buffer[16];
        let version = buffer[17];
        let exchange = ExchangeType::from_u8(buffer[18]).ok_or_else(|| {
            IpsecError::new(
                IpsecErrorKind::NoSupport,
                "unsupported IKE exchange type",
            )
        })?;
        let flags = buffer[19];
        let message_id = u32::from_be_bytes(buffer[20..24].try_into().unwrap());
        let length = u32::from_be_bytes(buffer[24..28].try_into().unwrap());
        if (version & 0xf0) != IKE_VERSION_2 {
            return Err(IpsecError::ike("unsupported IKE major version"));
        }
        if length as usize > buffer.len() || (length as usize) < IKE_HEADER_LEN
        {
            return Err(IpsecError::ike("invalid IKE message length"));
        }
        Ok(Self {
            initiator_spi,
            responder_spi,
            next_payload,
            version,
            exchange,
            flags,
            message_id,
            length,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub number: u8,
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub transform_type: u8,
    pub id: u16,
    pub attributes: Vec<TransformAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformAttribute {
    /// Attribute type (AF bit is handled by the codec).
    pub type_: u16,
    pub value: Vec<u8>,
}

impl TransformAttribute {
    pub fn key_length(bits: u16) -> Self {
        Self {
            type_: 14,
            value: bits.to_be_bytes().to_vec(),
        }
    }

    pub fn key_length_bits(&self) -> Option<u16> {
        if self.type_ == 14 && self.value.len() == 2 {
            Some(u16::from_be_bytes([self.value[0], self.value[1]]))
        } else {
            None
        }
    }
}

/// A traffic selector payload entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsSelector {
    pub ts_type: u8,
    pub protocol: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start: std::net::IpAddr,
    pub end: std::net::IpAddr,
}

/// Configuration payload attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigAttribute {
    pub type_: u16,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Sa(Vec<Proposal>),
    Ke {
        group: u16,
        data: Vec<u8>,
    },
    Id {
        initiator: bool,
        id_type: u8,
        data: Vec<u8>,
    },
    Cert {
        encoding: u8,
        data: Vec<u8>,
    },
    CertReq {
        encoding: u8,
        data: Vec<u8>,
    },
    Auth {
        method: u8,
        data: Vec<u8>,
    },
    Nonce(Vec<u8>),
    Notify {
        protocol: u8,
        spi: Vec<u8>,
        notify_type: u16,
        data: Vec<u8>,
    },
    Delete {
        protocol: u8,
        spi_size: u8,
        spis: Vec<u32>,
    },
    Ts {
        initiator: bool,
        selectors: Vec<TsSelector>,
    },
    Config(Vec<ConfigAttribute>),
    Eap(Vec<u8>),
    Encrypted {
        next: u8,
        data: Vec<u8>,
    },
    Other {
        payload_type: u8,
        data: Vec<u8>,
    },
}

impl Payload {
    pub fn payload_type(&self) -> u8 {
        match self {
            Self::Sa(_) => payload_type::SA,
            Self::Ke { .. } => payload_type::KE,
            Self::Id { initiator, .. } => {
                if *initiator {
                    payload_type::IDI
                } else {
                    payload_type::IDR
                }
            }
            Self::Cert { .. } => payload_type::CERT,
            Self::CertReq { .. } => payload_type::CERTREQ,
            Self::Auth { .. } => payload_type::AUTH,
            Self::Nonce(_) => payload_type::NONCE,
            Self::Notify { .. } => payload_type::NOTIFY,
            Self::Delete { .. } => payload_type::DELETE,
            Self::Ts { initiator, .. } => {
                if *initiator {
                    payload_type::TSI
                } else {
                    payload_type::TSR
                }
            }
            Self::Config(_) => payload_type::CP,
            Self::Eap(_) => payload_type::EAP,
            Self::Encrypted { .. } => payload_type::SK,
            Self::Other { payload_type, .. } => *payload_type,
        }
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, IpsecError> {
        match self {
            Self::Sa(proposals) => encode_sa(proposals),
            Self::Ke { group, data } => {
                let mut body = Vec::with_capacity(4 + data.len());
                body.extend_from_slice(&group.to_be_bytes());
                body.extend_from_slice(&[0, 0]);
                body.extend_from_slice(data);
                Ok(body)
            }
            Self::Id { id_type, data, .. } => {
                let mut body = Vec::with_capacity(4 + data.len());
                body.push(*id_type);
                body.extend_from_slice(&[0, 0, 0]);
                body.extend_from_slice(data);
                Ok(body)
            }
            Self::Cert { encoding, data }
            | Self::CertReq { encoding, data } => {
                let mut body = Vec::with_capacity(1 + data.len());
                body.push(*encoding);
                body.extend_from_slice(data);
                Ok(body)
            }
            Self::Auth { method, data } => {
                let mut body = Vec::with_capacity(4 + data.len());
                body.push(*method);
                body.extend_from_slice(&[0, 0, 0]);
                body.extend_from_slice(data);
                Ok(body)
            }
            Self::Nonce(data) => Ok(data.clone()),
            Self::Notify {
                protocol,
                spi,
                notify_type,
                data,
            } => {
                if spi.len() > u8::MAX as usize {
                    return Err(IpsecError::ike("notify SPI is too long"));
                }
                let mut body = Vec::with_capacity(8 + spi.len() + data.len());
                body.push(*protocol);
                body.push(spi.len() as u8);
                body.extend_from_slice(&notify_type.to_be_bytes());
                body.extend_from_slice(spi);
                body.extend_from_slice(data);
                Ok(body)
            }
            Self::Delete {
                protocol,
                spi_size,
                spis,
            } => {
                let mut body =
                    Vec::with_capacity(4 + spis.len() * *spi_size as usize);
                body.push(*protocol);
                body.push(*spi_size);
                body.extend_from_slice(&(spis.len() as u16).to_be_bytes());
                for spi in spis {
                    match *spi_size {
                        4 => body.extend_from_slice(&spi.to_be_bytes()),
                        8 => {
                            body.extend_from_slice(&(*spi as u64).to_be_bytes())
                        }
                        _ => {
                            return Err(IpsecError::ike(
                                "invalid delete SPI size",
                            ));
                        }
                    }
                }
                Ok(body)
            }
            Self::Ts { selectors, .. } => {
                let mut body = Vec::with_capacity(4 + selectors.len() * 16);
                body.push(selectors.len() as u8);
                body.extend_from_slice(&[0, 0, 0]);
                for selector in selectors {
                    encode_ts_selector(selector, &mut body)?;
                }
                Ok(body)
            }
            Self::Config(attributes) => {
                let mut body = Vec::new();
                for attribute in attributes {
                    if attribute.value.len() > u16::MAX as usize {
                        return Err(IpsecError::ike(
                            "configuration attribute is too long",
                        ));
                    }
                    body.extend_from_slice(&attribute.type_.to_be_bytes());
                    body.extend_from_slice(
                        &(attribute.value.len() as u16).to_be_bytes(),
                    );
                    body.extend_from_slice(&attribute.value);
                }
                Ok(body)
            }
            Self::Eap(data) => Ok(data.clone()),
            Self::Encrypted { data, .. } => Ok(data.clone()),
            Self::Other { data, .. } => Ok(data.clone()),
        }
    }
}

/// A complete IKE message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: IkeHeader,
    pub payloads: Vec<Payload>,
}

impl Message {
    pub fn new(header: IkeHeader, payloads: Vec<Payload>) -> Self {
        Self { header, payloads }
    }

    pub fn encode(&self) -> Result<Vec<u8>, IpsecError> {
        let chain = encode_chain(&self.payloads)?;
        let mut header = self.header.clone();
        header.next_payload = self
            .payloads
            .first()
            .map(Payload::payload_type)
            .unwrap_or(payload_type::NONE);
        let mut buffer = header.encode();
        buffer.extend_from_slice(&chain);
        let length = buffer.len() as u32;
        buffer[24..28].copy_from_slice(&length.to_be_bytes());
        Ok(buffer)
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, IpsecError> {
        let header = IkeHeader::decode(buffer)?;
        let buffer = &buffer[..header.length as usize];
        let payloads =
            decode_chain(header.next_payload, &buffer[IKE_HEADER_LEN..])?;
        Ok(Self { header, payloads })
    }

    pub fn payload(&self, kind: u8) -> Option<&Payload> {
        self.payloads
            .iter()
            .find(|payload| payload.payload_type() == kind)
    }
}

fn encode_sa(proposals: &[Proposal]) -> Result<Vec<u8>, IpsecError> {
    let mut body = Vec::new();
    for (index, proposal) in proposals.iter().enumerate() {
        let mut transforms = Vec::new();
        for (t_index, transform) in proposal.transforms.iter().enumerate() {
            let mut attributes = Vec::new();
            for attribute in &transform.attributes {
                if attribute.type_ == 14 && attribute.value.len() == 2 {
                    attributes.extend_from_slice(
                        &(0x8000 | attribute.type_).to_be_bytes(),
                    );
                    attributes.extend_from_slice(&attribute.value);
                } else {
                    attributes
                        .extend_from_slice(&attribute.type_.to_be_bytes());
                    attributes.extend_from_slice(
                        &(attribute.value.len() as u16).to_be_bytes(),
                    );
                    attributes.extend_from_slice(&attribute.value);
                }
            }
            let transform_len = 8 + attributes.len();
            transforms.push((
                t_index == proposal.transforms.len() - 1,
                transform,
                attributes,
                transform_len,
            ));
        }
        let mut proposal_body = Vec::new();
        proposal_body.push(proposal.number);
        proposal_body.push(proposal.protocol);
        if proposal.spi.len() > u8::MAX as usize {
            return Err(IpsecError::ike("proposal SPI is too long"));
        }
        proposal_body.push(proposal.spi.len() as u8);
        proposal_body.push(proposal.transforms.len() as u8);
        proposal_body.extend_from_slice(&proposal.spi);
        for (last, transform, attributes, transform_len) in transforms {
            proposal_body.push(if last { 0 } else { 3 });
            proposal_body.push(0);
            proposal_body
                .extend_from_slice(&(transform_len as u16).to_be_bytes());
            proposal_body.push(transform.transform_type);
            proposal_body.push(0);
            proposal_body.extend_from_slice(&transform.id.to_be_bytes());
            proposal_body.extend_from_slice(&attributes);
        }
        let proposal_len = 8
            + proposal.spi.len()
            + (proposal_body.len() - 4 - proposal.spi.len());
        body.push(if index == proposals.len() - 1 { 0 } else { 2 });
        body.push(0);
        body.extend_from_slice(&(proposal_len as u16).to_be_bytes());
        body.extend_from_slice(&proposal_body);
    }
    Ok(body)
}

fn decode_sa(body: &[u8]) -> Result<Vec<Proposal>, IpsecError> {
    let mut proposals = Vec::new();
    let mut offset = 0;
    while offset + 8 <= body.len() {
        let last = body[offset];
        let length =
            u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        if length < 8 || offset + length > body.len() {
            return Err(IpsecError::ike("invalid proposal length"));
        }
        let proposal = &body[offset..offset + length];
        let number = proposal[4];
        let protocol = proposal[5];
        let spi_len = proposal[6] as usize;
        let transform_count = proposal[7] as usize;
        if 8 + spi_len > proposal.len() {
            return Err(IpsecError::ike("invalid proposal SPI length"));
        }
        let spi = proposal[8..8 + spi_len].to_vec();
        let mut cursor = 8 + spi_len;
        let mut transforms = Vec::new();
        for _ in 0..transform_count {
            if cursor + 8 > proposal.len() {
                return Err(IpsecError::ike("truncated transform"));
            }
            let transform_len = u16::from_be_bytes([
                proposal[cursor + 2],
                proposal[cursor + 3],
            ]) as usize;
            if transform_len < 8 || cursor + transform_len > proposal.len() {
                return Err(IpsecError::ike("invalid transform length"));
            }
            let transform_type = proposal[cursor + 4];
            let id = u16::from_be_bytes([
                proposal[cursor + 6],
                proposal[cursor + 7],
            ]);
            let mut attributes = Vec::new();
            let mut attr_cursor = cursor + 8;
            while attr_cursor + 4 <= cursor + transform_len {
                let type_ = u16::from_be_bytes([
                    proposal[attr_cursor],
                    proposal[attr_cursor + 1],
                ]);
                let af = type_ & 0x8000 != 0;
                let type_ = type_ & 0x7fff;
                if af {
                    if attr_cursor + 4 > cursor + transform_len {
                        return Err(IpsecError::ike(
                            "truncated transform attribute",
                        ));
                    }
                    let value =
                        proposal[attr_cursor + 2..attr_cursor + 4].to_vec();
                    attributes.push(TransformAttribute { type_, value });
                    attr_cursor += 4;
                } else {
                    let len = u16::from_be_bytes([
                        proposal[attr_cursor + 2],
                        proposal[attr_cursor + 3],
                    ]) as usize;
                    if attr_cursor + 4 + len > cursor + transform_len {
                        return Err(IpsecError::ike(
                            "invalid transform attribute length",
                        ));
                    }
                    attributes.push(TransformAttribute {
                        type_,
                        value: proposal[attr_cursor + 4..attr_cursor + 4 + len]
                            .to_vec(),
                    });
                    attr_cursor += 4 + len;
                }
            }
            transforms.push(Transform {
                transform_type,
                id,
                attributes,
            });
            cursor += transform_len;
        }
        proposals.push(Proposal {
            number,
            protocol,
            spi,
            transforms,
        });
        offset += length;
        if last == 0 {
            break;
        }
    }
    Ok(proposals)
}

fn encode_ts_selector(
    selector: &TsSelector,
    buffer: &mut Vec<u8>,
) -> Result<(), IpsecError> {
    buffer.push(selector.ts_type);
    buffer.push(selector.protocol);
    buffer.extend_from_slice(&(16u16).to_be_bytes());
    buffer.extend_from_slice(&selector.start_port.to_be_bytes());
    buffer.extend_from_slice(&selector.end_port.to_be_bytes());
    match (selector.start, selector.end) {
        (std::net::IpAddr::V4(start), std::net::IpAddr::V4(end)) => {
            buffer.extend_from_slice(&start.octets());
            buffer.extend_from_slice(&end.octets());
        }
        (std::net::IpAddr::V6(start), std::net::IpAddr::V6(end)) => {
            buffer.extend_from_slice(&start.octets());
            buffer.extend_from_slice(&end.octets());
        }
        _ => {
            return Err(IpsecError::ike(
                "traffic selector address families differ",
            ));
        }
    }
    Ok(())
}

fn decode_ts(body: &[u8]) -> Result<Vec<TsSelector>, IpsecError> {
    if body.len() < 4 {
        return Err(IpsecError::ike("truncated traffic selector payload"));
    }
    let count = body[0] as usize;
    let mut offset = 4;
    let mut selectors = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 8 > body.len() {
            return Err(IpsecError::ike("truncated traffic selector"));
        }
        let ts_type = body[offset];
        let protocol = body[offset + 1];
        let length =
            u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        if length < 8 || offset + length > body.len() {
            return Err(IpsecError::ike("invalid traffic selector length"));
        }
        let start_port =
            u16::from_be_bytes([body[offset + 4], body[offset + 5]]);
        let end_port = u16::from_be_bytes([body[offset + 6], body[offset + 7]]);
        let (start, end) = match ts_type {
            7 | 8 => {
                if length != 16 {
                    return Err(IpsecError::ike(
                        "invalid IPv4 traffic selector length",
                    ));
                }
                (
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        body[offset + 8],
                        body[offset + 9],
                        body[offset + 10],
                        body[offset + 11],
                    )),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        body[offset + 12],
                        body[offset + 13],
                        body[offset + 14],
                        body[offset + 15],
                    )),
                )
            }
            9 | 10 => {
                if length != 40 {
                    return Err(IpsecError::ike(
                        "invalid IPv6 traffic selector length",
                    ));
                }
                (
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(&body[offset + 8..offset + 24])
                            .unwrap(),
                    )),
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(&body[offset + 24..offset + 40])
                            .unwrap(),
                    )),
                )
            }
            other => {
                return Err(IpsecError::new(
                    IpsecErrorKind::NoSupport,
                    format!("unsupported traffic selector type {other}"),
                ));
            }
        };
        selectors.push(TsSelector {
            ts_type,
            protocol,
            start_port,
            end_port,
            start,
            end,
        });
        offset += length;
    }
    Ok(selectors)
}

fn decode_payload(
    kind: u8,
    body: &[u8],
    next: u8,
) -> Result<Payload, IpsecError> {
    match kind {
        payload_type::SA => Ok(Payload::Sa(decode_sa(body)?)),
        payload_type::KE => {
            if body.len() < 4 {
                return Err(IpsecError::ike("truncated key exchange payload"));
            }
            Ok(Payload::Ke {
                group: u16::from_be_bytes([body[0], body[1]]),
                data: body[4..].to_vec(),
            })
        }
        payload_type::IDI | payload_type::IDR => {
            if body.len() < 4 {
                return Err(IpsecError::ike(
                    "truncated identification payload",
                ));
            }
            Ok(Payload::Id {
                initiator: kind == payload_type::IDI,
                id_type: body[0],
                data: body[4..].to_vec(),
            })
        }
        payload_type::CERT => {
            if body.is_empty() {
                return Err(IpsecError::ike("truncated certificate payload"));
            }
            Ok(Payload::Cert {
                encoding: body[0],
                data: body[1..].to_vec(),
            })
        }
        payload_type::CERTREQ => {
            if body.is_empty() {
                return Err(IpsecError::ike(
                    "truncated certificate request payload",
                ));
            }
            Ok(Payload::CertReq {
                encoding: body[0],
                data: body[1..].to_vec(),
            })
        }
        payload_type::AUTH => {
            if body.len() < 4 {
                return Err(IpsecError::ike(
                    "truncated authentication payload",
                ));
            }
            Ok(Payload::Auth {
                method: body[0],
                data: body[4..].to_vec(),
            })
        }
        payload_type::NONCE => Ok(Payload::Nonce(body.to_vec())),
        payload_type::NOTIFY => {
            if body.len() < 4 {
                return Err(IpsecError::ike("truncated notify payload"));
            }
            let protocol = body[0];
            let spi_size = body[1] as usize;
            let notify_type = u16::from_be_bytes([body[2], body[3]]);
            if 4 + spi_size > body.len() {
                return Err(IpsecError::ike("invalid notify SPI length"));
            }
            Ok(Payload::Notify {
                protocol,
                spi: body[4..4 + spi_size].to_vec(),
                notify_type,
                data: body[4 + spi_size..].to_vec(),
            })
        }
        payload_type::DELETE => {
            if body.len() < 4 {
                return Err(IpsecError::ike("truncated delete payload"));
            }
            let protocol = body[0];
            let spi_size = body[1] as usize;
            let count = u16::from_be_bytes([body[2], body[3]]) as usize;
            if !matches!(spi_size, 0 | 4 | 8)
                || 4 + count * spi_size > body.len()
            {
                return Err(IpsecError::ike("invalid delete payload"));
            }
            let mut spis = Vec::with_capacity(count);
            for index in 0..count {
                let start = 4 + index * spi_size;
                let spi = match spi_size {
                    4 => u32::from_be_bytes(
                        body[start..start + 4].try_into().unwrap(),
                    ),
                    8 => {
                        let high = u32::from_be_bytes(
                            body[start..start + 4].try_into().unwrap(),
                        );
                        let low = u32::from_be_bytes(
                            body[start + 4..start + 8].try_into().unwrap(),
                        );
                        if high != 0 {
                            return Err(IpsecError::ike(
                                "64-bit SPI does not fit the IKE SPI \
                                 representation",
                            ));
                        }
                        low
                    }
                    _ => 0,
                };
                spis.push(spi);
            }
            Ok(Payload::Delete {
                protocol,
                spi_size: spi_size as u8,
                spis,
            })
        }
        payload_type::TSI => Ok(Payload::Ts {
            initiator: true,
            selectors: decode_ts(body)?,
        }),
        payload_type::TSR => Ok(Payload::Ts {
            initiator: false,
            selectors: decode_ts(body)?,
        }),
        payload_type::CP => {
            let mut attributes = Vec::new();
            let mut offset = 0;
            while offset + 4 <= body.len() {
                let type_ =
                    u16::from_be_bytes([body[offset], body[offset + 1]])
                        & 0x7fff;
                let length =
                    u16::from_be_bytes([body[offset + 2], body[offset + 3]])
                        as usize;
                if offset + 4 + length > body.len() {
                    return Err(IpsecError::ike(
                        "invalid configuration attribute length",
                    ));
                }
                attributes.push(ConfigAttribute {
                    type_,
                    value: body[offset + 4..offset + 4 + length].to_vec(),
                });
                offset += 4 + length;
            }
            Ok(Payload::Config(attributes))
        }
        payload_type::EAP => Ok(Payload::Eap(body.to_vec())),
        payload_type::SK => Ok(Payload::Encrypted {
            next,
            data: body.to_vec(),
        }),
        other => Ok(Payload::Other {
            payload_type: other,
            data: body.to_vec(),
        }),
    }
}

/// Encode a payload chain without the IKE header.  The first generic
/// header's next-payload field is derived from the following payload.
pub fn encode_chain(payloads: &[Payload]) -> Result<Vec<u8>, IpsecError> {
    let bodies: Vec<(u8, Vec<u8>)> = payloads
        .iter()
        .map(|payload| Ok((payload.payload_type(), payload.encode_body()?)))
        .collect::<Result<_, IpsecError>>()?;
    let mut buffer = Vec::new();
    for (index, (kind, body)) in bodies.iter().enumerate() {
        let next = bodies
            .get(index + 1)
            .map(|(kind, _)| *kind)
            .unwrap_or(payload_type::NONE);
        let length = 4 + body.len();
        if length > u16::MAX as usize {
            return Err(IpsecError::ike("payload is too long"));
        }
        buffer.push(next);
        buffer.push(0);
        buffer.extend_from_slice(&(length as u16).to_be_bytes());
        buffer.extend_from_slice(body);
        let _ = kind;
    }
    Ok(buffer)
}

/// Decode a payload chain starting with `first_type`.
pub fn decode_chain(
    first_type: u8,
    mut data: &[u8],
) -> Result<Vec<Payload>, IpsecError> {
    let mut payload_type = first_type;
    let mut payloads = Vec::new();
    while payload_type != payload_type::NONE {
        if data.len() < 4 {
            return Err(IpsecError::ike("truncated payload header"));
        }
        let next = data[0];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if length < 4 || length > data.len() {
            return Err(IpsecError::ike("invalid payload length"));
        }
        let body = &data[4..length];
        let current = payload_type;
        payloads.push(decode_payload(current, body, next)?);
        data = &data[length..];
        if current == payload_type::SK {
            break;
        }
        payload_type = next;
    }
    if !data.is_empty() {
        return Err(IpsecError::ike(format!(
            "trailing bytes after last IKE payload ({} bytes)",
            data.len()
        )));
    }
    Ok(payloads)
}

impl fmt::Display for ExchangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IkeSaInit => f.write_str("IKE_SA_INIT"),
            Self::IkeAuth => f.write_str("IKE_AUTH"),
            Self::CreateChildSa => f.write_str("CREATE_CHILD_SA"),
            Self::Informational => f.write_str("INFORMATIONAL"),
        }
    }
}

/// Algorithm transform constants used by the proposal code.
pub mod transform_type {
    pub const ENCR: u8 = 1;
    pub const PRF: u8 = 2;
    pub const INTEG: u8 = 3;
    pub const DH: u8 = 4;
    pub const ESN: u8 = 5;
}

/// Helper converting a proposal to wire transforms.
pub fn ike_transforms(
    encryption: EncryptionAlgorithm,
    prf: PrfAlgorithm,
    integrity: IntegrityAlgorithm,
    dh: DhGroup,
) -> Vec<Transform> {
    let mut transforms = vec![Transform {
        transform_type: transform_type::ENCR,
        id: encryption.transform_id(),
        attributes: encryption
            .key_len_bits()
            .map(|bits| vec![TransformAttribute::key_length(bits)])
            .unwrap_or_default(),
    }];
    transforms.push(Transform {
        transform_type: transform_type::PRF,
        id: prf.transform_id(),
        attributes: Vec::new(),
    });
    if integrity != IntegrityAlgorithm::None {
        transforms.push(Transform {
            transform_type: transform_type::INTEG,
            id: integrity.transform_id(),
            attributes: Vec::new(),
        });
    }
    if dh != DhGroup::None {
        transforms.push(Transform {
            transform_type: transform_type::DH,
            id: dh.transform_id(),
            attributes: Vec::new(),
        });
    }
    transforms
}

/// Helper converting an ESP proposal to wire transforms.
pub fn esp_transforms(
    encryption: EncryptionAlgorithm,
    integrity: IntegrityAlgorithm,
    esn: bool,
    dh: DhGroup,
) -> Vec<Transform> {
    let mut transforms = vec![Transform {
        transform_type: transform_type::ENCR,
        id: encryption.transform_id(),
        attributes: encryption
            .key_len_bits()
            .map(|bits| vec![TransformAttribute::key_length(bits)])
            .unwrap_or_default(),
    }];
    if integrity != IntegrityAlgorithm::None {
        transforms.push(Transform {
            transform_type: transform_type::INTEG,
            id: integrity.transform_id(),
            attributes: Vec::new(),
        });
    }
    transforms.push(Transform {
        transform_type: transform_type::ESN,
        id: if esn { 1 } else { 0 },
        attributes: Vec::new(),
    });
    if dh != DhGroup::None {
        transforms.push(Transform {
            transform_type: transform_type::DH,
            id: dh.transform_id(),
            attributes: Vec::new(),
        });
    }
    transforms
}
