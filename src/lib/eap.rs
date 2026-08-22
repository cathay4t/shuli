// SPDX-License-Identifier: Apache-2.0

//! EAP (Extensible Authentication Protocol, RFC 3748) peer framing and
//! state machine.
//!
//! Shared by WiFi 802.1X (EAP over the nl80211 control
//! port) and wired 802.1X (EAPOL over Ethernet).  The EAPOL
//! framing itself lives in [`crate::ieee80211::eapol`]; this module
//! handles the EAP packet codec and the peer state machine.

use crate::{ErrorKind, WifiError};

/// EAP Code values (RFC 3748 §4.1).
pub const CODE_REQUEST: u8 = 1;
pub const CODE_RESPONSE: u8 = 2;
pub const CODE_SUCCESS: u8 = 3;
pub const CODE_FAILURE: u8 = 4;

/// EAP Type values (RFC 3748 §5 / IANA registry).
pub const TYPE_IDENTITY: u8 = 1;
pub const TYPE_NOTIFICATION: u8 = 2;
pub const TYPE_NAK: u8 = 3;
/// EAP-TLS (RFC 5216) / EAP-TLS 1.3 (RFC 9190).
pub const TYPE_TLS: u8 = 13;

/// Minimum EAP packet size: code(1) + identifier(1) + length(2).
pub const EAP_HDR_LEN: usize = 4;
/// EAP method MSK length in octets (RFC 3748 §7.10).
pub const MSK_LEN: usize = 64;

/// A parsed or built EAP packet.  `type_` is `None` for Success /
/// Failure, which carry no Type field (RFC 3748 §4.2/4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EapPacket {
    pub code: u8,
    pub identifier: u8,
    pub type_: Option<u8>,
    pub body: Vec<u8>,
}

impl EapPacket {
    /// Build an EAP packet: code(1) identifier(1) length(2) [type(1)]
    /// body.
    pub fn build(
        code: u8,
        identifier: u8,
        type_: Option<u8>,
        body: &[u8],
    ) -> Vec<u8> {
        let length = EAP_HDR_LEN + usize::from(type_.is_some()) + body.len();
        let mut pdu = vec![code, identifier];
        pdu.extend_from_slice(&(length as u16).to_be_bytes());
        if let Some(t) = type_ {
            pdu.push(t);
        }
        pdu.extend_from_slice(body);
        pdu
    }

    /// Parse an EAP packet.  The length field bounds the packet; a
    /// trailing buffer (e.g. a full EAPOL frame) is ignored by the
    /// caller passing just the EAP payload.
    pub fn parse(pdu: &[u8]) -> Option<Self> {
        if pdu.len() < EAP_HDR_LEN {
            return None;
        }
        let code = pdu[0];
        let identifier = pdu[1];
        let length = u16::from_be_bytes([pdu[2], pdu[3]]) as usize;
        if !(EAP_HDR_LEN..=pdu.len()).contains(&length) {
            return None;
        }
        let (type_, body_start) = match code {
            CODE_SUCCESS | CODE_FAILURE => (None, EAP_HDR_LEN),
            CODE_REQUEST | CODE_RESPONSE => {
                if length < EAP_HDR_LEN + 1 {
                    return None;
                }
                (Some(pdu[4]), EAP_HDR_LEN + 1)
            }
            _ => return None,
        };
        Some(Self {
            code,
            identifier,
            type_,
            body: pdu[body_start..length].to_vec(),
        })
    }

    pub fn is_success(&self) -> bool {
        self.code == CODE_SUCCESS
    }

    pub fn is_failure(&self) -> bool {
        self.code == CODE_FAILURE
    }
}

/// One EAP method (e.g. EAP-TLS).  The peer hands every
/// method-type Request to the active method; the method returns the
/// Response body (EAP framing is applied by [`EapPeer`]).
pub trait EapMethod: Send {
    /// This method's EAP Type (e.g. [`TYPE_TLS`]).
    fn method_type(&self) -> u8;

    /// Handle an EAP-Request of this method's type and return the
    /// EAP-Response body.
    fn handle_request(
        &mut self,
        identifier: u8,
        body: &[u8],
    ) -> Result<Vec<u8>, WifiError>;

    /// The 64-octet MSK once the method completed, `None` before.
    fn msk(&self) -> Option<[u8; MSK_LEN]>;
}

/// What the caller should do after feeding a packet to
/// [`EapPeer::handle_packet`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EapAction {
    /// Send this EAP-Response packet (already framed).
    Respond(Vec<u8>),
    /// EAP-Success: authentication complete, port authorized.
    Success,
    /// EAP-Failure: authentication rejected.
    Failure,
    /// Nothing to send; wait for the next authenticator packet.
    Wait,
}

/// EAP peer state machine.  Identity is handled here; method types are
/// delegated to an [`EapMethod`] when one is set, otherwise answered
/// with a Nak listing `supported_types`.
#[non_exhaustive]
pub struct EapPeer {
    identity: String,
    method: Option<Box<dyn EapMethod>>,
    supported_types: Vec<u8>,
}

impl EapPeer {
    pub fn new(identity: String) -> Self {
        Self {
            identity,
            method: None,
            supported_types: Vec::new(),
        }
    }

    /// Install the active EAP method (e.g. EAP-TLS).
    pub fn set_method(&mut self, method: Box<dyn EapMethod>) {
        self.method = Some(method);
    }

    /// The method's MSK, once the method completed.
    pub fn msk(&self) -> Option<[u8; MSK_LEN]> {
        self.method.as_ref().and_then(|m| m.msk())
    }

    /// Feed an authenticator packet into the state machine.
    pub fn handle_packet(
        &mut self,
        packet: &EapPacket,
    ) -> Result<EapAction, WifiError> {
        if packet.is_success() {
            return Ok(EapAction::Success);
        }
        if packet.is_failure() {
            return Ok(EapAction::Failure);
        }
        if packet.code != CODE_REQUEST {
            // A Response from the authenticator is not part of the
            // supplicant flow; ignore it.
            return Ok(EapAction::Wait);
        }

        let Some(type_) = packet.type_ else {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                "EAP Request without a Type",
            ));
        };
        let response = match type_ {
            TYPE_IDENTITY => EapPacket::build(
                CODE_RESPONSE,
                packet.identifier,
                Some(TYPE_IDENTITY),
                self.identity.as_bytes(),
            ),
            TYPE_NOTIFICATION => {
                // RFC 3748 §5.2: acknowledge with an empty
                // Notification response.
                EapPacket::build(
                    CODE_RESPONSE,
                    packet.identifier,
                    Some(TYPE_NOTIFICATION),
                    b"",
                )
            }
            TYPE_NAK => {
                // The authenticator answered our Nak; nothing to do.
                return Ok(EapAction::Wait);
            }
            type_
                if self
                    .method
                    .as_ref()
                    .is_some_and(|m| m.method_type() == type_) =>
            {
                let method = self.method.as_mut().unwrap();
                let body =
                    method.handle_request(packet.identifier, &packet.body)?;
                EapPacket::build(
                    CODE_RESPONSE,
                    packet.identifier,
                    Some(type_),
                    &body,
                )
            }
            _ => {
                // Unknown / unsupported method: Nak with the types we
                // can do (RFC 3748 §5.3).
                let mut body = self.supported_types.clone();
                body.retain(|t| *t != TYPE_IDENTITY && *t != TYPE_NAK);
                EapPacket::build(
                    CODE_RESPONSE,
                    packet.identifier,
                    Some(TYPE_NAK),
                    &body,
                )
            }
        };
        Ok(EapAction::Respond(response))
    }
}
