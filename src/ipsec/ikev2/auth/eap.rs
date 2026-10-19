// SPDX-License-Identifier: Apache-2.0

//! EAP-TLS client bridge for IKEv2 EAP authentication.

use shuli_core::{
    EapTlsMethod,
    eap::{EapAction, EapPacket, EapPeer, MSK_LEN},
};

use crate::{config::EapTlsConfig, error::IpsecError};

pub(crate) struct EapSession {
    peer: EapPeer,
}

impl EapSession {
    pub(crate) fn new(config: &EapTlsConfig) -> Result<Self, IpsecError> {
        config.validate()?;
        let core = config.to_core();
        let method = EapTlsMethod::from_config(&core)?;
        let mut peer = EapPeer::new(config.identity.clone());
        peer.set_method(Box::new(method));
        Ok(Self { peer })
    }

    /// Feed one EAP packet received in an EAP payload.  Returns the
    /// response packet to send, if any, and whether authentication
    /// completed.
    pub(crate) fn handle(
        &mut self,
        packet: &[u8],
    ) -> Result<(Option<Vec<u8>>, bool), IpsecError> {
        let packet = EapPacket::parse(packet).ok_or_else(|| {
            IpsecError::new(
                crate::error::IpsecErrorKind::Eap,
                "malformed EAP packet",
            )
        })?;
        match self.peer.handle_packet(&packet)? {
            EapAction::Respond(response) => Ok((Some(response), false)),
            EapAction::Success => Ok((None, true)),
            EapAction::Failure => Err(IpsecError::authentication(
                "EAP authentication rejected by the peer",
            )),
            EapAction::Wait => Ok((None, false)),
            _ => Ok((None, false)),
        }
    }

    pub(crate) fn msk(&self) -> Option<[u8; MSK_LEN]> {
        self.peer.msk()
    }
}
