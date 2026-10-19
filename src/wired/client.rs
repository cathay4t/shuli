// SPDX-License-Identifier: Apache-2.0

//! Unified wired client: 802.1X/EAP and MACsec/MKA.

use shuli_core::{EapConfig, WifiError};

use crate::{
    eap::{EapClient, EapState},
    mka::{MacsecConfig, MkaSession},
};

/// Authentication mode for a wired port.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WiredAuth {
    /// Wired 802.1X with EAP-TLS.
    Eap(EapConfig),
    /// MACsec with MKA (pre-shared CAK).
    Macsec(MacsecConfig),
}

/// Connection state of a wired port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WiredState {
    /// Socket ready; nothing sent yet.
    Init,
    /// EAP exchange in progress.
    Authenticating,
    /// EAP succeeded; MKA/MACsec is being established.
    Securing,
    /// Port authorized (EAP) or MACsec data path secured (MKA).
    Connected,
    /// Authentication or MKA failed; retry with a fresh client.
    Failed,
}

enum Mode {
    Eap(EapClient),
    Macsec(Box<MkaSession>),
}

/// A wired 802.1X/MACsec client for one Ethernet interface.
#[non_exhaustive]
pub struct WiredClient {
    mode: Mode,
    state: WiredState,
}

impl WiredClient {
    /// Create a wired 802.1X/EAP client (compatibility constructor).
    pub fn init(iface_name: &str, eap: &EapConfig) -> Result<Self, WifiError> {
        Self::init_with_auth(iface_name, WiredAuth::Eap(eap.clone()))
    }

    /// Create a wired client for the selected authentication mode.
    pub fn init_with_auth(
        iface_name: &str,
        auth: WiredAuth,
    ) -> Result<Self, WifiError> {
        let mode = match auth {
            WiredAuth::Eap(eap) => {
                Mode::Eap(EapClient::init(iface_name, &eap)?)
            }
            WiredAuth::Macsec(config) => {
                Mode::Macsec(Box::new(MkaSession::new(iface_name, &config)?))
            }
        };
        Ok(Self {
            mode,
            state: WiredState::Init,
        })
    }

    pub fn state(&self) -> WiredState {
        self.state
    }

    /// Advance the wired authentication flow by one step.
    pub async fn run(&mut self) -> Result<WiredState, WifiError> {
        self.state = match &mut self.mode {
            Mode::Eap(client) => match client.run().await? {
                EapState::Init => WiredState::Init,
                EapState::Authenticating => WiredState::Authenticating,
                EapState::Connected => WiredState::Connected,
                EapState::Failed => WiredState::Failed,
            },
            Mode::Macsec(session) => {
                if session.run().await? {
                    WiredState::Connected
                } else {
                    WiredState::Securing
                }
            }
        };
        Ok(self.state)
    }
}
