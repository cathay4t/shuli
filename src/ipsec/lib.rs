// SPDX-License-Identifier: Apache-2.0

//! Native IKEv2 and Linux XFRM support for shuli.
//!
//! The crate has two independent public layers:
//!
//! - [`IpsecClient`] negotiates IKE/Child SAs and reports key material and
//!   address leases as opaque handles.
//! - [`XfrmManager`] installs and removes the corresponding XFRM state,
//!   policies, and XFRM interfaces.
//!
//! Neither layer assigns IP addresses, installs ordinary routes, or writes
//! DNS configuration; that remains the job of shulid or nipart.

mod client;
pub mod config;
mod error;
mod identity;
pub mod ikev2;
pub mod xfrm;

#[cfg(test)]
mod tests;

/// Alias for the EAP-TLS client configuration used by
/// [`AuthConfig::EapTls`].
pub type EapConfig = EapTlsConfig;

pub use self::{
    client::{
        ChildSaHandle, ChildSaRemovalReason, IpsecClient, IpsecEvent,
        IpsecLease, IpsecState,
    },
    config::{
        AuthConfig, CertificateConfig, ChildConfig, ChildMode, DhGroup,
        DpdConfig, EapTlsConfig, EncryptionAlgorithm, IkeConfig, IkeProposal,
        IntegrityAlgorithm, IpNet, IpsecConfig, LocalConfig, PeerConfig,
        PrfAlgorithm, ProposalSet, RekeyConfig, RemoteConfig, Secret, Topology,
        TrafficSelector, TrafficSelectorPair, XfrmConfig,
    },
    error::{IpsecError, IpsecErrorKind},
    identity::Identity,
    xfrm::{
        InstallSpec, InstalledChildSa, XfrmInterface, XfrmInterfaceSpec,
        XfrmManager,
    },
};
