// SPDX-License-Identifier: Apache-2.0

use std::{fmt, io, net::IpAddr};

/// Broad category of an [`IpsecError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IpsecErrorKind {
    /// Invalid user configuration.
    Config,
    /// Underlying I/O failure.
    Io,
    /// Netlink transport or kernel request failure.
    Netlink,
    /// Failed to decode a netlink message.
    NetlinkDecode,
    /// XFRM operation failed.
    Xfrm,
    /// IKE protocol or state-machine failure.
    Ike,
    /// Peer authentication failed.
    Authentication,
    /// No mutually supported proposal.
    Proposal,
    /// Peer identity did not match the configuration or certificate.
    Identity,
    /// Certificate parsing or validation failure.
    Certificate,
    /// EAP/EAP-TLS failure.
    Eap,
    /// Operation timed out.
    Timeout,
    /// The requested configuration does not match a known peer.
    PeerNotFound,
    /// The requested feature is not implemented by this build.
    NoSupport,
    /// Resource allocation or internal invariant failure.
    Internal,
}

impl fmt::Display for IpsecErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Config => "config",
            Self::Io => "io",
            Self::Netlink => "netlink",
            Self::NetlinkDecode => "netlink-decode",
            Self::Xfrm => "xfrm",
            Self::Ike => "ike",
            Self::Authentication => "authentication",
            Self::Proposal => "proposal",
            Self::Identity => "identity",
            Self::Certificate => "certificate",
            Self::Eap => "eap",
            Self::Timeout => "timeout",
            Self::PeerNotFound => "peer-not-found",
            Self::NoSupport => "no-support",
            Self::Internal => "internal",
        };
        f.write_str(name)
    }
}

/// Error type shared by the IKE and XFRM layers.
///
/// This type is non-exhaustive so fields can be added without breaking
/// consumers; construct errors through the provided constructors.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsecError {
    pub kind: IpsecErrorKind,
    pub msg: String,
    pub connection: Option<String>,
    pub peer: Option<IpAddr>,
}

impl IpsecError {
    pub fn new(kind: IpsecErrorKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            msg: msg.into(),
            connection: None,
            peer: None,
        }
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::new(IpsecErrorKind::Config, msg)
    }

    pub fn xfrm(msg: impl Into<String>) -> Self {
        Self::new(IpsecErrorKind::Xfrm, msg)
    }

    pub fn ike(msg: impl Into<String>) -> Self {
        Self::new(IpsecErrorKind::Ike, msg)
    }

    pub fn authentication(msg: impl Into<String>) -> Self {
        Self::new(IpsecErrorKind::Authentication, msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(IpsecErrorKind::Internal, msg)
    }

    pub fn with_connection(mut self, connection: impl Into<String>) -> Self {
        self.connection = Some(connection.into());
        self
    }

    pub fn with_peer(mut self, peer: IpAddr) -> Self {
        self.peer = Some(peer);
        self
    }
}

impl fmt::Display for IpsecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)?;
        if let Some(connection) = &self.connection {
            write!(f, " [connection {connection}]")?;
        }
        if let Some(peer) = self.peer {
            write!(f, " [peer {peer}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for IpsecError {}

impl From<io::Error> for IpsecError {
    fn from(e: io::Error) -> Self {
        Self::new(IpsecErrorKind::Io, e.to_string())
    }
}

impl From<netlink_packet_core::DecodeError> for IpsecError {
    fn from(e: netlink_packet_core::DecodeError) -> Self {
        Self::new(IpsecErrorKind::NetlinkDecode, e.to_string())
    }
}

impl From<shuli_core::WifiError> for IpsecError {
    fn from(e: shuli_core::WifiError) -> Self {
        let kind = match e.kind {
            shuli_core::ErrorKind::AuthFailed
            | shuli_core::ErrorKind::WrongPassword => {
                IpsecErrorKind::Authentication
            }
            shuli_core::ErrorKind::InvalidConfig
            | shuli_core::ErrorKind::Config => IpsecErrorKind::Config,
            shuli_core::ErrorKind::HandshakeFailed => IpsecErrorKind::Eap,
            _ => IpsecErrorKind::Eap,
        };
        Self::new(kind, e.to_string())
    }
}
