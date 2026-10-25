// SPDX-License-Identifier: Apache-2.0

//! IKE identity handling.

use std::{fmt, net::IpAddr, str::FromStr};

use crate::error::IpsecError;

/// An IKEv2 identification payload value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum Identity {
    /// IPv4 or IPv6 address (ID types 1 and 5).
    Ip(IpAddr),
    /// Fully qualified domain name (ID type 2).
    Fqdn(String),
    /// RFC 822 email address (ID type 3).
    Email(String),
    /// X.500 distinguished name encoded as DER (ID type 9).
    DerAsn1Dn(Vec<u8>),
    /// Opaque key identifier (ID type 11).
    KeyId(Vec<u8>),
    /// Matches any peer identity.  Valid only for configured remote
    /// identities, never for the identity sent on the wire.
    #[default]
    Any,
}

impl Identity {
    /// IKEv2 ID type code.
    pub fn id_type(&self) -> Option<u8> {
        match self {
            Self::Ip(IpAddr::V4(_)) => Some(1),
            Self::Fqdn(_) => Some(2),
            Self::Email(_) => Some(3),
            Self::Ip(IpAddr::V6(_)) => Some(5),
            Self::KeyId(_) => Some(11),
            Self::DerAsn1Dn(_) => Some(9),
            Self::Any => None,
        }
    }

    /// Encode the identity value for an ID payload.
    pub fn encode(&self) -> Result<Vec<u8>, IpsecError> {
        match self {
            Self::Ip(IpAddr::V4(address)) => Ok(address.octets().to_vec()),
            Self::Ip(IpAddr::V6(address)) => Ok(address.octets().to_vec()),
            Self::Fqdn(value) | Self::Email(value) => {
                Ok(value.as_bytes().to_vec())
            }
            Self::DerAsn1Dn(value) | Self::KeyId(value) => Ok(value.clone()),
            Self::Any => Err(IpsecError::config(
                "the wildcard identity cannot be sent on the wire",
            )),
        }
    }

    /// Decode an identity from an ID payload.
    pub fn decode(id_type: u8, data: &[u8]) -> Result<Self, IpsecError> {
        match id_type {
            1 => {
                let bytes: [u8; 4] = data.try_into().map_err(|_| {
                    IpsecError::ike(
                        "IPv4 identity payload has the wrong length",
                    )
                })?;
                Ok(Self::Ip(IpAddr::V4(bytes.into())))
            }
            2 => {
                String::from_utf8(data.to_vec())
                    .map(Self::Fqdn)
                    .map_err(|_| {
                        IpsecError::ike("FQDN identity is not valid UTF-8")
                    })
            }
            3 => String::from_utf8(data.to_vec()).map(Self::Email).map_err(
                |_| IpsecError::ike("RFC 822 identity is not valid UTF-8"),
            ),
            11 => Ok(Self::KeyId(data.to_vec())),
            5 => {
                let bytes: [u8; 16] = data.try_into().map_err(|_| {
                    IpsecError::ike(
                        "IPv6 identity payload has the wrong length",
                    )
                })?;
                Ok(Self::Ip(IpAddr::V6(bytes.into())))
            }
            9 => Ok(Self::DerAsn1Dn(data.to_vec())),
            other => Err(IpsecError::new(
                crate::error::IpsecErrorKind::NoSupport,
                format!("unsupported IKE identity type {other}"),
            )),
        }
    }

    /// Whether this is the wildcard identity.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::Any)
    }

    /// Human-readable form used in diagnostics.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Fqdn(value) | Self::Email(value) => Some(value),
            _ => None,
        }
    }

    /// Whether a peer identity satisfies this configured identity.
    pub fn matches(&self, other: &Identity) -> bool {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => true,
            (Self::Ip(left), Self::Ip(right)) => left == right,
            (Self::Fqdn(left), Self::Fqdn(right)) => {
                left.eq_ignore_ascii_case(right)
            }
            (Self::Email(left), Self::Email(right)) => {
                left.eq_ignore_ascii_case(right)
            }
            (Self::DerAsn1Dn(left), Self::DerAsn1Dn(right)) => left == right,
            (Self::KeyId(left), Self::KeyId(right)) => left == right,
            _ => false,
        }
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(address) => write!(f, "{address}"),
            Self::Fqdn(value) => f.write_str(value),
            Self::Email(value) => f.write_str(value),
            Self::DerAsn1Dn(value) => write!(f, "dn:{}", hex(value)),
            Self::KeyId(value) => write!(f, "keyid:{}", hex(value)),
            Self::Any => f.write_str("*"),
        }
    }
}

fn hex(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn unhex(value: &str) -> Result<Vec<u8>, IpsecError> {
    if !value.len().is_multiple_of(2) {
        return Err(IpsecError::config("identity hex value has an odd length"));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| {
                IpsecError::config("identity contains invalid hex")
            })
        })
        .collect()
}

impl FromStr for Identity {
    type Err = IpsecError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "*" {
            return Ok(Self::Any);
        }
        if let Some(rest) = value.strip_prefix("keyid:") {
            return Ok(Self::KeyId(unhex(rest)?));
        }
        if let Some(rest) = value.strip_prefix("dn:") {
            return Ok(Self::DerAsn1Dn(unhex(rest)?));
        }
        if let Some(rest) = value.strip_prefix("fqdn:") {
            return Ok(Self::Fqdn(rest.to_string()));
        }
        if let Some(rest) = value.strip_prefix("email:") {
            return Ok(Self::Email(rest.to_string()));
        }
        if let Ok(address) = value.parse::<IpAddr>() {
            return Ok(Self::Ip(address));
        }
        if value.contains('@') {
            return Ok(Self::Email(value.to_string()));
        }
        if value.is_empty() {
            return Err(IpsecError::config("identity must not be empty"));
        }
        Ok(Self::Fqdn(value.to_string()))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Identity {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Identity {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}
