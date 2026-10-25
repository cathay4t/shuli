// SPDX-License-Identifier: Apache-2.0

//! UDP 500/4500 transport, NAT-T encapsulation, and retransmission
//! helpers.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::net::UdpSocket;

use crate::error::IpsecError;

/// NAT-T encapsulation port.
pub const NAT_T_PORT: u16 = 4500;

/// One IKE UDP socket.
pub struct IkeTransport {
    socket: UdpSocket,
    remote: SocketAddr,
    nat_t: bool,
    encapsulated: bool,
}

impl IkeTransport {
    pub async fn bind(
        local_address: Option<IpAddr>,
        local_port: u16,
        remote: SocketAddr,
        nat_t: bool,
    ) -> Result<Self, IpsecError> {
        let bind_address = match local_address {
            Some(IpAddr::V4(address)) => {
                SocketAddr::new(address.into(), local_port)
            }
            Some(IpAddr::V6(address)) => {
                SocketAddr::new(address.into(), local_port)
            }
            None => {
                if remote.is_ipv4() {
                    SocketAddr::from(([0, 0, 0, 0], local_port))
                } else {
                    SocketAddr::from(([0u16; 8], local_port))
                }
            }
        };
        let socket = UdpSocket::bind(bind_address).await.map_err(|e| {
            IpsecError::new(
                crate::error::IpsecErrorKind::Io,
                format!("bind IKE socket {bind_address}: {e}"),
            )
        })?;
        Ok(Self {
            socket,
            remote,
            nat_t,
            encapsulated: false,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, IpsecError> {
        self.socket.local_addr().map_err(Into::into)
    }

    pub fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub fn set_remote(&mut self, remote: SocketAddr) {
        self.remote = remote;
    }

    /// Switch to UDP-encapsulated IKE on port 4500 (RFC 7296 section
    /// 2.23).  Both the destination and the local source port must change
    /// so that subsequent responses arrive on the NAT-T socket.
    pub async fn enable_nat_t(&mut self) -> Result<(), IpsecError> {
        self.remote.set_port(NAT_T_PORT);
        if !self.nat_t || self.encapsulated {
            return Ok(());
        }
        let local = self.socket.local_addr()?;
        let bind_address = SocketAddr::new(local.ip(), NAT_T_PORT);
        let socket = UdpSocket::bind(bind_address).await.map_err(|e| {
            IpsecError::new(
                crate::error::IpsecErrorKind::Io,
                format!("bind NAT-T socket {bind_address}: {e}"),
            )
        })?;
        self.socket = socket;
        self.encapsulated = true;
        Ok(())
    }

    /// Determine the local source address the kernel would select for
    /// `remote`, even when the IKE socket is bound to a wildcard address.
    pub async fn route_source_ip(
        &self,
        remote: SocketAddr,
    ) -> Result<IpAddr, IpsecError> {
        let local = self.socket.local_addr()?;
        if !local.ip().is_unspecified() {
            return Ok(local.ip());
        }
        let bind_address = if remote.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let probe = UdpSocket::bind(bind_address).await.map_err(|e| {
            IpsecError::new(
                crate::error::IpsecErrorKind::Io,
                format!("bind route probe socket {bind_address}: {e}"),
            )
        })?;
        probe.connect(remote).await.map_err(|e| {
            IpsecError::new(
                crate::error::IpsecErrorKind::Io,
                format!("connect route probe to {remote}: {e}"),
            )
        })?;
        Ok(probe.local_addr()?.ip())
    }

    pub fn nat_t_enabled(&self) -> bool {
        self.encapsulated
    }

    pub async fn send(&self, message: &[u8]) -> Result<(), IpsecError> {
        if self.encapsulated {
            let mut datagram = Vec::with_capacity(4 + message.len());
            datagram.extend_from_slice(&[0, 0, 0, 0]);
            datagram.extend_from_slice(message);
            self.socket.send_to(&datagram, self.remote).await?;
        } else {
            self.socket.send_to(message, self.remote).await?;
        }
        Ok(())
    }

    pub async fn recv(&self) -> Result<(Vec<u8>, SocketAddr), IpsecError> {
        let mut buffer = vec![0u8; 65_535];
        let (length, source) = self.socket.recv_from(&mut buffer).await?;
        buffer.truncate(length);
        if self.encapsulated || source.port() == NAT_T_PORT {
            if buffer.len() >= 4 && buffer[..4] == [0, 0, 0, 0] {
                buffer.drain(..4);
            } else if !buffer.is_empty() && buffer[0] >> 4 == 4 {
                return Err(IpsecError::ike(
                    "received non-IKE packet on the NAT-T socket",
                ));
            }
        }
        Ok((buffer, source))
    }
}

/// Retransmission timer with exponential backoff.
pub struct Retransmit {
    message: Vec<u8>,
    deadline: tokio::time::Instant,
    timeout: Duration,
    attempts: u8,
    max_attempts: u8,
}

impl Retransmit {
    pub fn new(message: Vec<u8>, timeout: Duration, max_attempts: u8) -> Self {
        Self {
            message,
            deadline: tokio::time::Instant::now() + timeout,
            timeout,
            attempts: 0,
            max_attempts,
        }
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }

    pub fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    /// Record a retransmission and return whether another attempt is
    /// allowed.
    pub fn retry(&mut self) -> bool {
        self.attempts += 1;
        self.timeout = (self.timeout * 2).min(Duration::from_secs(60));
        self.deadline = tokio::time::Instant::now() + self.timeout;
        self.attempts < self.max_attempts
    }

    pub fn attempts(&self) -> u8 {
        self.attempts
    }
}

/// NAT detection hash (RFC 7296 section 2.23): SHA-1 of SPIi | SPIr |
/// address | port.
pub fn nat_detection_hash(
    spi_i: u64,
    spi_r: u64,
    address: IpAddr,
    port: u16,
) -> Vec<u8> {
    use aws_lc_rs::digest;
    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(&spi_i.to_be_bytes());
    context.update(&spi_r.to_be_bytes());
    match address {
        IpAddr::V4(address) => context.update(&address.octets()),
        IpAddr::V6(address) => context.update(&address.octets()),
    }
    context.update(&port.to_be_bytes());
    context.finish().as_ref().to_vec()
}

/// Check whether a peer NAT-D notify matches this local address/port.
pub fn nat_detection_matches(
    notify_data: &[u8],
    spi_i: u64,
    spi_r: u64,
    address: IpAddr,
    port: u16,
) -> bool {
    let expected = nat_detection_hash(spi_i, spi_r, address, port);
    expected.len() == notify_data.len()
        && aws_lc_rs::constant_time::verify_slices_are_equal(
            &expected,
            notify_data,
        )
        .is_ok()
}
