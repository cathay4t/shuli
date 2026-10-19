// SPDX-License-Identifier: Apache-2.0

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{FromRawFd, IntoRawFd},
};

use futures::StreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_xfrm::{XfrmMessage, constants::AF_INET};
use netlink_proto::sys::protocols::NETLINK_XFRM;
use netlink_sys::TokioSocket;

use crate::error::{IpsecError, IpsecErrorKind};

const XFRMNLGRP_ACQUIRE: u32 = 1;
const XFRMNLGRP_EXPIRE: u32 = 2;
const XFRMNLGRP_SA: u32 = 3;
const XFRMNLGRP_POLICY: u32 = 4;
const XFRMNLGRP_REPORT: u32 = 6;

/// Asynchronous XFRM kernel event.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum XfrmEvent {
    /// Traffic hit a policy that has no matching SA.
    Acquire {
        source: IpAddr,
        destination: IpAddr,
        proto: u8,
        spi: u32,
    },
    /// An SA soft or hard lifetime expired.
    Expire { reqid: u32, spi: u32, hard: bool },
    /// A policy lifetime expired.
    PolicyExpire { hard: bool },
    /// Kernel reported an XFRM error for a packet.
    Report {
        source: IpAddr,
        destination: IpAddr,
        proto: u8,
    },
}

pub(crate) struct XfrmMonitor {
    messages: futures::channel::mpsc::UnboundedReceiver<(
        netlink_packet_core::NetlinkMessage<XfrmMessage>,
        netlink_proto::sys::SocketAddr,
    )>,
    _task: tokio::task::JoinHandle<()>,
}

impl XfrmMonitor {
    pub(crate) fn new() -> Result<Self, IpsecError> {
        let mut socket =
            netlink_sys::Socket::new(NETLINK_XFRM).map_err(|e| {
                IpsecError::new(IpsecErrorKind::Netlink, e.to_string())
            })?;
        socket.bind_auto().map_err(|e| {
            IpsecError::new(IpsecErrorKind::Netlink, e.to_string())
        })?;
        for group in [
            XFRMNLGRP_ACQUIRE,
            XFRMNLGRP_EXPIRE,
            XFRMNLGRP_SA,
            XFRMNLGRP_POLICY,
            XFRMNLGRP_REPORT,
        ] {
            socket.add_membership(group).map_err(|e| {
                IpsecError::new(IpsecErrorKind::Netlink, e.to_string())
            })?;
        }
        let raw = socket.into_raw_fd();
        // SAFETY: the fd is valid and ownership is transferred exactly
        // once into TokioSocket.
        let socket = unsafe { TokioSocket::from_raw_fd(raw) };
        let (connection, _handle, messages) =
            netlink_proto::from_socket_with_codec::<
                XfrmMessage,
                _,
                netlink_proto::NetlinkCodec,
            >(socket);
        let task = tokio::spawn(connection);
        Ok(Self {
            messages,
            _task: task,
        })
    }

    pub(crate) async fn next(&mut self) -> Option<XfrmEvent> {
        loop {
            let (message, _address) = self.messages.next().await?;
            if let NetlinkPayload::InnerMessage(message) = message.payload
                && let Some(event) = convert(message)
            {
                return Some(event);
            }
        }
    }
}

fn convert(message: XfrmMessage) -> Option<XfrmEvent> {
    match message {
        XfrmMessage::Acquire(message) => {
            let acquire = message.acquire;
            Some(XfrmEvent::Acquire {
                source: selector_address(
                    &acquire.selector.saddr,
                    acquire.selector.family,
                ),
                destination: selector_address(
                    &acquire.selector.daddr,
                    acquire.selector.family,
                ),
                proto: acquire.id.proto,
                spi: acquire.id.spi,
            })
        }
        XfrmMessage::Expire(message) => Some(XfrmEvent::Expire {
            reqid: message.expire.state.reqid,
            spi: message.expire.state.id.spi,
            hard: message.expire.hard != 0,
        }),
        XfrmMessage::PolicyExpire(message) => Some(XfrmEvent::PolicyExpire {
            hard: message.expire.hard != 0,
        }),
        XfrmMessage::Report(message) => Some(XfrmEvent::Report {
            source: selector_address(
                &message.report.selector.saddr,
                message.report.selector.family,
            ),
            destination: selector_address(
                &message.report.selector.daddr,
                message.report.selector.family,
            ),
            proto: message.report.proto,
        }),
        _ => None,
    }
}

fn selector_address(
    address: &netlink_packet_xfrm::Address,
    family: u16,
) -> IpAddr {
    if family == AF_INET {
        IpAddr::V4(Ipv4Addr::from(
            address.addr[..4].try_into().unwrap_or([0; 4]),
        ))
    } else {
        IpAddr::V6(Ipv6Addr::from(address.addr))
    }
}
