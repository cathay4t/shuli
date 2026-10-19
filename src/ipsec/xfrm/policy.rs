// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, net::IpAddr, pin::Pin};

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST,
    NetlinkMessage,
};
use netlink_packet_xfrm::{
    Mark, Selector, UserPolicyId, UserPolicyInfo, UserTemplate, XfrmAttrs,
    XfrmMessage,
    constants::{
        IPPROTO_ESP, XFRM_MODE_TRANSPORT, XFRM_MODE_TUNNEL, XFRM_POLICY_ALLOW,
        XFRM_POLICY_FWD, XFRM_POLICY_IN, XFRM_POLICY_OUT,
    },
    policy::{DelGetMessage, ModifyMessage},
};

use crate::{
    client::ChildSaHandle,
    config::{ChildMode, TrafficSelector},
    error::IpsecError,
    xfrm::{InstallSpec, PolicyRecord},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    Out,
    In,
    Forward,
}

impl Direction {
    fn value(self) -> u8 {
        match self {
            Self::Out => XFRM_POLICY_OUT,
            Self::In => XFRM_POLICY_IN,
            Self::Forward => XFRM_POLICY_FWD,
        }
    }
}

pub(crate) fn build(
    direction: Direction,
    source: TrafficSelector,
    destination: TrafficSelector,
    spec: &InstallSpec,
    _child: &ChildSaHandle,
) -> Result<PolicyRecord, IpsecError> {
    if source.family() != destination.family() {
        return Err(IpsecError::xfrm(
            "policy selector addresses use different families",
        ));
    }
    let mut selector = Selector::default();
    selector.source_prefix(
        &source.start,
        common_prefix_len(&source.start, &source.end),
    );
    selector.destination_prefix(
        &destination.start,
        common_prefix_len(&destination.start, &destination.end),
    );
    selector.proto = source.protocol;
    selector.sport = source.start_port;
    selector.dport = destination.start_port;
    selector.sport_mask = if source.start_port == source.end_port {
        u16::MAX
    } else {
        0
    };
    selector.dport_mask = if destination.start_port == destination.end_port {
        u16::MAX
    } else {
        0
    };

    let if_id = if spec.interface.is_some() && spec.mode == ChildMode::Tunnel {
        spec.if_id
    } else {
        0
    };

    let info = UserPolicyInfo {
        selector,
        direction: direction.value(),
        action: XFRM_POLICY_ALLOW,
        priority: spec.priority,
        ..UserPolicyInfo::default()
    };

    let (template_src, template_dst) = match direction {
        Direction::Out => (spec.local_address, spec.remote_address),
        Direction::In | Direction::Forward => {
            (spec.remote_address, spec.local_address)
        }
    };
    let mut template = UserTemplate::default();
    template.source(&template_src);
    template.destination(&template_dst);
    template.protocol(IPPROTO_ESP);
    template.mode(match spec.mode {
        ChildMode::Transport => XFRM_MODE_TRANSPORT,
        ChildMode::Tunnel => XFRM_MODE_TUNNEL,
    });
    template.reqid = spec.reqid;

    let mut nlas = vec![XfrmAttrs::Template(vec![template])];
    if if_id != 0 {
        nlas.push(XfrmAttrs::IfId(if_id));
    }
    if let Some(mark) = spec.mark {
        nlas.push(XfrmAttrs::Mark(Mark {
            value: mark,
            mask: spec.mark_mask,
        }));
    }

    Ok(PolicyRecord {
        direction: direction.value(),
        selector,
        if_id,
        message: ModifyMessage {
            user_policy_info: info,
            nlas,
        },
    })
}

pub(crate) fn add<'a>(
    handle: &'a netlink_proto::ConnectionHandle<XfrmMessage>,
    record: &'a PolicyRecord,
) -> Pin<Box<dyn Future<Output = Result<(), IpsecError>> + Send + 'a>> {
    Box::pin(async move {
        let mut request = NetlinkMessage::from(XfrmMessage::AddPolicy(
            record.message.clone(),
        ));
        request.header.flags =
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
        match super::request(handle, request).await {
            Ok(_) => Ok(()),
            Err(error) if super::is_exists(&error) => {
                let mut update = NetlinkMessage::from(
                    XfrmMessage::UpdatePolicy(record.message.clone()),
                );
                update.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE;
                super::request(handle, update).await.map(|_| ())
            }
            Err(error) => Err(error),
        }
    })
}

pub(crate) fn delete<'a>(
    handle: &'a netlink_proto::ConnectionHandle<XfrmMessage>,
    record: &'a PolicyRecord,
) -> Pin<Box<dyn Future<Output = Result<(), IpsecError>> + Send + 'a>> {
    Box::pin(async move {
        let id = UserPolicyId {
            selector: record.selector,
            direction: record.direction,
            ..UserPolicyId::default()
        };
        let mut nlas = Vec::new();
        if record.if_id != 0 {
            nlas.push(XfrmAttrs::IfId(record.if_id));
        }
        let message = DelGetMessage {
            user_policy_id: id,
            nlas,
        };
        let mut request =
            NetlinkMessage::from(XfrmMessage::DeletePolicy(message));
        request.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        super::request(handle, request).await.map(|_| ())
    })
}

fn common_prefix_len(start: &IpAddr, end: &IpAddr) -> u8 {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            if start == end {
                32
            } else {
                (u32::from(*start) ^ u32::from(*end)).leading_zeros() as u8
            }
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            if start == end {
                128
            } else {
                (u128::from(*start) ^ u128::from(*end)).leading_zeros() as u8
            }
        }
        _ => 0,
    }
}
