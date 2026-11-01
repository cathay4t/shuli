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

    // The SA carries this if_id whenever it is non-zero (see
    // state::build); the policy must match it or the kernel never binds
    // the negotiated SA to the selector.  This matters for transport
    // mode too, where there is no XFRM interface.
    let if_id = spec.if_id;

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

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use super::*;
    use crate::config::{EncryptionAlgorithm, IpNet};

    fn child() -> ChildSaHandle {
        ChildSaHandle {
            local_spi: 1,
            remote_spi: 2,
            encryption: EncryptionAlgorithm::AesGcm16_128,
            integrity: None,
            esn: false,
            mode: ChildMode::Transport,
            local_selectors: Vec::new(),
            remote_selectors: Vec::new(),
            outbound_key: zeroize::Zeroizing::new(Vec::new()),
            outbound_integrity_key: None,
            inbound_key: zeroize::Zeroizing::new(Vec::new()),
            inbound_integrity_key: None,
        }
    }

    fn spec(mode: ChildMode, if_id: u32) -> InstallSpec {
        InstallSpec {
            interface: None,
            if_id,
            reqid: 7,
            local_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            mode,
            lifetime: Duration::from_secs(60),
            priority: 100,
            replay_window: 32,
            mark: None,
            mark_mask: 0,
            forward: false,
            nat_t: false,
        }
    }

    #[test]
    fn policy_if_id_matches_the_state_without_an_xfrm_interface() {
        let local = TrafficSelector::host(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let remote = TrafficSelector::host(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 2,
        )));
        for mode in [ChildMode::Transport, ChildMode::Tunnel] {
            let record =
                build(Direction::Out, local, remote, &spec(mode, 42), &child())
                    .unwrap();
            assert_eq!(record.if_id, 42, "{mode:?}");
            assert!(
                record
                    .message
                    .nlas
                    .iter()
                    .any(|attr| matches!(attr, XfrmAttrs::IfId(42))),
                "{mode:?}"
            );
        }

        // A zero if_id stays absent, matching the state builder.
        let record =
            build(Direction::Out, local, remote, &spec(ChildMode::Transport, 0), &child())
                .unwrap();
        assert_eq!(record.if_id, 0);
        assert!(
            !record
                .message
                .nlas
                .iter()
                .any(|attr| matches!(attr, XfrmAttrs::IfId(_)))
        );
    }

    #[test]
    fn prefix_selectors_use_the_common_prefix() {
        let net = |addr: Ipv4Addr, prefix: u8| {
            TrafficSelector::net(IpNet::new(IpAddr::V4(addr), prefix).unwrap())
        };
        let spec = spec(ChildMode::Tunnel, 0);
        let record = build(
            Direction::Out,
            net(Ipv4Addr::new(10, 0, 0, 0), 8),
            net(Ipv4Addr::new(10, 20, 0, 0), 16),
            &spec,
            &child(),
        )
        .unwrap();
        assert_eq!(record.selector.prefixlen_s, 8);
        assert_eq!(record.selector.prefixlen_d, 16);
    }
}
