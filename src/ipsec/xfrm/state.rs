// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, net::IpAddr, pin::Pin, time::Duration};

use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage};
use netlink_packet_xfrm::{
    Address, UserSaId, UserSaInfo, XFRM_ALG_AEAD_NAME_LEN,
    XFRM_ALG_AUTH_NAME_LEN, XFRM_ALG_NAME_LEN, XfrmAttrs, XfrmMessage,
    constants::{
        AF_INET, AF_INET6, IPPROTO_ESP, XFRM_MODE_TRANSPORT, XFRM_MODE_TUNNEL,
        XFRM_STATE_ESN,
    },
    nlas::{Alg, AlgAead, AlgAuth, EncapTmpl, ReplayEsn},
    state::{DelGetMessage, ModifyMessage},
};

use crate::{
    client::ChildSaHandle,
    config::{ChildMode, EncryptionAlgorithm, IntegrityAlgorithm},
    error::IpsecError,
    xfrm::InstallSpec,
};

pub(crate) fn build(
    child: &ChildSaHandle,
    spec: &InstallSpec,
    outbound: bool,
) -> Result<ModifyMessage, IpsecError> {
    let (src, dst, spi, enc_key, auth_key) = if outbound {
        (
            spec.local_address,
            spec.remote_address,
            child.remote_spi,
            child.outbound_key.clone(),
            child.outbound_integrity_key.clone(),
        )
    } else {
        (
            spec.remote_address,
            spec.local_address,
            child.local_spi,
            child.inbound_key.clone(),
            child.inbound_integrity_key.clone(),
        )
    };

    let mut info = UserSaInfo::default();
    info.id.daddr = Address::from_ip(&dst);
    info.id.spi = spi;
    info.id.proto = IPPROTO_ESP;
    info.saddr = Address::from_ip(&src);
    info.family = if src.is_ipv4() { AF_INET } else { AF_INET6 };
    info.mode = match spec.mode {
        ChildMode::Transport => XFRM_MODE_TRANSPORT,
        ChildMode::Tunnel => XFRM_MODE_TUNNEL,
    };
    info.reqid = spec.reqid;
    info.replay_window = if child.esn {
        0
    } else {
        spec.replay_window.min(u8::MAX as u32) as u8
    };
    info.lifetime_cfg.hard_add_expires_seconds = spec.lifetime.as_secs();
    info.lifetime_cfg.soft_add_expires_seconds =
        soft_lifetime(spec.lifetime).as_secs();
    if spec.mode == ChildMode::Tunnel {
        apply_tunnel_selector(&mut info.selector, child, outbound, spec)?;
    } else {
        info.selector.source_prefix(&src, full_prefix(&src));
        info.selector.destination_prefix(&dst, full_prefix(&dst));
    }

    let mut nlas =
        vec![encryption_transform(child.encryption, &enc_key, spec)?];
    if spec.if_id != 0 {
        nlas.push(XfrmAttrs::IfId(spec.if_id));
    }
    if let Some(integrity) = child.integrity.zip(auth_key.as_ref()) {
        nlas.push(integrity_transform(integrity.0, integrity.1)?);
    }
    if child.esn {
        info.flags |= XFRM_STATE_ESN;
        let window = spec.replay_window.min(4096);
        let bmp_len = window.div_ceil(32).max(1);
        nlas.push(XfrmAttrs::ReplayStateEsn(ReplayEsn {
            bmp_len,
            oseq: 0,
            seq: 0,
            oseq_hi: 0,
            seq_hi: 0,
            replay_window: window,
            bmp: vec![0; bmp_len as usize],
        }));
    }
    if spec.nat_t {
        nlas.push(XfrmAttrs::EncapsulationTemplate(EncapTmpl {
            encap_type: 2, // UDP_ENCAP_ESPINUDP
            encap_sport: 4500,
            encap_dport: 4500,
            encap_oa: Address::default(),
        }));
    }
    if let Some(mark) = spec.mark {
        nlas.push(XfrmAttrs::Mark(netlink_packet_xfrm::Mark {
            value: mark,
            mask: spec.mark_mask,
        }));
    }

    Ok(ModifyMessage {
        user_sa_info: info,
        nlas,
    })
}

pub(crate) fn delete<'a>(
    handle: &'a netlink_proto::ConnectionHandle<XfrmMessage>,
    source: IpAddr,
    destination: IpAddr,
    spi: u32,
    proto: u8,
    family: u16,
) -> Pin<Box<dyn Future<Output = Result<(), IpsecError>> + Send + 'a>> {
    Box::pin(async move {
        let mut id = UserSaId::default();
        id.destination(&destination);
        id.spi = spi;
        id.proto = proto;
        id.family = family;
        let message = DelGetMessage {
            user_sa_id: id,
            nlas: vec![XfrmAttrs::SrcAddr(Address::from_ip(&source))],
        };
        let mut request = NetlinkMessage::from(XfrmMessage::DeleteSa(message));
        request.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        super::request(handle, request).await.map(|_| ())
    })
}

fn apply_tunnel_selector(
    selector: &mut netlink_packet_xfrm::Selector,
    child: &ChildSaHandle,
    outbound: bool,
    spec: &InstallSpec,
) -> Result<(), IpsecError> {
    let (source, destination) = if outbound {
        (&child.local_selectors, &child.remote_selectors)
    } else {
        (&child.remote_selectors, &child.local_selectors)
    };
    if let ([source], [destination]) =
        (source.as_slice(), destination.as_slice())
    {
        if source.family() != destination.family() {
            return Err(IpsecError::xfrm(
                "traffic selectors use different address families",
            ));
        }
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
        selector.dport_mask = if destination.start_port == destination.end_port
        {
            u16::MAX
        } else {
            0
        };
        return Ok(());
    }

    let wildcard = if spec.local_address.is_ipv4() {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    selector.source_prefix(&wildcard, 0);
    selector.destination_prefix(&wildcard, 0);
    Ok(())
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
                let xor = u128::from(*start) ^ u128::from(*end);
                xor.leading_zeros() as u8
            }
        }
        _ => 0,
    }
}

fn encryption_transform(
    algorithm: EncryptionAlgorithm,
    key: &[u8],
    spec: &InstallSpec,
) -> Result<XfrmAttrs, IpsecError> {
    if algorithm.is_aead() {
        let name = c_name("rfc4106(gcm(aes))", XFRM_ALG_AEAD_NAME_LEN)?;
        Ok(XfrmAttrs::EncryptionAlgAead(AlgAead {
            alg_name: name,
            alg_key_len: (key.len() * 8) as u32,
            alg_icv_len: 128,
            alg_key: key.to_vec(),
        }))
    } else {
        let name = c_name("cbc(aes)", XFRM_ALG_NAME_LEN)?;
        let _ = spec;
        Ok(XfrmAttrs::EncryptionAlg(Alg {
            alg_name: name,
            alg_key_len: (key.len() * 8) as u32,
            alg_key: key.to_vec(),
        }))
    }
}

fn integrity_transform(
    algorithm: IntegrityAlgorithm,
    key: &[u8],
) -> Result<XfrmAttrs, IpsecError> {
    let (name, trunc) = match algorithm {
        IntegrityAlgorithm::HmacSha2_256_128 => ("hmac(sha256)", 128),
        IntegrityAlgorithm::HmacSha1_96 => ("hmac(sha1)", 96),
        IntegrityAlgorithm::None => {
            return Err(IpsecError::xfrm(
                "cannot install an integrity transform for NONE",
            ));
        }
    };
    Ok(XfrmAttrs::AuthenticationAlgTrunc(AlgAuth {
        alg_name: c_name(name, XFRM_ALG_AUTH_NAME_LEN)?,
        alg_key_len: (key.len() * 8) as u32,
        alg_trunc_len: trunc,
        alg_key: key.to_vec(),
    }))
}

fn c_name(value: &str, width: usize) -> Result<[u8; 64], IpsecError> {
    if value.len() + 1 > width || width != 64 {
        return Err(IpsecError::internal("invalid XFRM algorithm name width"));
    }
    let mut name = [0u8; 64];
    name[..value.len()].copy_from_slice(value.as_bytes());
    Ok(name)
}

fn full_prefix(address: &IpAddr) -> u8 {
    if address.is_ipv4() { 32 } else { 128 }
}

fn soft_lifetime(lifetime: Duration) -> Duration {
    lifetime.mul_f64(0.9)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::{
        InstallSpec,
        config::{EncryptionAlgorithm, IpNet, TrafficSelector},
    };

    fn child() -> ChildSaHandle {
        let local = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
        ChildSaHandle {
            local_spi: 0x1122_3344,
            remote_spi: 0x5566_7788,
            encryption: EncryptionAlgorithm::AesGcm16_256,
            integrity: None,
            esn: false,
            mode: ChildMode::Tunnel,
            local_selectors: vec![TrafficSelector::net(
                IpNet::new(local, 24).unwrap(),
            )],
            remote_selectors: vec![TrafficSelector::net(
                IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)), 24).unwrap(),
            )],
            outbound_key: zeroize::Zeroizing::new(vec![1; 36]),
            outbound_integrity_key: None,
            inbound_key: zeroize::Zeroizing::new(vec![2; 36]),
            inbound_integrity_key: None,
        }
    }

    fn spec(mode: ChildMode) -> InstallSpec {
        InstallSpec {
            interface: None,
            if_id: 0,
            reqid: 1,
            local_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            remote_address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
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
    fn state_spis_and_tunnel_selectors_follow_ikev2_directions() {
        let child = child();
        let outbound = build(&child, &spec(ChildMode::Tunnel), true).unwrap();
        assert_eq!(outbound.user_sa_info.id.spi, child.remote_spi);
        assert_eq!(
            outbound.user_sa_info.selector.saddr,
            Address::from_ip(&IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)))
        );
        assert_eq!(
            outbound.user_sa_info.selector.daddr,
            Address::from_ip(&IpAddr::V4(Ipv4Addr::new(10, 2, 0, 0)))
        );
        assert_eq!(outbound.user_sa_info.selector.prefixlen_s, 24);
        assert_eq!(outbound.user_sa_info.selector.prefixlen_d, 24);

        let inbound = build(&child, &spec(ChildMode::Tunnel), false).unwrap();
        assert_eq!(inbound.user_sa_info.id.spi, child.local_spi);
        assert_eq!(
            inbound.user_sa_info.selector.saddr,
            Address::from_ip(&IpAddr::V4(Ipv4Addr::new(10, 2, 0, 0)))
        );
        assert_eq!(
            inbound.user_sa_info.selector.daddr,
            Address::from_ip(&IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)))
        );
    }

    #[test]
    fn esn_state_sets_flag_and_zero_legacy_replay_window() {
        let mut child = child();
        child.esn = true;
        let outbound = build(&child, &spec(ChildMode::Tunnel), true).unwrap();
        assert_eq!(outbound.user_sa_info.replay_window, 0);
        assert_ne!(outbound.user_sa_info.flags & XFRM_STATE_ESN, 0);
        assert!(outbound.nlas.iter().any(|nla| matches!(
            nla,
            XfrmAttrs::ReplayStateEsn(state) if state.replay_window == 32
        )));
    }

    #[test]
    fn transport_state_selector_uses_underlay_addresses() {
        let child = child();
        let outbound =
            build(&child, &spec(ChildMode::Transport), true).unwrap();
        assert_eq!(
            outbound.user_sa_info.selector.saddr,
            Address::from_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            outbound.user_sa_info.selector.daddr,
            Address::from_ip(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
        );
    }
}
