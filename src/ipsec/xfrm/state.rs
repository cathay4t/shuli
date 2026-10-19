// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, net::IpAddr, pin::Pin, time::Duration};

use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage};
use netlink_packet_xfrm::{
    Address, UserSaId, UserSaInfo, XFRM_ALG_AEAD_NAME_LEN,
    XFRM_ALG_AUTH_NAME_LEN, XFRM_ALG_NAME_LEN, XfrmAttrs, XfrmMessage,
    constants::{
        AF_INET, AF_INET6, IPPROTO_ESP, XFRM_MODE_TRANSPORT, XFRM_MODE_TUNNEL,
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
            child.local_spi,
            child.outbound_key.clone(),
            child.outbound_integrity_key.clone(),
        )
    } else {
        (
            spec.remote_address,
            spec.local_address,
            child.remote_spi,
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
    info.replay_window = spec.replay_window.min(u8::MAX as u32) as u8;
    info.lifetime_cfg.hard_add_expires_seconds = spec.lifetime.as_secs();
    info.lifetime_cfg.soft_add_expires_seconds =
        soft_lifetime(spec.lifetime).as_secs();
    info.selector.source_prefix(&src, full_prefix(&src));
    info.selector.destination_prefix(&dst, full_prefix(&dst));

    let mut nlas =
        vec![encryption_transform(child.encryption, &enc_key, spec)?];
    if spec.if_id != 0 {
        nlas.push(XfrmAttrs::IfId(spec.if_id));
    }
    if let Some(integrity) = child.integrity.zip(auth_key.as_ref()) {
        nlas.push(integrity_transform(integrity.0, integrity.1)?);
    }
    if child.esn {
        let bmp_len = spec.replay_window.div_ceil(32).max(1);
        nlas.push(XfrmAttrs::ReplayStateEsn(ReplayEsn {
            bmp_len,
            oseq: 0,
            seq: 0,
            oseq_hi: 0,
            seq_hi: 0,
            replay_window: spec.replay_window,
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
