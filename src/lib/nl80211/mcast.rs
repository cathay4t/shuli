// SPDX-License-Identifier: Apache-2.0

// Helper to resolve nl80211 multicast group IDs and join them.

use netlink_packet_core::{
    Emitable, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_generic::{
    GenlMessage,
    ctrl::{
        GenlCtrl, GenlCtrlCmd,
        nlas::{GenlCtrlAttrs, McastGrpAttrs},
    },
};
use netlink_sys::{AsyncSocket, Socket, SocketAddr};

const NL80211_FAMILY_NAME: &str = "nl80211";
const GENL_ID_CTRL: u16 = 0x10;

/// Group names we need for STA operation.
const NEEDED_GROUPS: &[&str] = &["scan", "mlme", "config"];

/// Query the nl80211 family and return a map of group name -> group ID.
pub fn query_mcast_group_ids() -> Result<Vec<(String, u32)>, String> {
    let mut sock = Socket::new(netlink_sys::protocols::NETLINK_GENERIC)
        .map_err(|e| format!("create socket: {e}"))?;
    sock.bind(&SocketAddr::new(0, 0))
        .map_err(|e| format!("bind: {e}"))?;
    sock.connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("connect: {e}"))?;

    let genl_ctrl = GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName(NL80211_FAMILY_NAME.to_string())],
    };
    let mut genl_msg: GenlMessage<GenlCtrl> =
        GenlMessage::from_payload(genl_ctrl);
    genl_msg.finalize();
    genl_msg.set_resolved_family_id(GENL_ID_CTRL);
    let mut nl_msg = NetlinkMessage::from(genl_msg);
    nl_msg.header.flags = NLM_F_REQUEST;
    nl_msg.finalize();

    let mut buf = vec![0u8; nl_msg.buffer_len()];
    nl_msg.emit(&mut buf);
    sock.send(&buf, 0)
        .map_err(|e| format!("send getfamily: {e}"))?;

    let (recv_buf, _) =
        sock.recv_from_full().map_err(|e| format!("recv: {e}"))?;

    let rx_packet =
        NetlinkMessage::<GenlMessage<GenlCtrl>>::deserialize(&recv_buf)
            .map_err(|e| format!("parse: {e}"))?;

    let mut groups = Vec::new();
    if let NetlinkPayload::InnerMessage(genlmsg) = rx_packet.payload {
        for nla in &genlmsg.payload.nlas {
            if let GenlCtrlAttrs::McastGroups(mcast_groups) = nla {
                for grp_attrs in mcast_groups {
                    let mut name = String::new();
                    let mut id = 0;
                    for attr in grp_attrs {
                        match attr {
                            McastGrpAttrs::Name(n) => name = n.clone(),
                            McastGrpAttrs::Id(gid) => id = *gid,
                        }
                    }
                    if !name.is_empty() {
                        groups.push((name, id));
                    }
                }
            }
        }
    }

    if groups.is_empty() {
        return Err("no multicast groups found for nl80211".into());
    }
    Ok(groups)
}

pub fn join_multicast_groups(
    conn: &mut netlink_proto::Connection<
        genetlink::message::RawGenlMessage,
        netlink_proto::sys::TokioSocket,
    >,
) -> Result<(), String> {
    let groups = query_mcast_group_ids()?;

    let group_map: std::collections::HashMap<&str, u32> =
        groups.iter().map(|(n, id)| (n.as_str(), *id)).collect();

    let socket = conn.socket_mut().socket_mut();
    for name in NEEDED_GROUPS {
        if let Some(id) = group_map.get(name) {
            log::info!("Joining nl80211 multicast group: {name} (id={id})");
            socket
                .add_membership(*id)
                .map_err(|e| format!("join {name}: {e}"))?;
        } else {
            log::warn!("nl80211 multicast group {name} not found");
        }
    }
    Ok(())
}
