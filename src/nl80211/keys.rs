// SPDX-License-Identifier: Apache-2.0

// Key installation via NL80211_CMD_NEW_KEY, using the nested NL80211_ATTR_KEY
// attribute (the same form wpa_supplicant emits).

use futures::TryStreamExt;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage};
use netlink_packet_generic::GenlMessage;
use wl_nl80211::{
    Nl80211Attr, Nl80211Command, Nl80211Handle, Nl80211KeyAttr, Nl80211KeyType,
    Nl80211Message,
};

use crate::ShuliResult;

// Kernel-native cipher suite selector (WLAN_CIPHER_SUITE_CCMP), as expected by
// NL80211_KEY_CIPHER (distinct from the OUI-first wire encoding).
const WLAN_CIPHER_SUITE_CCMP: u32 = 0x000F_AC04;

/// Install a pairwise key (PTK).
/// The `key_data` should contain only the temporal key (TK), not the full PTK.
pub async fn install_ptk(
    handle: &Nl80211Handle,
    if_index: u32,
    peer_mac: [u8; 6],
    key_data: &[u8],
) -> ShuliResult<()> {
    let attrs = vec![
        Nl80211Attr::IfIndex(if_index),
        Nl80211Attr::Mac(peer_mac),
        Nl80211Attr::Key(vec![
            Nl80211KeyAttr::Data(key_data.to_vec()),
            Nl80211KeyAttr::Cipher(WLAN_CIPHER_SUITE_CCMP),
            Nl80211KeyAttr::Idx(0),
            Nl80211KeyAttr::Type(Nl80211KeyType::Pairwise),
        ]),
    ];

    send_new_key(handle, attrs).await
}

/// Install a group key (GTK).
/// `key_data` is the raw GTK.
/// `key_index` is the GTK index from the AP (usually 1-3).
pub async fn install_gtk(
    handle: &Nl80211Handle,
    if_index: u32,
    key_data: &[u8],
    key_index: u8,
) -> ShuliResult<()> {
    // Group keys must NOT carry a MAC address (cfg80211 rejects a group key
    // with a peer address as EINVAL).
    let attrs = vec![
        Nl80211Attr::IfIndex(if_index),
        Nl80211Attr::Key(vec![
            Nl80211KeyAttr::Data(key_data.to_vec()),
            Nl80211KeyAttr::Cipher(WLAN_CIPHER_SUITE_CCMP),
            Nl80211KeyAttr::Idx(key_index),
            Nl80211KeyAttr::Type(Nl80211KeyType::Group),
            Nl80211KeyAttr::Default,
        ]),
    ];

    send_new_key(handle, attrs).await
}

async fn send_new_key(
    handle: &Nl80211Handle,
    attrs: Vec<Nl80211Attr>,
) -> ShuliResult<()> {
    let mut nl_msg =
        NetlinkMessage::from(GenlMessage::from_payload(Nl80211Message {
            cmd: Nl80211Command::NewKey,
            attributes: attrs,
        }));
    nl_msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut handle = handle.clone();
    let mut stream = handle.request(nl_msg).await?;
    while let Some(msg) = stream.try_next().await? {
        if let netlink_packet_core::NetlinkPayload::Error(ref err) = msg.payload
            && let Some(code) = err.code
        {
            return Err(crate::ShuliError::HandshakeFailed(format!(
                "NEW_KEY failed: netlink error {code}"
            )));
        }
    }
    Ok(())
}
