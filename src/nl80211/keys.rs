// SPDX-License-Identifier: Apache-2.0

// Key installation via NL80211_CMD_NEW_KEY using the nested NL80211_ATTR_KEY
// attribute (the same form iwd and wpa_supplicant emit).
//
// For station mode, only NL80211_CMD_NEW_KEY is needed. The kernel selects
// the GTK for RX by the Key ID carried in the CCMP header's Key ID subfield
// (802.11-2020 §12.5.3.2).  NL80211_KEY_DEFAULT_TYPES is a future-proofing
// hint that has no effect in the current kernel's NEW_KEY handler.
//
// AP/IBSS modes additionally require NL80211_CMD_SET_KEY to mark the key as
// the default for TX (iwd iwd/src/ap.c:1767, wpa_supplicant
// driver_nl80211.c:3624).

use futures::TryStreamExt;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage};
use netlink_packet_generic::GenlMessage;
use wl_nl80211::{
    Nl80211Attr, Nl80211Command, Nl80211Handle, Nl80211KeyAttr,
    Nl80211KeyDefaultType, Nl80211KeyType, Nl80211Message,
};

use crate::ShuliResult;

const WLAN_CIPHER_SUITE_CCMP: u32 = 0x000F_AC04;

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

/// Install a group key (GTK) for station mode.
///
/// Sends a single `NL80211_CMD_NEW_KEY` with the key material and a
/// `NL80211_KEY_DEFAULT_TYPES` nested attribute carrying
/// `NL80211_KEY_DEFAULT_TYPE_MULTICAST`. This matches iwd
/// (`iwd/src/nl80211util.c:nl80211_build_new_key_group`, lines 409-440)
/// and wpa_supplicant (`driver_nl80211.c:3527`).
///
/// The kernel's RX path selects the GTK by the Key ID subfield in the CCMP
/// header (802.11-2020 §12.5.3.2), so a separate `NL80211_CMD_SET_KEY` is not
/// needed for station mode.
pub async fn install_gtk(
    handle: &Nl80211Handle,
    if_index: u32,
    key_data: &[u8],
    key_index: u8,
) -> ShuliResult<()> {
    let attrs = vec![
        Nl80211Attr::IfIndex(if_index),
        Nl80211Attr::Key(vec![
            Nl80211KeyAttr::Data(key_data.to_vec()),
            Nl80211KeyAttr::Cipher(WLAN_CIPHER_SUITE_CCMP),
            Nl80211KeyAttr::Idx(key_index),
            Nl80211KeyAttr::Type(Nl80211KeyType::Group),
            Nl80211KeyAttr::DefaultTypes(vec![
                Nl80211KeyDefaultType::Multicast,
            ]),
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
