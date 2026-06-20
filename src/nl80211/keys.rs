// SPDX-License-Identifier: Apache-2.0

// Key installation via NL80211_CMD_NEW_KEY.
// Uses raw netlink messages since wl-nl80211 does not yet expose key-related
// Nl80211Attr variants.

use futures::TryStreamExt;
use netlink_packet_core::{
    DefaultNla, NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage,
};
use netlink_packet_generic::GenlMessage;
use wl_nl80211::{Nl80211Attr, Nl80211Command, Nl80211Handle, Nl80211Message};

use crate::ShuliResult;

// NL80211 attribute constants not yet modelled in wl-nl80211.
const NL80211_ATTR_KEY_DATA: u16 = 7;
const NL80211_ATTR_KEY_IDX: u16 = 8;
const NL80211_ATTR_KEY_CIPHER: u16 = 9;
const NL80211_ATTR_KEY_DEFAULT: u16 = 11;
const NL80211_ATTR_KEY_TYPE: u16 = 55;

// Kernel-native cipher suite selector (WLAN_CIPHER_SUITE_CCMP), as expected by
// NL80211_ATTR_KEY_CIPHER (distinct from the OUI-first wire encoding).
const WLAN_CIPHER_SUITE_CCMP: u32 = 0x000F_AC04;

// Key type values (nl80211_key_type)
const NL80211_KEYTYPE_GROUP: u32 = 0;
const NL80211_KEYTYPE_PAIRWISE: u32 = 1;

/// Install a pairwise key (PTK).
/// The `key_data` should contain only the temporal key (TK), not the full PTK.
pub async fn install_ptk(
    handle: &Nl80211Handle,
    if_index: u32,
    peer_mac: [u8; 6],
    key_data: &[u8],
) -> ShuliResult<()> {
    let cipher = WLAN_CIPHER_SUITE_CCMP;

    let attrs = vec![
        Nl80211Attr::IfIndex(if_index),
        Nl80211Attr::Mac(peer_mac),
        Nl80211Attr::Other(DefaultNla::new(
            NL80211_ATTR_KEY_DATA,
            key_data.to_vec(),
        )),
        Nl80211Attr::Other(DefaultNla::new(
            NL80211_ATTR_KEY_IDX,
            vec![0u8], // key index 0
        )),
        Nl80211Attr::Other(DefaultNla::new(
            NL80211_ATTR_KEY_CIPHER,
            cipher.to_le_bytes().to_vec(),
        )),
        Nl80211Attr::Other(DefaultNla::new(
            NL80211_ATTR_KEY_TYPE,
            NL80211_KEYTYPE_PAIRWISE.to_le_bytes().to_vec(),
        )),
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
    let cipher = WLAN_CIPHER_SUITE_CCMP;

    // Group keys must NOT carry a MAC address (cfg80211 rejects a group key
    // with a peer address as EINVAL).
    let attrs = vec![
        Nl80211Attr::IfIndex(if_index),
        Nl80211Attr::Other(DefaultNla::new(
            NL80211_ATTR_KEY_DATA,
            key_data.to_vec(),
        )),
        Nl80211Attr::Other(DefaultNla::new(
            NL80211_ATTR_KEY_IDX,
            vec![key_index],
        )),
        Nl80211Attr::Other(DefaultNla::new(
            NL80211_ATTR_KEY_CIPHER,
            cipher.to_le_bytes().to_vec(),
        )),
        Nl80211Attr::Other(DefaultNla::new(
            NL80211_ATTR_KEY_TYPE,
            NL80211_KEYTYPE_GROUP.to_le_bytes().to_vec(),
        )),
        Nl80211Attr::Other(DefaultNla::new(NL80211_ATTR_KEY_DEFAULT, vec![])),
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
