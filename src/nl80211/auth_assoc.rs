// SPDX-License-Identifier: Apache-2.0

// Raw NL80211 command helpers for AUTHENTICATE, ASSOCIATE, and frame
// management. These commands are not exposed by wl-nl80211's high-level
// connect module, so we construct the messages directly.

use futures::TryStreamExt;
use log;
use netlink_packet_core::{
    DefaultNla, NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage,
};
use netlink_packet_generic::GenlMessage;
use wl_nl80211::{
    Nl80211Attr, Nl80211AuthType, Nl80211Command, Nl80211Handle,
    Nl80211Message, Nl80211UseMfp,
};

use crate::ShuliResult;

/// Send NL80211_CMD_AUTHENTICATE with SAE auth type and auth_data.
/// The auth_data is the SAE commit frame body (auth_alg=3, auth_seq=1,
/// status=0, scalar||element). This path works with mac80211-based drivers.
pub async fn authenticate_sae_commit(
    handle: &Nl80211Handle,
    if_index: u32,
    ssid: &str,
    bssid: [u8; 6],
    freq_mhz: u32,
    auth_data: &[u8],
) -> ShuliResult<()> {
    // Mirror wpa_supplicant's minimal NL80211_CMD_AUTHENTICATE attribute set
    // for the mac80211 SME-in-userspace path. Extra RSN/cipher attributes are
    // only valid for ASSOCIATE/CONNECT and confuse this command.
    let attrs = vec![
        Nl80211Attr::IfIndex(if_index),
        Nl80211Attr::Mac(bssid),
        Nl80211Attr::WiphyFreq(freq_mhz),
        Nl80211Attr::Ssid(ssid.to_string()),
        Nl80211Attr::AuthType(Nl80211AuthType::Sae),
        // NL80211_ATTR_AUTH_DATA = 156: SAE commit (trans||status||body)
        Nl80211Attr::Other(DefaultNla::new(156, auth_data.to_vec())),
    ];

    send_nl80211_cmd(handle, Nl80211Command::Authenticate, attrs).await
}

/// Send NL80211_CMD_AUTHENTICATE carrying the SAE confirm (transaction 2).
/// `confirm_hash` is the 32-byte CN output; the send-confirm counter is 1.
pub async fn authenticate_sae_confirm(
    handle: &Nl80211Handle,
    if_index: u32,
    ssid: &str,
    bssid: [u8; 6],
    freq_mhz: u32,
    confirm_hash: &[u8],
) -> ShuliResult<()> {
    // auth_data = trans(2 LE=2) || status(2 LE=0) || send_confirm(2 LE=1)
    //             || confirm_hash(32)
    let mut auth_data = Vec::with_capacity(6 + confirm_hash.len());
    auth_data.extend_from_slice(&2u16.to_le_bytes()); // transaction = confirm
    auth_data.extend_from_slice(&0u16.to_le_bytes()); // status
    auth_data.extend_from_slice(&1u16.to_le_bytes()); // send-confirm = 1
    auth_data.extend_from_slice(confirm_hash);

    let attrs = vec![
        Nl80211Attr::IfIndex(if_index),
        Nl80211Attr::Mac(bssid),
        Nl80211Attr::WiphyFreq(freq_mhz),
        Nl80211Attr::Ssid(ssid.to_string()),
        Nl80211Attr::AuthType(Nl80211AuthType::Sae),
        Nl80211Attr::Other(DefaultNla::new(156, auth_data)),
    ];

    send_nl80211_cmd(handle, Nl80211Command::Authenticate, attrs).await
}

/// Send NL80211_CMD_ASSOCIATE with RSNE for SAE.
pub async fn associate(
    handle: &Nl80211Handle,
    if_index: u32,
    ssid: &str,
    bssid: [u8; 6],
    freq_mhz: u32,
) -> ShuliResult<()> {
    // Build the RSNE + RSNXE exactly as they appear in 4-way handshake
    // Message 2 so the AP's consistency check passes.
    let mut ie_buf = crate::ieee80211::elements::sae_rsne();
    ie_buf.extend_from_slice(&crate::ieee80211::elements::rsnxe_h2e());
    log::debug!("associate IE: {ie_buf:02x?}");

    let attrs = vec![
        Nl80211Attr::IfIndex(if_index),
        Nl80211Attr::Mac(bssid),
        Nl80211Attr::WiphyFreq(freq_mhz),
        Nl80211Attr::Ssid(ssid.to_string()),
        Nl80211Attr::Ie(ie_buf),
        Nl80211Attr::UseMfp(Nl80211UseMfp::Required),
        Nl80211Attr::ControlPortOverNl80211,
        Nl80211Attr::SocketOwner,
    ];

    send_nl80211_cmd(handle, Nl80211Command::Associate, attrs).await
}

async fn send_nl80211_cmd(
    handle: &Nl80211Handle,
    cmd: Nl80211Command,
    attrs: Vec<Nl80211Attr>,
) -> ShuliResult<()> {
    let mut nl_msg =
        NetlinkMessage::from(GenlMessage::from_payload(Nl80211Message {
            cmd,
            attributes: attrs,
        }));
    nl_msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    log::info!("sending nl80211 cmd: {cmd:?}");

    let mut handle = handle.clone();
    let mut stream = handle.request(nl_msg).await?;
    while let Some(msg) = stream.try_next().await? {
        if let netlink_packet_core::NetlinkPayload::Error(ref err) = msg.payload
            && let Some(code) = err.code
        {
            return Err(crate::ShuliError::ConnectFailed(format!(
                "{cmd:?} failed: netlink error {code}"
            )));
        }
        log::debug!("nl80211 cmd response: {msg:?}");
    }
    log::info!("nl80211 cmd {cmd:?} done");
    Ok(())
}
