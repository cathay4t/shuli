// SPDX-License-Identifier: Apache-2.0

use netlink_packet_core::Emitable;
use wl_nl80211::{
    Nl80211AkmSuite, Nl80211CipherSuite, Nl80211Element, Nl80211ElementRsn,
    Nl80211ElementRsnExt, Nl80211Elements, Nl80211RsnCapbilities,
    Nl80211RsnExtCapbilities,
};

/// Build the RSNE + RSNXE for WPA3-Personal (SAE / CCMP-128, management frame
/// protection required, SAE Hash-to-Element). The exact same bytes are used in
/// the Association Request and in 4-way handshake Message 2; the AP verifies
/// they match, so both call sites must use this single builder.
pub fn sae_ie() -> Vec<u8> {
    let elements = Nl80211Elements(vec![
        Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::Sae],
            rsn_capbilities: Some(
                Nl80211RsnCapbilities::Mfpr | Nl80211RsnCapbilities::Mfpc,
            ),
            pmkids: vec![],
            group_mgmt_cipher: Some(Nl80211CipherSuite::BipCmac128),
        }),
        Nl80211Element::RsnExt(Nl80211ElementRsnExt {
            capabilities: Nl80211RsnExtCapbilities::SaeH2e,
        }),
    ]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}
