// SPDX-License-Identifier: Apache-2.0

use netlink_packet_core::Emitable;
use wl_nl80211::{
    Nl80211AkmSuite, Nl80211CipherSuite, Nl80211Element, Nl80211ElementRsn,
    Nl80211ElementRsnExt, Nl80211Elements, Nl80211Pmkid, Nl80211RsnCapbilities,
    Nl80211RsnExtCapbilities,
};

use crate::{
    ErrorKind, WifiError,
    crypto::{ft::ft_mic, handshake4},
};

/// Element ID of the Mobility Domain element (802.11-2020 §9.4.2.47).
pub const IE_ID_MDIE: u8 = 54;
/// Element ID of the Fast BSS Transition element (802.11-2020 §9.4.2.48).
pub const IE_ID_FTIE: u8 = 55;
/// Element ID of the RSNE (802.11-2020 §9.4.2.25).
pub const IE_ID_RSNE: u8 = 48;
/// Element ID of the RSNXE (802.11-2020 §9.4.2.25a).
pub const IE_ID_RSNXE: u8 = 244;

/// Find an element in an IE buffer and return the offset of its ID
/// octet.
pub fn find_ie_pos(ies: &[u8], id: u8) -> Option<usize> {
    let mut pos = 0;
    while pos + 2 <= ies.len() {
        let len = ies[pos + 1] as usize;
        if pos + 2 + len > ies.len() {
            break;
        }
        if ies[pos] == id {
            return Some(pos);
        }
        pos += 2 + len;
    }
    None
}

/// Find an element in an IE buffer and return its body (without the
/// ID/length header).
pub fn find_ie(ies: &[u8], id: u8) -> Option<&[u8]> {
    let pos = find_ie_pos(ies, id)?;
    let len = ies[pos + 1] as usize;
    Some(&ies[pos + 2..pos + 2 + len])
}

/// The full RSNE element (ID + length + body) at `pos`, as returned by
/// [`find_ie_pos`].
pub fn ie_at(ies: &[u8], pos: usize) -> &[u8] {
    let len = ies[pos + 1] as usize;
    &ies[pos..pos + 2 + len]
}

/// First PMKID of an RSNE body (after the element header), if the RSNE
/// carries one.
pub fn rsne_first_pmkid(body: &[u8]) -> Option<[u8; 16]> {
    // version(2) group(4) pcount(2) pciphers acount(2) akms capab(2)
    if body.len() < 8 {
        return None;
    }
    let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
    let mut pos = 8 + pcount * 4;
    if body.len() < pos + 2 {
        return None;
    }
    let acount = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + acount * 4 + 2; // AKMs + RSN capabilities
    if body.len() < pos + 2 {
        return None;
    }
    let count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    if count == 0 || body.len() < pos + 2 + 16 {
        return None;
    }
    Some(body[pos + 2..pos + 18].try_into().unwrap())
}

/// The group management (BIP) cipher the AP advertises in its RSNE
/// (full element, ID + length + body); `None` when absent (older
/// PMF-optional RSNEs omit it, and BIP-CMAC-128 is then assumed).
pub(crate) fn parse_group_mgmt_cipher(
    rsne: &[u8],
) -> Option<Nl80211CipherSuite> {
    if rsne.len() < 4 {
        return None;
    }
    let body = &rsne[2..];
    if body.len() < 8 {
        return None;
    }
    let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
    let akm_off = 8 + pcount * 4;
    if body.len() < akm_off + 2 {
        return None;
    }
    let acount =
        u16::from_le_bytes([body[akm_off], body[akm_off + 1]]) as usize;
    let cap_off = akm_off + 2 + acount * 4;
    if body.len() < cap_off + 2 {
        return None;
    }
    let pmkid_off = cap_off + 2;
    if body.len() < pmkid_off + 2 {
        return None;
    }
    let pmkid_count =
        u16::from_le_bytes([body[pmkid_off], body[pmkid_off + 1]]) as usize;
    let mgmt_off = pmkid_off + 2 + pmkid_count * 16;
    if body.len() < mgmt_off + 4 {
        return None;
    }
    let bytes: [u8; 4] = body[mgmt_off..mgmt_off + 4].try_into().ok()?;
    Some(Nl80211CipherSuite::from(u32::from_le_bytes(bytes)))
}

/// Whether the AP's RSNXE (full element: ID || length || body, as
/// stored in `BssInfo::ap_rsnxe`) advertises SAE Hash-to-Element
/// support. An empty slice (no RSNXE in the beacon/probe response) or
/// a malformed element both mean "not advertised": `SaePwe::Auto`
/// uses this to pick hunting-and-pecking up front for APs that never
/// claim H2E support, instead of sending an H2E commit the AP will
/// silently drop and only discovering the mismatch after the commit
/// times out.
pub fn ap_rsnxe_supports_sae_h2e(ap_rsnxe: &[u8]) -> bool {
    if ap_rsnxe.len() < 3 {
        return false;
    }
    Nl80211ElementRsnExt::parse(&ap_rsnxe[2..]).is_ok_and(|rsnxe| {
        rsnxe
            .capabilities
            .contains(Nl80211RsnExtCapbilities::SaeH2e)
    })
}

/// The RSN capabilities field (2 octets) of an RSNE body, if present.
fn rsne_capabilities_field(body: &[u8]) -> Option<u16> {
    if body.len() < 8 {
        return None;
    }
    let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
    let akm_offset = 8 + pcount * 4;
    if body.len() < akm_offset + 2 {
        return None;
    }
    let acount =
        u16::from_le_bytes([body[akm_offset], body[akm_offset + 1]]) as usize;
    let cap_offset = akm_offset + 2 + acount * 4;
    if body.len() < cap_offset + 2 {
        return None;
    }
    Some(u16::from_le_bytes([body[cap_offset], body[cap_offset + 1]]))
}

/// Whether the AP's RSNE (full element: ID || length || body, as stored
/// in `BssInfo::ap_rsne`) advertises the OCVC RSN capability (bit 14,
/// 802.11-2020 §9.4.2.25). Used to enable Operating Channel Validation
/// (Stage 3 M10) only when the AP actually supports it, instead of
/// enforcing OCI verification against an AP that will never include an
/// OCI KDE in Message 3 - which would otherwise always fail the 4-way
/// handshake.
pub fn ap_rsne_supports_ocv(ap_rsne: &[u8]) -> bool {
    if ap_rsne.len() < 2 {
        return false;
    }
    rsne_capabilities_field(&ap_rsne[2..]).is_some_and(|c| c & 0x4000 != 0)
}

/// Whether the AP's RSNE advertises the Extended Key ID for
/// Individually Addressed Frames RSN capability (bit 13,
/// 802.11-2020 §9.4.2.25). Used to request Extended Key ID (Stage 3
/// M11) only when the AP actually supports it, instead of requiring a
/// Key ID KDE in Message 3 that a non-supporting AP will never send.
pub fn ap_rsne_supports_ext_key_id(ap_rsne: &[u8]) -> bool {
    if ap_rsne.len() < 2 {
        return false;
    }
    rsne_capabilities_field(&ap_rsne[2..]).is_some_and(|c| c & 0x2000 != 0)
}

/// Negotiate the group management (BIP) cipher with the AP: the best
/// supported suite the AP advertises, defaulting to BIP-CMAC-128.
/// Preference order matches iwd: GMAC-256 > CMAC-256 > GMAC-128 >
/// CMAC-128 (Stage 3 M8).
pub fn negotiate_group_mgmt_cipher(ap_rsne: &[u8]) -> Nl80211CipherSuite {
    let Some(ap) = parse_group_mgmt_cipher(ap_rsne) else {
        return Nl80211CipherSuite::BipCmac128;
    };
    for preferred in [
        Nl80211CipherSuite::BipGmac256,
        Nl80211CipherSuite::BipCmac256,
        Nl80211CipherSuite::BipGmac128,
        Nl80211CipherSuite::BipCmac128,
    ] {
        if ap == preferred {
            return preferred;
        }
    }
    Nl80211CipherSuite::BipCmac128
}

/// Set or clear the OCV capability bit (bit 14) in the RSN
/// capabilities of a built RSNE (Stage 3 M10).
pub fn rsne_set_ocvc(rsne: &mut [u8], enabled: bool) {
    if rsne.len() < 4 {
        return;
    }
    let body = &rsne[2..];
    if body.len() < 8 {
        return;
    }
    let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
    let akm_off = 8 + pcount * 4;
    if body.len() < akm_off + 2 {
        return;
    }
    let acount =
        u16::from_le_bytes([body[akm_off], body[akm_off + 1]]) as usize;
    let cap_off = 2 + akm_off + 2 + acount * 4;
    if rsne.len() < cap_off + 2 {
        return;
    }
    let capab = u16::from_le_bytes([rsne[cap_off], rsne[cap_off + 1]]);
    let capab = if enabled {
        capab | 0x4000 // WPA_CAPABILITY_OCVC
    } else {
        capab & !0x4000
    };
    rsne[cap_off..cap_off + 2].copy_from_slice(&capab.to_le_bytes());
}

/// Set or clear the Extended Key ID capability bit (bit 13) in the RSN
/// capabilities of a built RSNE (Stage 3 M11).
pub fn rsne_set_ext_key_id(rsne: &mut [u8], enabled: bool) {
    if rsne.len() < 4 {
        return;
    }
    let body = &rsne[2..];
    if body.len() < 8 {
        return;
    }
    let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
    let akm_off = 8 + pcount * 4;
    if body.len() < akm_off + 2 {
        return;
    }
    let acount =
        u16::from_le_bytes([body[akm_off], body[akm_off + 1]]) as usize;
    let cap_off = 2 + akm_off + 2 + acount * 4;
    if rsne.len() < cap_off + 2 {
        return;
    }
    let capab = u16::from_le_bytes([rsne[cap_off], rsne[cap_off + 1]]);
    let capab = if enabled {
        capab | 0x2000 // WPA_CAPABILITY_EXT_KEY_ID_FOR_UNICAST
    } else {
        capab & !0x2000
    };
    rsne[cap_off..cap_off + 2].copy_from_slice(&capab.to_le_bytes());
}

/// The RSNXE element advertising SAE Hash-to-Element support; included
/// in FT Reassociation Requests (and their FTIE MIC) on FT-SAE.
pub fn sae_rsnxe() -> Vec<u8> {
    let elements =
        Nl80211Elements(vec![Nl80211Element::RsnExt(Nl80211ElementRsnExt {
            capabilities: Nl80211RsnExtCapbilities::SaeH2e,
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE + RSNXE for WPA3-Personal (SAE / CCMP-128, management frame
/// protection required, SAE Hash-to-Element). The exact same bytes are used in
/// the Association Request and in 4-way handshake Message 2; the AP verifies
/// they match, so both call sites must use this single builder.
/// [`sae_ie`] with a negotiated group management (BIP) cipher.
pub fn sae_ie_cipher(mgmt_cipher: Nl80211CipherSuite) -> Vec<u8> {
    sae_ie_with_pmkid_cipher(None, mgmt_cipher)
}

/// [`sae_ie_with_pmkid`] with a negotiated group management (BIP)
/// cipher (Stage 3 M8).
pub fn sae_ie_with_pmkid_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Nl80211CipherSuite,
) -> Vec<u8> {
    let elements = Nl80211Elements(vec![
        Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::Sae],
            rsn_capbilities: Some(
                Nl80211RsnCapbilities::Mfpr | Nl80211RsnCapbilities::Mfpc,
            ),
            pmkids: pmkid.into_iter().map(Nl80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        }),
        Nl80211Element::RsnExt(Nl80211ElementRsnExt {
            capabilities: Nl80211RsnExtCapbilities::SaeH2e,
        }),
    ]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE + RSNXE for SAE-EXT-KEY (AKM 00-0F-AC:24, Stage 3
/// M12): same security policy as SAE (CCMP-128, MFP required, H2E),
/// only the AKM differs.
pub fn sae_ext_key_ie_cipher(mgmt_cipher: Nl80211CipherSuite) -> Vec<u8> {
    sae_ext_key_ie_with_pmkid_cipher(None, mgmt_cipher)
}

/// [`sae_ext_key_ie_cipher`] carrying a PMKID.
pub fn sae_ext_key_ie_with_pmkid_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Nl80211CipherSuite,
) -> Vec<u8> {
    let elements = Nl80211Elements(vec![
        Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::SaeGroupDependentHash],
            rsn_capbilities: Some(
                Nl80211RsnCapbilities::Mfpr | Nl80211RsnCapbilities::Mfpc,
            ),
            pmkids: pmkid.into_iter().map(Nl80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        }),
        Nl80211Element::RsnExt(Nl80211ElementRsnExt {
            capabilities: Nl80211RsnExtCapbilities::SaeH2e,
        }),
    ]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the FT-SAE-EXT-KEY RSNE element only (AKM 00-0F-AC:25).
pub fn ft_sae_ext_key_rsne_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Nl80211CipherSuite,
) -> Vec<u8> {
    let elements =
        Nl80211Elements(vec![Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::FtSaeGroupDependentHash],
            rsn_capbilities: Some(
                Nl80211RsnCapbilities::Mfpr | Nl80211RsnCapbilities::Mfpc,
            ),
            pmkids: pmkid.into_iter().map(Nl80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE + RSNXE for FT-SAE-EXT-KEY (AKM 00-0F-AC:25).
pub fn ft_sae_ext_key_ie_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Nl80211CipherSuite,
) -> Vec<u8> {
    let mut buf = ft_sae_ext_key_rsne_cipher(pmkid, mgmt_cipher);
    buf.extend_from_slice(&sae_rsnxe());
    buf
}

/// Build the RSNE for OWE (AKM 00-0F-AC:18, CCMP-128, MFP required).
/// No RSNXE — OWE does not use SAE H2E.
/// [`owe_ie`] with a negotiated group management (BIP) cipher.
pub fn owe_ie_cipher(mgmt_cipher: Nl80211CipherSuite) -> Vec<u8> {
    let elements =
        Nl80211Elements(vec![Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::Owe],
            rsn_capbilities: Some(
                Nl80211RsnCapbilities::Mfpr | Nl80211RsnCapbilities::Mfpc,
            ),
            pmkids: vec![],
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE for WPA2-PSK (AKM 00-0F-AC:2, CCMP-128). Management
/// frame protection is negotiated as optional (MFPC without MFPR, iwd's
/// default `ManagementFrameProtection=1` behaviour): PMF-capable APs then
/// protect the connection with an IGTK, PMF-less APs still accept it.
/// [`wpa2_psk_ie`] with a negotiated group management (BIP) cipher.
pub fn wpa2_psk_ie_cipher(mgmt_cipher: Nl80211CipherSuite) -> Vec<u8> {
    wpa2_psk_ie_with_pmkid_cipher(None, mgmt_cipher)
}

/// [`wpa2_psk_ie_with_pmkid`] with a negotiated group management (BIP)
/// cipher.
pub fn wpa2_psk_ie_with_pmkid_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Nl80211CipherSuite,
) -> Vec<u8> {
    let elements =
        Nl80211Elements(vec![Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::Psk],
            rsn_capbilities: Some(Nl80211RsnCapbilities::Mfpc),
            pmkids: pmkid.into_iter().map(Nl80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE for WPA2-Personal with SHA-256 algorithms
/// (PSK-SHA256, AKM 00-0F-AC:6, CCMP-128). Same security policy as
/// [`wpa2_psk_ie`] (optional MFP), only the AKM suite differs.
/// [`wpa2_psk_sha256_ie`] with a negotiated group management (BIP)
/// cipher.
pub fn wpa2_psk_sha256_ie_cipher(mgmt_cipher: Nl80211CipherSuite) -> Vec<u8> {
    wpa2_psk_sha256_ie_with_pmkid_cipher(None, mgmt_cipher)
}

/// [`wpa2_psk_sha256_ie_with_pmkid`] with a negotiated group
/// management (BIP) cipher.
pub fn wpa2_psk_sha256_ie_with_pmkid_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Nl80211CipherSuite,
) -> Vec<u8> {
    let elements =
        Nl80211Elements(vec![Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::PskSha256],
            rsn_capbilities: Some(Nl80211RsnCapbilities::Mfpc),
            pmkids: pmkid.into_iter().map(Nl80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE for WPA2-Enterprise (802.1X, AKM 00-0F-AC:1,
/// CCMP-128) with optional management frame protection.
/// [`wpa2_ent_ie`] with a negotiated group management (BIP) cipher.
pub fn wpa2_ent_ie_cipher(mgmt_cipher: Nl80211CipherSuite) -> Vec<u8> {
    let elements =
        Nl80211Elements(vec![Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::Ieee8021x],
            rsn_capbilities: Some(Nl80211RsnCapbilities::Mfpc),
            pmkids: vec![],
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE for WPA3-Enterprise (802.1X-SHA256, AKM
/// 00-0F-AC:5, CCMP-128) with **mandatory** management frame
/// protection (MFPR + MFPC) - the WPA3 baseline requirement.
/// [`wpa2_ent_sha256_ie`] with a negotiated group management (BIP)
/// cipher.
pub fn wpa2_ent_sha256_ie_cipher(mgmt_cipher: Nl80211CipherSuite) -> Vec<u8> {
    let elements =
        Nl80211Elements(vec![Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::Ieee8021xSha256],
            rsn_capbilities: Some(
                Nl80211RsnCapbilities::Mfpr | Nl80211RsnCapbilities::Mfpc,
            ),
            pmkids: vec![],
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the FT-SAE RSNE element only (AKM 00-0F-AC:9). Used where the
/// RSNE and RSNXE must stay separate elements (FT Reassociation Request:
/// the FTIE MIC covers RSNE, MDIE, FTIE, then RSNXE in that order).
/// [`ft_sae_rsne`] with a negotiated group management (BIP) cipher.
pub fn ft_sae_rsne_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Nl80211CipherSuite,
) -> Vec<u8> {
    let elements =
        Nl80211Elements(vec![Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::FtSae],
            rsn_capbilities: Some(
                Nl80211RsnCapbilities::Mfpr | Nl80211RsnCapbilities::Mfpc,
            ),
            pmkids: pmkid.into_iter().map(Nl80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the FT-PSK RSNE element only (AKM 00-0F-AC:4); see
/// [`ft_sae_rsne`].
/// [`ft_psk_rsne`] with a negotiated group management (BIP) cipher.
pub fn ft_psk_rsne_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Nl80211CipherSuite,
) -> Vec<u8> {
    let elements =
        Nl80211Elements(vec![Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::FtPsk],
            rsn_capbilities: Some(Nl80211RsnCapbilities::Mfpc),
            pmkids: pmkid.into_iter().map(Nl80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE + RSNXE for FT-SAE (AKM 00-0F-AC:9): same crypto
/// policy as [`sae_ie`] (CCMP-128, MFP required, SAE H2E), only the AKM
/// differs. `pmkid` carries PMKR0Name / PMKR1Name during FT.
/// [`ft_sae_ie`] with a negotiated group management (BIP) cipher.
pub fn ft_sae_ie_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Nl80211CipherSuite,
) -> Vec<u8> {
    let mut buf = ft_sae_rsne_cipher(pmkid, mgmt_cipher);
    buf.extend_from_slice(&sae_rsnxe());
    buf
}

/// Build the RSNE for FT-PSK (AKM 00-0F-AC:4): same crypto policy as
/// [`wpa2_psk_ie`] (CCMP-128, optional MFP). `pmkid` carries PMKR0Name
/// / PMKR1Name during FT.
/// [`ft_psk_ie`] with a negotiated group management (BIP) cipher.
pub fn ft_psk_ie_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Nl80211CipherSuite,
) -> Vec<u8> {
    ft_psk_rsne_cipher(pmkid, mgmt_cipher)
}

/// Build a Mobility Domain element: MDID (2) || FT Capability and
/// Policy (1). `ft_capab` is normally echoed from the target AP's
/// MDIE.
pub fn mdie(mdid: [u8; 2], ft_capab: u8) -> Vec<u8> {
    vec![IE_ID_MDIE, 3, mdid[0], mdid[1], ft_capab]
}

/// Parse a Mobility Domain element body: (MDID, FT capability/policy).
pub fn parse_mdie(body: &[u8]) -> Option<([u8; 2], u8)> {
    if body.len() < 3 {
        return None;
    }
    Some(([body[0], body[1]], body[2]))
}

/// FTIE subelement identifiers (802.11-2020 §9.4.2.48).
const FTIE_SUBELEM_R1KH_ID: u8 = 1;
const FTIE_SUBELEM_GTK: u8 = 2;
const FTIE_SUBELEM_R0KH_ID: u8 = 3;
const FTIE_SUBELEM_IGTK: u8 = 4;
const FTIE_SUBELEM_BIGTK: u8 = 6;

/// Build the FTIE of an over-the-air FT Authentication request
/// (transaction 1): SNonce and the R0KH-ID subelement, with the MIC
/// left zeroed - the first FT authentication frame carries no MIC
/// (wpa_supplicant's `wpa_ft_prepare_auth_request` does the same).
pub fn ftie_auth_request(snonce: &[u8; 32], r0kh_id: &[u8]) -> Vec<u8> {
    let body_len = 2 + 16 + 32 + 32 + 2 + r0kh_id.len();
    let mut e = Vec::with_capacity(2 + body_len);
    e.push(IE_ID_FTIE);
    e.push(body_len as u8);
    // MIC Control: MIC length code 0 (= 16 octets), element count 0.
    e.extend_from_slice(&[0, 0]);
    e.extend_from_slice(&[0u8; 16]); // MIC (zero)
    e.extend_from_slice(&[0u8; 32]); // ANonce (zero in the request)
    e.extend_from_slice(snonce);
    e.push(FTIE_SUBELEM_R0KH_ID);
    e.push(r0kh_id.len() as u8);
    e.extend_from_slice(r0kh_id);
    e
}

/// Build the FTIE of an FT Reassociation Request, MIC included
/// (802.11-2020 §12.8.4: transaction sequence number 5 over
/// STA-ADDR || AP-ADDR || seq || RSNE || MDIE || FTIE(MIC=0) ||
/// [RSNXE]). `rsne` / `mdie` / `rsnxe` are full elements (with their
/// IE headers).
#[allow(clippy::too_many_arguments)] // the FTIE MIC covers all of them
pub fn ftie_reassoc_request(
    kck: &[u8; 16],
    sta_addr: [u8; 6],
    ap_addr: [u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    r0kh_id: &[u8],
    r1kh_id: &[u8; 6],
    rsne: &[u8],
    mdie: &[u8],
    rsnxe: Option<&[u8]>,
) -> Result<Vec<u8>, WifiError> {
    let elem_count = 3 + u8::from(rsnxe.is_some());
    // RSNXE Used bit in the MIC Control when the RSNXE is part of the
    // MIC (SAE H2E networks).
    let mic_control = [u8::from(rsnxe.is_some()), elem_count];

    let body_len = 2 + 16 + 32 + 32 + (2 + 6) + (2 + r0kh_id.len());
    let mut ftie = Vec::with_capacity(2 + body_len);
    ftie.push(IE_ID_FTIE);
    ftie.push(body_len as u8);
    ftie.extend_from_slice(&mic_control);
    let mic_pos = ftie.len();
    ftie.extend_from_slice(&[0u8; 16]);
    ftie.extend_from_slice(anonce);
    ftie.extend_from_slice(snonce);
    ftie.push(FTIE_SUBELEM_R1KH_ID);
    ftie.push(6);
    ftie.extend_from_slice(r1kh_id);
    ftie.push(FTIE_SUBELEM_R0KH_ID);
    ftie.push(r0kh_id.len() as u8);
    ftie.extend_from_slice(r0kh_id);

    let mut mic_data = Vec::with_capacity(
        rsne.len()
            + mdie.len()
            + ftie.len()
            + rsnxe.map(<[u8]>::len).unwrap_or(0),
    );
    mic_data.extend_from_slice(rsne);
    mic_data.extend_from_slice(mdie);
    mic_data.extend_from_slice(&ftie);
    if let Some(rsnxe) = rsnxe {
        mic_data.extend_from_slice(rsnxe);
    }
    let mic = ft_mic(kck, sta_addr, ap_addr, 5, &mic_data)?;
    ftie[mic_pos..mic_pos + 16].copy_from_slice(&mic);
    Ok(ftie)
}

/// A group key delivered in an FTIE subelement (GTK / IGTK / BIGTK),
/// still AES-Key-Wrapped with the KEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtKeySubelem {
    pub key_index: u8,
    /// Receive sequence counter: RSC (8) for the GTK, IPN/BIPN (6) for
    /// IGTK/BIGTK.
    pub rsc: Vec<u8>,
    pub wrapped_key: Vec<u8>,
}

/// Parsed Fast BSS Transition element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtIe {
    pub mic_control: [u8; 2],
    pub mic: [u8; 16],
    pub anonce: [u8; 32],
    pub snonce: [u8; 32],
    pub r0kh_id: Option<Vec<u8>>,
    pub r1kh_id: Option<[u8; 6]>,
    pub gtk: Option<FtKeySubelem>,
    pub igtk: Option<FtKeySubelem>,
    pub bigtk: Option<FtKeySubelem>,
}

fn parse_ft_key_subelem(body: &[u8], rsc_len: usize) -> Option<FtKeySubelem> {
    if rsc_len == 8 {
        // GTK: Key Info[2] | Key Length[1] | RSC[8] | wrapped Key
        // (802.11-2020 §9.4.2.48.3); only the first 6 RSC octets are
        // the actual CCMP receive counter.
        if body.len() < 11 {
            return None;
        }
        let key_index = u16::from_le_bytes([body[0], body[1]]) & 0x03;
        Some(FtKeySubelem {
            key_index: key_index as u8,
            rsc: body[3..9].to_vec(),
            wrapped_key: body[11..].to_vec(),
        })
    } else {
        // IGTK / BIGTK: Key Info[2] | IPN[6] | Key Length[1] | wrapped
        // Key. Key Info carries the full key index (4-7), not a GTK
        // index masked to two bits.
        if body.len() < 9 {
            return None;
        }
        let key_index = u16::from_le_bytes([body[0], body[1]]) as u8;
        Some(FtKeySubelem {
            key_index,
            rsc: body[2..8].to_vec(),
            wrapped_key: body[9..].to_vec(),
        })
    }
}

/// Parse a Fast BSS Transition element body (after the IE header).
pub fn parse_ftie(body: &[u8]) -> Option<FtIe> {
    // Fixed part: MIC Control(2) || MIC(16) || ANonce(32) || SNonce(32).
    if body.len() < 2 + 16 + 32 + 32 {
        return None;
    }
    let mut ftie = FtIe {
        mic_control: [body[0], body[1]],
        mic: body[2..18].try_into().unwrap(),
        anonce: body[18..50].try_into().unwrap(),
        snonce: body[50..82].try_into().unwrap(),
        r0kh_id: None,
        r1kh_id: None,
        gtk: None,
        igtk: None,
        bigtk: None,
    };

    let mut pos = 82;
    while pos + 2 <= body.len() {
        let id = body[pos];
        let len = body[pos + 1] as usize;
        let start = pos + 2;
        let end = start + len;
        if end > body.len() {
            break;
        }
        let sub = &body[start..end];
        match id {
            FTIE_SUBELEM_R0KH_ID => ftie.r0kh_id = Some(sub.to_vec()),
            FTIE_SUBELEM_R1KH_ID if len == 6 => {
                ftie.r1kh_id = Some(sub.try_into().unwrap());
            }
            FTIE_SUBELEM_GTK => ftie.gtk = parse_ft_key_subelem(sub, 8),
            FTIE_SUBELEM_IGTK => ftie.igtk = parse_ft_key_subelem(sub, 6),
            FTIE_SUBELEM_BIGTK => ftie.bigtk = parse_ft_key_subelem(sub, 6),
            _ => {}
        }
        pos = end;
    }
    Some(ftie)
}

/// Compare two RSNE elements semantically while ignoring the PMKID
/// list: FT (Re)Association Responses carry PMKR0Name / PMKR1Name as
/// the PMKID, which the beacon RSNE lacks (wpa_supplicant's
/// `wpa_compare_rsn_ie` does the same for FT AKMs).
pub fn rsne_match_ignore_pmkid(a: &[u8], b: &[u8]) -> bool {
    let body_a = find_ie(a, IE_ID_RSNE).unwrap_or(a);
    let body_b = find_ie(b, IE_ID_RSNE).unwrap_or(b);
    // body: version(2) group(4) pcount(2) pciphers(4n) acount(2)
    // akms(4m) [capab(2) [pmkid_count(2) pmkids] [group_mgmt(4)]] -
    // everything but the PMKID list is compared verbatim.
    let strip_pmkids = |body: &[u8]| -> Option<Vec<u8>> {
        if body.len() < 8 {
            return None;
        }
        let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
        let mut pos = 8 + pcount * 4;
        if body.len() < pos + 2 {
            return None;
        }
        let acount = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2 + acount * 4;
        // RSN capabilities (optional) precede the PMKID list.
        if body.len() < pos + 2 {
            return Some(body[..pos].to_vec());
        }
        pos += 2;
        let prefix = &body[..pos];
        let mut rest = &body[pos..];
        if rest.len() >= 2 {
            let count = u16::from_le_bytes([rest[0], rest[1]]) as usize;
            let pmk_len = 2 + count * 16;
            if rest.len() < pmk_len {
                return None;
            }
            // Skip the PMKID list; keep the optional trailing group
            // management cipher suite.
            rest = &rest[pmk_len..];
        }
        let mut out = prefix.to_vec();
        out.extend_from_slice(rest);
        Some(out)
    };
    match (strip_pmkids(body_a), strip_pmkids(body_b)) {
        (Some(x), Some(y)) => x == y,
        _ => body_a == body_b,
    }
}

/// Unwrap a group key from an FTIE subelement with the KEK.
pub fn unwrap_ft_key(
    kek: &[u8; 16],
    subelem: &FtKeySubelem,
) -> Result<Vec<u8>, WifiError> {
    handshake4::aes_key_unwrap(kek, &subelem.wrapped_key).map_err(|e| {
        WifiError::new(
            ErrorKind::HandshakeFailed,
            format!("FT key unwrap failed: {e}"),
        )
    })
}
