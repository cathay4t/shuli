// SPDX-License-Identifier: Apache-2.0

// WPA3-Personal authentication via NL80211_CMD_CONNECT.
// Provides both external-auth (path A) and direct SAE connect paths.

use futures::TryStreamExt;
use wl_nl80211::{
    Nl80211AkmSuite, Nl80211Attr, Nl80211AuthType, Nl80211CipherSuite,
    Nl80211ConnectionHandle, Nl80211UseMfp, Nl80211WpaVersions,
};

use crate::ShuliResult;

/// Build the attribute list for a WPA3-Personal (SAE) connection.
/// `external_auth` controls whether userspace handles SAE (path A) or the
/// driver/firmware does (SAE offload, path B), provided the driver supports it.
pub fn build_sae_connect_attrs(
    if_index: u32,
    ssid: &str,
    bssid: [u8; 6],
    external_auth: bool,
) -> Vec<Nl80211Attr> {
    let builder = wl_nl80211::Nl80211Connect::new(if_index)
        .ssid(ssid)
        .mac(bssid)
        .auth_type(Nl80211AuthType::Sae)
        .wpa_versions(Nl80211WpaVersions::WPA2)
        .ciphers_pairwise(vec![Nl80211CipherSuite::Ccmp128])
        .cipher_group(Nl80211CipherSuite::Ccmp128)
        .akm_suites(vec![Nl80211AkmSuite::Sae])
        .use_mfp(Nl80211UseMfp::Required)
        .privacy(true)
        .control_port_over_nl80211(true)
        .socket_owner(true);

    if external_auth {
        builder.external_auth_support(true).build()
    } else {
        builder.build()
    }
}

/// Send CONNECT with external-auth support (for drivers with ExternalAuth
/// feature). Userspace must then handle SAE and report result via
/// `NL80211_CMD_EXTERNAL_AUTH`.
pub async fn sae_external_auth_connect(
    conn_handle: &mut Nl80211ConnectionHandle,
    if_index: u32,
    ssid: &str,
    bssid: [u8; 6],
) -> ShuliResult<()> {
    let attrs = build_sae_connect_attrs(if_index, ssid, bssid, true);
    let mut stream = conn_handle.connect(attrs).execute().await;
    while let Some(_msg) = stream.try_next().await? {}
    Ok(())
}

/// Send CONNECT without external-auth (kernel/driver handles SAE internally).
pub async fn sae_connect(
    conn_handle: &mut Nl80211ConnectionHandle,
    if_index: u32,
    ssid: &str,
    bssid: [u8; 6],
) -> ShuliResult<()> {
    let attrs = build_sae_connect_attrs(if_index, ssid, bssid, false);
    let mut stream = conn_handle.connect(attrs).execute().await;
    while let Some(_msg) = stream.try_next().await? {}
    Ok(())
}

pub async fn disconnect(
    conn_handle: &mut Nl80211ConnectionHandle,
    if_index: u32,
) -> ShuliResult<()> {
    let attrs = wl_nl80211::Nl80211Disconnect::new(if_index).build();
    let mut stream = conn_handle.disconnect(attrs).execute().await;
    while let Some(_msg) = stream.try_next().await? {}
    Ok(())
}
