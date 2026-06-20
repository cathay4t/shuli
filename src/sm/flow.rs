// SPDX-License-Identifier: Apache-2.0

// Connection flow: scan -> SAE authenticate -> event-driven handshake.

use log::{info, warn};
use wl_nl80211::Nl80211Handle;

use crate::{
    ShuliResult,
    crypto::sae::SaeState,
    nl80211::{
        auth_assoc,
        scan::{
            extract_bssid, extract_freq, find_bss_by_ssid, get_scan_results,
            trigger_scan,
        },
    },
    sm::connection::{ConnectionSm, ConnectionState},
};

const SCAN_SLEEP_SECS: u64 = 3;

/// Result of the initial scan + SAE commit.
#[derive(Debug)]
pub struct ConnectFlowResult {
    pub bssid: [u8; 6],
    pub freq: u32,
    pub sae: SaeState,
}

/// Run the initial connection flow:
/// 1. Trigger a scan for the target SSID
/// 2. Select the best BSS
/// 3. Register for authentication mgmt frames
/// 4. Derive PWE, build SAE commit, send AUTHENTICATE with auth_data
///
/// Returns BSS info + SAE state for the event-driven follow-up.
pub async fn run_connect_flow(
    sm: &mut ConnectionSm,
    handle: &Nl80211Handle,
    _conn_handle: &mut wl_nl80211::Nl80211ConnectionHandle,
    ssid: &str,
    password: &str,
    sta_mac: [u8; 6],
) -> ShuliResult<ConnectFlowResult> {
    info!("scanning for SSID '{}'...", ssid);
    trigger_scan(handle, sm.if_index, Some(ssid)).await?;
    sm.transition(ConnectionState::Scanning);

    tokio::time::sleep(std::time::Duration::from_secs(SCAN_SLEEP_SECS)).await;

    let bss_list = get_scan_results(handle, sm.if_index).await?;
    info!("scan found {} BSS entries", bss_list.len());

    let target_bss = find_bss_by_ssid(&bss_list, ssid).ok_or_else(|| {
        crate::ShuliError::NoMatchingBss {
            ssid: ssid.to_string(),
        }
    })?;

    let bssid = extract_bssid(target_bss).ok_or_else(|| {
        crate::ShuliError::ScanFailed("no BSSID in scan result".into())
    })?;
    let freq = extract_freq(target_bss).unwrap_or(0);
    info!("selected BSS: bssid={bssid:02x?}, freq={freq} MHz");

    // Create SAE state and build commit
    let mut sae = SaeState::new(password, ssid, sta_mac, bssid)?;
    let (scalar, element) =
        sae.build_commit(&mut elliptic_curve::rand_core::OsRng);

    // Build SAE commit auth_data for NL80211_ATTR_AUTH_DATA. The kernel reads
    // the first 4 bytes as transaction(2 LE) and status(2 LE); the remaining
    // bytes become the authentication frame body. For H2E the status code is
    // SAE_HASH_TO_ELEMENT (126), and the body is:
    //   group(2 LE) || scalar(32) || element(64)
    const SAE_STATUS_H2E: u16 = 126;
    let mut auth_body = Vec::with_capacity(6 + scalar.len() + element.len());
    auth_body.extend_from_slice(&1u16.to_le_bytes()); // transaction = commit
    auth_body.extend_from_slice(&SAE_STATUS_H2E.to_le_bytes()); // status
    auth_body.extend_from_slice(&sae.group_id().to_le_bytes()); // group 19
    auth_body.extend_from_slice(&scalar);
    auth_body.extend_from_slice(&element);

    info!("sending SAE authenticate with commit...");
    let result = auth_assoc::authenticate_sae_commit(
        handle,
        sm.if_index,
        ssid,
        bssid,
        freq,
        &auth_body,
    )
    .await;
    if let Err(ref e) = result {
        warn!("authenticate_sae_commit failed: {e}");
    }
    result?;
    sm.transition(ConnectionState::Authenticating);
    info!("SAE authenticate sent successfully");

    Ok(ConnectFlowResult { bssid, freq, sae })
}

/// Get the MAC address of a local interface.
pub async fn get_sta_mac(
    handle: &Nl80211Handle,
    if_index: u32,
) -> ShuliResult<Option<[u8; 6]>> {
    use futures::TryStreamExt;
    let mut dump = handle.interface().get(vec![]).execute().await;
    use wl_nl80211::Nl80211Attr;
    while let Some(msg) = dump.try_next().await? {
        let mut found_if = false;
        let mut mac = None;
        for attr in &msg.payload.attributes {
            match attr {
                Nl80211Attr::IfIndex(idx) if *idx == if_index => {
                    found_if = true;
                }
                Nl80211Attr::Mac(m) if found_if => {
                    mac = Some(*m);
                }
                _ => {}
            }
        }
        if found_if {
            return Ok(mac);
        }
    }
    Ok(None)
}
