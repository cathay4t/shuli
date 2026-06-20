// SPDX-License-Identifier: Apache-2.0

use futures::TryStreamExt;
use wl_nl80211::{Nl80211Attr, Nl80211BssInfo, Nl80211Handle};

use crate::ShuliResult;

pub async fn trigger_scan(
    handle: &Nl80211Handle,
    if_index: u32,
    ssid: Option<&str>,
) -> ShuliResult<()> {
    let mut builder = wl_nl80211::Nl80211Scan::new(if_index);
    if let Some(ssid) = ssid {
        builder = builder.ssids(vec![ssid.to_string()]);
    } else {
        builder = builder.passive(true);
    }
    let attrs = builder.build();
    let mut stream = handle.scan().trigger(attrs).execute().await;
    while let Some(_msg) = stream.try_next().await? {
        // consume ACK
    }
    Ok(())
}

pub async fn get_scan_results(
    handle: &Nl80211Handle,
    if_index: u32,
) -> ShuliResult<Vec<Vec<Nl80211BssInfo>>> {
    let mut dump = handle.scan().dump(if_index).execute().await;
    let mut bss_list = Vec::new();
    while let Some(msg) = dump.try_next().await? {
        for attr in &msg.payload.attributes {
            if let Nl80211Attr::Bss(bss_infos) = attr {
                bss_list.push(bss_infos.clone());
            }
        }
    }
    Ok(bss_list)
}

/// Extract SSID from raw information elements.
pub fn extract_ssid_from_ies(ies: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 1 < ies.len() {
        let elem_id = ies[i];
        let elem_len = ies[i + 1] as usize;
        if i + 2 + elem_len > ies.len() {
            break;
        }
        if elem_id == 0 && elem_len > 0 {
            let ssid_bytes = &ies[i + 2..i + 2 + elem_len];
            return Some(String::from_utf8_lossy(ssid_bytes).to_string());
        }
        i += 2 + elem_len;
    }
    None
}

/// Extract signal strength (SignalMbm) from a BSS info entry list.
pub fn extract_signal(bss: &[Nl80211BssInfo]) -> Option<i32> {
    for info in bss {
        if let Nl80211BssInfo::SignalMbm(signal) = info {
            return Some(*signal);
        }
    }
    None
}

/// Extract frequency from a BSS info entry list.
pub fn extract_freq(bss: &[Nl80211BssInfo]) -> Option<u32> {
    for info in bss {
        if let Nl80211BssInfo::Frequency(freq) = info {
            return Some(*freq);
        }
    }
    None
}

/// Extract raw IEs from a BSS info entry list (probe response or beacon).
pub fn extract_ies(bss: &[Nl80211BssInfo]) -> Option<&[u8]> {
    for info in bss {
        match info {
            Nl80211BssInfo::RawInformationElements(ies) => return Some(ies),
            Nl80211BssInfo::RawBeaconInformationElements(ies) => {
                return Some(ies);
            }
            _ => {}
        }
    }
    None
}

/// Extract BSSID from a BSS info entry list.
pub fn extract_bssid(bss: &[Nl80211BssInfo]) -> Option<[u8; 6]> {
    for info in bss {
        if let Nl80211BssInfo::Bssid(bssid) = info {
            return Some(*bssid);
        }
    }
    None
}

pub fn find_bss_by_ssid<'a>(
    bss_list: &'a [Vec<Nl80211BssInfo>],
    ssid: &str,
) -> Option<&'a Vec<Nl80211BssInfo>> {
    let mut best: Option<&Vec<Nl80211BssInfo>> = None;
    let mut best_signal = i32::MIN;

    for bss in bss_list {
        let ies = extract_ies(bss)?;
        let bss_ssid = extract_ssid_from_ies(ies)?;
        if bss_ssid != ssid {
            continue;
        }
        let signal = extract_signal(bss).unwrap_or(i32::MIN);
        if signal > best_signal {
            best_signal = signal;
            best = Some(bss);
        }
    }

    best
}
