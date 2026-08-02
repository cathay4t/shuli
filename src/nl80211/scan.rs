// SPDX-License-Identifier: Apache-2.0

use futures::TryStreamExt;
use netlink_packet_core::Parseable;
use wl_nl80211::{
    Nl80211Attr, Nl80211BssInfo, Nl80211Element, Nl80211Elements, Nl80211Handle,
};

use crate::WpaError;

pub async fn trigger_scan(
    handle: &Nl80211Handle,
    if_index: u32,
    ssid: Option<&str>,
) -> Result<(), WpaError> {
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
) -> Result<Vec<Vec<Nl80211BssInfo>>, WpaError> {
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

pub fn extract_ssid_from_ies(ies: &[u8]) -> Option<String> {
    let elements = Nl80211Elements::parse(ies).ok()?;
    for element in elements.0 {
        if let Nl80211Element::Ssid(ssid) = element {
            return Some(ssid);
        }
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
