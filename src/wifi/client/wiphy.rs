// SPDX-License-Identifier: Apache-2.0

use futures::TryStreamExt;
use wl_nl80211::{Nl80211Attr, Nl80211Handle, Nl80211WowlanTriggersSupport};

use super::MAX_SCHED_SCAN_SSIDS;
use crate::WifiError;

/// Whether the netlink error is `-EOPNOTSUPP`, i.e. the driver has no
/// `sched_scan_start` op. Netlink NACK codes carry the negated errno.
pub(crate) fn is_eopnotsupp(e: &wl_nl80211::Nl80211Error) -> bool {
    matches!(
        e,
        wl_nl80211::Nl80211Error::NetlinkError(err)
            if err.code == std::num::NonZeroI32::new(-95)
    )
}

/// Build one PNO chunk the way wpa_supplicant does: reserve one slot
/// for the wildcard probe when visible networks are configured, then
/// take a contiguous slice of the rotating hidden SSID list within
/// `cap`. Returns `(ssids, more)` where `more` is true when hidden
/// SSIDs remain for a later chunk.
pub(crate) fn next_sched_scan_ssids(
    hidden_ssids: &[String],
    wildcard: bool,
    cursor: &mut usize,
    cap: usize,
) -> (Vec<String>, bool) {
    let cap = cap.clamp(1, MAX_SCHED_SCAN_SSIDS);
    let specific_cap = cap - if wildcard { 1 } else { 0 };
    let mut ssids = Vec::new();
    if wildcard {
        ssids.push(String::new());
    }
    let mut idx = (*cursor).min(hidden_ssids.len());
    let mut added = 0usize;
    while idx < hidden_ssids.len() && added < specific_cap {
        ssids.push(hidden_ssids[idx].clone());
        idx += 1;
        added += 1;
    }
    let more = idx < hidden_ssids.len();
    *cursor = if more { idx } else { 0 };
    (ssids, more)
}

/// Hardware scheduled scan (PNO) capabilities of the wiphy owning
/// `wiphy_idx`. The kernel omits
/// `NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS` for drivers without a
/// `sched_scan_start` op, so its presence means the feature is
/// available.
pub(crate) struct WiphySchedScanCaps {
    pub(crate) supported: bool,
    pub(crate) max_ssids: usize,
    pub(crate) max_match_sets: usize,
}

pub(crate) async fn wiphy_sched_scan_caps(
    handle: &Nl80211Handle,
    wiphy_idx: u32,
) -> Result<WiphySchedScanCaps, WifiError> {
    let mut dump = handle.wireless_physic().get().execute().await;
    while let Some(msg) = dump.try_next().await? {
        let mut idx = None;
        let mut max_ssids = 0u8;
        let mut max_match_sets = 0u8;
        for attr in &msg.payload.attributes {
            match attr {
                Nl80211Attr::Wiphy(i) => idx = Some(*i),
                Nl80211Attr::MaxNumSchedScanSsids(n) => max_ssids = *n,
                Nl80211Attr::MaxMatchSets(n) => max_match_sets = *n,
                _ => {}
            }
        }
        if idx == Some(wiphy_idx) {
            return Ok(WiphySchedScanCaps {
                supported: max_ssids > 0,
                max_ssids: max_ssids as usize,
                max_match_sets: max_match_sets as usize,
            });
        }
    }
    Ok(WiphySchedScanCaps {
        supported: false,
        max_ssids: 0,
        max_match_sets: 0,
    })
}

/// the WoWLAN triggers the wiphy owning `wiphy_idx` advertises via
/// `NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED` (empty when the driver has
/// no WoWLAN support).
pub(crate) async fn wiphy_wowlan_support(
    handle: &Nl80211Handle,
    wiphy_idx: u32,
) -> Result<Vec<Nl80211WowlanTriggersSupport>, WifiError> {
    let mut dump = handle.wireless_physic().get().execute().await;
    while let Some(msg) = dump.try_next().await? {
        let mut idx = None;
        let mut triggers = Vec::new();
        for attr in &msg.payload.attributes {
            match attr {
                Nl80211Attr::Wiphy(i) => idx = Some(*i),
                Nl80211Attr::WowlanTriggersSupport(supported) => {
                    triggers.clone_from(supported)
                }
                _ => {}
            }
        }
        if idx == Some(wiphy_idx) {
            return Ok(triggers);
        }
    }
    Ok(Vec::new())
}
