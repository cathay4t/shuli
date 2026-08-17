// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(crate) async fn drain_request<S>(stream: S) -> Result<(), WifiError>
where
    S: futures::TryStream<
            Ok = netlink_packet_generic::GenlMessage<
                wl_nl80211::Nl80211Message,
            >,
            Error = wl_nl80211::Nl80211Error,
        > + Unpin,
{
    let mut stream = stream;
    while let Some(_msg) = stream.try_next().await? {}
    Ok(())
}

pub(crate) async fn get_if_index_and_mac(
    handle: &Nl80211Handle,
    ifname: &str,
) -> Result<(u32, [u8; ETH_ALEN], u32), WifiError> {
    let mut dump = handle.interface().get(vec![]).execute().await;
    while let Some(msg) = dump.try_next().await? {
        if msg.payload.attributes.iter().any(
            |attr| matches!(attr, Nl80211Attr::IfName(name) if name == ifname),
        ) {
            let mut index = 0;
            let mut mac = [0u8; ETH_ALEN];
            let mut wiphy = None;
            for attr in &msg.payload.attributes {
                if let Nl80211Attr::IfIndex(idx) = attr {
                    index = *idx;
                } else if let Nl80211Attr::Mac(mac_addr) = attr {
                    mac.copy_from_slice(mac_addr);
                } else if let Nl80211Attr::Wiphy(w) = attr {
                    wiphy = Some(*w);
                }
            }
            if index != 0 && mac != [0u8; ETH_ALEN] {
                return match wiphy {
                    Some(w) => Ok((index, mac, w)),
                    None => Err(WifiError::new(
                        ErrorKind::Nl80211,
                        format!(
                            "interface {ifname}: wiphy index missing from \
                             netlink message: {msg:?}",
                        ),
                    )),
                };
            } else {
                return Err(WifiError::new(
                    ErrorKind::InterfaceNotFound,
                    format!(
                        "interface {ifname}: index or mac not found in \
                         netlink message: {msg:?}",
                    ),
                ));
            }
        }
    }
    Err(WifiError::new(
        ErrorKind::InterfaceNotFound,
        format!("interface {ifname} not found"),
    ))
}

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

/// The maximum number of SSIDs the wiphy accepts in one scan request
/// (`NL80211_ATTR_MAX_NUM_SCAN_SSIDS`). Returns 0 when the kernel did
/// not advertise the attribute.
pub(crate) async fn wiphy_max_scan_ssids(
    handle: &Nl80211Handle,
    wiphy_idx: u32,
) -> Result<u8, WifiError> {
    let mut dump = handle.wireless_physic().get().execute().await;
    while let Some(msg) = dump.try_next().await? {
        let mut idx = None;
        let mut max_ssids = 0u8;
        for attr in &msg.payload.attributes {
            match attr {
                Nl80211Attr::Wiphy(i) => idx = Some(*i),
                Nl80211Attr::MaxNumScanSsids(n) => max_ssids = *n,
                _ => {}
            }
        }
        if idx == Some(wiphy_idx) {
            return Ok(max_ssids);
        }
    }
    Ok(0)
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
