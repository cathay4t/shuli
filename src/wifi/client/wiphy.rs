// SPDX-License-Identifier: Apache-2.0

use futures::TryStreamExt;
use wl_nl80211::{
    Nl80211Attr, Nl80211Command, Nl80211ExtFeature, Nl80211Handle,
    Nl80211WowlanTriggersSupport,
};

use super::{ControlPortMode, MAX_SCHED_SCAN_SSIDS, MlmeMode};
use crate::{ErrorKind, WifiError};

/// Connection-mode capabilities probed from one wiphy.
pub(crate) struct WiphyMlmeCaps {
    pub(crate) mlme: MlmeMode,
    pub(crate) control_port: ControlPortMode,
}

/// Pick the MLME owner from `NL80211_ATTR_SUPPORTED_COMMANDS`.
///
/// `None` means the kernel did not advertise the attribute at all; keep
/// the historical userspace-SME path in that case.  A present but
/// insufficient command list is an error.
pub(crate) fn mlme_mode_from_commands(
    commands: Option<&[Nl80211Command]>,
) -> Result<MlmeMode, ()> {
    let Some(commands) = commands else {
        return Ok(MlmeMode::SoftMac);
    };
    let has = |cmd| commands.contains(&cmd);
    if has(Nl80211Command::Authenticate) && has(Nl80211Command::Associate) {
        Ok(MlmeMode::SoftMac)
    } else if has(Nl80211Command::Connect) {
        Ok(MlmeMode::FullMac)
    } else {
        Err(())
    }
}

/// Pick the EAPOL transport from the wiphy extension features.
///
/// In-tree only mac80211 advertises `CONTROL_PORT_OVER_NL80211`; every
/// FullMAC driver needs a raw PAE socket.  When the feature list is
/// absent, keep the old nl80211 transport for SoftMAC and assume raw for
/// FullMAC.
pub(crate) fn control_port_mode_for(
    mlme: MlmeMode,
    features: Option<&[Nl80211ExtFeature]>,
) -> ControlPortMode {
    match features {
        Some(features)
            if features
                .contains(&Nl80211ExtFeature::ControlPortOverNl80211) =>
        {
            ControlPortMode::Nl80211
        }
        Some(_) => ControlPortMode::RawEapol,
        None => match mlme {
            MlmeMode::SoftMac => ControlPortMode::Nl80211,
            MlmeMode::FullMac => ControlPortMode::RawEapol,
        },
    }
}

/// Query the wiphy's supported commands and extension features.
pub(crate) async fn wiphy_mlme_caps(
    handle: &Nl80211Handle,
    wiphy_idx: u32,
) -> Result<WiphyMlmeCaps, WifiError> {
    let mut dump = handle
        .wireless_physic()
        .get()
        .wiphy_index(wiphy_idx)
        .execute()
        .await;
    let mut commands: Option<Vec<Nl80211Command>> = None;
    let mut features: Option<Vec<Nl80211ExtFeature>> = None;
    while let Some(msg) = dump.try_next().await? {
        let mut idx = None;
        let mut msg_commands = None;
        let mut msg_features = None;
        for attr in &msg.payload.attributes {
            match attr {
                Nl80211Attr::Wiphy(i) => idx = Some(*i),
                Nl80211Attr::SupportedCommand(cmds) => {
                    msg_commands = Some(cmds.clone());
                }
                Nl80211Attr::ExtFeatures(feats) => {
                    msg_features = Some(feats.clone());
                }
                _ => {}
            }
        }
        if idx == Some(wiphy_idx) {
            if msg_commands.is_some() {
                commands = msg_commands;
            }
            if msg_features.is_some() {
                features = msg_features;
            }
        }
    }

    let mlme = mlme_mode_from_commands(commands.as_deref()).map_err(|()| {
        WifiError::new(
            ErrorKind::NoSupport,
            format!(
                "wiphy {wiphy_idx} supports neither \
                 NL80211_CMD_AUTHENTICATE/ASSOCIATE (SoftMAC) nor \
                 NL80211_CMD_CONNECT (FullMAC)"
            ),
        )
    })?;
    if commands.is_none() {
        log::warn!(
            "wiphy {wiphy_idx} did not advertise \
             NL80211_ATTR_SUPPORTED_COMMANDS; assuming SoftMAC userspace SME"
        );
    }
    let control_port = control_port_mode_for(mlme, features.as_deref());
    Ok(WiphyMlmeCaps { mlme, control_port })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlme_mode_prefers_userspace_sme_when_authenticate_is_present() {
        let commands = [
            Nl80211Command::Authenticate,
            Nl80211Command::Associate,
            Nl80211Command::Connect,
        ];
        assert_eq!(
            mlme_mode_from_commands(Some(&commands)),
            Ok(MlmeMode::SoftMac)
        );
    }

    #[test]
    fn mlme_mode_is_fullmac_with_connect_only() {
        assert_eq!(
            mlme_mode_from_commands(Some(&[Nl80211Command::Connect])),
            Ok(MlmeMode::FullMac)
        );
    }

    #[test]
    fn mlme_mode_defaults_to_softmac_without_command_list() {
        assert_eq!(mlme_mode_from_commands(None), Ok(MlmeMode::SoftMac));
    }

    #[test]
    fn mlme_mode_rejects_unsupported_command_list() {
        assert_eq!(
            mlme_mode_from_commands(Some(&[
                Nl80211Command::Authenticate,
                Nl80211Command::GetInterface,
            ])),
            Err(())
        );
    }

    #[test]
    fn control_port_uses_nl80211_only_when_advertised() {
        let with_feature = [Nl80211ExtFeature::ControlPortOverNl80211];
        let without_feature = [Nl80211ExtFeature::Rrm];
        assert_eq!(
            control_port_mode_for(MlmeMode::SoftMac, Some(&with_feature)),
            ControlPortMode::Nl80211
        );
        assert_eq!(
            control_port_mode_for(MlmeMode::FullMac, Some(&with_feature)),
            ControlPortMode::Nl80211
        );
        assert_eq!(
            control_port_mode_for(MlmeMode::FullMac, Some(&without_feature)),
            ControlPortMode::RawEapol
        );
        assert_eq!(
            control_port_mode_for(MlmeMode::SoftMac, Some(&without_feature)),
            ControlPortMode::RawEapol
        );
        // Legacy kernels without the ext-feature attribute keep the old
        // SoftMAC transport, while FullMAC defaults to raw EAPOL.
        assert_eq!(
            control_port_mode_for(MlmeMode::SoftMac, None),
            ControlPortMode::Nl80211
        );
        assert_eq!(
            control_port_mode_for(MlmeMode::FullMac, None),
            ControlPortMode::RawEapol
        );
    }
}
