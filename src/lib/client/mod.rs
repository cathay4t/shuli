// SPDX-License-Identifier: Apache-2.0

//! WPA client core: one `WifiIface` per wifi-phy, multiplexed by the
//! shared `WifiClient` event dispatcher.
//!
//! The flow is a simple linear walk over [`WifiState`] - Init -> Scanning ->
//! Authenticating -> Connected - driven by repeated calls to
//! [`WifiIface::run`]. There is no internal transition table; events
//! (SAE frames, association results, EAPOL-Key messages) advance the
//! current state directly. Scan specifics live in `scan.rs`,
//! pre-association authentication (SAE today, WPA2/EAP later) in
//! `auth.rs`, and nl80211 details in `nl80211.rs`.

use netlink_packet_core::NetlinkMessage;
use wl_nl80211::{
    Ieee80211ReasonCode, Ieee80211StatusCode, Nl80211Attr, Nl80211Authenticate,
    Nl80211Disconnect, Nl80211Event, Nl80211Key, Nl80211KeyDefaultType,
    Nl80211RekeyOffload, Nl80211SchedScanMatch, Nl80211SchedScanMatchAttr,
    Nl80211SchedScanPlan, Nl80211SchedScanPlanAttr, Nl80211Wowlan,
    Nl80211WowlanTriggersSupport,
};

use crate::{
    ErrorKind, NetworkConfig, ShuliNl80211Connection, WifiError,
    auth::{AuthAction, AuthMethod},
    config::WifiConfig,
    crypto::{
        handshake4::{FourWayState, MicAlg},
        kdf,
        owe::{self, OweAuth},
    },
    eap::{EapAction, EapPacket, EapPeer},
    ieee80211::{auth, eapol, elements},
    pmksa::{
        PMK_LIFETIME_SECS, PMK_REAUTH_THRESHOLD_PERCENT, PmksaCache,
        PmksaEntry, entry_with_fresh_lifetime,
    },
    scan::{SecurityType, format_ssids},
};

type Nl80211EventMsg = NetlinkMessage<genetlink::message::RawGenlMessage>;
type Nl80211EventSender =
    futures::channel::mpsc::UnboundedSender<Nl80211EventMsg>;
type Nl80211EventReceiver =
    futures::channel::mpsc::UnboundedReceiver<Nl80211EventMsg>;

/// Initial scan-retry backoff (seconds) used while hunting for the
/// configured SSID. Doubles after each failed scan, capped at
/// [`RETRY_BACKOFF_MAX_SEC`].
pub(crate) const RETRY_BACKOFF_INIT_SEC: u64 = 10;
/// Cap (seconds) for the scan-retry backoff; mirrors iwd's
/// `MaximumPeriodicScanInterval` default.
const RETRY_BACKOFF_MAX_SEC: u64 = 300;
/// Interval (seconds) between hardware scheduled scan (PNO) iterations
/// while hunting for the configured SSID. The firmware scans this often
/// while the host sleeps; shuli only wakes on
/// `NL80211_CMD_SCHED_SCAN_RESULTS`.
const SCHED_SCAN_INTERVAL_SEC: u32 = 10;
/// Cap on specific-SSID probes in one scheduled-scan request, matching
/// wpa_supplicant's `WPAS_MAX_SCAN_SSIDS` (16).
const MAX_SCHED_SCAN_SSIDS: usize = 16;
/// Watchdog (seconds) for [`WifiState::SchedScanWait`]: with an SSID
/// match set the firmware only reports on a match, so an absent AP
/// produces no results events at all. If none arrives this long, the
/// scan is re-armed via the host fallback (the firmware may have
/// silently stopped). Longer than the firmware's scan interval, so a
/// match (present AP) always wakes us first.
const SCHED_SCAN_WATCHDOG_SECS: u64 = 60;
/// How long to wait for our own `SCHED_SCAN_STOPPED` echo while
/// rotating a PNO chunk before force-starting the next chunk.
const SCHED_SCAN_STOP_ECHO_TIMEOUT_SECS: u64 = 5;
/// Backoff (seconds) after a fatal authentication failure (wrong
/// password, unknown SAE password identifier, SAE-PK required, ...):
/// retrying is futile, but the wait must stay short enough that the
/// connection recovers without operator intervention when the AP-side
/// state changes. Transient rejections (e.g. status 30) do not use
/// this; they retry on the short `Failed` backoff.
const RETRY_AUTH_SEC: u64 = 120;
/// Max time to wait for the next authentication event (SAE frame, association
/// result, 4-way handshake message) before giving up and retrying.
const AUTH_EVENT_TIMEOUT_SECS: u64 = 15;
/// Interval (seconds) at which the connected state polls the AP's signal
/// when the driver has no kernel connection quality monitor (CQM) support:
/// the fallback to the CQM event-driven roam trigger.
pub(crate) const ROAM_SIGNAL_CHECK_SECS: u64 = 5;
/// SAE retransmission period (seconds): 802.11-2020 §12.4.8.6.2 sets
/// the t0 (retransmission) timer to `dot11RSNASAERetransPeriod`, whose
/// MIB default is 2000 ms (iwd uses the same 2 s). While the SAE
/// commit is in flight, a lost frame - or a rejection with a temporary
/// status (see §12.4.8.6.4) - is answered with a retransmission after
/// this period instead of the full `AUTH_EVENT_TIMEOUT_SECS` + rescan.
const SAE_COMMIT_RETRANSMIT_TIMEOUT_SECS: u64 = 2;
/// maximum SAE Sync counter (commit retransmissions), matching
/// iwd's `SAE_SYNC_MAX` of 3.
const SAE_SYNC_MAX: u8 = 3;

mod associate;
mod events;
mod state;
mod wifi_client;
mod wifi_iface;
mod wiphy;

pub use state::WifiState;
pub(crate) use state::{
    AuthSession, IfaceCore, Link, RoamEngine, ScanEngine, WifiIface, WiphyCaps,
    WowlanState,
};
pub use wifi_client::{WifiClient, WifiIfaceState};
#[cfg(test)]
pub(crate) use wifi_iface::desired_wowlan_triggers;
pub(crate) use wifi_iface::{
    fatal_disconnect_error, fmt_transition_disable, is_fatal_disconnect_reason,
    wowlan_wakeup_requires_reconnect,
};
pub(crate) use wiphy::{
    is_eopnotsupp, next_sched_scan_ssids, wiphy_sched_scan_caps,
    wiphy_wowlan_support,
};

pub(crate) use crate::nl80211::drain_request;
#[cfg(test)]
mod tests {
    use wl_nl80211::{
        Ieee80211ReasonCode, Nl80211WowlanTriggersSupport, Nl80211WowlanWakeup,
    };

    use super::{
        MAX_SCHED_SCAN_SSIDS, desired_wowlan_triggers, fatal_disconnect_error,
        fmt_transition_disable, is_fatal_disconnect_reason,
        next_sched_scan_ssids, wowlan_wakeup_requires_reconnect,
    };

    /// reasons 2 (PREV_AUTH_NOT_VALID) and 23
    /// (IEEE_802_1X_AUTH_FAILED) mean a fatal credential/PMKSA problem
    /// and must use the long authentication backoff; every other
    /// reason (and a missing one) is transient.
    #[test]
    fn fatal_disconnect_reasons_are_2_and_23() {
        assert!(is_fatal_disconnect_reason(Some(
            Ieee80211ReasonCode::PrevAuthNotValid
        )));
        assert!(is_fatal_disconnect_reason(Some(
            Ieee80211ReasonCode::Ieee8021xFailed
        )));
    }

    #[test]
    fn fatal_disconnect_error_reports_wrong_password() {
        let err =
            fatal_disconnect_error(Some(Ieee80211ReasonCode::PrevAuthNotValid));
        assert_eq!(err.kind, crate::ErrorKind::WrongPassword);
        assert!(
            err.to_string().contains("password is wrong"),
            "unexpected error: {err}"
        );

        let err =
            fatal_disconnect_error(Some(Ieee80211ReasonCode::Ieee8021xFailed));
        assert_eq!(err.kind, crate::ErrorKind::AuthFailed);
    }

    #[test]
    fn transient_disconnect_reasons() {
        for reason in [
            Ieee80211ReasonCode::Unspecified,
            Ieee80211ReasonCode::DeauthLeaving,
            Ieee80211ReasonCode::DisassocDueToInactivity,
            Ieee80211ReasonCode::MicFailure,
            Ieee80211ReasonCode::GroupKeyHandshakeTimeout,
        ] {
            assert!(
                !is_fatal_disconnect_reason(Some(reason)),
                "{reason:?} must be transient"
            );
        }
        // A disconnect without a parseable reason is transient.
        assert!(!is_fatal_disconnect_reason(None));
    }

    /// only triggers the wiphy actually advertises are armed, and
    /// GTK-rekey-failure alone is enough to enable WoWLAN.
    #[test]
    fn wowlan_desired_triggers_filtered_by_support() {
        let all = vec![
            Nl80211WowlanTriggersSupport::Disconnect,
            Nl80211WowlanTriggersSupport::GtkRekeyFailure,
        ];
        assert_eq!(desired_wowlan_triggers(&all), all);

        let rekey_only = vec![Nl80211WowlanTriggersSupport::GtkRekeyFailure];
        assert_eq!(
            desired_wowlan_triggers(&rekey_only),
            vec![Nl80211WowlanTriggersSupport::GtkRekeyFailure]
        );

        let none = vec![Nl80211WowlanTriggersSupport::MagicPkt];
        assert!(desired_wowlan_triggers(&none).is_empty());
    }

    /// a GTK-rekey-failure or disconnect wake must rebuild the
    /// connection; any other wake (magic packet, rfkill, ...) does not
    /// invalidate it.
    #[test]
    fn wowlan_wakeup_reconnect_reasons() {
        assert!(wowlan_wakeup_requires_reconnect(&[
            Nl80211WowlanWakeup::GtkRekeyFailure
        ]));
        assert!(wowlan_wakeup_requires_reconnect(&[
            Nl80211WowlanWakeup::Disconnect
        ]));
        assert!(!wowlan_wakeup_requires_reconnect(&[
            Nl80211WowlanWakeup::MagicPkt
        ]));
        assert!(!wowlan_wakeup_requires_reconnect(&[
            Nl80211WowlanWakeup::Any
        ]));
        assert!(!wowlan_wakeup_requires_reconnect(&[]));
    }

    /// the Transition Disable bitmap maps to the AKM group
    /// names (bit 0 = WPA3-Personal, 1 = SAE-PK, 2 = WPA3-Enterprise,
    /// 3 = Enhanced Open).
    #[test]
    fn transition_disable_bitmap_names() {
        let s = fmt_transition_disable(0x01);
        assert!(s.contains("WPA3-Personal"));
        assert!(!s.contains("Enhanced Open"));
        let s = fmt_transition_disable(0x08);
        assert!(s.contains("Enhanced Open"));
        assert!(!s.contains("WPA3-Personal"));
        let s = fmt_transition_disable(0x0F);
        assert_eq!(s, "WPA3-Personal, SAE-PK, WPA3-Enterprise, Enhanced Open");
        assert_eq!(fmt_transition_disable(0), "none");
    }

    #[test]
    fn sched_scan_chunk_reserves_wildcard_and_rotates() {
        let hidden: Vec<String> =
            ["A", "B", "C", "D"].iter().map(|s| s.to_string()).collect();
        let mut cursor = 0;
        let (round, more) =
            next_sched_scan_ssids(&hidden, true, &mut cursor, 4);
        assert_eq!(round, vec!["", "A", "B", "C"]);
        assert!(more);
        assert_eq!(cursor, 3);

        let (round, more) =
            next_sched_scan_ssids(&hidden, true, &mut cursor, 4);
        assert_eq!(round, vec!["", "D"]);
        assert!(!more);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn sched_scan_chunk_fits_all_hidden_ssids() {
        let hidden: Vec<String> =
            ["A", "B"].iter().map(|s| s.to_string()).collect();
        let mut cursor = 0;
        let (round, more) =
            next_sched_scan_ssids(&hidden, false, &mut cursor, 4);
        assert_eq!(round, vec!["A", "B"]);
        assert!(!more);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn sched_scan_chunk_caps_at_wpa_supplicant_max() {
        let hidden: Vec<String> = (0..20).map(|i| format!("S{i:02}")).collect();
        let mut cursor = 0;
        let (round, more) =
            next_sched_scan_ssids(&hidden, true, &mut cursor, 255);
        assert_eq!(round.len(), MAX_SCHED_SCAN_SSIDS);
        assert_eq!(round[0], "");
        assert_eq!(round[1], "S00");
        assert_eq!(round[15], "S14");
        assert!(more);
        assert_eq!(cursor, 15);

        let (round, more) =
            next_sched_scan_ssids(&hidden, true, &mut cursor, 255);
        assert_eq!(round, vec!["", "S15", "S16", "S17", "S18", "S19"]);
        assert!(!more);
        assert_eq!(cursor, 0);
    }
}
