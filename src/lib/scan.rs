// SPDX-License-Identifier: Apache-2.0

//! Scan flow: trigger a scan, wait for results, then pick the strongest BSS
//! matching the configured SSID.

use std::collections::HashMap;

use futures::{StreamExt, TryStreamExt};
use wl_nl80211::{Ieee80211CipherSuite, Nl80211BssInfo, Nl80211Event};

use crate::{
    ETH_ALEN, ErrorKind, NetworkConfig, WifiClient, WifiError,
    nl80211::scan::{
        extract_bssid, extract_freq, extract_ies, extract_signal_dbm,
        extract_ssid_from_ies, get_scan_results, trigger_scan,
    },
};

const SCAN_SLEEP_SECS: u64 = 3;
/// Bounds how long [`WifiClient::wait_scan_finish`] waits for the
/// `NL80211_CMD_NEW_SCAN_RESULTS` completion event before giving up and
/// dumping the scan results anyway.  Generous on purpose: the event is the
/// completion signal (a busy environment can keep a scan running for
/// several seconds), the timeout only guards against a missed event.
const SCAN_COMPLETE_TIMEOUT_SECS: u64 = 15;

/// Security type detected from the BSS's RSNE in scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityType {
    /// No RSNE — open / no encryption.
    #[default]
    Open,
    /// RSNE with AKM 00-0F-AC:2 — WPA2-PSK.
    Wpa2Psk,
    /// RSNE with AKM 00-0F-AC:6 — WPA2-Personal with SHA-256
    /// algorithms (PSK-SHA256): KDF-Hash-Length + AES-CMAC.
    Wpa2PskSha256,
    /// RSNE with AKM 00-0F-AC:1 — WPA2-Enterprise (802.1X).
    Wpa2Ent,
    /// RSNE with AKM 00-0F-AC:5 — WPA2-Enterprise with SHA-256
    /// algorithms (802.1X-SHA256).
    Wpa2EntSha256,
    /// RSNE with AKM 00-0F-AC:18 — OWE (opportunistic encryption).
    Owe,
    /// RSNE with AKM 00-0F-AC:8 — WPA3-SAE.
    Sae,
    /// RSNE with AKM 00-0F-AC:4 — FT over WPA2-PSK (802.11r).
    FtPsk,
    /// RSNE with AKM 00-0F-AC:9 — FT over WPA3-SAE (802.11r).
    FtSae,
    /// RSNE with AKM 00-0F-AC:24 — SAE-EXT-KEY (SAE with the
    /// AKM-defined 4-way key hierarchy).
    SaeExtKey,
    /// RSNE with AKM 00-0F-AC:25 — FT over SAE-EXT-KEY (802.11r).
    FtSaeExtKey,
    /// Encrypted with a security mode shuli does not support (e.g.
    /// WPA-Enterprise / 802.1X, WPA1/TKIP). Never connect to such a
    /// BSS: it must not be treated as open.
    Unsupported,
}

impl SecurityType {
    /// Whether this security type supports Fast BSS Transition.
    pub(crate) fn is_ft(&self) -> bool {
        matches!(
            self,
            SecurityType::FtPsk
                | SecurityType::FtSae
                | SecurityType::FtSaeExtKey
        )
    }

    /// The non-FT counterpart of an FT AKM (used to match a roam
    /// candidate against the network's authentication method).
    pub(crate) fn base(&self) -> SecurityType {
        match self {
            SecurityType::FtPsk => SecurityType::Wpa2Psk,
            SecurityType::FtSae => SecurityType::Sae,
            SecurityType::FtSaeExtKey => SecurityType::SaeExtKey,
            other => *other,
        }
    }
}

/// Mobility Domain element contents (802.11-2020 §9.4.2.47).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdieInfo {
    pub mdid: [u8; 2],
    pub ft_capab: u8,
}

/// The best BSS candidate for the configured SSID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BssInfo {
    pub bssid: [u8; ETH_ALEN],
    pub freq_mhz: u32,
    /// Signal strength of the BSS in dBm (converted from the kernel's
    /// mBm scan signal).
    pub signal_dbm: i32,
    pub security: SecurityType,
    /// The AP's RSNE as a full element (ID + length + body) from the
    /// beacon / probe response; empty on open BSSes. Used to validate
    /// 4-way handshake Message 3 against downgrade attacks.
    pub ap_rsne: Vec<u8>,
    /// The AP's RSNXE as a full element (ID 244), empty when the AP
    /// advertises none.
    pub ap_rsnxe: Vec<u8>,
    /// Negotiated group management (BIP) cipher (Stage 3 M8):
    /// best supported suite the AP advertises, defaulting to
    /// BIP-CMAC-128.
    pub(crate) group_mgmt_cipher: Ieee80211CipherSuite,
    /// Mobility Domain (present only on FT-capable BSSes).
    pub mdie: Option<MdieInfo>,
    /// Whether the AP hides its SSID in beacons while still answering
    /// directed probe requests with the SSID.
    pub hidden: bool,
    /// Whether the AP advertises the BSS Transition (802.11v)
    /// capability (Extended Capabilities bit 19).
    pub btm_support: bool,
    /// Whether the AP advertises the Neighbor Report (802.11k)
    /// capability (RM Enabled Capabilities octet 0 bit 1).
    pub rm_neighbor_report: bool,
}

impl Default for BssInfo {
    fn default() -> Self {
        Self {
            bssid: [0; ETH_ALEN],
            freq_mhz: 0,
            signal_dbm: 0,
            security: SecurityType::Open,
            ap_rsne: Vec::new(),
            ap_rsnxe: Vec::new(),
            group_mgmt_cipher: Ieee80211CipherSuite::BipCmac128,
            mdie: None,
            hidden: false,
            btm_support: false,
            rm_neighbor_report: false,
        }
    }
}

const RSN_CAP_MFPR: u16 = 1 << 6;
const RSN_CAP_MFPC: u16 = 1 << 7;

impl BssInfo {
    /// Whether the AP advertises management frame protection (IEEE
    /// 802.11w) in its RSNE capabilities: MFPC (optional) or MFPR
    /// (required). When true, shuli requests MFP at association time -
    /// `NL80211_CMD_ASSOCIATE` only accepts `NL80211_MFP_REQUIRED` or
    /// no MFP (iwd resolves "optional PMF" the same way).
    pub(crate) fn ap_mfp_capable(&self) -> bool {
        rsne_mfp_capable(&self.ap_rsne)
    }

    /// Whether the AP's RSNXE (beacon/probe response) advertises SAE
    /// Hash-to-Element support. Used to pick H2E vs. hunting-and-pecking
    /// up front instead of guessing (Stage 2 G2b).
    pub(crate) fn ap_supports_sae_h2e(&self) -> bool {
        crate::ieee80211::elements::ap_rsnxe_supports_sae_h2e(&self.ap_rsnxe)
    }

    /// Whether the AP advertises the OCVC RSN capability (Operating
    /// Channel Validation, Stage 3 M10). Enabling OCV against an AP
    /// that doesn't advertise this always fails the 4-way handshake
    /// (no OCI KDE in Message 3), so it must be gated on this check
    /// rather than on local network config alone.
    pub(crate) fn ap_ocv_capable(&self) -> bool {
        crate::ieee80211::elements::ap_rsne_supports_ocv(&self.ap_rsne)
    }

    /// Whether the AP advertises the Extended Key ID RSN capability
    /// (Stage 3 M11). Requesting Extended Key ID against an AP that
    /// doesn't advertise this always fails the 4-way handshake (no Key
    /// ID KDE in Message 3), so it must be gated on this check rather
    /// than on local network config alone.
    pub(crate) fn ap_ext_key_id_capable(&self) -> bool {
        crate::ieee80211::elements::ap_rsne_supports_ext_key_id(&self.ap_rsne)
    }

    /// Whether the AP advertises a capability that makes a client
    /// signal-triggered roam meaningful: 802.11v BSS Transition or
    /// 802.11k Neighbor Report. APs advertising neither do not
    /// participate in managed roaming, so scanning for a roam target
    /// against them is skipped (the connected link is only ever
    /// abandoned on an actual failure).
    pub(crate) fn ap_supports_signal_roam(&self) -> bool {
        self.btm_support || self.rm_neighbor_report
    }
}

/// Parse an RSNE element (ID + length + body) and report the MFPC/MFPR
/// bits of its RSN capabilities field.
fn rsne_mfp_capable(rsne: &[u8]) -> bool {
    // Skip element ID + length; need version(2) + group(4) + pcount(2).
    if rsne.len() < 2 + 8 {
        return false;
    }
    let body = &rsne[2..];
    let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
    let akm_offset = 8 + pcount * 4;
    if body.len() < akm_offset + 2 {
        return false;
    }
    let acount =
        u16::from_le_bytes([body[akm_offset], body[akm_offset + 1]]) as usize;
    let cap_offset = akm_offset + 2 + acount * 4;
    if body.len() < cap_offset + 2 {
        return false;
    }
    let capab = u16::from_le_bytes([body[cap_offset], body[cap_offset + 1]]);
    capab & (RSN_CAP_MFPR | RSN_CAP_MFPC) != 0
}

// Prefer the strongest signal; break ties by frequency (higher band first),
// then BSSID for a stable total order.
impl Ord for BssInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.signal_dbm, self.freq_mhz, self.bssid).cmp(&(
            other.signal_dbm,
            other.freq_mhz,
            other.bssid,
        ))
    }
}

impl PartialOrd for BssInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl WifiClient {
    pub(crate) async fn send_out_scan_request(
        &mut self,
    ) -> Result<(), WifiError> {
        let ssids: Vec<String> = self
            .config
            .networks
            .iter()
            .map(|network| network.ssid.clone())
            .collect();
        if self.roam_scan {
            log::trace!("scanning for SSIDs [{}]", ssids.join(", "));
        } else {
            log::info!("scanning for SSIDs [{}]", ssids.join(", "));
        }
        trigger_scan(&self.handle, self.if_index, Some(&ssids)).await
    }

    // Wait for the kernel's `NL80211_CMD_NEW_SCAN_RESULTS` multicast event
    // instead of a fixed sleep: a scan can finish in well under a second in
    // a quiet environment and take several in a busy one, and the client is
    // already subscribed to the `Scan` group.  The wait is bounded by
    // `SCAN_COMPLETE_TIMEOUT_SECS` (generous: the event is the completion
    // signal, the timeout only guards against a missed event) and falls
    // back to dumping the results when the event never arrives.  Other
    // events observed while scanning (e.g. a disconnect during a roam
    // scan) are fed to the state machine so they are not lost.
    pub(crate) async fn wait_scan_finish(&mut self) {
        log::trace!("Waiting for scan to finish");
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(SCAN_COMPLETE_TIMEOUT_SECS);
        loop {
            let remaining =
                deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, self.event_receiver.next())
                .await
            {
                Ok(Some((raw_msg, _addr))) => {
                    if let Some(event) =
                        wl_nl80211::Nl80211Event::parse(raw_msg)
                    {
                        match event {
                            Nl80211Event::NewScanResults => {
                                if self.roam_scan {
                                    log::trace!("scan finished");
                                } else {
                                    log::debug!("scan finished");
                                }
                                return;
                            }
                            other => {
                                self.handle_event(other).await;
                            }
                        }
                    }
                }
                Ok(None) => {
                    // Event channel closed; proceed to the results dump
                    // (the state machine will surface the error if the
                    // channel is truly gone).
                    break;
                }
                Err(_) => break, // event timeout; proceed to the results dump
            }
        }
    }

    /// Dump the scan results and keep the strongest BSS matching any of
    /// the configured networks; the matched network (with its passphrase)
    /// is recorded for the authentication phase.
    pub(crate) async fn process_scan_results(
        &mut self,
    ) -> Result<(), WifiError> {
        self.collect_scan_candidates().await?;

        // A roam that fell back to full reconnection steers the retry
        // loop to its target BSSID; otherwise the strongest BSS wins.
        let hinted = self.roam_target.take().and_then(|hint| {
            self.last_scan_candidates
                .iter()
                .find(|(bss, _)| bss.bssid == hint)
                .cloned()
        });
        let best = hinted.or_else(|| {
            self.last_scan_candidates
                .iter()
                .max_by(|a, b| a.0.cmp(&b.0))
                .cloned()
        });
        let Some((bss_info, network)) = best else {
            return Err(WifiError::new(
                ErrorKind::SsidNotFound,
                format!(
                    "no configured SSID ([{}]) found in scan results",
                    self.config.ssids().collect::<Vec<_>>().join(", ")
                ),
            ));
        };
        self.bss_info = bss_info;
        self.network = network;
        log::info!(
            "selected BSS: ssid={}, bssid={:02x?}, freq={} MHz, signal={} dBm",
            self.network.ssid,
            self.bss_info.bssid,
            self.bss_info.freq_mhz,
            self.bss_info.signal_dbm
        );
        Ok(())
    }

    /// Roam scan results: pick the best roam candidate and start roaming
    /// to it; stay put when no candidate qualifies. Same-network
    /// candidates are BSSes of the same security family that are not
    /// weaker than the current one (the low-frequency background scan
    /// requires a strictly stronger one, so equal-signal BSSes do not
    /// ping-pong on every scan interval). When the current link is
    /// critical (signal below `switch_ssid_lower_than_dbm`), a
    /// well-signalled BSS of a *different* configured SSID also qualifies
    /// - switching SSIDs terminates the current session.
    pub(crate) async fn process_roam_scan_results(&mut self) {
        if let Err(e) = self.collect_scan_candidates().await {
            log::warn!("roam scan failed: {e}");
            return;
        }
        self.roam_scan_count += 1;
        let current_base = self.bss_info.security.base();
        let current_ssid = self.network.ssid.clone();
        // Freshly measured signal of the current BSS from this same scan
        // dump (identical measurement source as the candidates), so the
        // "not weaker" comparison is apples-to-apples. When the current
        // BSS is absent from the dump (it went off-channel / hidden),
        // fall back to the signal recorded when it was selected.
        let current_signal = self
            .last_scan_candidates
            .iter()
            .find(|(bss, _)| bss.bssid == self.bss_info.bssid)
            .map(|(bss, _)| bss.signal_dbm)
            .unwrap_or(self.bss_info.signal_dbm);
        let strict = self.background_scan;
        // Same-network candidates: any BSS of the *connected* SSID (its
        // security family, FT or not) that is not weaker than the current
        // one. A different configured SSID only qualifies through the
        // critical-link branch below.
        let best = self
            .last_scan_candidates
            .iter()
            .filter(|(bss, network)| {
                bss.bssid != self.bss_info.bssid
                    && network.ssid == current_ssid
                    && bss.security.base() == current_base
                    && if strict {
                        bss.signal_dbm > current_signal
                    } else {
                        bss.signal_dbm >= current_signal
                    }
            })
            .max_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(bss, _)| bss.clone());
        let mut target = best;
        let mut target_network = self.network.clone();
        if target.is_none()
            && current_signal < self.network.switch_ssid_lower_than_dbm
        {
            // The current link is critical: abandon it for a
            // well-signalled BSS of a different configured SSID, even
            // though switching terminates the current session.
            let good_signal = self
                .roam_threshold()
                .unwrap_or(self.network.switch_ssid_lower_than_dbm);
            if let Some((bss, network)) = self
                .last_scan_candidates
                .iter()
                .filter(|(bss, network)| {
                    bss.bssid != self.bss_info.bssid
                        && network.ssid != current_ssid
                        && bss.signal_dbm >= good_signal
                        && network.can_roam_to_security(bss.security)
                })
                .max_by(|(a, _), (b, _)| a.signal_dbm.cmp(&b.signal_dbm))
            {
                log::info!(
                    "current signal {current_signal} dBm is below the \
                     critical {} dBm; switching to configured SSID {} (bssid \
                     {:02x?}, signal {} dBm)",
                    self.network.switch_ssid_lower_than_dbm,
                    network.ssid,
                    bss.bssid,
                    bss.signal_dbm
                );
                target = Some(bss.clone());
                target_network = network.clone();
            }
        }
        let Some(target) = target else {
            log::trace!("roam scan found no better BSS; staying");
            return;
        };
        log::info!(
            "roam scan selected bssid={:02x?}, freq={} MHz, signal={} dBm",
            target.bssid,
            target.freq_mhz,
            target.signal_dbm
        );
        self.start_roam(target, target_network).await;
    }

    /// Dump the scan results and record every BSS whose SSID matches a
    /// configured network in `last_scan_candidates`.
    async fn collect_scan_candidates(&mut self) -> Result<(), WifiError> {
        let bss_list = get_scan_results(&self.handle, self.if_index).await?;
        log::trace!("scan dump returned {} BSS entries", bss_list.len());

        let mut candidates: Vec<(BssInfo, NetworkConfig)> = Vec::new();
        for bss in &bss_list {
            let Some(ies) = extract_ies(bss) else {
                continue;
            };
            let Some(bss_ssid) = extract_ssid_from_ies(ies) else {
                continue;
            };
            let Some(network) = self
                .config
                .networks
                .iter()
                .find(|network| network.ssid == bss_ssid)
                .cloned()
            else {
                continue;
            };
            let (Some(bssid), Some(freq_mhz), Some(signal_dbm)) = (
                extract_bssid(bss),
                extract_freq(bss),
                extract_signal_dbm(bss),
            ) else {
                log::trace!("BSS missing bssid/freq/signal; skipping");
                continue;
            };
            log::trace!(
                "candidate BSS: ssid={bss_ssid}, bssid={bssid:02x?}, \
                 freq={freq_mhz} MHz, signal={signal_dbm}"
            );
            let bss_security = detect_security(ies);
            // M7 (G5): never present an AP shuli cannot actually join
            // (WPA1/TKIP, ...) as a connection candidate - classifying
            // it open would make the client associate without
            // encryption.
            if bss_security.security == SecurityType::Unsupported {
                log::info!(
                    "BSS {bssid:02x?} (ssid={bss_ssid}) has no supported \
                     security mode; skipping"
                );
                continue;
            }
            candidates.push((
                BssInfo {
                    bssid,
                    freq_mhz,
                    signal_dbm,
                    security: bss_security.security,
                    ap_rsne: bss_security.ap_rsne,
                    ap_rsnxe: bss_security.ap_rsnxe,
                    group_mgmt_cipher: bss_security.group_mgmt_cipher,
                    mdie: bss_security.mdie,
                    hidden: false,
                    btm_support:
                        crate::ieee80211::elements::ap_supports_btm(ies),
                    rm_neighbor_report:
                        crate::ieee80211::elements::ap_supports_rm_neighbor_report(
                            ies,
                        ),
                },
                network,
            ));
        }

        self.last_scan_candidates = candidates;
        Ok(())
    }
}

const IE_ID_RSN: u8 = 48;
const IE_ID_RSNXE: u8 = 244;
const IE_ID_MDIE: u8 = 54;
const IE_ID_VENDOR: u8 = 0xDD;
const AKM_PSK: u8 = 2;
const AKM_PSK_SHA256: u8 = 6;
const AKM_1X: u8 = 1;
const AKM_1X_SHA256: u8 = 5;
const AKM_FT_PSK: u8 = 4;
const AKM_OWE: u8 = 18;
const AKM_SAE: u8 = 8;
const AKM_FT_SAE: u8 = 9;
const AKM_SAE_EXT_KEY: u8 = 24;
const AKM_FT_SAE_EXT_KEY: u8 = 25;
/// WPA vendor IE OUI (Microsoft): 00:50:F2, type 1 = WPA (WPA1/TKIP).
const WPA_IE_OUI: [u8; 3] = [0x00, 0x50, 0xF2];
const WPA_IE_TYPE: u8 = 1;
/// Cipher suite 00:50:F2:2 = TKIP (WPA1 default; rejected by shuli).
const CIPHER_TKIP: u8 = 2;

/// Security facts about a BSS collected from its scan IEs.
pub(crate) struct BssScanSecurity {
    pub(crate) security: SecurityType,
    pub(crate) ap_rsne: Vec<u8>,
    pub(crate) ap_rsnxe: Vec<u8>,
    pub(crate) group_mgmt_cipher: Ieee80211CipherSuite,
    pub(crate) mdie: Option<MdieInfo>,
}

/// Walk an 802.11 IE buffer and determine the security type from the
/// RSNE's AKM suites. Also collects the raw RSNE / RSNXE elements (ID +
/// length + body) for the 4-way handshake Message 3 downgrade check and
/// the Mobility Domain element for FT; all are empty/None when absent.
///
/// A BSS is `Unsupported` when it is encrypted in a way shuli cannot
/// join - an RSNE whose AKMs are all unknown, an RSNE with a TKIP
/// group cipher, or a WPA1 AP (vendor WPA IE, no RSNE). Such a BSS
/// must never fall through to `Open`, which would make the client
/// associate without encryption.
pub(crate) fn detect_security(ies: &[u8]) -> BssScanSecurity {
    let mut rsne = Vec::new();
    let mut rsnxe = Vec::new();
    let mut mdie = None;
    let mut wpa_ie = false;
    let mut pos = 0;
    while pos + 2 <= ies.len() {
        let id = ies[pos];
        let len = ies[pos + 1] as usize;
        if pos + 2 + len > ies.len() {
            break;
        }
        match id {
            IE_ID_RSN if rsne.is_empty() => {
                rsne = ies[pos..pos + 2 + len].to_vec();
            }
            IE_ID_RSNXE if rsnxe.is_empty() => {
                rsnxe = ies[pos..pos + 2 + len].to_vec();
            }
            IE_ID_MDIE if mdie.is_none() => {
                mdie = crate::ieee80211::elements::parse_mdie(
                    &ies[pos + 2..pos + 2 + len],
                )
                .map(|(mdid, ft_capab)| MdieInfo { mdid, ft_capab });
            }
            IE_ID_VENDOR if !wpa_ie => {
                // Vendor-specific: WPA (OUI 00:50:F2, type 1) marks a
                // WPA1/TKIP AP - encrypted, but not joinable by shuli.
                let body = &ies[pos + 2..pos + 2 + len];
                wpa_ie = body.len() >= 4
                    && body[..3] == WPA_IE_OUI
                    && body[3] == WPA_IE_TYPE;
            }
            _ => {}
        }
        pos += 2 + len;
    }
    let security = if rsne.len() > 2 {
        security_from_rsne(&rsne[2..])
    } else if wpa_ie {
        SecurityType::Unsupported
    } else {
        SecurityType::Open
    };
    let group_mgmt_cipher = if rsne.len() > 2 {
        crate::ieee80211::elements::negotiate_group_mgmt_cipher(&rsne)
    } else {
        Ieee80211CipherSuite::BipCmac128
    };
    BssScanSecurity {
        security,
        ap_rsne: rsne,
        ap_rsnxe: rsnxe,
        group_mgmt_cipher,
        mdie,
    }
}

/// Rank for choosing among several advertised AKMs: FT variants win so
/// shuli can roam within the mobility domain, then SAE, then the
/// personal/OWE AKMs, and finally 802.1X (a network configured with a
/// passphrase must not pick an enterprise AKM it has no EAP
/// credentials for).
fn akm_rank(security: SecurityType) -> u8 {
    match security {
        SecurityType::FtSae => 5,
        SecurityType::FtSaeExtKey => 5,
        SecurityType::FtPsk => 4,
        SecurityType::Sae => 4,
        SecurityType::SaeExtKey => 4,
        SecurityType::Wpa2PskSha256 => 3,
        SecurityType::Owe | SecurityType::Wpa2Psk => 2,
        SecurityType::Wpa2EntSha256 | SecurityType::Wpa2Ent => 1,
        SecurityType::Open | SecurityType::Unsupported => 0,
    }
}

/// Parse the RSNE body (after element ID + length) and check AKM suites.
/// RSNE layout: version(2) | group(4) | pcount(2) | pciphers(4*n) |
///              acount(2) | akms(4*m) | ...
///
/// The caller only passes a body from an actual RSNE element, so a
/// result of `Open` would mean "no usable security information": every
/// parse failure and every all-unsupported AKM list maps to
/// `Unsupported` instead (an encrypted AP shuli cannot join must not be
/// treated as open).
fn security_from_rsne(body: &[u8]) -> SecurityType {
    // Minimum: version(2) + group(4) + pcount(2) = 8 bytes before
    // pairwise ciphers.
    if body.len() < 8 {
        return SecurityType::Unsupported;
    }
    // TKIP as the group cipher means a WPA1/WPA2 hybrid or TKIP-only
    // AP - shuli does not implement TKIP and must not connect. The
    // group cipher suite (RSN OUI 00-0F-AC) sits at body[2..6].
    if body.len() >= 6
        && body[2] == 0x00
        && body[3] == 0x0F
        && body[4] == 0xAC
        && body[5] == CIPHER_TKIP
    {
        return SecurityType::Unsupported;
    }
    let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
    let akm_offset = 8 + pcount * 4;
    if body.len() < akm_offset + 2 {
        return SecurityType::Unsupported;
    }
    let acount =
        u16::from_le_bytes([body[akm_offset], body[akm_offset + 1]]) as usize;
    let mut off = akm_offset + 2;
    let mut best = SecurityType::Open;
    for _ in 0..acount {
        if body.len() < off + 4 {
            break;
        }
        // AKM suite: OUI(3) + type(1).  We only care about 00-0F-AC.
        if body[off] == 0x00 && body[off + 1] == 0x0F && body[off + 2] == 0xAC {
            let candidate = match body[off + 3] {
                AKM_FT_SAE => SecurityType::FtSae,
                AKM_FT_SAE_EXT_KEY => SecurityType::FtSaeExtKey,
                AKM_FT_PSK => SecurityType::FtPsk,
                AKM_SAE => SecurityType::Sae,
                AKM_SAE_EXT_KEY => SecurityType::SaeExtKey,
                AKM_OWE => SecurityType::Owe,
                AKM_PSK => SecurityType::Wpa2Psk,
                AKM_PSK_SHA256 => SecurityType::Wpa2PskSha256,
                AKM_1X => SecurityType::Wpa2Ent,
                AKM_1X_SHA256 => SecurityType::Wpa2EntSha256,
                _ => SecurityType::Unsupported,
            };
            if akm_rank(candidate) > akm_rank(best) {
                best = candidate;
            }
        }
        off += 4;
    }
    // No supported AKM suite among the advertised ones: an encrypted
    // AP shuli cannot join.
    if best == SecurityType::Open {
        SecurityType::Unsupported
    } else {
        best
    }
}

/// Standalone scan: create a nl80211 handle, trigger a scan on the
/// given interface, wait, and return all discovered BSSes with their
/// raw IE buffers (for generation detection by the caller).
pub async fn scan_wifi_with_ies(
    iface_name: &str,
) -> Result<Vec<(BssInfo, Vec<u8>)>, WifiError> {
    let (conn, handle, _) = wl_nl80211::new_connection()
        .map_err(|e| WifiError::new(ErrorKind::Nl80211, e.to_string()))?;
    tokio::spawn(conn);

    let if_index = resolve_if_index(&handle, iface_name).await?;

    trigger_scan(&handle, if_index, None).await?;
    tokio::time::sleep(std::time::Duration::from_secs(SCAN_SLEEP_SECS)).await;

    let bss_list = get_scan_results(&handle, if_index).await?;
    let mut beacon_has_ssid: HashMap<[u8; ETH_ALEN], bool> = HashMap::new();
    for bss in &bss_list {
        let Some(bssid) = extract_bssid(bss) else {
            continue;
        };
        for info in bss {
            if let Nl80211BssInfo::RawBeaconInformationElements(ies) = info {
                let ssid = extract_ssid_from_ies(ies);
                beacon_has_ssid
                    .insert(bssid, ssid.is_some_and(|s| !s.is_empty()));
            }
        }
    }
    let mut results = Vec::new();
    for bss in &bss_list {
        let Some(ies) = extract_ies(bss) else {
            continue;
        };
        let Some(ssid) = extract_ssid_from_ies(ies) else {
            continue;
        };
        if ssid.is_empty() {
            continue;
        }
        let (Some(bssid), Some(freq_mhz), Some(signal_dbm)) = (
            extract_bssid(bss),
            extract_freq(bss),
            extract_signal_dbm(bss),
        ) else {
            continue;
        };
        let bss_security = detect_security(ies);
        let info = BssInfo {
            bssid,
            freq_mhz,
            signal_dbm,
            security: bss_security.security,
            ap_rsne: bss_security.ap_rsne,
            ap_rsnxe: bss_security.ap_rsnxe,
            group_mgmt_cipher: bss_security.group_mgmt_cipher,
            mdie: bss_security.mdie,
            hidden: beacon_has_ssid.get(&bssid) == Some(&false),
            btm_support: crate::ieee80211::elements::ap_supports_btm(ies),
            rm_neighbor_report:
                crate::ieee80211::elements::ap_supports_rm_neighbor_report(ies),
        };
        results.push((info, ies.to_vec()));
    }
    Ok(results)
}

async fn resolve_if_index(
    handle: &wl_nl80211::Nl80211Handle,
    iface_name: &str,
) -> Result<u32, WifiError> {
    let mut dump = handle.interface().get(vec![]).execute().await;
    while let Some(msg) = dump.try_next().await? {
        if msg.payload.attributes.iter().any(|attr| {
            matches!(attr, wl_nl80211::Nl80211Attr::IfName(n) if n == iface_name)
        }) {
            for attr in &msg.payload.attributes {
                if let wl_nl80211::Nl80211Attr::IfIndex(idx) = attr {
                    return Ok(*idx);
                }
            }
        }
    }
    Err(WifiError::new(
        ErrorKind::InterfaceNotFound,
        format!("interface {iface_name} not found"),
    ))
}
