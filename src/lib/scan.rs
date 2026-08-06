// SPDX-License-Identifier: Apache-2.0

//! Scan flow: trigger a scan, wait for results, then pick the strongest BSS
//! matching the configured SSID.

use futures::TryStreamExt;

use crate::{
    ETH_ALEN, ErrorKind, NetworkConfig, WifiClient, WifiError,
    nl80211::scan::{
        extract_bssid, extract_freq, extract_ies, extract_signal,
        extract_ssid_from_ies, get_scan_results, trigger_scan,
    },
};

const SCAN_SLEEP_SECS: u64 = 3;

/// Security type detected from the BSS's RSNE in scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityType {
    /// No RSNE — open / no encryption.
    #[default]
    Open,
    /// RSNE with AKM 00-0F-AC:2 — WPA2-PSK.
    Wpa2Psk,
    /// RSNE with AKM 00-0F-AC:18 — OWE (opportunistic encryption).
    Owe,
    /// RSNE with AKM 00-0F-AC:8 — WPA3-SAE.
    Sae,
}

/// The best BSS candidate for the configured SSID.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BssInfo {
    pub bssid: [u8; ETH_ALEN],
    pub freq_mhz: u32,
    pub signal_dbm: i32,
    pub security: SecurityType,
    /// The AP's RSNE as a full element (ID + length + body) from the
    /// beacon / probe response; empty on open BSSes. Used to validate
    /// 4-way handshake Message 3 against downgrade attacks.
    pub ap_rsne: Vec<u8>,
    /// The AP's RSNXE as a full element (ID 244), empty when the AP
    /// advertises none.
    pub ap_rsnxe: Vec<u8>,
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
        log::info!("scanning for SSIDs [{}]", ssids.join(", "));
        trigger_scan(&self.handle, self.if_index, Some(&ssids)).await
    }

    // TODO: use multicast to wait for scan completion instead of a fixed
    // sleep: https://github.com/rust-netlink/wl-nl80211/pull/36
    pub(crate) async fn wait_scan_finish(&mut self) {
        log::trace!("Waiting for scan to finish");
        tokio::time::sleep(std::time::Duration::from_secs(SCAN_SLEEP_SECS))
            .await;
    }

    /// Dump the scan results and keep the strongest BSS matching any of
    /// the configured networks; the matched network (with its passphrase)
    /// is recorded for the authentication phase.
    pub(crate) async fn process_scan_results(
        &mut self,
    ) -> Result<(), WifiError> {
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
            let (Some(bssid), Some(freq_mhz), Some(signal_dbm)) =
                (extract_bssid(bss), extract_freq(bss), extract_signal(bss))
            else {
                log::trace!("BSS missing bssid/freq/signal; skipping");
                continue;
            };
            log::trace!(
                "candidate BSS: ssid={bss_ssid}, bssid={bssid:02x?}, \
                 freq={freq_mhz} MHz, signal={signal_dbm}"
            );
            let (security, ap_rsne, ap_rsnxe) = detect_security(ies);
            candidates.push((
                BssInfo {
                    bssid,
                    freq_mhz,
                    signal_dbm,
                    security,
                    ap_rsne,
                    ap_rsnxe,
                },
                network,
            ));
        }

        let best = candidates.into_iter().max_by(|a, b| a.0.cmp(&b.0));
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
}

const IE_ID_RSN: u8 = 48;
const IE_ID_RSNXE: u8 = 244;
const AKM_PSK: u8 = 2;
const AKM_OWE: u8 = 18;
const AKM_SAE: u8 = 8;

/// Walk an 802.11 IE buffer and determine the security type from the
/// RSNE's AKM suites. Also returns the raw RSNE / RSNXE elements (ID +
/// length + body) for the 4-way handshake Message 3 downgrade check;
/// both are empty when absent.
fn detect_security(ies: &[u8]) -> (SecurityType, Vec<u8>, Vec<u8>) {
    let mut rsne = Vec::new();
    let mut rsnxe = Vec::new();
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
            _ => {}
        }
        pos += 2 + len;
    }
    let security = if rsne.len() > 2 {
        security_from_rsne(&rsne[2..])
    } else {
        SecurityType::Open
    };
    (security, rsne, rsnxe)
}

/// Parse the RSNE body (after element ID + length) and check AKM suites.
/// RSNE layout: version(2) | group(4) | pcount(2) | pciphers(4*n) |
///              acount(2) | akms(4*m) | ...
fn security_from_rsne(body: &[u8]) -> SecurityType {
    // Minimum: version(2) + group(4) + pcount(2) = 8 bytes before
    // pairwise ciphers.
    if body.len() < 8 {
        return SecurityType::Open;
    }
    let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
    let akm_offset = 8 + pcount * 4;
    if body.len() < akm_offset + 2 {
        return SecurityType::Open;
    }
    let acount =
        u16::from_le_bytes([body[akm_offset], body[akm_offset + 1]]) as usize;
    let mut off = akm_offset + 2;
    for _ in 0..acount {
        if body.len() < off + 4 {
            break;
        }
        // AKM suite: OUI(3) + type(1).  We only care about 00-0F-AC.
        if body[off] == 0x00 && body[off + 1] == 0x0F && body[off + 2] == 0xAC {
            match body[off + 3] {
                AKM_SAE => return SecurityType::Sae,
                AKM_OWE => return SecurityType::Owe,
                AKM_PSK => return SecurityType::Wpa2Psk,
                _ => {}
            }
        }
        off += 4;
    }
    // RSNE present but no SAE/OWE AKM — treat as open for now
    // (WPA2-PSK etc. will be added later).
    SecurityType::Open
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
    let mut results = Vec::new();
    for bss in &bss_list {
        let Some(ies) = extract_ies(bss) else {
            continue;
        };
        if extract_ssid_from_ies(ies).is_none() {
            continue;
        }
        let (Some(bssid), Some(freq_mhz), Some(signal_dbm)) =
            (extract_bssid(bss), extract_freq(bss), extract_signal(bss))
        else {
            continue;
        };
        let (security, ap_rsne, ap_rsnxe) = detect_security(ies);
        let info = BssInfo {
            bssid,
            freq_mhz,
            signal_dbm,
            security,
            ap_rsne,
            ap_rsnxe,
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
