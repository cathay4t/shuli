// SPDX-License-Identifier: Apache-2.0

//! Scan flow: trigger a scan, wait for results, then pick the strongest BSS
//! matching the configured SSID.

use crate::{
    ETH_ALEN, ErrorKind, WifiClient, WifiError,
    nl80211::scan::{
        extract_bssid, extract_freq, extract_ies, extract_signal,
        extract_ssid_from_ies, get_scan_results, trigger_scan,
    },
};

use futures::TryStreamExt;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BssInfo {
    pub bssid: [u8; ETH_ALEN],
    pub freq_mhz: u32,
    pub signal_dbm: i32,
    pub security: SecurityType,
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
        log::info!("scanning for SSID '{}'", self.config.ssid);
        trigger_scan(&self.handle, self.if_index, Some(&self.config.ssid)).await
    }

    // TODO: use multicast to wait for scan completion instead of a fixed
    // sleep: https://github.com/rust-netlink/wl-nl80211/pull/36
    pub(crate) async fn wait_scan_finish(&mut self) {
        log::trace!("Waiting for scan to finish");
        tokio::time::sleep(std::time::Duration::from_secs(SCAN_SLEEP_SECS))
            .await;
    }

    /// Dump the scan results and keep the strongest BSS matching our SSID.
    pub(crate) async fn process_scan_results(
        &mut self,
    ) -> Result<(), WifiError> {
        let bss_list = get_scan_results(&self.handle, self.if_index).await?;
        log::trace!("scan dump returned {} BSS entries", bss_list.len());

        let mut candidates: Vec<BssInfo> = Vec::new();
        for bss in &bss_list {
            let Some(ies) = extract_ies(bss) else {
                continue;
            };
            let Some(bss_ssid) = extract_ssid_from_ies(ies) else {
                continue;
            };
            if bss_ssid != self.config.ssid {
                continue;
            }
            let (Some(bssid), Some(freq_mhz), Some(signal_dbm)) =
                (extract_bssid(bss), extract_freq(bss), extract_signal(bss))
            else {
                log::trace!("BSS missing bssid/freq/signal; skipping");
                continue;
            };
            log::trace!(
                "candidate BSS: bssid={bssid:02x?}, freq={freq_mhz} MHz, \
                 signal={signal_dbm}"
            );
            candidates.push(BssInfo {
                bssid,
                freq_mhz,
                signal_dbm,
                security: detect_security(ies),
            });
        }

        let best = candidates.into_iter().max();
        self.bss_info = best.ok_or_else(|| {
            WifiError::new(
                ErrorKind::SsidNotFound,
                format!(
                    "SSID '{}' not found in scan results",
                    self.config.ssid
                ),
            )
        })?;
        log::info!(
            "selected BSS: ssid={}, bssid={:02x?}, freq={} MHz, signal={} dBm",
            self.config.ssid,
            self.bss_info.bssid,
            self.bss_info.freq_mhz,
            self.bss_info.signal_dbm
        );
        Ok(())
    }
}

const IE_ID_RSN: u8 = 48;
const AKM_PSK: u8 = 2;
const AKM_OWE: u8 = 18;
const AKM_SAE: u8 = 8;

/// Walk an 802.11 IE buffer and determine the security type from the
/// RSNE's AKM suites.
fn detect_security(ies: &[u8]) -> SecurityType {
    let mut pos = 0;
    while pos + 2 <= ies.len() {
        let id = ies[pos];
        let len = ies[pos + 1] as usize;
        if id == IE_ID_RSN && pos + 2 + len <= ies.len() {
            return security_from_rsne(&ies[pos + 2..pos + 2 + len]);
        }
        pos += 2 + len;
    }
    SecurityType::Open
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
        let info = BssInfo {
            bssid,
            freq_mhz,
            signal_dbm,
            security: detect_security(ies),
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
