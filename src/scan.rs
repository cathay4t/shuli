// SPDX-License-Identifier: Apache-2.0

//! Scan flow: trigger a scan, wait for results, then pick the strongest BSS
//! matching the configured SSID.

use crate::{
    ETH_ALEN, ErrorKind, WpaClient, WpaError,
    nl80211::scan::{
        extract_bssid, extract_freq, extract_ies, extract_signal,
        extract_ssid_from_ies, get_scan_results, trigger_scan,
    },
};

const SCAN_SLEEP_SECS: u64 = 3;

/// The best BSS candidate for the configured SSID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct BssInfo {
    pub(crate) bssid: [u8; ETH_ALEN],
    pub(crate) freq_mhz: u32,
    pub(crate) signal_dbm: i32,
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

impl WpaClient {
    pub(crate) async fn send_out_scan_request(
        &mut self,
    ) -> Result<(), WpaError> {
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
    ) -> Result<(), WpaError> {
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
            });
        }

        let best = candidates.into_iter().max();
        self.bss_info = best.ok_or_else(|| {
            WpaError::new(
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
