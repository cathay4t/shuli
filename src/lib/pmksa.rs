// SPDX-License-Identifier: Apache-2.0

//! Userspace PMKSA cache.
//!
//! After a successful 4-way handshake the (PMK, PMKID) pair is cached per
//! (SSID, BSSID). On a later connection to the same BSS the PMKID is put
//! into the (Re)Association RSNE: when the AP holds the matching PMKSA
//! (its own cache, or the driver cache fed via `NL80211_CMD_SET_PMKSA`),
//! it accepts the association and runs only the 4-way handshake with the
//! cached PMK - skipping the full SAE exchange. A rejected PMKID falls
//! back to full authentication (802.11-2020 §12.7.1.6).

use std::{
    fmt,
    time::{Duration, Instant},
};

use crate::{ETH_ALEN, crypto::handshake4::MicAlg};

/// PMK lifetime (seconds): 802.11-2020 §12.7.1.6 recommends 43200
/// (12 hours); wpa_supplicant uses the same default.
pub(crate) const PMK_LIFETIME_SECS: u64 = 43200;
/// Reauthentication threshold in percent of the lifetime (wpa_supplicant
/// default): reauthenticate once 70 % of the PMK lifetime elapsed.
pub(crate) const PMK_REAUTH_THRESHOLD_PERCENT: u8 = 70;
/// Cap on cache entries; the oldest entry is evicted on overflow
/// (wpa_supplicant caps its cache the same way).
const MAX_ENTRIES: usize = 32;

/// A PMKSA cache entry. The PMK never appears in `Debug` output.
#[derive(Clone)]
pub(crate) struct PmksaEntry {
    pub ssid: String,
    pub bssid: [u8; ETH_ALEN],
    pub pmkid: [u8; 16],
    pub pmk: [u8; 32],
    /// MIC / KDF algorithm of the AKM the entry was created with; the
    /// 4-way handshake over a cached PMK must keep using it.
    pub mic_alg: MicAlg,
    pub expires: Instant,
}

impl fmt::Debug for PmksaEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PmksaEntry")
            .field("ssid", &self.ssid)
            .field("bssid", &self.bssid)
            .field("pmkid", &self.pmkid)
            .field("mic_alg", &self.mic_alg)
            .finish_non_exhaustive()
    }
}

/// The PMKSA cache of one interface.
#[derive(Debug, Default)]
pub(crate) struct PmksaCache {
    entries: Vec<PmksaEntry>,
}

impl PmksaCache {
    /// Insert or refresh the entry for (SSID, BSSID). Evicts expired
    /// entries first, then the oldest entry when over [`MAX_ENTRIES`].
    pub fn insert(&mut self, entry: PmksaEntry) {
        self.remove_expired();
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|e| e.ssid == entry.ssid && e.bssid == entry.bssid)
        {
            *slot = entry;
            return;
        }
        if self.entries.len() == MAX_ENTRIES {
            // Replace the entry expiring soonest.
            let mut oldest = 0;
            for (i, e) in self.entries.iter().enumerate().skip(1) {
                if e.expires < self.entries[oldest].expires {
                    oldest = i;
                }
            }
            self.entries.swap_remove(oldest);
        }
        self.entries.push(entry);
    }

    /// Look up the (unexpired) entry for (SSID, BSSID).
    pub fn lookup(
        &mut self,
        ssid: &str,
        bssid: [u8; ETH_ALEN],
    ) -> Option<PmksaEntry> {
        self.remove_expired();
        self.entries
            .iter()
            .find(|e| e.ssid == ssid && e.bssid == bssid)
            .cloned()
    }

    /// Remove and return the entry for (SSID, BSSID), e.g. because the
    /// AP rejected the PMKID or the connection was shut down.
    pub fn invalidate(
        &mut self,
        ssid: &str,
        bssid: [u8; ETH_ALEN],
    ) -> Option<PmksaEntry> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.ssid == ssid && e.bssid == bssid)?;
        Some(self.entries.swap_remove(pos))
    }

    /// Drop every entry whose PMK lifetime elapsed.
    pub fn remove_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|e| e.expires > now);
    }
}

/// Refresh helper: a reused entry gets its lifetime restarted.
pub(crate) fn entry_with_fresh_lifetime(mut entry: PmksaEntry) -> PmksaEntry {
    entry.expires = Instant::now() + Duration::from_secs(PMK_LIFETIME_SECS);
    entry
}
