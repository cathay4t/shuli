// SPDX-License-Identifier: Apache-2.0

//! Userspace PMKSA cache.
//!
//! After a successful 4-way handshake the (PMK, PMKID) pair is cached per
//! (SSID, BSSID, AKM). On a later connection to the same BSS the PMKID is
//! put into the (Re)Association RSNE: when the AP holds the matching PMKSA
//! (its own cache, or the driver cache fed via `NL80211_CMD_SET_PMKSA`),
//! it accepts the association and runs only the 4-way handshake with the
//! cached PMK - skipping the full SAE exchange. A rejected PMKID falls
//! back to full authentication (802.11-2020 §12.7.1.6).
//!
//! A cache entry is used for at most
//! [`PMK_REAUTH_THRESHOLD_PERCENT`] of its lifetime. Once the
//! reauthentication threshold passed, a new connection runs full
//! authentication and replaces the entry; a successful connection that
//! merely reused a cached entry keeps the original expiry, so repeatedly
//! reconnecting to a BSS can never extend a PMKSA's lifetime.
//!
//! wpa_supplicant preserves the original expiry in the same way, but only
//! refuses SAE entries past the threshold (a PSK PMK is fixed by the
//! passphrase, so it keeps using the entry until it expires). shuli
//! refuses every cached AKM at the threshold: the full authentication
//! re-proves the credentials and installs a new PMKSA, which is also the
//! point where a changed password would otherwise have gone unnoticed.

use std::{
    fmt,
    time::{Duration, Instant},
};

use crate::{ETH_ALEN, crypto::handshake4::MicAlg, scan::SecurityType};

/// PMK lifetime (seconds): 802.11-2020 §12.7.1.6 recommends 43200
/// (12 hours); wpa_supplicant uses the same default.
pub(crate) const PMK_LIFETIME_SECS: u64 = 43200;
/// Reauthentication threshold in percent of the lifetime (wpa_supplicant
/// default): reauthenticate once 70 % of the PMK lifetime elapsed.
pub(crate) const PMK_REAUTH_THRESHOLD_PERCENT: u8 = 70;
/// Cap on cache entries; the entry expiring soonest is evicted on overflow
/// (wpa_supplicant caps its cache the same way).
const MAX_ENTRIES: usize = 32;

/// A PMKSA cache entry. The PMK never appears in `Debug` output.
#[derive(Clone)]
pub(crate) struct PmksaEntry {
    pub ssid: String,
    pub bssid: [u8; ETH_ALEN],
    /// AKM the PMKSA was created with. A PMK from one AKM family must
    /// never be used for another (e.g. a PSK PMK for SAE).
    pub security: SecurityType,
    pub pmkid: [u8; 16],
    pub pmk: [u8; 32],
    /// MIC / KDF algorithm of the AKM the entry was created with; the
    /// 4-way handshake over a cached PMK must keep using it.
    pub mic_alg: MicAlg,
    pub expires: Instant,
    /// When the reauthentication threshold is reached: from then on the
    /// entry is no longer offered for new associations.
    pub reauth_at: Instant,
}

impl PmksaEntry {
    /// Create an entry whose lifetime starts now.
    pub(crate) fn new(
        ssid: String,
        bssid: [u8; ETH_ALEN],
        security: SecurityType,
        pmkid: [u8; 16],
        pmk: [u8; 32],
        mic_alg: MicAlg,
    ) -> Self {
        let established = Instant::now();
        let lifetime = Duration::from_secs(PMK_LIFETIME_SECS);
        let reauth = Duration::from_secs(
            PMK_LIFETIME_SECS * u64::from(PMK_REAUTH_THRESHOLD_PERCENT) / 100,
        );
        Self {
            ssid,
            bssid,
            security,
            pmkid,
            pmk,
            mic_alg,
            expires: established + lifetime,
            reauth_at: established + reauth,
        }
    }

    /// FT and non-FT variants of an AKM share the PMK and PMKID
    /// derivation, so both match the same cache entry.
    fn akm(&self) -> SecurityType {
        self.security.base()
    }

    fn matches(
        &self,
        ssid: &str,
        bssid: [u8; ETH_ALEN],
        security: SecurityType,
    ) -> bool {
        self.ssid == ssid
            && self.bssid == bssid
            && self.akm() == security.base()
    }

    fn past_reauth_threshold(&self, now: Instant) -> bool {
        now >= self.reauth_at
    }

    /// Remaining lifetime in whole seconds, for driver offload. The
    /// kernel rejects a lifetime of 0.
    pub(crate) fn remaining_lifetime_secs(&self) -> u32 {
        self.expires
            .saturating_duration_since(Instant::now())
            .as_secs()
            .clamp(1, u64::from(u32::MAX)) as u32
    }

    /// Remaining time until the reauthentication threshold as a
    /// percentage of the remaining lifetime, for driver offload. The
    /// kernel accepts 1..=100 only.
    pub(crate) fn remaining_reauth_percent(&self) -> u8 {
        let now = Instant::now();
        let lifetime = self.expires.saturating_duration_since(now).as_secs();
        if lifetime == 0 {
            return 1;
        }
        let reauth = self.reauth_at.saturating_duration_since(now).as_secs();
        ((reauth * 100) / lifetime).clamp(1, 100) as u8
    }
}

impl fmt::Debug for PmksaEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PmksaEntry")
            .field("ssid", &self.ssid)
            .field("bssid", &self.bssid)
            .field("security", &self.security)
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
    /// Insert or replace the entry for (SSID, BSSID, AKM). The caller
    /// owns the entry's timestamps: reusing an existing entry must pass
    /// it back unchanged to preserve its original lifetime, while a full
    /// authentication creates a new entry with a fresh lifetime. Evicts
    /// expired entries first, then the entry expiring soonest when over
    /// [`MAX_ENTRIES`].
    pub fn insert(&mut self, entry: PmksaEntry) {
        self.remove_expired();
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|e| e.matches(&entry.ssid, entry.bssid, entry.security))
        {
            *slot = entry;
            return;
        }
        if self.entries.len() == MAX_ENTRIES {
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

    /// Look up an unexpired entry that is still usable for a new
    /// association, i.e. one whose reauthentication threshold has not
    /// passed.
    pub fn lookup(
        &mut self,
        ssid: &str,
        bssid: [u8; ETH_ALEN],
        security: SecurityType,
    ) -> Option<PmksaEntry> {
        self.remove_expired();
        let now = Instant::now();
        self.entries
            .iter()
            .find(|e| {
                e.matches(ssid, bssid, security)
                    && !e.past_reauth_threshold(now)
            })
            .cloned()
    }

    /// Look up an unexpired entry that passed its reauthentication
    /// threshold. It must not be offered for a new association; the
    /// caller uses it to withdraw the PMKID from the driver cache before
    /// running full authentication.
    pub fn lookup_past_reauth(
        &mut self,
        ssid: &str,
        bssid: [u8; ETH_ALEN],
        security: SecurityType,
    ) -> Option<PmksaEntry> {
        self.remove_expired();
        let now = Instant::now();
        self.entries
            .iter()
            .find(|e| {
                e.matches(ssid, bssid, security) && e.past_reauth_threshold(now)
            })
            .cloned()
    }

    /// Whether an unexpired entry exists for the key, regardless of its
    /// reauthentication threshold.
    pub fn contains(
        &mut self,
        ssid: &str,
        bssid: [u8; ETH_ALEN],
        security: SecurityType,
    ) -> bool {
        self.remove_expired();
        self.entries
            .iter()
            .any(|e| e.matches(ssid, bssid, security))
    }

    /// Remove and return the entry for (SSID, BSSID, AKM), e.g. because
    /// the AP rejected the PMKID or the connection was shut down.
    pub fn invalidate(
        &mut self,
        ssid: &str,
        bssid: [u8; ETH_ALEN],
        security: SecurityType,
    ) -> Option<PmksaEntry> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.matches(ssid, bssid, security))?;
        Some(self.entries.swap_remove(pos))
    }

    /// Remove every entry for `ssid`, returning them so the caller can
    /// also withdraw them from the driver cache (e.g. after a password
    /// or EAP credential change).
    pub fn remove_ssid(&mut self, ssid: &str) -> Vec<PmksaEntry> {
        let mut removed = Vec::new();
        let mut kept = Vec::with_capacity(self.entries.len());
        for entry in self.entries.drain(..) {
            if entry.ssid == ssid {
                removed.push(entry);
            } else {
                kept.push(entry);
            }
        }
        self.entries = kept;
        removed
    }

    /// Drop every entry whose PMK lifetime elapsed.
    pub fn remove_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|e| e.expires > now);
    }
}
