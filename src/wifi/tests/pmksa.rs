// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use crate::{
    crypto::{
        handshake4::MicAlg,
        kdf::{pmkid_sha1, pmkid_sha256},
    },
    pmksa::{PMK_LIFETIME_SECS, PmksaCache, PmksaEntry},
    scan::SecurityType,
};

const SSID: &str = "Test-WIFI";
const BSSID: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];

fn entry_with_security(
    ssid: &str,
    bssid: [u8; 6],
    pmkid: [u8; 16],
    security: SecurityType,
) -> PmksaEntry {
    PmksaEntry::new(
        ssid.to_string(),
        bssid,
        security,
        pmkid,
        [0x42; 32],
        MicAlg::AesCmac,
    )
}

fn entry(ssid: &str, bssid: [u8; 6], pmkid: [u8; 16]) -> PmksaEntry {
    entry_with_security(ssid, bssid, pmkid, SecurityType::Sae)
}

#[test]
fn test_pmkid_kats() {
    // Known-answer vectors for 802.11-2020 §9.4.2.25.3:
    // PMKID = Truncate-128(HMAC-Hash(PMK, "PMK Name" || AA || SPA)).
    let pmk = [0x01u8; 32];
    let aa = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
    let spa = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        pmkid_sha256(&pmk, &aa, &spa),
        [
            0x4b, 0xc8, 0xe3, 0xa5, 0x5a, 0xa6, 0xdb, 0x15, 0xb9, 0x8f, 0xab,
            0xf2, 0x78, 0x14, 0x59, 0xce,
        ]
    );
    assert_eq!(
        pmkid_sha1(&pmk, &aa, &spa),
        [
            0xe4, 0x84, 0x4e, 0xb1, 0x16, 0x4c, 0x39, 0x29, 0xe9, 0x1e, 0x84,
            0xa7, 0x9c, 0x02, 0x9e, 0xda,
        ]
    );
}

#[test]
fn test_pmksa_insert_lookup() {
    let mut cache = PmksaCache::default();
    cache.insert(entry(SSID, BSSID, [0x11; 16]));

    let hit = cache
        .lookup(SSID, BSSID, SecurityType::Sae)
        .expect("cache hit");
    assert_eq!(hit.pmkid, [0x11; 16]);
    assert_eq!(hit.pmk, [0x42; 32]);
    assert_eq!(hit.mic_alg, MicAlg::AesCmac);

    // Different BSSID / SSID / AKM must not match.
    assert!(cache.lookup(SSID, [0xff; 6], SecurityType::Sae).is_none());
    assert!(cache.lookup("Other", BSSID, SecurityType::Sae).is_none());
    assert!(
        cache.lookup(SSID, BSSID, SecurityType::Wpa2Psk).is_none(),
        "a SAE PMK must never satisfy a PSK lookup"
    );
}

#[test]
fn test_pmksa_akm_families() {
    let mut cache = PmksaCache::default();
    cache.insert(entry_with_security(
        SSID,
        BSSID,
        [0x11; 16],
        SecurityType::Wpa2Psk,
    ));
    // FT and non-FT variants share the PMK/PMKID derivation.
    assert!(
        cache.lookup(SSID, BSSID, SecurityType::FtPsk).is_some(),
        "FT-PSK must reuse the WPA2-PSK entry"
    );
    assert!(
        cache
            .lookup(SSID, BSSID, SecurityType::Wpa2PskSha256)
            .is_none(),
        "PSK-SHA256 uses a different PMKID derivation"
    );
}

#[test]
fn test_pmksa_refresh_replaces() {
    let mut cache = PmksaCache::default();
    cache.insert(entry(SSID, BSSID, [0x11; 16]));
    cache.insert(entry(SSID, BSSID, [0x22; 16]));
    assert_eq!(
        cache.lookup(SSID, BSSID, SecurityType::Sae).unwrap().pmkid,
        [0x22; 16]
    );
}

#[test]
fn test_pmksa_expiry() {
    let mut cache = PmksaCache::default();
    let mut expired = entry(SSID, BSSID, [0x33; 16]);
    // One second past the PMK lifetime.
    expired.expires = Instant::now() - Duration::from_secs(1);
    cache.insert(expired);
    assert!(
        cache.lookup(SSID, BSSID, SecurityType::Sae).is_none(),
        "expired entry must miss"
    );
}

#[test]
fn test_pmksa_reauth_threshold() {
    let mut cache = PmksaCache::default();
    let mut due = entry(SSID, BSSID, [0x44; 16]);
    due.reauth_at = Instant::now() - Duration::from_secs(1);
    cache.insert(due);

    assert!(
        cache.lookup(SSID, BSSID, SecurityType::Sae).is_none(),
        "an entry past the reauth threshold must not be offered"
    );
    assert!(
        cache
            .lookup_past_reauth(SSID, BSSID, SecurityType::Sae)
            .is_some(),
        "the entry is kept until it expires"
    );
    assert!(
        cache.contains(SSID, BSSID, SecurityType::Sae),
        "OKC must not resurrect a threshold-expired entry"
    );
}

#[test]
fn test_pmksa_remaining_values_for_driver_offload() {
    let entry = entry(SSID, BSSID, [0x55; 16]);
    let lifetime = entry.remaining_lifetime_secs();
    assert!(
        lifetime <= PMK_LIFETIME_SECS as u32
            && lifetime + 5 >= PMK_LIFETIME_SECS as u32,
        "unexpected remaining lifetime {lifetime}"
    );
    let reauth = entry.remaining_reauth_percent();
    assert!(
        (69..=70).contains(&reauth),
        "unexpected remaining reauth threshold {reauth}%"
    );
}

#[test]
fn test_pmksa_invalidate() {
    let mut cache = PmksaCache::default();
    cache.insert(entry(SSID, BSSID, [0x11; 16]));
    let removed = cache
        .invalidate(SSID, BSSID, SecurityType::Sae)
        .expect("entry removed");
    assert_eq!(removed.pmkid, [0x11; 16]);
    assert!(cache.lookup(SSID, BSSID, SecurityType::Sae).is_none());
    assert!(cache.invalidate(SSID, BSSID, SecurityType::Sae).is_none());
}

#[test]
fn test_pmksa_remove_ssid() {
    let mut cache = PmksaCache::default();
    cache.insert(entry(SSID, BSSID, [0x11; 16]));
    cache.insert(entry(
        SSID,
        [0x02, 0x00, 0x00, 0x00, 0x01, 0x01],
        [0x12; 16],
    ));
    cache.insert(entry("Other", BSSID, [0x13; 16]));

    let removed = cache.remove_ssid(SSID);
    assert_eq!(removed.len(), 2);
    assert!(!cache.contains(SSID, BSSID, SecurityType::Sae));
    assert!(cache.contains("Other", BSSID, SecurityType::Sae));
}

#[test]
fn test_pmksa_capacity() {
    let mut cache = PmksaCache::default();
    for i in 0u8..40 {
        let bssid = [0x02, 0x00, 0x00, 0x00, 0x01, i];
        cache.insert(entry(SSID, bssid, [i; 16]));
    }
    // The cache is capped: the freshest entry survives while one of the
    // earliest got evicted.
    assert!(
        cache
            .lookup(
                SSID,
                [0x02, 0x00, 0x00, 0x00, 0x01, 39],
                SecurityType::Sae,
            )
            .is_some()
    );
    let survivors = (0u8..40)
        .filter(|i| {
            cache
                .lookup(
                    SSID,
                    [0x02, 0x00, 0x00, 0x00, 0x01, *i],
                    SecurityType::Sae,
                )
                .is_some()
        })
        .count();
    assert_eq!(survivors, 32, "cache must be capped at 32 entries");
}

#[test]
fn test_rsne_pmkid_builder_roundtrip() {
    // The PMKID must appear verbatim in the RSNE built for association
    // and Message 2 (17th/18th bytes of the body = pmkid_count, then
    // the PMKID itself).
    use wl_nl80211::sae_ie_with_pmkid_cipher;
    let pmkid = [0xAB; 16];
    let ie = sae_ie_with_pmkid_cipher(
        Some(pmkid),
        wl_nl80211::Ieee80211CipherSuite::BipCmac128,
    );
    // RSNE element: id(1) len(1) version(2) group(4) pcount(2) pcipher(4)
    // acount(2) akm(4) capab(2) pmkid_count(2) pmkid(16) ...
    let pmkid_count = u16::from_le_bytes([ie[22], ie[23]]);
    assert_eq!(pmkid_count, 1);
    assert_eq!(&ie[24..40], pmkid.as_slice());
    // No PMKID: count must be zero.
    let ie = sae_ie_with_pmkid_cipher(
        None,
        wl_nl80211::Ieee80211CipherSuite::BipCmac128,
    );
    assert_eq!(u16::from_le_bytes([ie[22], ie[23]]), 0);
}
