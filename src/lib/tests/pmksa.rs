// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use crate::{
    crypto::{
        handshake4::MicAlg,
        kdf::{pmkid_sha1, pmkid_sha256},
    },
    pmksa::{PMK_LIFETIME_SECS, PmksaCache, PmksaEntry},
};

const SSID: &str = "Test-WIFI";
const BSSID: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];

fn entry(ssid: &str, bssid: [u8; 6], pmkid: [u8; 16]) -> PmksaEntry {
    PmksaEntry {
        ssid: ssid.to_string(),
        bssid,
        pmkid,
        pmk: [0x42; 32],
        mic_alg: MicAlg::AesCmac,
        expires: Instant::now() + Duration::from_secs(PMK_LIFETIME_SECS),
    }
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

    let hit = cache.lookup(SSID, BSSID).expect("cache hit");
    assert_eq!(hit.pmkid, [0x11; 16]);
    assert_eq!(hit.pmk, [0x42; 32]);
    assert_eq!(hit.mic_alg, MicAlg::AesCmac);

    // Different BSSID / SSID must not match.
    assert!(cache.lookup(SSID, [0xff; 6]).is_none());
    assert!(cache.lookup("Other", BSSID).is_none());
}

#[test]
fn test_pmksa_refresh_replaces() {
    let mut cache = PmksaCache::default();
    cache.insert(entry(SSID, BSSID, [0x11; 16]));
    cache.insert(entry(SSID, BSSID, [0x22; 16]));
    assert_eq!(cache.lookup(SSID, BSSID).unwrap().pmkid, [0x22; 16]);
}

#[test]
fn test_pmksa_expiry() {
    let mut cache = PmksaCache::default();
    let mut expired = entry(SSID, BSSID, [0x33; 16]);
    // One second past the PMK lifetime.
    expired.expires = Instant::now() - Duration::from_secs(1);
    cache.insert(expired);
    assert!(
        cache.lookup(SSID, BSSID).is_none(),
        "expired entry must miss"
    );
}

#[test]
fn test_pmksa_invalidate() {
    let mut cache = PmksaCache::default();
    cache.insert(entry(SSID, BSSID, [0x11; 16]));
    let removed = cache.invalidate(SSID, BSSID).expect("entry removed");
    assert_eq!(removed.pmkid, [0x11; 16]);
    assert!(cache.lookup(SSID, BSSID).is_none());
    assert!(cache.invalidate(SSID, BSSID).is_none());
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
            .lookup(SSID, [0x02, 0x00, 0x00, 0x00, 0x01, 39])
            .is_some()
    );
    let survivors = (0u8..40)
        .filter(|i| {
            cache
                .lookup(SSID, [0x02, 0x00, 0x00, 0x00, 0x01, *i])
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
    use crate::ieee80211::elements;
    let pmkid = [0xAB; 16];
    let ie = elements::sae_ie_with_pmkid_cipher(
        Some(pmkid),
        wl_nl80211::Nl80211CipherSuite::BipCmac128,
    );
    // RSNE element: id(1) len(1) version(2) group(4) pcount(2) pcipher(4)
    // acount(2) akm(4) capab(2) pmkid_count(2) pmkid(16) ...
    let pmkid_count = u16::from_le_bytes([ie[22], ie[23]]);
    assert_eq!(pmkid_count, 1);
    assert_eq!(&ie[24..40], pmkid.as_slice());
    // No PMKID: count must be zero.
    let ie = elements::sae_ie_with_pmkid_cipher(
        None,
        wl_nl80211::Nl80211CipherSuite::BipCmac128,
    );
    assert_eq!(u16::from_le_bytes([ie[22], ie[23]]), 0);
}
