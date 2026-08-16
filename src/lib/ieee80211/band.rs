// SPDX-License-Identifier: Apache-2.0

//! Channel / operating-class helpers used to turn neighbor-report
//! entries (802.11k / BTM candidate lists) into frequencies for quick
//! roaming scans.
//!
//! The `Channel Number` field of a Neighbor Report element is the
//! *primary* channel of the AP, so the center-frequency formulas of
//! Annex E apply regardless of the BSS channel width.

/// Map a global operating class + channel number to the primary-channel
/// frequency in MHz (802.11-2020 Annex E, Table E-1). Local
/// (country-specific) operating classes are rejected; hostapd and most
/// enterprise APs report global classes.
pub fn operating_class_channel_to_freq(
    operating_class: u8,
    channel: u8,
) -> Option<u32> {
    match operating_class {
        // 2.4 GHz, classes 81-87 (20/40 MHz channels 1-14).
        81..=87 => match (operating_class, channel) {
            (_, 1..=13) => Some(2407 + u32::from(channel) * 5),
            (82, 14) => Some(2484),
            _ => None,
        },
        // 5 GHz, classes 115-130 (20/40/80/160 MHz channels 32-196).
        115..=130 if (32..=196).contains(&channel) => {
            Some(5000 + u32::from(channel) * 5)
        }
        // 6 GHz, classes 131-155 (20 MHz channel numbers 1, 5, ..., 233).
        131..=155 if channel % 2 == 1 && channel <= 233 => {
            Some(5950 + u32::from(channel) * 5)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operating_class_channel_to_freq_2ghz() {
        assert_eq!(operating_class_channel_to_freq(81, 1), Some(2412));
        assert_eq!(operating_class_channel_to_freq(81, 6), Some(2437));
        assert_eq!(operating_class_channel_to_freq(81, 13), Some(2472));
        assert_eq!(operating_class_channel_to_freq(82, 14), Some(2484));
        assert_eq!(operating_class_channel_to_freq(81, 14), None);
    }

    #[test]
    fn operating_class_channel_to_freq_5ghz() {
        assert_eq!(operating_class_channel_to_freq(115, 36), Some(5180));
        assert_eq!(operating_class_channel_to_freq(124, 149), Some(5745));
        assert_eq!(operating_class_channel_to_freq(128, 177), Some(5885));
        assert_eq!(operating_class_channel_to_freq(115, 20), None);
    }

    #[test]
    fn operating_class_channel_to_freq_6ghz() {
        assert_eq!(operating_class_channel_to_freq(131, 1), Some(5955));
        assert_eq!(operating_class_channel_to_freq(131, 5), Some(5975));
        assert_eq!(operating_class_channel_to_freq(155, 233), Some(7115));
        assert_eq!(operating_class_channel_to_freq(131, 2), None);
    }

    #[test]
    fn operating_class_channel_to_freq_unknown() {
        assert_eq!(operating_class_channel_to_freq(200, 1), None);
        assert_eq!(operating_class_channel_to_freq(0, 6), None);
    }
}
