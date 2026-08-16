// SPDX-License-Identifier: Apache-2.0

use crate::ieee80211::band::operating_class_channel_to_freq;

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
