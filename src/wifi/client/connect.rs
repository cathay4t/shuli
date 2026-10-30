// SPDX-License-Identifier: Apache-2.0

//! `NL80211_CMD_CONNECT` path for FullMAC drivers.
//!
//! The driver/firmware performs authentication and association; shuli
//! supplies the full RSN parameters and then runs the 4-way handshake in
//! userspace over the interface's control port.

use netlink_packet_core::DefaultNla;
use wl_nl80211::{
    Ieee80211AkmSuite, Ieee80211CipherSuite, Nl80211Attr, Nl80211AuthType,
    Nl80211Connect, Nl80211UseMfp, Nl80211WpaVersions,
};

use super::{ControlPortMode, MlmeMode, WifiIface};
use crate::{
    ErrorKind, SecurityType, WifiError, nl80211::extract_rsn_from_ies,
};

impl WifiIface {
    /// Send `NL80211_CMD_CONNECT` for the selected BSS.
    pub(crate) async fn send_out_connect_request(
        &mut self,
    ) -> Result<(), WifiError> {
        let security = self.link.bss_info.security;
        let ssid = self.link.network.ssid.clone();
        let unsupported = |reason: &str| {
            WifiError::new(ErrorKind::NoSupport, reason.to_string())
                .with_ssid(ssid.clone())
        };
        match security {
            SecurityType::Open
            | SecurityType::Wpa2Psk
            | SecurityType::Wpa2PskSha256
            | SecurityType::Wpa2Ent
            | SecurityType::Wpa2EntSha256 => {}
            SecurityType::Sae
            | SecurityType::SaeExtKey
            | SecurityType::FtSae
            | SecurityType::FtSaeExtKey => {
                return Err(unsupported(
                    "WPA3-SAE requires a SoftMAC driver \
                     (NL80211_CMD_AUTHENTICATE)",
                ));
            }
            SecurityType::FtPsk => {
                return Err(unsupported(
                    "802.11r FT-PSK requires a SoftMAC driver",
                ));
            }
            SecurityType::Owe => {
                return Err(unsupported(
                    "OWE is not supported on FullMAC drivers yet",
                ));
            }
            SecurityType::Unsupported => {
                return Err(unsupported("unsupported security mode"));
            }
        }
        if self.caps.mlme != MlmeMode::FullMac {
            return Err(WifiError::new(
                ErrorKind::Config,
                "send_out_connect_request called in SoftMAC mode",
            ));
        }

        let pmkid = self.link.pmksa_in_use.as_ref().map(|entry| entry.pmkid);
        let ie = if security == SecurityType::Open {
            Vec::new()
        } else {
            self.rsne_with_pmkid(pmkid)
        };
        self.link.assoc_wpa_ie = extract_rsn_from_ies(&ie).unwrap_or_default();

        let builder = Nl80211Connect::new(self.core.nl.if_index)
            .ssid(&self.link.network.ssid)
            .mac(self.link.bss_info.bssid)
            .frequency(self.link.bss_info.freq_mhz)
            .auth_type(Nl80211AuthType::OpenSystem)
            .privacy(security != SecurityType::Open)
            .socket_owner(true);

        let builder = if security == SecurityType::Open {
            builder
        } else {
            let akm = match security {
                SecurityType::Wpa2Psk => Ieee80211AkmSuite::Psk,
                SecurityType::Wpa2PskSha256 => Ieee80211AkmSuite::PskSha256,
                SecurityType::Wpa2Ent => Ieee80211AkmSuite::Ieee8021x,
                SecurityType::Wpa2EntSha256 => {
                    Ieee80211AkmSuite::Ieee8021xSha256
                }
                _ => unreachable!(),
            };
            let mfp = match security {
                SecurityType::Wpa2EntSha256 => Some(Nl80211UseMfp::Required),
                SecurityType::Wpa2Ent
                | SecurityType::Wpa2Psk
                | SecurityType::Wpa2PskSha256 => self
                    .link
                    .bss_info
                    .ap_mfp_capable()
                    .then_some(Nl80211UseMfp::Required),
                _ => None,
            };
            let mut builder = builder
                .wpa_versions(Nl80211WpaVersions::WPA2)
                .ciphers_pairwise(vec![Ieee80211CipherSuite::Ccmp128])
                .cipher_group(Ieee80211CipherSuite::Ccmp128)
                .akm_suites(vec![akm])
                .ie(ie)
                // Keep the data port closed until the userspace 4-way
                // handshake authorizes the station.
                .replace(Nl80211Attr::Other(DefaultNla::new(
                    crate::nl80211::NL80211_ATTR_CONTROL_PORT,
                    Vec::new(),
                )));
            if let Some(mfp) = mfp {
                builder = builder.use_mfp(mfp);
            }
            if self.caps.control_port == ControlPortMode::Nl80211 {
                builder = builder.control_port_over_nl80211(true);
            }
            builder
        };

        // The raw PAE socket must be listening before the firmware can
        // deliver the first EAPOL/4-way frame.
        if security != SecurityType::Open {
            self.ensure_control_port()?;
        }

        let attrs = builder.build();
        log::info!(
            "CONNECT: ssid={}, bssid={:02x?}, freq={} MHz, security={:?}",
            self.link.network.ssid,
            self.link.bss_info.bssid,
            self.link.bss_info.freq_mhz,
            security
        );
        self.core.nl.connect(attrs).await
    }
}
