// SPDX-License-Identifier: Apache-2.0

use super::*;

impl WifiIface {
    /// enable OCV on the 4-way state with our OCI derived
    /// from the BSS frequency, but only when the AP's RSNE actually
    /// advertises OCVC support. Otherwise Message 3 will never carry an
    /// OCI KDE and `verify_oci()` would unconditionally fail the
    /// handshake, so proceed without OCV instead (matches
    /// wpa_supplicant's `wpa_sm_ocv_enabled()`, which requires both the
    /// local config and the AP's OCVC bit). Returns false (and logs)
    /// only when OCV is otherwise usable but the frequency cannot be
    /// mapped to an OCI.
    pub(crate) fn enable_ocv(&self, fw: &mut FourWayState) -> bool {
        if !self.link.network.ocv {
            return true;
        }
        if !self.link.bss_info.ap_ocv_capable() {
            log::warn!(
                "OCV requested but AP does not advertise OCVC support; \
                 proceeding without OCV"
            );
            return true;
        }
        match crate::crypto::ocv::oci_from_freq(self.link.bss_info.freq_mhz) {
            Some(oci) => {
                fw.set_ocv(true, oci, self.link.bss_info.freq_mhz);
                true
            }
            None => {
                log::warn!(
                    "OCV: cannot map BSS freq {} MHz to an OCI",
                    self.link.bss_info.freq_mhz
                );
                false
            }
        }
    }

    /// whether Extended Key ID should be requested for
    /// this 4-way handshake - both the network config and the AP's
    /// advertised RSN capability (bit 13) must agree, otherwise Message
    /// 3 will never carry a Key ID KDE and the handshake would
    /// unconditionally fail. Proceed without it (with a warning)
    /// instead, matching the same opportunistic gating as OCV.
    pub(crate) fn ext_key_id_enabled(&self) -> bool {
        if !self.link.network.ext_key_id {
            return false;
        }
        if !self.link.bss_info.ap_ext_key_id_capable() {
            log::warn!(
                "Extended Key ID requested but AP does not advertise support \
                 for it; proceeding without it"
            );
            return false;
        }
        true
    }

    /// Send `NL80211_CMD_ASSOCIATE` for the selected BSS.
    ///
    /// `ie` carries the RSN element built for the network's security mode
    /// (plus e.g. the OWE DH Parameter Element); empty for open networks.
    /// `mfp` requests management frame protection (IEEE 802.11w): required
    /// for SAE and OWE, optional for WPA2-PSK (MFPC), absent for open.
    pub(crate) async fn associate(
        &mut self,
        mut ie: Vec<u8>,
        mfp: Option<Nl80211UseMfp>,
    ) -> Result<(), WifiError> {
        // advertise the OCVC RSN capability when OCV is
        // enabled for this network.
        if self.link.network.ocv {
            elements::rsne_set_ocvc(&mut ie, true);
        }
        if self.link.network.ext_key_id {
            elements::rsne_set_ext_key_id(&mut ie, true);
        }
        let mut builder = Nl80211Associate::new(self.core.if_index)
            .ssid(&self.link.network.ssid)
            .mac(self.link.bss_info.bssid)
            .frequency(self.link.bss_info.freq_mhz);
        if !ie.is_empty() {
            builder = builder.ie(ie);
        }
        if let Some(mfp) = mfp {
            builder = builder.use_mfp(mfp);
        }
        // Encrypted networks carry EAPOL over nl80211 and tie the
        // connection's lifetime to this socket; open networks don't.
        if self.link.bss_info.security != SecurityType::Open {
            builder =
                builder.control_port_over_nl80211(true).socket_owner(true);
        }
        let attrs = builder.build();
        drain_request(self.core.conn_handle.associate(attrs).execute().await)
            .await
    }
}

impl WifiIface {
    /// The RSNE sent in the association request / 4-way Message 2 for the
    /// current security type, optionally carrying a PMKID (PMKSA caching).
    /// Both sites must stay byte-identical - the AP verifies that.
    pub(crate) fn rsne_with_pmkid(&self, pmkid: Option<[u8; 16]>) -> Vec<u8> {
        match self.link.bss_info.security {
            SecurityType::Sae => elements::sae_ie_with_pmkid_cipher(
                pmkid,
                self.link.bss_info.group_mgmt_cipher,
            ),
            SecurityType::SaeExtKey => {
                elements::sae_ext_key_ie_with_pmkid_cipher(
                    pmkid,
                    self.link.bss_info.group_mgmt_cipher,
                )
            }
            SecurityType::FtSae => elements::ft_sae_ie_cipher(
                pmkid,
                self.link.bss_info.group_mgmt_cipher,
            ),
            SecurityType::FtSaeExtKey => elements::ft_sae_ext_key_ie_cipher(
                pmkid,
                self.link.bss_info.group_mgmt_cipher,
            ),
            SecurityType::Wpa2Psk => elements::wpa2_psk_ie_with_pmkid_cipher(
                pmkid,
                self.link.bss_info.group_mgmt_cipher,
            ),
            SecurityType::Wpa2PskSha256 => {
                elements::wpa2_psk_sha256_ie_with_pmkid_cipher(
                    pmkid,
                    self.link.bss_info.group_mgmt_cipher,
                )
            }
            SecurityType::Wpa2Ent => elements::wpa2_ent_ie_cipher(
                self.link.bss_info.group_mgmt_cipher,
            ),
            SecurityType::Wpa2EntSha256 => elements::wpa2_ent_sha256_ie_cipher(
                self.link.bss_info.group_mgmt_cipher,
            ),
            SecurityType::FtPsk => elements::ft_psk_ie_cipher(
                pmkid,
                self.link.bss_info.group_mgmt_cipher,
            ),
            SecurityType::Owe => {
                elements::owe_ie_cipher(self.link.bss_info.group_mgmt_cipher)
            }
            SecurityType::Open | SecurityType::Unsupported => Vec::new(),
        }
    }

    /// associate with the cached PMKID in the RSNE so the AP can
    /// skip the full authentication. MFP stays required for SAE and is
    /// requested on MFP-capable WPA2-PSK APs, matching the full-auth
    /// association.
    pub(crate) async fn associate_with_pmksa(&mut self) {
        let Some(entry) = self.link.pmksa_in_use.clone() else {
            return;
        };
        log::info!(
            "open-system AUTHENTICATE ok - sending ASSOCIATE with cached PMKID"
        );
        let ie = self.rsne_with_pmkid(Some(entry.pmkid));
        let mfp = match self.link.bss_info.security {
            SecurityType::Sae
            | SecurityType::SaeExtKey
            | SecurityType::FtSaeExtKey => Some(Nl80211UseMfp::Required),
            _ => self
                .link
                .bss_info
                .ap_mfp_capable()
                .then_some(Nl80211UseMfp::Required),
        };
        if let Err(e) = self.associate(ie, mfp).await {
            log::warn!("ASSOCIATE with cached PMKID failed: {e}");
            self.pmksa_fallback().await;
        }
    }

    /// fallback: the AP rejected the cached PMKID (association
    /// rejected) or the handshake over the cached PMK failed (stale
    /// entry). Drop the entry from both caches and retry immediately
    /// with full authentication.
    pub(crate) async fn pmksa_fallback(&mut self) {
        if let Some(entry) = self.link.pmksa_in_use.take() {
            self.pmksa_cache.invalidate(&entry.ssid, entry.bssid);
            self.driver_del_pmksa(&entry).await;
        }
        if let Err(e) = self.send_out_auth_request().await {
            log::warn!("PMKSA fallback authentication failed: {e}");
            self.state = WifiState::Failed;
        } else {
            self.state = WifiState::Authenticating;
        }
    }

    /// the 4-way handshake proved the PMK - remember the PMKSA for
    /// the next reconnect/roam and hand it to the driver's PMKSA cache.
    /// A reused entry simply gets a fresh lifetime.
    pub(crate) async fn cache_pmksa(&mut self) {
        let entry = match self.link.pmksa_in_use.take() {
            Some(entry) => entry_with_fresh_lifetime(entry),
            None => {
                let (pmk, pmkid, mic_alg) = match self.link.bss_info.security {
                    // SAE: the PMKID is derived by the SAE exchange
                    // itself (L(val, 0, 128)); the AP caches that one.
                    SecurityType::Sae => {
                        let Some((pmk, pmkid)) = self
                            .auth
                            .method
                            .as_ref()
                            .and_then(|a| a.pmk().zip(a.pmkid()))
                        else {
                            return;
                        };
                        (pmk, pmkid, MicAlg::AesCmac)
                    }
                    // SAE-EXT-KEY: same SAE PMK/PMKID derivation; the
                    // 4-way MIC is HMAC-SHA256 (AKM-defined).
                    SecurityType::SaeExtKey => {
                        let Some((pmk, pmkid)) = self
                            .auth
                            .method
                            .as_ref()
                            .and_then(|a| a.pmk().zip(a.pmkid()))
                        else {
                            return;
                        };
                        (pmk, pmkid, MicAlg::HmacSha256)
                    }
                    // WPA2-PSK: PMKID = Truncate-128(HMAC-SHA1(PMK,
                    // "PMK Name" || AA || SPA)), 802.11-2020 §9.4.2.25.3.
                    SecurityType::Wpa2Psk => {
                        let Some(pmk) = self.auth.psk_pmk else {
                            return;
                        };
                        (
                            pmk,
                            kdf::pmkid_sha1(
                                &pmk,
                                &self.link.bss_info.bssid,
                                &self.core.mac,
                            ),
                            MicAlg::HmacSha1,
                        )
                    }
                    // PSK-SHA256: PMKID = Truncate-128(HMAC-SHA256(PMK,
                    // "PMK Name" || AA || SPA)).
                    SecurityType::Wpa2PskSha256 => {
                        let Some(pmk) = self.auth.psk_pmk else {
                            return;
                        };
                        (
                            pmk,
                            kdf::pmkid_sha256(
                                &pmk,
                                &self.link.bss_info.bssid,
                                &self.core.mac,
                            ),
                            MicAlg::AesCmac,
                        )
                    }
                    _ => return,
                };
                PmksaEntry {
                    ssid: self.link.network.ssid.clone(),
                    bssid: self.link.bss_info.bssid,
                    pmkid,
                    pmk,
                    mic_alg,
                    expires: std::time::Instant::now()
                        + std::time::Duration::from_secs(PMK_LIFETIME_SECS),
                }
            }
        };
        self.driver_set_pmksa(&entry).await;
        log::info!(
            "PMKSA cached: ssid={}, bssid={:02x?}",
            entry.ssid,
            entry.bssid
        );
        self.pmksa_cache.insert(entry);
    }

    /// Hand a PMKSA entry to the driver/firmware cache
    /// (`NL80211_CMD_SET_PMKSA`). Best effort: mac80211-based drivers
    /// (including mac80211_hwsim) return `-EOPNOTSUPP`, and the
    /// userspace cache works without them.
    pub(crate) async fn driver_set_pmksa(&mut self, entry: &PmksaEntry) {
        let attrs = Nl80211Pmksa::new(self.core.if_index)
            .pmkid(entry.pmkid.to_vec())
            .mac(entry.bssid)
            .pmk(entry.pmk.to_vec())
            .pmk_lifetime(PMK_LIFETIME_SECS as u32)
            .pmk_reauth_threshold(PMK_REAUTH_THRESHOLD_PERCENT)
            .build();
        match drain_request(
            self.core.conn_handle.set_pmksa(attrs).execute().await,
        )
        .await
        {
            Ok(()) => log::info!("PMKSA offloaded to driver"),
            Err(e) => log::debug!("driver PMKSA cache not available: {e}"),
        }
    }

    /// Drop a PMKSA entry from the driver/firmware cache
    /// (`NL80211_CMD_DEL_PMKSA`), best effort.
    pub(crate) async fn driver_del_pmksa(&mut self, entry: &PmksaEntry) {
        let attrs = Nl80211Pmksa::new(self.core.if_index)
            .pmkid(entry.pmkid.to_vec())
            .mac(entry.bssid)
            .build();
        if let Err(e) = drain_request(
            self.core.conn_handle.del_pmksa(attrs).execute().await,
        )
        .await
        {
            log::debug!("driver del_pmksa not available: {e}");
        }
    }
}
