// SPDX-License-Identifier: Apache-2.0

use futures::{TryStream, TryStreamExt};
use netlink_packet_core::{
    EthernetProtocol, NetlinkMessage, NetlinkPayload, Parseable,
};
use netlink_packet_generic::GenlMessage;
use wl_nl80211::{
    Ieee80211Element, Ieee80211Elements, Nl80211Attr, Nl80211BssInfo,
    Nl80211Command, Nl80211ConnectionHandle, Nl80211ControlPortFrame,
    Nl80211Error, Nl80211Event, Nl80211Handle, Nl80211Message,
    Nl80211RekeyData,
};

use crate::{ETH_ALEN, ErrorKind, WifiError};

/// A nl80211 event decoded for shuli. The upstream event parser does not
/// model `NL80211_CMD_SET_REKEY_OFFLOAD` notifications (the driver reports
/// the replay counter it used for a GTK rekey while the host was
/// suspended), so shuli decodes that one event itself and forwards every
/// other event unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientEvent {
    /// A regular event from [`Nl80211Event::parse`].
    Nl80211(Nl80211Event),
    /// `NL80211_CMD_SET_REKEY_OFFLOAD` notification: the driver completed a
    /// GTK rekey and reports the new replay counter.
    RekeyOffload {
        bssid: [u8; ETH_ALEN],
        replay_ctr: [u8; 8],
    },
}

/// Parse a raw multicast nl80211 message into a [`ClientEvent`].
///
/// The rekey-offload notification is checked first because
/// [`Nl80211Event::parse`] would otherwise report it as `Unknown` and the
/// replay counter would be lost.
pub(crate) fn parse_client_event(
    msg: NetlinkMessage<genetlink::message::RawGenlMessage>,
) -> Option<ClientEvent> {
    let (header, payload) = msg.into_parts();
    if let Some((bssid, replay_ctr)) = parse_rekey_offload_event(&payload) {
        return Some(ClientEvent::RekeyOffload { bssid, replay_ctr });
    }
    Nl80211Event::parse(NetlinkMessage::new(header, payload))
        .map(ClientEvent::Nl80211)
}

fn parse_rekey_offload_event(
    payload: &NetlinkPayload<genetlink::message::RawGenlMessage>,
) -> Option<([u8; ETH_ALEN], [u8; 8])> {
    let NetlinkPayload::InnerMessage(raw_genlmsg) = payload else {
        return None;
    };
    let Ok(genl_msg) = raw_genlmsg.parse_into_genlmsg::<Nl80211Message>()
    else {
        return None;
    };
    let nl_msg = genl_msg.payload;
    if nl_msg.cmd != Nl80211Command::SetRekeyOffload {
        return None;
    }

    let bssid = nl_msg.attributes.iter().find_map(|attr| match attr {
        Nl80211Attr::Mac(mac) => Some(*mac),
        _ => None,
    })?;
    let replay_ctr = nl_msg.attributes.iter().find_map(|attr| match attr {
        Nl80211Attr::RekeyData(nlas) => nlas.iter().find_map(|nla| match nla {
            Nl80211RekeyData::ReplayCtr(ctr) => ctr.as_slice().try_into().ok(),
            _ => None,
        }),
        _ => None,
    })?;
    Some((bssid, replay_ctr))
}

#[cfg(test)]
mod tests {
    use genetlink::message::RawGenlMessage;
    use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
    use netlink_packet_generic::GenlMessage;
    use wl_nl80211::{
        Nl80211Attr, Nl80211Command, Nl80211Event, Nl80211Message,
        Nl80211RekeyData,
    };

    use super::{ClientEvent, parse_client_event};

    fn wrap(msg: Nl80211Message) -> NetlinkMessage<RawGenlMessage> {
        let raw = RawGenlMessage::from_genlmsg(GenlMessage::from_payload(msg));
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(raw),
        )
    }

    #[test]
    fn parse_rekey_offload_notification() {
        let bssid = [0x02; 6];
        let replay_ctr = [1, 2, 3, 4, 5, 6, 7, 8];
        let msg = Nl80211Message {
            cmd: Nl80211Command::SetRekeyOffload,
            attributes: vec![
                Nl80211Attr::IfIndex(7),
                Nl80211Attr::Mac(bssid),
                Nl80211Attr::RekeyData(vec![Nl80211RekeyData::ReplayCtr(
                    replay_ctr.to_vec(),
                )]),
            ],
        };

        match parse_client_event(wrap(msg)) {
            Some(ClientEvent::RekeyOffload {
                bssid: got_bssid,
                replay_ctr: got_replay_ctr,
            }) => {
                assert_eq!(got_bssid, bssid);
                assert_eq!(got_replay_ctr, replay_ctr);
            }
            other => panic!("expected RekeyOffload, got {other:?}"),
        }
    }

    #[test]
    fn rekey_offload_without_payload_falls_back_to_unknown() {
        let msg = Nl80211Message {
            cmd: Nl80211Command::SetRekeyOffload,
            attributes: vec![Nl80211Attr::IfIndex(7)],
        };
        assert!(matches!(
            parse_client_event(wrap(msg)),
            Some(ClientEvent::Nl80211(Nl80211Event::Unknown {
                cmd: Nl80211Command::SetRekeyOffload,
            }))
        ));
    }
}

/// Drain a nl80211 request stream until the kernel ACK/response is
/// consumed, converting errors into [`WifiError`].
pub(crate) async fn drain_request<S>(stream: S) -> Result<(), WifiError>
where
    S: TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
        + Unpin,
{
    let mut stream = stream;
    while let Some(_msg) = stream.try_next().await? {}
    Ok(())
}

/// One nl80211 connection plus the interface/wiphy metadata shuli
/// resolved from it.
///
/// The connection owns both the generic request handle and the
/// connection handle (they share the same socket), so every nl80211
/// operation on an interface goes through this type instead of being
/// scattered across free helper functions.
#[derive(Debug)]
pub(crate) struct ShuliNl80211Connection {
    pub(crate) handle: Nl80211Handle,
    pub(crate) conn_handle: Nl80211ConnectionHandle,
    pub(crate) if_index: u32,
    pub(crate) mac: [u8; ETH_ALEN],
    pub(crate) wiphy_index: u32,
    pub(crate) wiphy_max_scan_count: u8,
}

impl ShuliNl80211Connection {
    /// Open a dedicated nl80211 connection for `iface_name` and resolve
    /// the interface metadata. Used by the standalone [`WifiClient::scan`]
    /// path, which must not share the client's multicast event socket.
    pub(crate) async fn new(iface_name: &str) -> Result<Self, WifiError> {
        let (conn, handle, _) = wl_nl80211::new_connection()
            .map_err(|e| WifiError::new(ErrorKind::Nl80211, e.to_string()))?;
        tokio::spawn(conn);
        let conn_handle = handle.connection();
        let (if_index, mac, wiphy_index) =
            get_if_index_and_mac(&handle, iface_name).await?;
        let wiphy_max_scan_count =
            wiphy_max_scan_count(&handle, wiphy_index).await?;
        Ok(Self {
            handle,
            conn_handle,
            if_index,
            mac,
            wiphy_index,
            wiphy_max_scan_count,
        })
    }

    /// Wrap an existing shared nl80211 handle (used by every interface
    /// of a multi-interface [`crate::WifiClient`]).
    ///
    /// The per-scan SSID cap is best-effort here: a wiphy that fails to
    /// answer keeps the previous wildcard-only fallback instead of
    /// failing the whole client.
    pub(crate) async fn from_handle(
        handle: Nl80211Handle,
        iface_name: &str,
    ) -> Result<Self, WifiError> {
        let conn_handle = handle.connection();
        let (if_index, mac, wiphy_index) =
            get_if_index_and_mac(&handle, iface_name).await?;
        let wiphy_max_scan_count =
            match wiphy_max_scan_count(&handle, wiphy_index).await {
                Ok(n) => n,
                Err(e) => {
                    log::debug!(
                        "could not query max scan SSIDs: {e}; using \
                         wildcard-only scans"
                    );
                    0
                }
            };
        Ok(Self {
            handle,
            conn_handle,
            if_index,
            mac,
            wiphy_index,
            wiphy_max_scan_count,
        })
    }

    /// Trigger an active scan probing for `ssids` (all of them in one
    /// scan); `None` or an empty list performs a passive scan instead.
    /// `freqs` restricts the scan to the given channels - the fast path
    /// used by roaming, which only needs to re-check the frequencies where
    /// the ESS has already been seen instead of sweeping the whole band.
    pub(crate) async fn trigger_scan(
        &mut self,
        ssids: Option<&[String]>,
        freqs: Option<&[u32]>,
    ) -> Result<(), WifiError> {
        let mut builder = wl_nl80211::Nl80211Scan::new(self.if_index);
        match ssids {
            Some(ssids) if !ssids.is_empty() => {
                builder = builder.ssids(ssids.to_vec());
            }
            _ => builder = builder.passive(true),
        }
        if let Some(freqs) = freqs {
            builder = builder.scan_frequencies(freqs.to_vec());
        }
        let attrs = builder.build();
        drain_request(self.handle.scan().trigger(attrs).execute().await).await
    }

    /// Dump the current scan results for this interface.
    pub(crate) async fn get_scan_results(
        &mut self,
    ) -> Result<Vec<Vec<Nl80211BssInfo>>, WifiError> {
        let mut dump = self.handle.scan().dump(self.if_index).execute().await;
        let mut bss_list = Vec::new();
        while let Some(msg) = dump.try_next().await? {
            for attr in &msg.payload.attributes {
                if let Nl80211Attr::Bss(bss_infos) = attr {
                    bss_list.push(bss_infos.clone());
                }
            }
        }
        Ok(bss_list)
    }

    /// Tear down the current connection with `NL80211_CMD_DISCONNECT`.
    pub(crate) async fn disconnect(&mut self) -> Result<(), WifiError> {
        let attrs = wl_nl80211::Nl80211Disconnect::new(self.if_index).build();
        drain_request(self.conn_handle.disconnect(attrs).execute().await).await
    }

    pub(crate) async fn authenticate(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), WifiError> {
        drain_request(self.conn_handle.authenticate(attrs).execute().await)
            .await
    }

    pub(crate) async fn associate(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), WifiError> {
        drain_request(self.conn_handle.associate(attrs).execute().await).await
    }

    pub(crate) async fn register_frame(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), WifiError> {
        drain_request(self.conn_handle.register_frame(attrs).execute().await)
            .await
    }

    pub(crate) async fn send_frame(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), WifiError> {
        drain_request(self.conn_handle.frame(attrs).execute().await).await
    }

    pub(crate) async fn send_ctrl_port_frame(
        &mut self,
        bssid: [u8; ETH_ALEN],
        frame: &[u8],
    ) -> Result<(), WifiError> {
        let attrs = Nl80211ControlPortFrame::new(self.if_index)
            .mac(bssid)
            .frame(frame.to_vec())
            .control_port_ethertype(EthernetProtocol::Pae)
            .build();
        drain_request(
            self.conn_handle.control_port_frame(attrs).execute().await,
        )
        .await
    }

    pub(crate) async fn new_key(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), WifiError> {
        drain_request(self.conn_handle.new_key(attrs).execute().await).await
    }

    pub(crate) async fn set_wowlan(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), WifiError> {
        drain_request(self.conn_handle.set_wowlan(attrs).execute().await).await
    }

    pub(crate) async fn set_cqm(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), WifiError> {
        drain_request(self.conn_handle.set_cqm(attrs).execute().await).await
    }

    pub(crate) async fn set_pmksa(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), WifiError> {
        drain_request(self.conn_handle.set_pmksa(attrs).execute().await).await
    }

    pub(crate) async fn del_pmksa(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), WifiError> {
        drain_request(self.conn_handle.del_pmksa(attrs).execute().await).await
    }

    pub(crate) async fn set_rekey_offload(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), WifiError> {
        drain_request(self.conn_handle.set_rekey_offload(attrs).execute().await)
            .await
    }

    /// Start a hardware scheduled scan (PNO). Returns the raw nl80211
    /// error so callers can distinguish `-EOPNOTSUPP` from transient
    /// failures.
    pub(crate) async fn start_sched_scan(
        &mut self,
        attrs: Vec<Nl80211Attr>,
    ) -> Result<(), Nl80211Error> {
        let mut stream =
            self.handle.scan().schedule_start(attrs).execute().await;
        while let Some(_msg) = stream.try_next().await? {}
        Ok(())
    }

    /// Stop every hardware scheduled scan on this interface.
    pub(crate) async fn stop_sched_scan(&mut self) -> Result<(), WifiError> {
        drain_request(
            self.handle
                .scan()
                .schedule_stop_all(self.if_index)
                .execute()
                .await,
        )
        .await
    }
}

/// Extract the SSID from a raw information-elements buffer.
pub(crate) fn extract_ssid_from_ies(ies: &[u8]) -> Option<String> {
    let elements = Ieee80211Elements::parse(ies).ok()?;
    for element in elements.0 {
        if let Ieee80211Element::Ssid(ssid) = element {
            return Some(ssid);
        }
    }
    None
}

/// Extract signal strength in dBm from a BSS info entry list. The kernel
/// reports scan BSS signal in mBm (100 * dBm); convert it to dBm so the
/// value matches its name everywhere it is stored and logged.
pub(crate) fn extract_signal_dbm(bss: &[Nl80211BssInfo]) -> Option<i32> {
    for info in bss {
        if let Nl80211BssInfo::SignalMbm(signal) = info {
            return Some(*signal / 100);
        }
    }
    None
}

/// Extract frequency from a BSS info entry list.
pub(crate) fn extract_freq(bss: &[Nl80211BssInfo]) -> Option<u32> {
    for info in bss {
        if let Nl80211BssInfo::Frequency(freq) = info {
            return Some(*freq);
        }
    }
    None
}

/// Extract raw IEs from a BSS info entry list (probe response or beacon).
pub(crate) fn extract_ies(bss: &[Nl80211BssInfo]) -> Option<&[u8]> {
    for info in bss {
        match info {
            Nl80211BssInfo::RawInformationElements(ies) => return Some(ies),
            Nl80211BssInfo::RawBeaconInformationElements(ies) => {
                return Some(ies);
            }
            _ => {}
        }
    }
    None
}

/// Extract BSSID from a BSS info entry list.
pub(crate) fn extract_bssid(bss: &[Nl80211BssInfo]) -> Option<[u8; 6]> {
    for info in bss {
        if let Nl80211BssInfo::Bssid(bssid) = info {
            return Some(*bssid);
        }
    }
    None
}

async fn get_if_index_and_mac(
    handle: &Nl80211Handle,
    ifname: &str,
) -> Result<(u32, [u8; ETH_ALEN], u32), WifiError> {
    let mut dump = handle.interface().get(vec![]).execute().await;
    while let Some(msg) = dump.try_next().await? {
        if msg.payload.attributes.iter().any(
            |attr| matches!(attr, Nl80211Attr::IfName(name) if name == ifname),
        ) {
            let mut index = 0;
            let mut mac = [0u8; ETH_ALEN];
            let mut wiphy = None;
            for attr in &msg.payload.attributes {
                if let Nl80211Attr::IfIndex(idx) = attr {
                    index = *idx;
                } else if let Nl80211Attr::Mac(mac_addr) = attr {
                    mac.copy_from_slice(mac_addr);
                } else if let Nl80211Attr::Wiphy(w) = attr {
                    wiphy = Some(*w);
                }
            }
            if index != 0 && mac != [0u8; ETH_ALEN] {
                return match wiphy {
                    Some(w) => Ok((index, mac, w)),
                    None => Err(WifiError::new(
                        ErrorKind::Nl80211,
                        format!(
                            "interface {ifname}: wiphy index missing from \
                             netlink message: {msg:?}",
                        ),
                    )),
                };
            } else {
                return Err(WifiError::new(
                    ErrorKind::InterfaceNotFound,
                    format!(
                        "interface {ifname}: index or mac not found in \
                         netlink message: {msg:?}",
                    ),
                ));
            }
        }
    }
    Err(WifiError::new(
        ErrorKind::InterfaceNotFound,
        format!("interface {ifname} not found"),
    ))
}

/// The maximum number of SSIDs the wiphy accepts in one scan request
/// (`NL80211_ATTR_MAX_NUM_SCAN_SSIDS`). Returns 0 when the kernel did
/// not advertise the attribute.
async fn wiphy_max_scan_count(
    handle: &Nl80211Handle,
    wiphy_idx: u32,
) -> Result<u8, WifiError> {
    let mut dump = handle
        .wireless_physic()
        .get()
        .wiphy_index(wiphy_idx)
        .execute()
        .await;
    while let Some(msg) = dump.try_next().await? {
        for attr in &msg.payload.attributes {
            if let Nl80211Attr::MaxNumScanSsids(n) = attr {
                return Ok(*n);
            }
        }
    }
    Ok(0)
}
