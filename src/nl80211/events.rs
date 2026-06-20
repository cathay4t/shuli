// SPDX-License-Identifier: Apache-2.0

// Event parsing: receives multicast nl80211 events and converts to WifiEvent.

use genetlink::message::RawGenlMessage;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use wl_nl80211::{Nl80211Attr, Nl80211Command};

#[derive(Debug)]
pub enum WifiEvent {
    ExternalAuth {
        bssid: [u8; 6],
        ssid: String,
    },
    ConnectResult {
        status: u16,
    },
    Disconnect {
        reason: u16,
    },
    Frame {
        frame: Vec<u8>,
        freq: Option<u32>,
    },
    ControlPortFrame {
        frame: Vec<u8>,
    },
    PortAuthorized,
    ScanStart,
    NewScanResults,
    Authenticated {
        status: u16,
        /// Full 802.11 auth frame (present for SAE exchange frames)
        auth_frame: Option<Vec<u8>>,
    },
    Associated {
        status: u16,
    },
    Unknown {
        cmd: Nl80211Command,
    },
}

pub fn parse_event(msg: NetlinkMessage<RawGenlMessage>) -> Option<WifiEvent> {
    let (_header, payload) = msg.into_parts();
    match payload {
        NetlinkPayload::InnerMessage(raw_genlmsg) => {
            match raw_genlmsg.parse_into_genlmsg::<wl_nl80211::Nl80211Message>()
            {
                Ok(genl_msg) => {
                    let nl_msg = genl_msg.payload;
                    match nl_msg.cmd {
                        Nl80211Command::ExternalAuth => {
                            parse_external_auth(&nl_msg)
                        }
                        Nl80211Command::Connect => {
                            parse_connect_result(&nl_msg)
                        }
                        Nl80211Command::Disconnect => parse_disconnect(&nl_msg),
                        Nl80211Command::Frame => parse_frame(&nl_msg),
                        Nl80211Command::PortAuthorized => {
                            Some(WifiEvent::PortAuthorized)
                        }
                        Nl80211Command::TriggerScan => {
                            Some(WifiEvent::ScanStart)
                        }
                        Nl80211Command::NewScanResults => {
                            Some(WifiEvent::NewScanResults)
                        }
                        Nl80211Command::Authenticate => {
                            parse_authenticate(&nl_msg)
                        }
                        Nl80211Command::Associate => parse_associate(&nl_msg),
                        Nl80211Command::ControlPortFrame => {
                            parse_ctrl_port_frame(&nl_msg)
                        }
                        other => Some(WifiEvent::Unknown { cmd: other }),
                    }
                }
                Err(e) => {
                    log::warn!("Failed to parse nl80211 event: {e}");
                    None
                }
            }
        }
        NetlinkPayload::Error(err) => {
            log::warn!("Netlink error event: {err:?}");
            None
        }
        _ => None,
    }
}

fn parse_external_auth(msg: &wl_nl80211::Nl80211Message) -> Option<WifiEvent> {
    let mut bssid = None;
    let mut ssid = None;
    for attr in &msg.attributes {
        match attr {
            Nl80211Attr::Bssid(addr) => bssid = Some(*addr),
            Nl80211Attr::Ssid(s) => ssid = Some(s.clone()),
            _ => {}
        }
    }
    Some(WifiEvent::ExternalAuth {
        bssid: bssid.unwrap_or([0u8; 6]),
        ssid: ssid.unwrap_or_default(),
    })
}

fn parse_connect_result(msg: &wl_nl80211::Nl80211Message) -> Option<WifiEvent> {
    let mut status = 0u16;
    for attr in &msg.attributes {
        if let Nl80211Attr::StatusCode(code) = attr {
            status = *code;
        }
    }
    Some(WifiEvent::ConnectResult { status })
}

fn parse_disconnect(msg: &wl_nl80211::Nl80211Message) -> Option<WifiEvent> {
    let mut reason = 0u16;
    for attr in &msg.attributes {
        if let Nl80211Attr::ReasonCode(code) = attr {
            reason = *code;
        }
    }
    Some(WifiEvent::Disconnect { reason })
}

fn parse_authenticate(msg: &wl_nl80211::Nl80211Message) -> Option<WifiEvent> {
    let mut status = 0u16;
    let mut auth_frame = None;
    for attr in &msg.attributes {
        match attr {
            Nl80211Attr::StatusCode(code) => status = *code,
            Nl80211Attr::Frame(frame) => auth_frame = Some(frame.clone()),
            _ => {}
        }
    }

    // Extract status_code from the auth frame body if StatusCode attr absent.
    if status == 0
        && let Some(ref frame) = auth_frame
        && frame.len() >= 24 + 6
    {
        let body = &frame[24..];
        status = u16::from_le_bytes([body[4], body[5]]);
    }

    Some(WifiEvent::Authenticated { status, auth_frame })
}

fn parse_associate(msg: &wl_nl80211::Nl80211Message) -> Option<WifiEvent> {
    let mut status = 0u16;
    for attr in &msg.attributes {
        if let Nl80211Attr::StatusCode(code) = attr {
            status = *code;
        }
    }
    Some(WifiEvent::Associated { status })
}

fn parse_frame(msg: &wl_nl80211::Nl80211Message) -> Option<WifiEvent> {
    let mut frame = None;
    let mut freq = None;
    for attr in &msg.attributes {
        match attr {
            Nl80211Attr::Frame(f) => frame = Some(f.clone()),
            Nl80211Attr::WiphyFreq(f) => freq = Some(*f),
            _ => {}
        }
    }
    frame.map(|f| WifiEvent::Frame { frame: f, freq })
}

fn parse_ctrl_port_frame(
    msg: &wl_nl80211::Nl80211Message,
) -> Option<WifiEvent> {
    for attr in &msg.attributes {
        if let Nl80211Attr::Frame(frame) = attr {
            return Some(WifiEvent::ControlPortFrame {
                frame: frame.clone(),
            });
        }
    }
    None
}
