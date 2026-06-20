// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use futures::{StreamExt, TryStreamExt};
use log::{debug, error, info, warn};
use shuli::{
    ShuliResult, config,
    crypto::{handshake4::FourWayState, sae::SaeState},
    ieee80211::{auth, eapol, elements},
    nl80211::{
        auth_assoc, connect,
        events::{WifiEvent, parse_event},
        keys, mcast,
    },
    sm::{
        connection::{ConnectionSm, ConnectionState},
        flow,
    },
};
use tokio::signal;
use wl_nl80211::{Nl80211Attr, Nl80211Handle};

#[derive(Parser)]
#[command(name = "shulid", about = "WiFi authentication daemon")]
struct Cli {
    #[arg(short, long, default_value = "/etc/shuli/config.yml")]
    config: PathBuf,
}

struct FlowState {
    sm: ConnectionSm,
    ssid: String,
    bssid: [u8; 6],
    freq: u32,
    sta_mac: [u8; 6],
    sae: SaeState,
    fourway: Option<FourWayState>,
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("trace"),
    )
    .init();

    let cli = Cli::parse();

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> ShuliResult<()> {
    let cfg = config::load_config(&cli.config)?;
    let iface = cfg.interfaces.first().expect("no interfaces");
    let wifi = iface.wifi.as_ref().expect("no wifi config");

    info!("shulid: iface={}, ssid={}", iface.name, wifi.ssid);

    let (mut conn, handle, event_receiver) = wl_nl80211::new_connection()
        .map_err(|e| shuli::ShuliError::Config(e.to_string()))?;

    if let Err(e) = mcast::join_multicast_groups(&mut conn) {
        warn!("multicast join: {e}");
    }
    tokio::spawn(conn);

    let mut conn_handle = handle.connection();
    let if_index =
        get_if_index(&handle, &iface.name).await?.ok_or_else(|| {
            shuli::ShuliError::InterfaceNotFound(iface.name.clone())
        })?;

    let sta_mac =
        flow::get_sta_mac(&handle, if_index).await?.ok_or_else(|| {
            shuli::ShuliError::InterfaceNotFound(format!(
                "{}: mac not found",
                iface.name
            ))
        })?;

    info!(
        "interface {} if_index={}, mac={sta_mac:02x?}",
        iface.name, if_index
    );

    let mut sm = ConnectionSm::new(if_index, iface.name.clone());

    // Step 1: Scan + SAE authenticate
    let scan_result = flow::run_connect_flow(
        &mut sm,
        &handle,
        &mut conn_handle,
        &wifi.ssid,
        &wifi.password,
        sta_mac,
    )
    .await?;

    let mut state = FlowState {
        sm,
        ssid: wifi.ssid.clone(),
        bssid: scan_result.bssid,
        freq: scan_result.freq,
        sta_mac,
        sae: scan_result.sae,
        fourway: None,
    };

    // Step 2: Event-driven handshake loop. Once Connected, keep running so the
    // socket-owned association stays up (an external tool can run DHCP/ping),
    // until SIGINT/SIGTERM or a disconnect.
    let mut event_receiver = event_receiver;
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("shutting down");
                let _ = connect::disconnect(&mut conn_handle, if_index).await;
                break;
            }
            maybe_event = event_receiver.next() => {
                match maybe_event {
                    Some((raw_msg, _addr)) => {
                        log::debug!("nl event raw: {:?}", raw_msg);
                        if let Some(event) = parse_event(raw_msg) {
                            let connected = handle_event(
                                &mut conn_handle, &handle, &mut state, event,
                            )
                            .await;
                            if connected {
                                info!(
                                    "connection established - link up, \
                                     holding (Ctrl-C to disconnect)"
                                );
                            }
                            if state.sm.state == ConnectionState::Failed {
                                break;
                            }
                        }
                    }
                    None => {
                        warn!("event channel closed");
                        break;
                    }
                }
            }
        }
    }

    if state.sm.state == ConnectionState::Connected {
        info!("connection established");
        Ok(())
    } else {
        Err(shuli::ShuliError::ConnectFailed(format!(
            "final state: {:?}",
            state.sm.state
        )))
    }
}

/// Returns true when the connection is fully established.
async fn handle_event(
    _conn_handle: &mut wl_nl80211::Nl80211ConnectionHandle,
    handle: &Nl80211Handle,
    state: &mut FlowState,
    event: WifiEvent,
) -> bool {
    match event {
        WifiEvent::Frame { frame, freq } => {
            handle_sae_frame(handle, state, &frame, freq).await;
        }

        WifiEvent::Authenticated { status, auth_frame } => {
            // SAE: the auth frame carries the AP's commit (transaction 1) or
            // confirm (transaction 2). Drive the SAE state machine from it.
            if let Some(frame) = auth_frame {
                handle_sae_frame(handle, state, &frame, None).await;
            } else if status != 0 {
                warn!("AUTHENTICATE failed: status={status}");
                state.sm.transition(ConnectionState::Failed);
            } else {
                debug!("AUTHENTICATE event without frame (status=0)");
            }
        }

        WifiEvent::Associated { status } => {
            if status == 0 {
                info!("ASSOCIATED - waiting for 4-way handshake");
                state.sm.transition(ConnectionState::FourWayHandshake);
            } else {
                warn!("ASSOCIATE failed: status={status}");
                state.sm.transition(ConnectionState::Failed);
            }
        }

        WifiEvent::ControlPortFrame { frame } => {
            handle_control_port_frame(handle, state, &frame).await;
            if state.sm.state == ConnectionState::Connected {
                return true;
            }
        }

        WifiEvent::ConnectResult { status } => {
            // In the SME (AUTHENTICATE/ASSOCIATE) path cfg80211 also emits a
            // CONNECT event after association. This only means "associated",
            // NOT that the 4-way handshake is done, so do not finalize here.
            if status == 0 {
                debug!("CONNECT event (associated); awaiting 4-way handshake");
                if state.sm.state == ConnectionState::Associating {
                    state.sm.transition(ConnectionState::FourWayHandshake);
                }
            } else {
                warn!("CONNECT failed: status={status}");
                state.sm.transition(ConnectionState::Failed);
            }
        }

        WifiEvent::PortAuthorized => {
            info!("PORT_AUTHORIZED - connection ready");
            state.sm.transition(ConnectionState::Connected);
            return true;
        }

        WifiEvent::Disconnect { reason } => {
            warn!("DISCONNECT: reason={reason}");
            state.sm.transition(ConnectionState::Failed);
        }

        WifiEvent::ScanStart => info!("scan started"),
        WifiEvent::NewScanResults => info!("scan results available"),
        WifiEvent::ExternalAuth { .. } => {
            debug!("EXTERNAL_AUTH event (unsupported in this mode)")
        }
        WifiEvent::Unknown { cmd } => debug!("event: {cmd:?}"),
    }
    false
}

/// Drive SAE from an Authentication frame delivered by the kernel SME
/// (NL80211_CMD_AUTHENTICATE event). The AP's commit (transaction 1) and
/// confirm (transaction 2) are processed; our confirm and the subsequent
/// ASSOCIATE are sent via NL80211_CMD_AUTHENTICATE / NL80211_CMD_ASSOCIATE.
async fn handle_sae_frame(
    handle: &Nl80211Handle,
    state: &mut FlowState,
    frame: &[u8],
    _freq: Option<u32>,
) -> bool {
    let Some((auth_seq, status_code, sae_payload)) =
        auth::parse_sae_auth_frame(frame)
    else {
        debug!("received mgmt frame: {} bytes", frame.len());
        return false;
    };

    debug!("SAE frame: seq={auth_seq}, status={status_code}");

    // Status 126 (SAE_HASH_TO_ELEMENT) in a commit is the H2E indicator, not a
    // failure. The confirm must carry status 0.
    const SAE_STATUS_H2E: u16 = 126;
    let status_ok = match auth_seq {
        1 => status_code == 0 || status_code == SAE_STATUS_H2E,
        _ => status_code == 0,
    };
    if !status_ok {
        warn!("SAE auth failed: seq={auth_seq} status={status_code}");
        state.sm.transition(ConnectionState::Failed);
        return false;
    }

    if auth_seq == 1 {
        // AP's commit body: group(2 LE) || scalar(32) || element(64).
        if sae_payload.len() < 2 + 32 + 64 {
            warn!("SAE commit too short: {} bytes", sae_payload.len());
            state.sm.transition(ConnectionState::Failed);
            return false;
        }
        let peer_scalar = &sae_payload[2..34];
        let peer_elem = &sae_payload[34..98];

        match state.sae.process_commit(peer_scalar, peer_elem) {
            Ok(confirm) => {
                if let Err(e) = auth_assoc::authenticate_sae_confirm(
                    handle,
                    state.sm.if_index,
                    &state.ssid,
                    state.bssid,
                    state.freq,
                    &confirm,
                )
                .await
                {
                    warn!("send SAE confirm failed: {e}");
                    state.sm.transition(ConnectionState::Failed);
                } else {
                    info!("SAE confirm sent");
                    state.sm.transition(ConnectionState::SaeCommitSent);
                }
            }
            Err(e) => {
                warn!("SAE process_commit failed: {e}");
                state.sm.transition(ConnectionState::Failed);
            }
        }
    } else if auth_seq == 2 {
        // AP's confirm body: send_confirm(2 LE) || CN(32). Verify, then
        // associate.
        match state.sae.process_confirm(&sae_payload) {
            Ok(_pmk) => {
                info!("SAE completed successfully - sending ASSOCIATE");
                state.sm.transition(ConnectionState::Associating);
                if let Err(e) = auth_assoc::associate(
                    handle,
                    state.sm.if_index,
                    &state.ssid,
                    state.bssid,
                    state.freq,
                )
                .await
                {
                    warn!("ASSOCIATE failed: {e}");
                    state.sm.transition(ConnectionState::Failed);
                }
            }
            Err(e) => {
                warn!("SAE verify confirm failed: {e}");
                state.sm.transition(ConnectionState::Failed);
            }
        }
    }
    false
}

/// Handle EAPOL control port frames (4-way handshake).
async fn handle_control_port_frame(
    handle: &Nl80211Handle,
    state: &mut FlowState,
    frame: &[u8],
) {
    let Some(parsed) = eapol::parse_eapol_key_frame(frame) else {
        debug!("unparseable control port frame");
        return;
    };

    debug!(
        "EAPOL-Key: info={} replay={}",
        eapol::fmt_key_info(parsed.key_info),
        parsed.replay_counter
    );

    if !parsed.has_mic() && parsed.has_ack() {
        // Message 1: ANonce from AP
        info!("4-way handshake: Message 1 (ANonce)");

        // Create the 4-way state once so the SNonce is stable across M1
        // retransmissions.
        if state.fourway.is_none() {
            let pmk = state.sae.pmk().expect("PMK must be available");
            let pmkid = state.sae.pmkid().expect("PMKID must be available");
            // The RSNE/RSNXE in Message 2 must match the Association Request.
            let mut rsne = elements::sae_rsne();
            rsne.extend_from_slice(&elements::rsnxe_h2e());
            state.fourway = Some(FourWayState::new(
                &pmk,
                &pmkid,
                state.sta_mac,
                state.bssid,
                rsne,
            ));
        }
        let fw = state.fourway.as_mut().unwrap();

        match fw.process_message_1(&parsed.key_nonce) {
            Ok(msg2) => {
                if let Err(e) = send_ctrl_port_frame(
                    handle,
                    state.sm.if_index,
                    state.bssid,
                    &msg2,
                )
                .await
                {
                    warn!("send msg2 failed: {e}");
                    state.sm.transition(ConnectionState::Failed);
                    return;
                }
                info!("4-way: Message 2 sent");
            }
            Err(e) => {
                warn!("process_message_1 failed: {e}");
                state.sm.transition(ConnectionState::Failed);
            }
        }
    } else if parsed.has_mic() && parsed.is_secure() && parsed.is_pairwise() {
        // Message 3: GTK delivery from AP
        info!("4-way handshake: Message 3");

        let fw = match state.fourway.as_mut() {
            Some(f) => f,
            None => {
                warn!("no 4-way state for Message 3");
                state.sm.transition(ConnectionState::Failed);
                return;
            }
        };

        match fw.process_message_3(&parsed) {
            Ok((msg4, gtk)) => {
                if let Err(e) = send_ctrl_port_frame(
                    handle,
                    state.sm.if_index,
                    state.bssid,
                    &msg4,
                )
                .await
                {
                    warn!("send msg4 failed: {e}");
                    state.sm.transition(ConnectionState::Failed);
                    return;
                }
                info!("4-way: Message 4 sent");

                if let Some(tk) = fw.tk() {
                    if let Err(e) = keys::install_ptk(
                        handle,
                        state.sm.if_index,
                        state.bssid,
                        &tk,
                    )
                    .await
                    {
                        warn!("install PTK failed: {e}");
                    } else {
                        info!("PTK installed");
                    }
                }

                if let Some(ref gtk_data) = gtk {
                    let gtk_idx = fw.gtk_index();
                    if let Err(e) = keys::install_gtk(
                        handle,
                        state.sm.if_index,
                        gtk_data,
                        gtk_idx,
                    )
                    .await
                    {
                        warn!("install GTK failed: {e}");
                    } else {
                        info!("GTK[{}] installed", gtk_idx);
                    }
                }

                info!("keys installed - connection established");
                state.sm.transition(ConnectionState::Connected);
            }
            Err(e) => {
                warn!("process_message_3 failed: {e}");
                state.sm.transition(ConnectionState::Failed);
            }
        }
    } else {
        debug!("unhandled EAPOL-Key frame type");
    }
}

/// Send an EAPOL-Key PDU over the control port (control-port-over-nl80211).
/// The frame is the raw 802.1X PDU; the destination MAC (the AP) and the
/// EAPOL EtherType are passed as separate attributes.
async fn send_ctrl_port_frame(
    handle: &Nl80211Handle,
    if_index: u32,
    bssid: [u8; 6],
    frame: &[u8],
) -> ShuliResult<()> {
    const NL80211_ATTR_CONTROL_PORT_ETHERTYPE: u16 = 102;
    const ETH_P_PAE: u16 = 0x888E;

    let mut nl_msg = netlink_packet_core::NetlinkMessage::from(
        netlink_packet_generic::GenlMessage::from_payload(
            wl_nl80211::Nl80211Message {
                cmd: wl_nl80211::Nl80211Command::ControlPortFrame,
                attributes: vec![
                    Nl80211Attr::IfIndex(if_index),
                    Nl80211Attr::Mac(bssid),
                    Nl80211Attr::Frame(frame.to_vec()),
                    Nl80211Attr::Other(netlink_packet_core::DefaultNla::new(
                        NL80211_ATTR_CONTROL_PORT_ETHERTYPE,
                        ETH_P_PAE.to_le_bytes().to_vec(),
                    )),
                ],
            },
        ),
    );
    nl_msg.header.flags =
        netlink_packet_core::NLM_F_REQUEST | netlink_packet_core::NLM_F_ACK;

    let mut h = handle.clone();
    let mut stream = h.request(nl_msg).await?;
    while let Some(_msg) = stream.try_next().await? {}
    Ok(())
}

async fn get_if_index(
    handle: &Nl80211Handle,
    ifname: &str,
) -> ShuliResult<Option<u32>> {
    use futures::TryStreamExt;
    let mut dump = handle.interface().get(vec![]).execute().await;
    while let Some(msg) = dump.try_next().await? {
        for attr in &msg.payload.attributes {
            if let Nl80211Attr::IfIndex(idx) = attr {
                for name_attr in &msg.payload.attributes {
                    if let Nl80211Attr::IfName(name) = name_attr
                        && name == ifname
                    {
                        return Ok(Some(*idx));
                    }
                }
            }
        }
    }
    Ok(None)
}
