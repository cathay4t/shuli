// SPDX-License-Identifier: Apache-2.0

//! Wired 802.1X supplicant: EAPOL over an Ethernet
//! NIC with a raw AF_PACKET socket.
//!
//! Unlike WiFi there is no association, no 4-way handshake and no key
//! installation: EAP runs directly on the wire (ethertype 0x888E) and
//! EAP-Success authorizes the port.  The EAP peer state machine and
//! EAP-TLS method are shared with the WiFi 802.1X path.

use std::{
    fs, io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use tokio::io::unix::AsyncFd;

use crate::{
    ErrorKind, WifiError,
    config::EapConfig,
    eap::{EapAction, EapPacket, EapPeer},
    eap_tls::EapTlsMethod,
    ieee80211::eapol::{build_eapol_eap_frame, parse_eapol_eap_frame},
};

/// PAE group address used for EAPOL on wired links (802.1X-2010).
const PAE_GROUP_ADDR: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03];
const ETH_P_PAE: u16 = 0x888E;
/// EAPOL-Start (version 2, type 1, length 0).
const EAPOL_START: [u8; 4] = [0x02, 0x01, 0x00, 0x00];
const AUTH_EVENT_TIMEOUT_SECS: u64 = 15;

/// Connection state of a wired 802.1X port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WiredState {
    /// Socket ready; EAPOL-Start not sent yet.
    Init,
    /// EAP exchange in progress.
    Authenticating,
    /// EAP-Success received; the port is authorized.
    Connected,
    /// EAP-Failure or timeout; retry with a fresh client.
    Failed,
}

/// A wired 802.1X supplicant for one Ethernet interface.
#[non_exhaustive]
pub struct WiredClient {
    fd: OwnedFd,
    async_fd: AsyncFd<OwnedFd>,
    if_index: u32,
    mac: [u8; 6],
    peer: EapPeer,
    state: WiredState,
}

impl WiredClient {
    /// Open the raw EAPOL socket on `iface_name` and prepare the EAP
    /// peer with the given credentials.
    pub fn init(iface_name: &str, eap: &EapConfig) -> Result<Self, WifiError> {
        let (fd, if_index, mac) = open_eapol_socket(iface_name)?;
        let async_fd =
            AsyncFd::new(fd.try_clone().map_err(io_err)?).map_err(|e| {
                WifiError::new(ErrorKind::Io, format!("EAPOL socket: {e}"))
            })?;

        let method = EapTlsMethod::from_config(eap)?;
        let mut peer = EapPeer::new(eap.identity.clone());
        peer.set_method(Box::new(method));

        Ok(Self {
            fd,
            async_fd,
            if_index,
            mac,
            peer,
            state: WiredState::Init,
        })
    }

    pub fn state(&self) -> WiredState {
        self.state
    }

    /// Advance the wired authentication flow by one step.
    pub async fn run(&mut self) -> Result<WiredState, WifiError> {
        match self.state {
            WiredState::Init => {
                // Kick the authenticator into sending the Identity
                // request.
                send_eapol_frame(
                    self.fd.as_raw_fd(),
                    self.if_index,
                    &self.mac,
                    &EAPOL_START,
                )?;
                self.state = WiredState::Authenticating;
                Ok(self.state)
            }
            WiredState::Authenticating => {
                let frame = loop {
                    let timed = tokio::time::timeout(
                        std::time::Duration::from_secs(AUTH_EVENT_TIMEOUT_SECS),
                        self.async_fd.readable(),
                    )
                    .await;
                    let mut guard = match timed {
                        Ok(Ok(guard)) => guard,
                        Ok(Err(e)) => {
                            return Err(WifiError::new(
                                ErrorKind::Io,
                                format!("EAPOL socket: {e:?}"),
                            ));
                        }
                        Err(_) => {
                            log::warn!("wired 802.1X timed out; will retry");
                            self.state = WiredState::Failed;
                            return Ok(self.state);
                        }
                    };
                    match guard.try_io(|inner| {
                        recv_eapol_frame(inner.get_ref().as_raw_fd())
                    }) {
                        Ok(Ok(frame)) => break frame,
                        Ok(Err(e)) => return Err(io_err(e)),
                        Err(_) => continue, // would block; wait again
                    }
                };
                self.handle_eapol(&frame)?;
                Ok(self.state)
            }
            WiredState::Connected => Ok(WiredState::Connected),
            WiredState::Failed => Ok(WiredState::Failed),
        }
    }

    /// Feed one received EAPOL frame into the EAP peer and send the
    /// response (if any).
    fn handle_eapol(&mut self, frame: &[u8]) -> Result<(), WifiError> {
        let Some(eap_pdu) = parse_eapol_eap_frame(frame) else {
            log::debug!("ignoring non-EAP EAPOL frame ({} bytes)", frame.len());
            return Ok(());
        };
        let Some(packet) = EapPacket::parse(eap_pdu) else {
            log::warn!("unparseable EAP packet");
            return Ok(());
        };
        match self.peer.handle_packet(&packet)? {
            EapAction::Respond(response) => {
                send_eapol_frame(
                    self.fd.as_raw_fd(),
                    self.if_index,
                    &self.mac,
                    &build_eapol_eap_frame(&response),
                )?;
            }
            EapAction::Success => {
                if self.peer.msk().is_none() {
                    return Err(WifiError::new(
                        ErrorKind::HandshakeFailed,
                        "EAP-Success without an MSK",
                    ));
                }
                log::info!("wired 802.1X EAP-Success - port authorized");
                self.state = WiredState::Connected;
            }
            EapAction::Failure => {
                log::warn!("wired 802.1X EAP-Failure");
                self.state = WiredState::Failed;
            }
            EapAction::Wait => {}
        }
        Ok(())
    }
}

/// Open a raw EAPOL (ethertype 0x888E) packet socket bound to
/// `iface_name`; returns (socket, ifindex, MAC).  Shared with the
/// test authenticator.
pub(crate) fn open_eapol_socket(
    iface_name: &str,
) -> Result<(OwnedFd, u32, [u8; 6]), WifiError> {
    let if_index = read_sysfs_u32(iface_name, "ifindex")?;
    let mac = read_sysfs_mac(iface_name)?;
    let fd = create_eapol_socket(if_index)?;
    Ok((fd, if_index, mac))
}

/// Send an EAPOL payload as an Ethernet frame addressed to the PAE
/// group address.
pub(crate) fn send_eapol_frame(
    fd: RawFd,
    if_index: u32,
    src_mac: &[u8; 6],
    payload: &[u8],
) -> Result<(), WifiError> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&PAE_GROUP_ADDR);
    frame.extend_from_slice(src_mac);
    frame.extend_from_slice(&ETH_P_PAE.to_be_bytes());
    frame.extend_from_slice(payload);

    let mut dll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    dll.sll_family = libc::AF_PACKET as u16;
    dll.sll_protocol = ETH_P_PAE.to_be();
    dll.sll_ifindex = if_index as i32;
    dll.sll_halen = 6;
    dll.sll_addr[..6].copy_from_slice(&PAE_GROUP_ADDR);

    let rc = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &dll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io_err(io::Error::last_os_error()));
    }
    log::trace!("sent EAPOL frame: {} bytes", payload.len());
    Ok(())
}

fn create_eapol_socket(if_index: u32) -> Result<OwnedFd, WifiError> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            (ETH_P_PAE.to_be()) as i32,
        )
    };
    if fd < 0 {
        return Err(io_err(io::Error::last_os_error()));
    }

    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ETH_P_PAE.to_be();
    sll.sll_ifindex = if_index as i32;
    let rc = unsafe {
        libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(io_err(e));
    }

    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(owned)
}

pub(crate) fn recv_eapol_frame(fd: RawFd) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 2048];
    let n = unsafe {
        libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    if n < 14 || u16::from_be_bytes([buf[12], buf[13]]) != ETH_P_PAE {
        return Ok(Vec::new());
    }
    Ok(buf[14..n].to_vec())
}

fn read_sysfs_u32(iface: &str, file: &str) -> Result<u32, WifiError> {
    let path = format!("/sys/class/net/{iface}/{file}");
    let value = fs::read_to_string(&path).map_err(|e| {
        WifiError::new(
            ErrorKind::InterfaceNotFound,
            format!("read {path}: {e}"),
        )
    })?;
    value.trim().parse().map_err(|e| {
        WifiError::new(
            ErrorKind::InterfaceNotFound,
            format!("parse {path}: {e}"),
        )
    })
}

fn read_sysfs_mac(iface: &str) -> Result<[u8; 6], WifiError> {
    let path = format!("/sys/class/net/{iface}/address");
    let value = fs::read_to_string(&path).map_err(|e| {
        WifiError::new(
            ErrorKind::InterfaceNotFound,
            format!("read {path}: {e}"),
        )
    })?;
    let parts: Vec<&str> = value.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(WifiError::new(
            ErrorKind::InterfaceNotFound,
            format!("invalid MAC in {path}: {value:?}"),
        ));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|e| {
            WifiError::new(
                ErrorKind::InterfaceNotFound,
                format!("invalid MAC octet {part:?} in {path}: {e}"),
            )
        })?;
    }
    Ok(mac)
}

fn io_err(e: io::Error) -> WifiError {
    WifiError::new(ErrorKind::Io, e.to_string())
}
