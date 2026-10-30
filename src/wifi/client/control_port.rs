// SPDX-License-Identifier: Apache-2.0

//! EAPOL transport for FullMAC wiphys.
//!
//! In-tree FullMAC drivers do not advertise
//! `NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211`, so EAPOL frames cannot
//! travel over `NL80211_CMD_CONTROL_PORT_FRAME`.  They are delivered to the
//! netdevice instead and must be read/written with a raw `AF_PACKET` socket
//! (the same approach iwd uses).

use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Arc,
};

use futures::channel::mpsc::UnboundedSender;
use tokio::{io::unix::AsyncFd, task::JoinHandle};

use super::WifiEvent;
use crate::{ETH_ALEN, ErrorKind, WifiError};

const ETH_P_PAE: u16 = 0x888E;

/// One EAPOL frame received on the raw PAE socket.
#[derive(Debug, Clone)]
pub(crate) struct RawEapolFrame {
    /// Source MAC address (the AP BSSID for infrastructure frames).
    pub(crate) src: [u8; ETH_ALEN],
    /// EAPOL frame starting at the EAPOL header (no Ethernet header).
    pub(crate) payload: Vec<u8>,
}

/// Where EAPOL frames come from/go to for this interface.
pub(crate) enum ControlPort {
    /// `NL80211_CMD_CONTROL_PORT_FRAME` (advertised by mac80211).
    Nl80211,
    /// Raw `AF_PACKET` socket, opened lazily when a connection needs it.
    Raw { port: Option<RawControlPort> },
}

impl ControlPort {
    pub(crate) fn is_raw(&self) -> bool {
        matches!(self, Self::Raw { .. })
    }
}

/// Raw EAPOL transport bound to one wireless netdevice.
pub(crate) struct RawControlPort {
    async_fd: Arc<AsyncFd<OwnedFd>>,
    if_index: u32,
}

impl RawControlPort {
    /// Open the PAE socket for `if_index`.
    ///
    /// The socket is bound to the interface, so it only sees frames of this
    /// netdevice.  EAPOL on WiFi is unicast to the AP BSSID, not to the wired
    /// PAE group address.
    pub(crate) fn open(if_index: u32) -> Result<Self, WifiError> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                i32::from(ETH_P_PAE.to_be()),
            )
        };
        if fd < 0 {
            return Err(io_err(
                "create raw EAPOL socket",
                io::Error::last_os_error(),
            ));
        }

        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ETH_P_PAE.to_be();
        sll.sll_ifindex = if_index as i32;
        let rc = unsafe {
            libc::bind(
                fd,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(io_err("bind raw EAPOL socket", e));
        }

        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let async_fd = unsafe { AsyncFd::register(owned) }
            .map_err(|e| io_err("register raw EAPOL socket", e.into()))?;

        Ok(Self {
            async_fd: Arc::new(async_fd),
            if_index,
        })
    }

    /// Send one EAPOL frame to `dst`.
    pub(crate) fn send(
        &self,
        dst: [u8; ETH_ALEN],
        payload: &[u8],
    ) -> Result<(), WifiError> {
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ETH_P_PAE.to_be();
        sll.sll_ifindex = self.if_index as i32;
        sll.sll_halen = ETH_ALEN as u8;
        sll.sll_addr[..ETH_ALEN].copy_from_slice(&dst);

        let rc = unsafe {
            libc::sendto(
                self.async_fd.get_ref().as_raw_fd(),
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io_err(
                "send raw EAPOL frame",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    /// Move the socket into a reader task that forwards frames to the
    /// interface event queue.
    pub(crate) fn spawn_reader(
        &self,
        event_tx: UnboundedSender<WifiEvent>,
    ) -> JoinHandle<()> {
        let async_fd = Arc::clone(&self.async_fd);
        tokio::spawn(async move {
            loop {
                let mut guard = match async_fd.readable().await {
                    Ok(guard) => guard,
                    Err(e) => {
                        log::debug!("raw EAPOL socket closed: {e}");
                        return;
                    }
                };
                loop {
                    match guard
                        .try_io(|inner| recv_eapol(inner.get_ref().as_raw_fd()))
                    {
                        Ok(Ok(Some(frame))) => {
                            if event_tx
                                .unbounded_send(WifiEvent::Eapol(frame))
                                .is_err()
                            {
                                return;
                            }
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(e)) => {
                            log::warn!("raw EAPOL receive failed: {e}");
                            break;
                        }
                        // Would block: clear readiness and wait again.
                        Err(_) => break,
                    }
                }
            }
        })
    }
}

fn recv_eapol(fd: RawFd) -> io::Result<Option<RawEapolFrame>> {
    let mut buf = [0u8; 4096];
    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    let mut addr_len = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut sll as *mut libc::sockaddr_ll as *mut libc::sockaddr,
            &mut addr_len,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    if n == 0 || sll.sll_protocol != ETH_P_PAE.to_be() {
        return Ok(None);
    }
    if sll.sll_halen != ETH_ALEN as u8 {
        return Ok(None);
    }
    let mut src = [0u8; ETH_ALEN];
    src.copy_from_slice(&sll.sll_addr[..ETH_ALEN]);
    Ok(Some(RawEapolFrame {
        src,
        payload: buf[..n].to_vec(),
    }))
}

fn io_err(what: &str, e: io::Error) -> WifiError {
    WifiError::new(ErrorKind::Io, format!("{what}: {e}"))
}
