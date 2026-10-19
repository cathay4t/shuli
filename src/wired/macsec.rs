// SPDX-License-Identifier: Apache-2.0

//! Linux MACsec netdevice setup and SA installation.
//!
//! The data plane is provided by the kernel `macsec` driver: this module
//! creates the MACsec netdev with rtnetlink and manages TX/RX SAs through
//! the `nl-macsec` crate (the `macsec` generic-netlink family).

use std::{ffi::CString, time::Duration};

use nl_macsec::{
    MacsecConfig as NlMacsecConfig, MacsecHandle, MacsecRxScConfig,
    MacsecSaConfig,
};
use rtnetlink::{
    LinkMacSec, LinkMessageBuilder, LinkUnspec,
    packet_route::link::{
        InfoData, InfoKind, InfoMacSec, MacSecCipherId, MacSecValidate,
    },
};
use shuli_core::{ErrorKind, WifiError};

use crate::mka::KeyId;

fn macsec_err(msg: impl Into<String>) -> WifiError {
    WifiError::new(ErrorKind::Io, msg)
}

fn keyid_bytes(ki: &KeyId) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&ki.mi);
    out.extend_from_slice(&ki.kn.to_be_bytes());
    out
}

fn sci_native(sci: &[u8; 8]) -> u64 {
    u64::from_ne_bytes(*sci)
}

fn sci_be(sci: &[u8; 8]) -> u64 {
    u64::from_be_bytes(*sci)
}

/// A kernel MACsec interface with a handle for SA management.
pub(crate) struct MacsecDevice {
    name: String,
    if_index: u32,
    rtnl: rtnetlink::Handle,
    macsec: MacsecHandle,
    desired: NlMacsecConfig,
}

impl MacsecDevice {
    /// Create (or reuse) a MACsec netdev on `base_iface` with `sci`.
    pub(crate) async fn create(
        base_iface: &str,
        name: &str,
        sci: [u8; 8],
        replay_window: u32,
        encrypt: bool,
    ) -> Result<Self, WifiError> {
        let base_index = if_nametoindex(base_iface)?;
        let (rtnl, handle, _) = rtnetlink::new_connection()
            .map_err(|e| macsec_err(format!("rtnetlink connection: {e}")))?;
        tokio::spawn(rtnl);

        let mut link = LinkMacSec::new(name, base_index)
            .sci(sci_native(&sci))
            .port(1)
            .icv_len(16)
            .cipher_suite(MacSecCipherId::GcmAes128)
            .encrypt(encrypt)
            .protect(true)
            .inc_sci(true)
            .es(false)
            .scb(false)
            .validation(MacSecValidate::Strict)
            .up();
        link = if replay_window > 0 {
            link.replay_protect(true).window(replay_window)
        } else {
            link.replay_protect(false)
        };
        if let Err(e) = handle.link().add(link.build()).execute().await {
            // Reusing an existing macsec netdev (from a previous run) is
            // fine; the SAs are installed below.
            if libc_if_nametoindex(name).is_none() {
                return Err(macsec_err(format!(
                    "create macsec dev {name}: {e}"
                )));
            }
            log::debug!("reusing existing macsec dev {name}: {e}");
        }

        let (genl_conn, macsec_handle, _) = nl_macsec::new_connection()
            .map_err(|e| {
                macsec_err(format!("macsec netlink connection: {e}"))
            })?;
        tokio::spawn(genl_conn);
        let if_index = wait_ifindex(name).await?;

        let mut desired = NlMacsecConfig::new(if_index);
        // Clear stale SAs when reusing a device left by a previous run.
        desired.tx_sa = Some(Vec::new());
        desired.rx_sc = Some(Vec::new());
        let mut dev = Self {
            name: name.to_string(),
            if_index,
            rtnl: handle,
            macsec: macsec_handle,
            desired,
        };
        dev.apply().await?;
        Ok(dev)
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Remove every installed TX/RX SA, keeping the netdev.
    pub(crate) async fn clear_sas(&mut self) -> Result<(), WifiError> {
        self.desired.tx_sa = Some(Vec::new());
        self.desired.rx_sc = Some(Vec::new());
        self.apply().await
    }

    /// Remove the MACsec netdev (and thereby all its SAs).
    pub(crate) async fn remove(mut self) -> Result<(), WifiError> {
        let _ = self.clear_sas().await;
        self.rtnl
            .link()
            .del(self.if_index)
            .execute()
            .await
            .map_err(|e| {
                macsec_err(format!("delete macsec dev {}: {e}", self.name))
            })
    }

    async fn apply(&mut self) -> Result<(), WifiError> {
        self.macsec
            .apply(&self.desired)
            .await
            .map_err(|e| macsec_err(format!("macsec apply: {e}")))
    }

    /// Select `an` as the transmit encoding SA.
    async fn set_encoding_sa(&mut self, an: u8) -> Result<(), WifiError> {
        let msg = LinkMessageBuilder::<LinkUnspec>::new_with_info_kind(
            InfoKind::MacSec,
        )
        .name(self.name.clone())
        .set_info_data(InfoData::MacSec(vec![InfoMacSec::EncodingSa(an)]))
        .build();
        self.rtnl
            .link()
            .change(msg)
            .execute()
            .await
            .map_err(|e| macsec_err(format!("set MACsec encoding SA: {e}")))
    }

    /// Install the transmit SA and optionally activate it.
    pub(crate) async fn install_tx_sa(
        &mut self,
        an: u8,
        ki: &KeyId,
        sak: &[u8],
        active: bool,
    ) -> Result<(), WifiError> {
        let key_id = keyid_bytes(ki);
        let mut replace = false;
        let same_key = {
            let tx_sa = self.desired.tx_sa.get_or_insert_with(Vec::new);
            match tx_sa.iter().position(|sa| sa.an == an) {
                Some(pos) if tx_sa[pos].key_id == key_id => true,
                Some(pos) => {
                    tx_sa.remove(pos);
                    replace = true;
                    false
                }
                None => false,
            }
        };
        if same_key {
            // Same KI: only the active state can change; never reset
            // the packet number of an existing SA.
            if active {
                let tx_sa = self.desired.tx_sa.get_or_insert_with(Vec::new);
                if let Some(sa) = tx_sa.iter_mut().find(|sa| sa.an == an) {
                    sa.active = Some(true);
                }
            }
            self.apply().await?;
            if active {
                self.set_encoding_sa(an).await?;
            }
            return Ok(());
        }
        if replace {
            // The kernel updates an existing AN in place, so delete the
            // old SA first before installing a new key for this AN.
            self.apply().await?;
        }
        let tx_sa = self.desired.tx_sa.get_or_insert_with(Vec::new);
        let mut sa = MacsecSaConfig::new(an);
        sa.pn = Some(1);
        sa.active = Some(active);
        sa.key_id = key_id;
        sa.key = Some(sak.to_vec());
        tx_sa.push(sa);
        self.apply().await?;
        if active {
            self.set_encoding_sa(an).await?;
        }
        Ok(())
    }

    /// Activate the transmit SA with association number `an`.
    pub(crate) async fn set_tx_sa_active(
        &mut self,
        an: u8,
    ) -> Result<(), WifiError> {
        if let Some(tx_sa) = self.desired.tx_sa.as_mut()
            && let Some(sa) = tx_sa.iter_mut().find(|sa| sa.an == an)
        {
            sa.active = Some(true);
        }
        self.apply().await?;
        self.set_encoding_sa(an).await
    }

    /// Install a receive SC/SA for `peer_sci`.
    pub(crate) async fn install_rx_sa(
        &mut self,
        peer_sci: &[u8; 8],
        an: u8,
        ki: &KeyId,
        sak: &[u8],
    ) -> Result<(), WifiError> {
        let sci = sci_be(peer_sci);
        let key_id = keyid_bytes(ki);
        let index = {
            let rx_scs = self.desired.rx_sc.get_or_insert_with(Vec::new);
            match rx_scs.iter().position(|sc| sc.sci == sci) {
                Some(index) => index,
                None => {
                    rx_scs.push(MacsecRxScConfig::new(sci));
                    rx_scs.len() - 1
                }
            }
        };
        let mut replace = false;
        let same_key = {
            let rx_scs = self.desired.rx_sc.get_or_insert_with(Vec::new);
            rx_scs[index].active = Some(true);
            let sa_list = rx_scs[index].sa_list.get_or_insert_with(Vec::new);
            match sa_list.iter().position(|sa| sa.an == an) {
                Some(pos) if sa_list[pos].key_id == key_id => true,
                Some(pos) => {
                    sa_list.remove(pos);
                    replace = true;
                    false
                }
                None => false,
            }
        };
        if same_key {
            return self.apply().await;
        }
        if replace {
            // The kernel updates an existing AN in place, so delete the
            // old SA first before installing a new key for this AN.
            self.apply().await?;
        }
        let rx_scs = self.desired.rx_sc.get_or_insert_with(Vec::new);
        let sa_list = rx_scs[index].sa_list.get_or_insert_with(Vec::new);
        let mut sa = MacsecSaConfig::new(an);
        sa.pn = Some(1);
        sa.active = Some(true);
        sa.key_id = key_id;
        sa.key = Some(sak.to_vec());
        sa_list.push(sa);
        self.apply().await
    }
}

fn libc_if_nametoindex(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

fn if_nametoindex(name: &str) -> Result<u32, WifiError> {
    libc_if_nametoindex(name)
        .ok_or_else(|| macsec_err(format!("interface {name} not found")))
}

async fn wait_ifindex(name: &str) -> Result<u32, WifiError> {
    for _ in 0..40 {
        if let Some(index) = libc_if_nametoindex(name) {
            return Ok(index);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(macsec_err(format!("macsec device {name} did not appear")))
}
