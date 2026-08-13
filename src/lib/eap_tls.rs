// SPDX-License-Identifier: Apache-2.0

//! EAP-TLS method (RFC 5216 framing, RFC 9190 TLS 1.3 key export).
//!
//! TLS runs directly over EAP: each EAP-TLS message carries a flags
//! octet, an optional 4-octet TLS message length (L bit), and raw TLS
//! records (fragmented per RFC 5216).  TLS 1.3 is required so the MSK
//! can be derived with the RFC 9190 exporter
//! (`EXPORTER_EAP_TLS_Key_Material`, context = EAP type 13).

use std::{io::Cursor, sync::Arc};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};

use crate::{
    ErrorKind, WifiError,
    config::EapConfig,
    eap::{EapMethod, MSK_LEN, TYPE_TLS},
};

/// EAP-TLS flags (RFC 5216 §2.1).
pub(crate) const EAP_TLS_FLAG_L: u8 = 0x80;
pub(crate) const EAP_TLS_FLAG_M: u8 = 0x40;
pub(crate) const EAP_TLS_FLAG_START: u8 = 0x20;

/// Build an EAP-TLS message body from TLS data.  Empty data produces
/// the one-octet ACK (flags = 0, no TLS data; RFC 5216 §2.1,
/// `eap_peer_tls_build_ack` in wpa_supplicant).
pub(crate) fn build_tls_message(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![0];
    }
    let mut msg = Vec::with_capacity(1 + 4 + data.len());
    msg.push(EAP_TLS_FLAG_L);
    msg.extend_from_slice(&(data.len() as u32).to_be_bytes());
    msg.extend_from_slice(data);
    msg
}

/// Parse an EAP-TLS message body into (flags, TLS data).
pub(crate) fn parse_tls_message(body: &[u8]) -> Result<(u8, &[u8]), WifiError> {
    if body.is_empty() {
        return Ok((0, &[]));
    }
    let flags = body[0];
    let data = if flags & EAP_TLS_FLAG_L != 0 {
        if body.len() < 5 {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                "EAP-TLS message with L bit but no length field",
            ));
        }
        &body[5..]
    } else {
        &body[1..]
    };
    Ok((flags, data))
}

/// Build a TLS 1.3-only client config with mutual TLS (client
/// certificate required, as EAP-TLS deployments expect).
pub(crate) fn client_config(
    ca_der: &[CertificateDer<'static>],
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ClientConfig>, WifiError> {
    let mut roots = RootCertStore::empty();
    for cert in ca_der {
        roots.add(cert.clone()).map_err(tls_err)?;
    }
    let config = ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
    ])
    .with_root_certificates(roots)
    .with_client_auth_cert(cert_chain, key)
    .map_err(tls_err)?;
    Ok(Arc::new(config))
}

/// Parse a PEM certificate (first certificate in the file).
pub(crate) fn cert_from_pem(
    pem: &str,
) -> Result<CertificateDer<'static>, WifiError> {
    CertificateDer::from_pem_slice(pem.as_bytes()).map_err(tls_err)
}

/// Parse a PEM private key.
pub(crate) fn key_from_pem(
    pem: &str,
) -> Result<PrivateKeyDer<'static>, WifiError> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(tls_err)
}

fn tls_err(e: impl std::fmt::Display) -> WifiError {
    WifiError::new(ErrorKind::HandshakeFailed, format!("EAP-TLS: {e}"))
}

/// The EAP-TLS method: drives a rustls client connection over EAP
/// fragments and exports the RFC 9190 MSK.
pub(crate) struct EapTlsMethod {
    conn: Option<ClientConnection>,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    /// TLS bytes received but not yet consumed by rustls.
    rx_buf: Vec<u8>,
    /// TLS bytes of the current (possibly fragmented) EAP-TLS message.
    rx_fragments: Vec<u8>,
    /// Total TLS length announced by the L bit of the first fragment.
    rx_expected_len: Option<u32>,
    msk: Option<[u8; MSK_LEN]>,
}

impl EapTlsMethod {
    pub(crate) fn new(
        config: Arc<ClientConfig>,
        server_name: &str,
    ) -> Result<Self, WifiError> {
        let server_name =
            ServerName::try_from(server_name.to_string()).map_err(tls_err)?;
        Ok(Self {
            conn: None,
            config,
            server_name,
            rx_buf: Vec::new(),
            rx_fragments: Vec::new(),
            rx_expected_len: None,
            msk: None,
        })
    }

    /// Build the method from an [`EapConfig`] (certificate PEM files on
    /// disk).  Identity is handled by the [`EapPeer`](crate::eap::EapPeer).
    pub(crate) fn from_config(config: &EapConfig) -> Result<Self, WifiError> {
        let read_pem = |path: &std::path::Path, what: &str| {
            std::fs::read_to_string(path).map_err(|e| {
                WifiError::new(
                    ErrorKind::InvalidConfig,
                    format!("read {what} {}: {e}", path.display()),
                )
            })
        };
        let ca_path = config.ca_cert.as_ref().ok_or_else(|| {
            WifiError::new(ErrorKind::InvalidConfig, "EAP: ca_cert required")
        })?;
        let client_cert = config.client_cert.as_ref().ok_or_else(|| {
            WifiError::new(
                ErrorKind::InvalidConfig,
                "EAP-TLS: client_cert required",
            )
        })?;
        let client_key = config.client_key.as_ref().ok_or_else(|| {
            WifiError::new(
                ErrorKind::InvalidConfig,
                "EAP-TLS: client_key required",
            )
        })?;
        let server_name = config.server_name.as_deref().ok_or_else(|| {
            WifiError::new(
                ErrorKind::InvalidConfig,
                "EAP-TLS: server_name required",
            )
        })?;

        let ca = cert_from_pem(&read_pem(ca_path, "CA certificate")?)?;
        let cert =
            cert_from_pem(&read_pem(client_cert, "client certificate")?)?;
        let key = key_from_pem(&read_pem(client_key, "client key")?)?;
        let config = client_config(&[ca], vec![cert], key)?;
        Self::new(config, server_name)
    }
}

impl EapMethod for EapTlsMethod {
    fn method_type(&self) -> u8 {
        TYPE_TLS
    }

    fn handle_request(
        &mut self,
        _identifier: u8,
        body: &[u8],
    ) -> Result<Vec<u8>, WifiError> {
        let (flags, data) = parse_tls_message(body)?;

        // The Start flag creates the TLS connection and answers with
        // the ClientHello.
        if flags & EAP_TLS_FLAG_START != 0 && self.conn.is_none() {
            self.conn = Some(
                ClientConnection::new(
                    self.config.clone(),
                    self.server_name.clone(),
                )
                .map_err(tls_err)?,
            );
        }
        let Some(conn) = self.conn.as_mut() else {
            return Err(WifiError::new(
                ErrorKind::HandshakeFailed,
                "EAP-TLS data received before Start",
            ));
        };

        // RFC 5216 receive-side fragmentation: a message with the M
        // bit (or one whose L bit announced a longer total) is
        // acknowledged with an empty EAP-TLS response and only fed to
        // TLS once all fragments arrived.
        if flags & EAP_TLS_FLAG_L != 0 {
            if body.len() < 5 {
                return Err(WifiError::new(
                    ErrorKind::HandshakeFailed,
                    "EAP-TLS message with L bit but no length field",
                ));
            }
            let len = u32::from_be_bytes(body[1..5].try_into().unwrap());
            self.rx_expected_len = Some(len);
        }
        if !data.is_empty() {
            self.rx_fragments.extend_from_slice(data);
        }
        let complete = self
            .rx_expected_len
            .is_none_or(|len| self.rx_fragments.len() as u32 >= len)
            && flags & EAP_TLS_FLAG_M == 0;
        if !complete {
            // ACK this fragment; the rest of the message is coming.
            return Ok(build_tls_message(&[]));
        }
        self.rx_expected_len = None;
        if !self.rx_fragments.is_empty() {
            self.rx_buf.append(&mut self.rx_fragments);
            while !self.rx_buf.is_empty() {
                let used = conn
                    .read_tls(&mut Cursor::new(&self.rx_buf))
                    .map_err(tls_err)?;
                if used == 0 {
                    break;
                }
                self.rx_buf.drain(..used);
            }
            conn.process_new_packets().map_err(tls_err)?;
        }

        // Collect the TLS records the connection wants to send.
        let mut out = Vec::new();
        conn.write_tls(&mut out).map_err(tls_err)?;

        // RFC 9190 §5.1: MSK = first 64 octets of
        // TLS-Exporter("EXPORTER_EAP_TLS_Key_Material", context =
        // EAP-Type, 128).
        if !conn.is_handshaking() && self.msk.is_none() {
            let mut km = [0u8; MSK_LEN * 2];
            let km = conn
                .export_keying_material(
                    &mut km,
                    b"EXPORTER_EAP_TLS_Key_Material",
                    Some(&[TYPE_TLS]),
                )
                .map_err(tls_err)?;
            let mut msk = [0u8; MSK_LEN];
            msk.copy_from_slice(&km[..MSK_LEN]);
            self.msk = Some(msk);
        }

        Ok(build_tls_message(&out))
    }

    fn msk(&self) -> Option<[u8; MSK_LEN]> {
        self.msk
    }
}
