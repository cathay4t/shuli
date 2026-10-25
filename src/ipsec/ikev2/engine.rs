// SPDX-License-Identifier: Apache-2.0

//! Per-connection IKEv2 engine.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};

use tokio::{
    sync::{Mutex, mpsc, watch},
    task::JoinHandle,
};

use crate::{
    client::{ChildSaHandle, IpsecEvent, IpsecLease, IpsecState, error_event},
    config::{
        AuthConfig, ChildProposal, IkeProposal, IpNet, IpsecConfig,
        TrafficSelector, TrafficSelectorPair,
    },
    error::{IpsecError, IpsecErrorKind},
    ikev2::{
        auth::{self, cert::LocalAuth, eap::EapSession},
        codec::{
            self, ExchangeType, FLAG_INITIATOR, FLAG_RESPONSE, IkeHeader,
            Payload, TsSelector,
        },
        crypto::{self, DhKeyPair},
        proposal,
        sa::{self, IkeKeys, Role},
        transport::{IkeTransport, NAT_T_PORT, Retransmit},
    },
};

const NONCE_LEN: usize = 32;
const RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RETRANSMITS: u8 = 6;

pub(crate) async fn spawn(
    config: IpsecConfig,
    events: mpsc::UnboundedSender<IpsecEvent>,
    states: Arc<Mutex<HashMap<String, IpsecState>>>,
    shutdown: watch::Receiver<bool>,
) -> Result<JoinHandle<()>, IpsecError> {
    let peer = config
        .peers
        .first()
        .ok_or_else(|| IpsecError::config("connection has no peers"))?
        .clone();
    let remote = peer
        .remote
        .address
        .map(|address| SocketAddr::new(address, peer.remote.port));
    let transport = IkeTransport::bind(
        config.local.address,
        config.local.port,
        remote.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
        config.local.nat_t,
    )
    .await?;

    Ok(tokio::spawn(async move {
        let runner = Runner {
            config,
            events,
            states,
            shutdown,
            transport,
            phase: Phase::Init,
            ike: None,
            peer_index: 0,
            retransmit: None,
            next_message_id: 1,
            pending_sa_init: None,
            eap: None,
            dpd_deadline: None,
            dpd_failures: 0,
            rekey_deadline: None,
            pending_rekey: None,
            started: false,
        };
        runner.run().await;
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Init,
    SaInitSent,
    AuthSent,
    EapAuth,
    Established,
    Closed,
}

struct PendingSaInit {
    private: DhKeyPair,
    nonce: Vec<u8>,
    proposals: Vec<IkeProposal>,
    real_message1: Vec<u8>,
    local_spi: u64,
}

struct PendingRekey {
    private: Option<DhKeyPair>,
    nonce_i: Vec<u8>,
    local_spi: u32,
    suite: ChildProposal,
}

struct IkeRuntime {
    role: Role,
    local_spi: u64,
    remote_spi: u64,
    keys: IkeKeys,
    suite: IkeProposal,
    nonce_i: Vec<u8>,
    nonce_r: Vec<u8>,
    real_message1: Vec<u8>,
    real_message2: Vec<u8>,
    local_child_spi: u32,
    child: Option<ChildRuntime>,
    inner_addresses: Vec<IpNet>,
    dns: Vec<IpAddr>,
}

struct ChildRuntime {
    handle: ChildSaHandle,
}

struct Runner {
    config: IpsecConfig,
    events: mpsc::UnboundedSender<IpsecEvent>,
    states: Arc<Mutex<HashMap<String, IpsecState>>>,
    shutdown: watch::Receiver<bool>,
    transport: IkeTransport,
    phase: Phase,
    ike: Option<IkeRuntime>,
    peer_index: usize,
    retransmit: Option<Retransmit>,
    next_message_id: u32,
    pending_sa_init: Option<PendingSaInit>,
    eap: Option<EapSession>,
    dpd_deadline: Option<tokio::time::Instant>,
    dpd_failures: u8,
    rekey_deadline: Option<tokio::time::Instant>,
    pending_rekey: Option<PendingRekey>,
    started: bool,
}

impl Runner {
    async fn run(mut self) {
        if self.config.peers[0].remote.address.is_some() {
            self.started = true;
            if let Err(error) = self.send_sa_init().await {
                self.report_error(error);
            }
        }
        loop {
            let retransmit_at =
                self.retransmit.as_ref().map(Retransmit::deadline);
            let dpd_at = self.dpd_deadline;
            let rekey_at = self.rekey_deadline;
            tokio::select! {
                changed = self.shutdown.changed() => {
                    if changed.is_err() || *self.shutdown.borrow() {
                        break;
                    }
                }
                received = self.transport.recv() => {
                    match received {
                        Ok((data, source)) => {
                            if let Err(error) = self.handle_datagram(&data, source).await {
                                self.report_error(error);
                            }
                        }
                        Err(error) => {
                            self.report_error(error);
                        }
                    }
                }
                _ = wait_until(retransmit_at) => {
                    if let Err(error) = self.on_retransmit().await {
                        self.report_error(error);
                    }
                }
                _ = wait_until(dpd_at) => {
                    if let Err(error) = self.on_dpd().await {
                        self.report_error(error);
                    }
                }
                _ = wait_until(rekey_at) => {
                    if let Err(error) = self.initiate_rekey().await {
                        self.report_error(error);
                    }
                }
            }
        }
        self.shutdown_connection().await;
    }

    async fn send_sa_init(&mut self) -> Result<(), IpsecError> {
        let peer = self
            .config
            .peers
            .get(self.peer_index)
            .ok_or_else(|| IpsecError::config("peer index out of range"))?
            .clone();
        let dh = self
            .config
            .ike
            .proposals
            .proposals
            .first()
            .map(|proposal| proposal.dh)
            .unwrap_or(crate::config::DhGroup::Ecp256);
        let key_pair = DhKeyPair::generate(dh)?;
        let mut nonce = vec![0u8; NONCE_LEN];
        crypto::random_bytes(&mut nonce)?;
        let local_spi = crypto::random_u64()?;
        let proposals =
            proposal::build_ike(&self.config.ike.proposals.proposals);
        let source_address = self
            .config
            .local
            .address
            .unwrap_or_else(|| self.transport.remote().ip());
        let payloads = vec![
            Payload::Sa(proposals),
            Payload::Ke {
                group: dh.transform_id(),
                data: key_pair.public().to_vec(),
            },
            Payload::Nonce(nonce.clone()),
            Payload::Notify {
                protocol: codec::protocol_id::IKE,
                spi: Vec::new(),
                notify_type: codec::notify_type::NAT_DETECTION_SOURCE_IP,
                data: crate::ikev2::transport::nat_detection_hash(
                    local_spi,
                    0,
                    source_address,
                    self.config.local.port,
                ),
            },
            Payload::Notify {
                protocol: codec::protocol_id::IKE,
                spi: Vec::new(),
                notify_type: codec::notify_type::NAT_DETECTION_DESTINATION_IP,
                data: crate::ikev2::transport::nat_detection_hash(
                    local_spi,
                    0,
                    self.transport.remote().ip(),
                    self.transport.remote().port(),
                ),
            },
        ];
        if peer.remote.address.is_none() {
            // A responder-only connection does not send the first
            // message; this path is only reached for initiators.
            return Ok(());
        }
        let header = IkeHeader::new(
            local_spi,
            0,
            ExchangeType::IkeSaInit,
            FLAG_INITIATOR,
            0,
        );
        let message = codec::Message::new(header, payloads.clone()).encode()?;
        self.transport.send(&message).await?;
        self.pending_sa_init = Some(PendingSaInit {
            private: key_pair,
            nonce: nonce.clone(),
            proposals: self.config.ike.proposals.proposals.clone(),
            real_message1: message.clone(),
            local_spi,
        });
        self.retransmit = Some(Retransmit::new(
            message,
            self.config.dpd.timeout.max(RETRANSMIT_TIMEOUT),
            MAX_RETRANSMITS,
        ));
        self.phase = Phase::SaInitSent;
        Ok(())
    }

    async fn handle_datagram(
        &mut self,
        data: &[u8],
        source: SocketAddr,
    ) -> Result<(), IpsecError> {
        if source.port() == NAT_T_PORT {
            self.transport.set_remote(source);
            self.transport.enable_nat_t();
        } else if self.config.local.nat_t && self.transport.nat_t_enabled() {
            self.transport.set_remote(source);
        }
        let message = codec::Message::decode(data)?;
        if message.header.is_response() {
            match self.phase {
                Phase::SaInitSent => {
                    self.handle_sa_init_response(data, &message).await
                }
                Phase::AuthSent | Phase::EapAuth => {
                    self.handle_auth_response(&message).await
                }
                Phase::Established => {
                    if message.header.exchange == ExchangeType::CreateChildSa {
                        return self
                            .handle_create_child_response(&message)
                            .await;
                    }
                    if message.header.exchange == ExchangeType::Informational {
                        self.retransmit = None;
                        self.dpd_failures = 0;
                        self.dpd_deadline = Some(
                            tokio::time::Instant::now()
                                + self.config.dpd.interval,
                        );
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        } else {
            match message.header.exchange {
                ExchangeType::IkeSaInit => {
                    self.handle_sa_init_request(data, source, &message).await
                }
                ExchangeType::IkeAuth => {
                    self.handle_auth_request(&message, source).await
                }
                ExchangeType::Informational => {
                    self.handle_informational_request(&message, source).await
                }
                ExchangeType::CreateChildSa => {
                    self.handle_create_child_request(&message, source).await
                }
            }
        }
    }

    async fn handle_sa_init_request(
        &mut self,
        raw: &[u8],
        source: SocketAddr,
        message: &codec::Message,
    ) -> Result<(), IpsecError> {
        if self.ike.is_some() {
            // Re-transmitted IKE_SA_INIT for a live SA: ignore.
            return Ok(());
        }
        let peer = self
            .config
            .peers
            .iter()
            .find(|peer| {
                peer.remote
                    .address
                    .is_none_or(|address| address == source.ip())
            })
            .cloned()
            .ok_or_else(|| {
                IpsecError::authentication("no configured peer for IKE_SA_INIT")
            })?;
        self.transport.set_remote(source);
        let sa = message
            .payload(codec::payload_type::SA)
            .ok_or_else(|| IpsecError::ike("IKE_SA_INIT without SA payload"))?;
        let Payload::Sa(offers) = sa else {
            return Err(IpsecError::ike("malformed SA payload"));
        };
        let (suite, proposal_number) =
            proposal::select_ike(&self.config.ike.proposals.proposals, offers)?;
        let ke = message
            .payload(codec::payload_type::KE)
            .ok_or_else(|| IpsecError::ike("IKE_SA_INIT without KE payload"))?;
        let Payload::Ke {
            group,
            data: peer_public,
        } = ke
        else {
            return Err(IpsecError::ike("malformed KE payload"));
        };
        if *group != suite.dh.transform_id() {
            self.send_plain_notify(
                message.header.initiator_spi,
                0,
                0,
                codec::notify_type::INVALID_KE_PAYLOAD,
                &suite.dh.transform_id().to_be_bytes(),
            )
            .await?;
            return Err(IpsecError::new(
                IpsecErrorKind::Proposal,
                "peer used an unexpected DH group",
            ));
        }
        let nonce_i = match message.payload(codec::payload_type::NONCE) {
            Some(Payload::Nonce(nonce)) if !nonce.is_empty() => nonce.clone(),
            _ => return Err(IpsecError::ike("IKE_SA_INIT without a nonce")),
        };
        if self.config.local.nat_t {
            for payload in &message.payloads {
                if let Payload::Notify {
                    notify_type, data, ..
                } = payload
                    && *notify_type
                        == codec::notify_type::NAT_DETECTION_SOURCE_IP
                    && !crate::ikev2::transport::nat_detection_matches(
                        data,
                        message.header.initiator_spi,
                        0,
                        source.ip(),
                        source.port(),
                    )
                {
                    log::debug!("NAT detected on inbound IKE_SA_INIT");
                    self.transport.enable_nat_t();
                }
            }
        }
        let private = DhKeyPair::generate(suite.dh)?;
        let public = private.public().to_vec();
        let shared = private.agree(peer_public)?;
        let remote_spi = crypto::random_u64()?;
        let mut nonce_r = vec![0u8; NONCE_LEN];
        crypto::random_bytes(&mut nonce_r)?;
        let keys = IkeKeys::derive(
            suite.prf,
            &shared,
            &nonce_i,
            &nonce_r,
            message.header.initiator_spi,
            remote_spi,
            suite.encryption,
            suite.integrity,
        );

        let response_sa = vec![codec::Proposal {
            number: proposal_number,
            protocol: codec::protocol_id::IKE,
            spi: Vec::new(),
            transforms: codec::ike_transforms(
                suite.encryption,
                suite.prf,
                suite.integrity,
                suite.dh,
            ),
        }];
        let payloads = vec![
            Payload::Sa(response_sa),
            Payload::Ke {
                group: suite.dh.transform_id(),
                data: public,
            },
            Payload::Nonce(nonce_r.clone()),
            Payload::Notify {
                protocol: codec::protocol_id::IKE,
                spi: Vec::new(),
                notify_type: codec::notify_type::NAT_DETECTION_SOURCE_IP,
                data: crate::ikev2::transport::nat_detection_hash(
                    message.header.initiator_spi,
                    remote_spi,
                    source.ip(),
                    source.port(),
                ),
            },
            Payload::Notify {
                protocol: codec::protocol_id::IKE,
                spi: Vec::new(),
                notify_type: codec::notify_type::NAT_DETECTION_DESTINATION_IP,
                data: crate::ikev2::transport::nat_detection_hash(
                    message.header.initiator_spi,
                    remote_spi,
                    self.config.local.address.unwrap_or_else(|| {
                        self.transport
                            .local_addr()
                            .map(|a| a.ip())
                            .unwrap_or(source.ip())
                    }),
                    self.config.local.port,
                ),
            },
        ];
        let _ = &payloads;
        // The DH private key is consumed above; retransmissions reuse the
        // cached response bytes.
        let header = IkeHeader::new(
            message.header.initiator_spi,
            remote_spi,
            ExchangeType::IkeSaInit,
            FLAG_RESPONSE,
            0,
        );
        let response = codec::Message::new(header, payloads).encode()?;
        self.transport.send(&response).await?;
        self.retransmit = Some(Retransmit::new(
            response.clone(),
            self.config.dpd.timeout.max(RETRANSMIT_TIMEOUT),
            MAX_RETRANSMITS,
        ));
        self.ike = Some(IkeRuntime {
            role: Role::Responder,
            local_spi: remote_spi,
            remote_spi: message.header.initiator_spi,
            keys,
            suite,
            nonce_i,
            nonce_r,
            real_message1: raw.to_vec(),
            real_message2: response,
            local_child_spi: 0,
            child: None,
            inner_addresses: Vec::new(),
            dns: Vec::new(),
        });
        self.peer_index = self
            .config
            .peers
            .iter()
            .position(|candidate| candidate == &peer)
            .unwrap_or(self.peer_index);
        self.phase = Phase::AuthSent;
        self.set_state(IpsecState::Connecting).await;
        Ok(())
    }

    async fn handle_sa_init_response(
        &mut self,
        raw: &[u8],
        message: &codec::Message,
    ) -> Result<(), IpsecError> {
        let pending = self.pending_sa_init.take().ok_or_else(|| {
            IpsecError::internal("unexpected IKE_SA_INIT response")
        })?;
        let PendingSaInit {
            private,
            nonce: nonce_i,
            proposals: offered_proposals,
            real_message1,
            local_spi,
        } = pending;
        let sa = message.payload(codec::payload_type::SA).ok_or_else(|| {
            IpsecError::ike("IKE_SA_INIT response without SA")
        })?;
        let Payload::Sa(proposals) = sa else {
            return Err(IpsecError::ike("malformed SA payload"));
        };
        let suite = proposal::parse_selected_ike(proposals)?;
        if !offered_proposals.contains(&suite) {
            return Err(IpsecError::new(
                IpsecErrorKind::Proposal,
                "peer selected an IKE proposal that was not offered",
            ));
        }
        let ke = message.payload(codec::payload_type::KE).ok_or_else(|| {
            IpsecError::ike("IKE_SA_INIT response without KE")
        })?;
        let Payload::Ke {
            group,
            data: peer_public,
        } = ke
        else {
            return Err(IpsecError::ike("malformed KE payload"));
        };
        if *group != suite.dh.transform_id() {
            return Err(IpsecError::new(
                IpsecErrorKind::Proposal,
                "peer selected an unexpected DH group",
            ));
        }
        let nonce_r = match message.payload(codec::payload_type::NONCE) {
            Some(Payload::Nonce(nonce)) if !nonce.is_empty() => nonce.clone(),
            _ => {
                return Err(IpsecError::ike(
                    "IKE_SA_INIT response without a nonce",
                ));
            }
        };
        let shared = private.agree(peer_public)?;
        let remote_spi = message.header.responder_spi;
        let keys = IkeKeys::derive(
            suite.prf,
            &shared,
            &nonce_i,
            &nonce_r,
            local_spi,
            remote_spi,
            suite.encryption,
            suite.integrity,
        );
        self.retransmit = None;

        // NAT detection: if our source hash does not match, encapsulate
        // on UDP 4500.
        let mut nat_detected = false;
        for payload in &message.payloads {
            if let Payload::Notify {
                notify_type, data, ..
            } = payload
                && *notify_type == codec::notify_type::NAT_DETECTION_SOURCE_IP
            {
                let source = self.config.local.address.unwrap_or_else(|| {
                    self.transport
                        .local_addr()
                        .map(|a| a.ip())
                        .unwrap_or_else(|_| self.transport.remote().ip())
                });
                if !crate::ikev2::transport::nat_detection_matches(
                    data,
                    local_spi,
                    remote_spi,
                    source,
                    self.config.local.port,
                ) {
                    nat_detected = true;
                }
            }
        }
        if nat_detected && self.config.local.nat_t {
            self.transport.enable_nat_t();
        }

        self.ike = Some(IkeRuntime {
            role: Role::Initiator,
            local_spi,
            remote_spi,
            keys,
            suite,
            nonce_i: nonce_i.clone(),
            nonce_r: nonce_r.clone(),
            real_message1: real_message1.clone(),
            real_message2: raw.to_vec(),
            local_child_spi: crypto::random_u32()?,
            child: None,
            inner_addresses: Vec::new(),
            dns: Vec::new(),
        });
        self.send_auth().await
    }

    async fn send_auth(&mut self) -> Result<(), IpsecError> {
        let peer = self
            .config
            .peers
            .get(self.peer_index)
            .cloned()
            .ok_or_else(|| IpsecError::config("peer index out of range"))?;
        let local_child_spi = {
            let ike = self.ike.as_ref().unwrap();
            ike.local_child_spi
        };
        let mut payloads = Vec::new();
        let id_body = self.local_id_body()?;
        payloads.push(self.local_id_payload(true));
        let mut eap_mode = false;
        match &peer.auth {
            AuthConfig::Psk(secret) => {
                let ike = self.ike.as_ref().unwrap();
                let signed = auth::signed_octets(
                    &ike.real_message1,
                    &ike.nonce_r,
                    ike.suite.prf,
                    &ike.keys.sk_pi,
                    &id_body,
                );
                let auth =
                    auth::psk::compute(secret.expose(), ike.suite.prf, &signed);
                payloads.push(Payload::Auth {
                    method: auth::AUTH_PSK,
                    data: auth,
                });
            }
            AuthConfig::Certificate(config) => {
                let local = LocalAuth::load(config)?;
                for payload in crate::ikev2::auth::cert::certificate_payloads(
                    local.certificates(),
                ) {
                    payloads.push(payload);
                }
                if !config.certificate_requests.is_empty() {
                    for request in &config.certificate_requests {
                        payloads.push(Payload::CertReq {
                            encoding: 4,
                            data: request.clone(),
                        });
                    }
                }
                let ike = self.ike.as_ref().unwrap();
                let signed = auth::signed_octets(
                    &ike.real_message1,
                    &ike.nonce_r,
                    ike.suite.prf,
                    &ike.keys.sk_pi,
                    &id_body,
                );
                let (method, signature) = local.sign(&signed)?;
                payloads.push(Payload::Auth {
                    method,
                    data: signature,
                });
            }
            AuthConfig::EapTls(config) => {
                eap_mode = true;
                self.eap = Some(EapSession::new(config)?);
            }
        }
        if self.config.local.request_inner_address
            || self.config.local.request_dns
        {
            let mut attributes = Vec::new();
            if self.config.local.request_inner_address {
                attributes.push(codec::ConfigAttribute {
                    type_: if self
                        .config
                        .peers
                        .get(self.peer_index)
                        .and_then(|peer| peer.remote.address)
                        .is_some_and(|address| address.is_ipv6())
                    {
                        8
                    } else {
                        1
                    },
                    value: Vec::new(),
                });
            }
            if self.config.local.request_dns {
                attributes.push(codec::ConfigAttribute {
                    type_: 3,
                    value: Vec::new(),
                });
                attributes.push(codec::ConfigAttribute {
                    type_: 10,
                    value: Vec::new(),
                });
            }
            payloads.push(Payload::Config(attributes));
        }
        payloads.push(Payload::Sa(proposal::build_esp(
            &self.config.child.proposals.proposals,
            local_child_spi,
            false,
        )));
        let selectors = self.config.peers[self.peer_index].selectors.clone();
        payloads.push(Payload::Ts {
            initiator: true,
            selectors: selectors.local.iter().map(ts_wire).collect(),
        });
        payloads.push(Payload::Ts {
            initiator: false,
            selectors: selectors.remote.iter().map(ts_wire).collect(),
        });

        let message_id = 1;
        self.next_message_id = 2;
        let exchange = ExchangeType::IkeAuth;
        let header = self.header_for(exchange, message_id, true);
        let encrypted = self.seal(&header, &payloads)?;
        self.transport.send(&encrypted).await?;
        self.retransmit = Some(Retransmit::new(
            encrypted,
            self.config.dpd.timeout.max(RETRANSMIT_TIMEOUT),
            MAX_RETRANSMITS,
        ));
        self.phase = if eap_mode {
            Phase::EapAuth
        } else {
            Phase::AuthSent
        };
        Ok(())
    }

    async fn handle_auth_request(
        &mut self,
        message: &codec::Message,
        source: SocketAddr,
    ) -> Result<(), IpsecError> {
        self.transport.set_remote(source);
        self.retransmit = None;
        let payloads = self.open_encrypted(message)?;
        let peer = self
            .config
            .peers
            .get(self.peer_index)
            .cloned()
            .ok_or_else(|| IpsecError::config("no configured peer"))?;
        let initiator_id = find_id(&payloads, true)
            .ok_or_else(|| IpsecError::ike("IKE_AUTH without IDi"))?;
        let id_body = id_payload_body(initiator_id);
        if !peer
            .remote
            .identity
            .matches(&initiator_id_identity(initiator_id)?)
        {
            return Err(IpsecError::new(
                IpsecErrorKind::Identity,
                format!(
                    "peer identity {} does not match configured identity {}",
                    initiator_id_identity(initiator_id)?,
                    peer.remote.identity
                ),
            ));
        }
        match &peer.auth {
            AuthConfig::Psk(secret) => {
                let auth_payload = payloads
                    .iter()
                    .find_map(|payload| match payload {
                        Payload::Auth { method, data }
                            if *method == auth::AUTH_PSK =>
                        {
                            Some(data.clone())
                        }
                        _ => None,
                    })
                    .ok_or_else(|| {
                        IpsecError::authentication("IKE_AUTH without AUTH")
                    })?;
                let ike = self.ike.as_ref().unwrap();
                let signed = auth::signed_octets(
                    &ike.real_message1,
                    &ike.nonce_r,
                    ike.suite.prf,
                    &ike.keys.sk_pi,
                    &id_body,
                );
                auth::psk::verify(
                    secret.expose(),
                    ike.suite.prf,
                    &signed,
                    &auth_payload,
                )?;
            }
            AuthConfig::Certificate(config) => {
                let chain = certificate_chain(&payloads);
                let auth_payload = payloads
                    .iter()
                    .find_map(|payload| match payload {
                        Payload::Auth { method, data } => {
                            Some((*method, data.clone()))
                        }
                        _ => None,
                    })
                    .ok_or_else(|| {
                        IpsecError::authentication("IKE_AUTH without AUTH")
                    })?;
                let ike = self.ike.as_ref().unwrap();
                crate::ikev2::auth::cert::verify_peer(
                    &config.ca_certificates,
                    &chain,
                    &initiator_id_identity(initiator_id)?,
                    crate::ikev2::auth::cert::PeerRole::Initiator,
                )?;
                let signed = auth::signed_octets(
                    &ike.real_message1,
                    &ike.nonce_r,
                    ike.suite.prf,
                    &ike.keys.sk_pi,
                    &id_body,
                );
                crate::ikev2::auth::cert::verify_signature(
                    &chain,
                    auth_payload.0,
                    &signed,
                    &auth_payload.1,
                )?;
            }
            AuthConfig::EapTls(_) => {
                return Err(IpsecError::new(
                    IpsecErrorKind::NoSupport,
                    "EAP-TLS responder authentication is not supported",
                ));
            }
        }

        let sa = payloads
            .iter()
            .find_map(|payload| match payload {
                Payload::Sa(proposals) => Some(proposals.clone()),
                _ => None,
            })
            .ok_or_else(|| IpsecError::ike("IKE_AUTH without SA payload"))?;
        let (child_suite, _) = proposal::select_esp_initial(
            &self.config.child.proposals.proposals,
            &sa,
        )?;
        let remote_child_spi = sa
            .first()
            .and_then(|proposal| proposal.spi.get(..4))
            .map(|spi| u32::from_be_bytes(spi.try_into().unwrap()))
            .ok_or_else(|| IpsecError::ike("IKE_AUTH SA without an SPI"))?;
        let local_child_spi = crypto::random_u32()?;
        let (local_selectors, remote_selectors) = narrow_request_selectors(
            &self.config.peers[self.peer_index].selectors,
            &payloads,
        )?;

        let responder_id_body = self.local_id_body()?;
        let mut response_payloads = vec![self.local_id_payload(false)];
        match &peer.auth {
            AuthConfig::Psk(secret) => {
                let ike = self.ike.as_ref().unwrap();
                let signed = auth::signed_octets(
                    &ike.real_message2,
                    &ike.nonce_i,
                    ike.suite.prf,
                    &ike.keys.sk_pr,
                    &responder_id_body,
                );
                let auth =
                    auth::psk::compute(secret.expose(), ike.suite.prf, &signed);
                response_payloads.push(Payload::Auth {
                    method: auth::AUTH_PSK,
                    data: auth,
                });
            }
            AuthConfig::Certificate(config) => {
                let local = LocalAuth::load(config)?;
                for payload in crate::ikev2::auth::cert::certificate_payloads(
                    local.certificates(),
                ) {
                    response_payloads.push(payload);
                }
                let ike = self.ike.as_ref().unwrap();
                let signed = auth::signed_octets(
                    &ike.real_message2,
                    &ike.nonce_i,
                    ike.suite.prf,
                    &ike.keys.sk_pr,
                    &responder_id_body,
                );
                let (method, signature) = local.sign(&signed)?;
                response_payloads.push(Payload::Auth {
                    method,
                    data: signature,
                });
            }
            AuthConfig::EapTls(_) => unreachable!(),
        }
        response_payloads.push(Payload::Sa(vec![codec::Proposal {
            number: 1,
            protocol: codec::protocol_id::ESP,
            spi: local_child_spi.to_be_bytes().to_vec(),
            transforms: codec::esp_transforms(
                child_suite.encryption,
                child_suite.integrity,
                child_suite.esn,
                child_suite.dh,
            ),
        }]));
        response_payloads.push(Payload::Ts {
            initiator: true,
            selectors: remote_selectors.iter().map(ts_wire).collect(),
        });
        response_payloads.push(Payload::Ts {
            initiator: false,
            selectors: local_selectors.iter().map(ts_wire).collect(),
        });
        let header = self.header_for(
            ExchangeType::IkeAuth,
            message.header.message_id,
            false,
        );
        let encrypted = self.seal(&header, &response_payloads)?;
        self.transport.send(&encrypted).await?;

        let key_material = {
            let ike = self.ike.as_ref().unwrap();
            sa::derive_child_keys(
                ike.suite.prf,
                &ike.keys.sk_d,
                &ike.nonce_i,
                &ike.nonce_r,
                None,
                ike.role,
                child_suite.encryption,
                child_suite.integrity,
                local_child_spi,
                remote_child_spi,
                self.config.child.mode,
                local_selectors.clone(),
                remote_selectors.clone(),
                child_suite.esn,
            )
        };
        self.install_child(key_material, child_suite).await;
        Ok(())
    }

    async fn handle_auth_response(
        &mut self,
        message: &codec::Message,
    ) -> Result<(), IpsecError> {
        self.retransmit = None;
        let payloads = self.open_encrypted(message)?;

        if let Some(eap_payload) =
            payloads.iter().find_map(|payload| match payload {
                Payload::Eap(data) => Some(data.clone()),
                _ => None,
            })
        {
            return self.handle_eap(message, &payloads, &eap_payload).await;
        }

        let peer = self
            .config
            .peers
            .get(self.peer_index)
            .cloned()
            .ok_or_else(|| IpsecError::config("no configured peer"))?;
        let responder_id = find_id(&payloads, false)
            .ok_or_else(|| IpsecError::ike("IKE_AUTH response without IDr"))?;
        let responder_identity = initiator_id_identity(responder_id)?;
        if !peer.remote.identity.matches(&responder_identity)
            && !peer.remote.identity.is_wildcard()
        {
            return Err(IpsecError::new(
                IpsecErrorKind::Identity,
                format!(
                    "responder identity {responder_identity} does not match {}",
                    peer.remote.identity
                ),
            ));
        }
        match &peer.auth {
            AuthConfig::Psk(secret) => {
                let auth_payload = payloads
                    .iter()
                    .find_map(|payload| match payload {
                        Payload::Auth { method, data }
                            if *method == auth::AUTH_PSK =>
                        {
                            Some(data.clone())
                        }
                        _ => None,
                    })
                    .ok_or_else(|| {
                        IpsecError::authentication(
                            "IKE_AUTH response without AUTH",
                        )
                    })?;
                let ike = self.ike.as_ref().unwrap();
                let id_body = id_payload_body(responder_id);
                let signed = auth::signed_octets(
                    &ike.real_message2,
                    &ike.nonce_i,
                    ike.suite.prf,
                    &ike.keys.sk_pr,
                    &id_body,
                );
                auth::psk::verify(
                    secret.expose(),
                    ike.suite.prf,
                    &signed,
                    &auth_payload,
                )?;
            }
            AuthConfig::Certificate(config) => {
                let chain = certificate_chain(&payloads);
                let auth_payload = payloads
                    .iter()
                    .find_map(|payload| match payload {
                        Payload::Auth { method, data } => {
                            Some((*method, data.clone()))
                        }
                        _ => None,
                    })
                    .ok_or_else(|| {
                        IpsecError::authentication(
                            "IKE_AUTH response without AUTH",
                        )
                    })?;
                let ike = self.ike.as_ref().unwrap();
                crate::ikev2::auth::cert::verify_peer(
                    &config.ca_certificates,
                    &chain,
                    &responder_identity,
                    crate::ikev2::auth::cert::PeerRole::Responder,
                )?;
                let id_body = id_payload_body(responder_id);
                let signed = auth::signed_octets(
                    &ike.real_message2,
                    &ike.nonce_i,
                    ike.suite.prf,
                    &ike.keys.sk_pr,
                    &id_body,
                );
                crate::ikev2::auth::cert::verify_signature(
                    &chain,
                    auth_payload.0,
                    &signed,
                    &auth_payload.1,
                )?;
            }
            AuthConfig::EapTls(_) => {
                let auth_payload = payloads
                    .iter()
                    .find_map(|payload| match payload {
                        Payload::Auth { data, .. } => Some(data.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        IpsecError::authentication(
                            "EAP IKE_AUTH response without AUTH",
                        )
                    })?;
                let msk = self
                    .eap
                    .as_ref()
                    .and_then(|session| session.msk())
                    .ok_or_else(|| {
                    IpsecError::authentication("EAP-TLS MSK is not available")
                })?;
                let ike = self.ike.as_ref().unwrap();
                let id_body = id_payload_body(responder_id);
                let signed = auth::signed_octets(
                    &ike.real_message2,
                    &ike.nonce_i,
                    ike.suite.prf,
                    &ike.keys.sk_pr,
                    &id_body,
                );
                auth::psk::verify(&msk, ike.suite.prf, &signed, &auth_payload)?;
            }
        }

        let sa = payloads
            .iter()
            .find_map(|payload| match payload {
                Payload::Sa(proposals) => Some(proposals.clone()),
                _ => None,
            })
            .ok_or_else(|| IpsecError::ike("IKE_AUTH response without SA"))?;
        let (child_suite, _) = proposal::select_esp_initial(
            &self.config.child.proposals.proposals,
            &sa,
        )?;
        let remote_child_spi = sa
            .first()
            .and_then(|proposal| proposal.spi.get(..4))
            .map(|spi| u32::from_be_bytes(spi.try_into().unwrap()))
            .ok_or_else(|| IpsecError::ike("responder SA without an SPI"))?;
        let (local_selectors, remote_selectors) = narrow_response_selectors(
            &self.config.peers[self.peer_index].selectors,
            &payloads,
        )?;
        let local_child_spi = {
            let ike = self.ike.as_ref().unwrap();
            ike.local_child_spi
        };
        let (inner_addresses, dns) = parse_config_payload(&payloads);
        if let Some(ike) = self.ike.as_mut() {
            ike.inner_addresses = inner_addresses;
            ike.dns = dns;
        }
        let key_material = {
            let ike = self.ike.as_ref().unwrap();
            sa::derive_child_keys(
                ike.suite.prf,
                &ike.keys.sk_d,
                &ike.nonce_i,
                &ike.nonce_r,
                None,
                ike.role,
                child_suite.encryption,
                child_suite.integrity,
                local_child_spi,
                remote_child_spi,
                self.config.child.mode,
                local_selectors.clone(),
                remote_selectors.clone(),
                child_suite.esn,
            )
        };
        self.install_child(key_material, child_suite).await;
        Ok(())
    }

    async fn handle_eap(
        &mut self,
        message: &codec::Message,
        payloads: &[Payload],
        eap_data: &[u8],
    ) -> Result<(), IpsecError> {
        let session = self
            .eap
            .as_mut()
            .ok_or_else(|| IpsecError::ike("unexpected EAP payload"))?;
        let (response, success) = session.handle(eap_data)?;
        if let Some(response) = response {
            let header = self.header_for(
                ExchangeType::IkeAuth,
                self.next_message_id,
                true,
            );
            self.next_message_id = self.next_message_id.wrapping_add(1);
            let encrypted = self.seal(&header, &[Payload::Eap(response)])?;
            self.transport.send(&encrypted).await?;
            self.retransmit = Some(Retransmit::new(
                encrypted,
                self.config.dpd.timeout.max(RETRANSMIT_TIMEOUT),
                MAX_RETRANSMITS,
            ));
            return Ok(());
        }
        if success {
            let msk = session.msk().ok_or_else(|| {
                IpsecError::authentication("EAP-TLS did not export an MSK")
            })?;
            let id_body = self.local_id_body()?;
            let ike = self.ike.as_ref().unwrap();
            let signed = auth::signed_octets(
                &ike.real_message1,
                &ike.nonce_r,
                ike.suite.prf,
                &ike.keys.sk_pi,
                &id_body,
            );
            let auth = auth::psk::compute(&msk, ike.suite.prf, &signed);
            let header = self.header_for(
                ExchangeType::IkeAuth,
                self.next_message_id,
                true,
            );
            self.next_message_id = self.next_message_id.wrapping_add(1);
            let encrypted = self.seal(
                &header,
                &[Payload::Auth {
                    method: auth::AUTH_PSK,
                    data: auth,
                }],
            )?;
            self.transport.send(&encrypted).await?;
            self.retransmit = Some(Retransmit::new(
                encrypted,
                self.config.dpd.timeout.max(RETRANSMIT_TIMEOUT),
                MAX_RETRANSMITS,
            ));
        }
        let _ = (message, payloads);
        Ok(())
    }

    async fn handle_informational_request(
        &mut self,
        message: &codec::Message,
        _source: SocketAddr,
    ) -> Result<(), IpsecError> {
        let payloads = self.open_encrypted(message)?;
        let mut response = Vec::new();
        for payload in &payloads {
            match payload {
                Payload::Notify {
                    notify_type, data, ..
                } if *notify_type == codec::notify_type::COOKIE => {
                    response.push(Payload::Notify {
                        protocol: codec::protocol_id::IKE,
                        spi: Vec::new(),
                        notify_type: codec::notify_type::COOKIE,
                        data: data.clone(),
                    });
                }
                Payload::Delete { protocol, spis, .. }
                    if *protocol == codec::protocol_id::ESP =>
                {
                    if let Some(ike) = self.ike.as_ref()
                        && ike.child.as_ref().is_some_and(|child| {
                            spis.contains(&child.handle.local_spi)
                        })
                    {
                        self.remove_child(
                            crate::client::ChildSaRemovalReason::PeerDelete,
                        )
                        .await;
                    }
                }
                _ => {}
            }
        }
        let header = self.header_for(
            ExchangeType::Informational,
            message.header.message_id,
            false,
        );
        let encrypted = self.seal(&header, &response)?;
        self.transport.send(&encrypted).await?;
        Ok(())
    }

    async fn initiate_rekey(&mut self) -> Result<(), IpsecError> {
        self.rekey_deadline = None;
        if self.phase != Phase::Established || self.ike.is_none() {
            return Ok(());
        }
        if self.pending_rekey.is_some() {
            self.rekey_deadline =
                Some(tokio::time::Instant::now() + Duration::from_secs(5));
            return Ok(());
        }
        let suite = *self
            .config
            .child
            .proposals
            .proposals
            .first()
            .ok_or_else(|| IpsecError::config("no Child SA proposal"))?;
        let local_spi = crypto::random_u32()?;
        let mut nonce_i = vec![0u8; NONCE_LEN];
        crypto::random_bytes(&mut nonce_i)?;
        let mut payloads = vec![Payload::Sa(proposal::build_esp(
            &self.config.child.proposals.proposals,
            local_spi,
            true,
        ))];
        let private = if suite.dh != crate::config::DhGroup::None {
            let private = DhKeyPair::generate(suite.dh)?;
            payloads.push(Payload::Ke {
                group: suite.dh.transform_id(),
                data: private.public().to_vec(),
            });
            Some(private)
        } else {
            None
        };
        payloads.push(Payload::Nonce(nonce_i.clone()));
        let selectors = self.config.peers[self.peer_index].selectors.clone();
        payloads.push(Payload::Ts {
            initiator: true,
            selectors: selectors.local.iter().map(ts_wire).collect(),
        });
        payloads.push(Payload::Ts {
            initiator: false,
            selectors: selectors.remote.iter().map(ts_wire).collect(),
        });
        let header = self.header_for(
            ExchangeType::CreateChildSa,
            self.next_message_id,
            true,
        );
        self.next_message_id = self.next_message_id.wrapping_add(1);
        let encrypted = self.seal(&header, &payloads)?;
        self.transport.send(&encrypted).await?;
        self.retransmit = Some(Retransmit::new(
            encrypted,
            self.config.dpd.timeout.max(RETRANSMIT_TIMEOUT),
            MAX_RETRANSMITS,
        ));
        self.pending_rekey = Some(PendingRekey {
            private,
            nonce_i,
            local_spi,
            suite,
        });
        self.set_state(IpsecState::Rekeying).await;
        Ok(())
    }

    async fn handle_create_child_response(
        &mut self,
        message: &codec::Message,
    ) -> Result<(), IpsecError> {
        self.retransmit = None;
        let payloads = self.open_encrypted(message)?;
        let pending = self.pending_rekey.take().ok_or_else(|| {
            IpsecError::internal("unexpected CREATE_CHILD_SA response")
        })?;
        let sa = payloads
            .iter()
            .find_map(|payload| match payload {
                Payload::Sa(proposals) => Some(proposals.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                IpsecError::ike("CREATE_CHILD_SA response without SA")
            })?;
        let (suite, _) =
            proposal::select_esp(&self.config.child.proposals.proposals, &sa)?;
        if suite.dh != pending.suite.dh {
            return Err(IpsecError::new(
                IpsecErrorKind::Proposal,
                "responder selected a different PFS group",
            ));
        }
        let remote_spi = sa
            .first()
            .and_then(|proposal| proposal.spi.get(..4))
            .map(|spi| u32::from_be_bytes(spi.try_into().unwrap()))
            .ok_or_else(|| {
                IpsecError::ike("CREATE_CHILD_SA response SA without SPI")
            })?;
        let nonce_r = payloads
            .iter()
            .find_map(|payload| match payload {
                Payload::Nonce(nonce) => Some(nonce.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                IpsecError::ike("CREATE_CHILD_SA response without nonce")
            })?;
        let shared = match (
            pending.private,
            payloads.iter().find_map(|payload| match payload {
                Payload::Ke { data, .. } => Some(data.clone()),
                _ => None,
            }),
        ) {
            (Some(private), Some(peer_public)) => {
                Some(private.agree(&peer_public)?)
            }
            (None, None) => None,
            _ => {
                return Err(IpsecError::ike("CREATE_CHILD_SA KE mismatch"));
            }
        };
        let (local_selectors, remote_selectors) = narrow_response_selectors(
            &self.config.peers[self.peer_index].selectors,
            &payloads,
        )?;
        let key_material = {
            let ike = self.ike.as_ref().unwrap();
            sa::derive_child_keys(
                ike.suite.prf,
                &ike.keys.sk_d,
                &pending.nonce_i,
                &nonce_r,
                shared.as_ref().map(|value| value.as_slice()),
                ike.role,
                suite.encryption,
                suite.integrity,
                pending.local_spi,
                remote_spi,
                self.config.child.mode,
                local_selectors,
                remote_selectors,
                suite.esn,
            )
        };
        self.install_child(key_material, suite).await;
        Ok(())
    }

    async fn handle_create_child_request(
        &mut self,
        message: &codec::Message,
        _source: SocketAddr,
    ) -> Result<(), IpsecError> {
        let payloads = self.open_encrypted(message)?;
        let sa = payloads
            .iter()
            .find_map(|payload| match payload {
                Payload::Sa(proposals) => Some(proposals.clone()),
                _ => None,
            })
            .ok_or_else(|| IpsecError::ike("CREATE_CHILD_SA without SA"))?;
        let (suite, proposal_number) =
            proposal::select_esp(&self.config.child.proposals.proposals, &sa)?;
        let remote_spi = sa
            .first()
            .and_then(|proposal| proposal.spi.get(..4))
            .map(|spi| u32::from_be_bytes(spi.try_into().unwrap()))
            .ok_or_else(|| IpsecError::ike("CREATE_CHILD_SA SA without SPI"))?;
        let local_spi = crypto::random_u32()?;
        let nonce_i = payloads
            .iter()
            .find_map(|payload| match payload {
                Payload::Nonce(nonce) => Some(nonce.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                IpsecError::ike("CREATE_CHILD_SA without a nonce")
            })?;
        let mut nonce_r = vec![0u8; NONCE_LEN];
        crypto::random_bytes(&mut nonce_r)?;
        let (local_selectors, remote_selectors) = narrow_request_selectors(
            &self.config.peers[self.peer_index].selectors,
            &payloads,
        )?;
        let peer_ke = payloads.iter().find_map(|payload| match payload {
            Payload::Ke { group, data } => Some((*group, data.clone())),
            _ => None,
        });
        let mut response = vec![Payload::Sa(vec![codec::Proposal {
            number: proposal_number,
            protocol: codec::protocol_id::ESP,
            spi: local_spi.to_be_bytes().to_vec(),
            transforms: codec::esp_transforms(
                suite.encryption,
                suite.integrity,
                suite.esn,
                suite.dh,
            ),
        }])];
        let shared = if let Some((group, peer_public)) = peer_ke {
            let private = DhKeyPair::generate(suite.dh)?;
            let public = private.public().to_vec();
            response.push(Payload::Ke {
                group,
                data: public,
            });
            Some(private.agree(&peer_public)?)
        } else {
            None
        };
        response.push(Payload::Nonce(nonce_r.clone()));
        response.push(Payload::Ts {
            initiator: true,
            selectors: remote_selectors.iter().map(ts_wire).collect(),
        });
        response.push(Payload::Ts {
            initiator: false,
            selectors: local_selectors.iter().map(ts_wire).collect(),
        });
        let header = self.header_for(
            ExchangeType::CreateChildSa,
            message.header.message_id,
            false,
        );
        let encrypted = self.seal(&header, &response)?;
        self.transport.send(&encrypted).await?;
        let key_material = {
            let ike = self.ike.as_ref().unwrap();
            sa::derive_child_keys(
                ike.suite.prf,
                &ike.keys.sk_d,
                &nonce_i,
                &nonce_r,
                shared.as_ref().map(|value| value.as_slice()),
                ike.role,
                suite.encryption,
                suite.integrity,
                local_spi,
                remote_spi,
                self.config.child.mode,
                local_selectors,
                remote_selectors,
                suite.esn,
            )
        };
        self.install_child(key_material, suite).await;
        Ok(())
    }

    async fn install_child(
        &mut self,
        handle: ChildSaHandle,
        suite: ChildProposal,
    ) {
        let lease = self.lease(&handle);
        let connection = self.config.name.clone();
        if let Some(ike) = self.ike.as_mut() {
            let refreshed = ike.child.is_some();
            ike.child = Some(ChildRuntime {
                handle: clone_handle(&handle),
            });
            let _ = suite;
            let event = if refreshed {
                IpsecEvent::ChildSaRefreshed {
                    connection,
                    peer_index: self.peer_index,
                    child: handle,
                    lease,
                }
            } else {
                IpsecEvent::ChildSaReady {
                    connection,
                    peer_index: self.peer_index,
                    child: handle,
                    lease,
                }
            };
            let _ = self.events.send(event);
        }
        self.phase = Phase::Established;
        self.retransmit = None;
        self.set_state(IpsecState::Established).await;
        if self.config.dpd.enabled {
            self.dpd_deadline =
                Some(tokio::time::Instant::now() + self.config.dpd.interval);
        }
        let lifetime = self.config.child.lifetime;
        let margin = self.config.rekey.child_margin_percent.clamp(1, 99) as u64;
        let rekey_after = lifetime.mul_f64(margin as f64 / 100.0);
        self.rekey_deadline = Some(tokio::time::Instant::now() + rekey_after);
    }

    async fn remove_child(
        &mut self,
        reason: crate::client::ChildSaRemovalReason,
    ) {
        if let Some(ike) = self.ike.as_mut() {
            ike.child = None;
        }
        let _ = self.events.send(IpsecEvent::ChildSaRemoved {
            connection: self.config.name.clone(),
            peer_index: self.peer_index,
            reason,
        });
    }

    fn lease(&self, handle: &ChildSaHandle) -> IpsecLease {
        let (local_inner_addresses, dns) = self
            .ike
            .as_ref()
            .map(|ike| (ike.inner_addresses.clone(), ike.dns.clone()))
            .unwrap_or_default();
        let local_inner_addresses = if local_inner_addresses.is_empty() {
            handle
                .local_selectors
                .iter()
                .filter_map(selector_to_net)
                .collect()
        } else {
            local_inner_addresses
        };
        let remote_inner_addresses = handle
            .remote_selectors
            .iter()
            .filter_map(selector_to_net)
            .collect();
        IpsecLease {
            connection: self.config.name.clone(),
            peer_index: self.peer_index,
            xfrm_interface: self.config.xfrm.interface.clone(),
            if_id: self
                .config
                .xfrm
                .if_id
                .unwrap_or_else(|| stable_id(&self.config.name)),
            reqid: self.config.xfrm.reqid.unwrap_or_else(|| {
                stable_id(&self.config.name).wrapping_add(1)
            }),
            local_selectors: handle.local_selectors.clone(),
            remote_selectors: handle.remote_selectors.clone(),
            local_inner_addresses,
            remote_inner_addresses,
            local_address: self.config.local.address,
            remote_address: self
                .config
                .peers
                .get(self.peer_index)
                .and_then(|peer| peer.remote.address)
                .or_else(|| Some(self.transport.remote().ip())),
            nat_t: self.transport.nat_t_enabled(),
            dns,
            expires_at: Some(SystemTime::now() + self.config.child.lifetime),
        }
    }

    async fn on_retransmit(&mut self) -> Result<(), IpsecError> {
        let Some(retransmit) = self.retransmit.as_mut() else {
            return Ok(());
        };
        if retransmit.retry() {
            let message = retransmit.message().to_vec();
            let header = codec::IkeHeader::decode(&message)?;
            log::debug!(
                "retransmitting {} message id {} after {} attempts",
                header.exchange,
                header.message_id,
                retransmit.attempts()
            );
            self.transport.send(&message).await?;
            Ok(())
        } else {
            self.retransmit = None;
            if self.phase == Phase::Established {
                self.remove_child(
                    crate::client::ChildSaRemovalReason::PeerDead,
                )
                .await;
                self.phase = Phase::Closed;
            }
            self.set_state(IpsecState::Failed).await;
            Err(IpsecError::new(
                IpsecErrorKind::Timeout,
                "peer did not respond to IKE retransmissions",
            ))
        }
    }

    async fn on_dpd(&mut self) -> Result<(), IpsecError> {
        self.dpd_deadline = None;
        if self.phase != Phase::Established {
            return Ok(());
        }
        if self.dpd_failures >= self.config.dpd.retries {
            self.remove_child(crate::client::ChildSaRemovalReason::PeerDead)
                .await;
            self.phase = Phase::Closed;
            self.set_state(IpsecState::Failed).await;
            return Err(IpsecError::new(
                IpsecErrorKind::Timeout,
                "dead peer detection declared the peer dead",
            ));
        }
        let header = self.header_for(
            ExchangeType::Informational,
            self.next_message_id,
            true,
        );
        self.next_message_id = self.next_message_id.wrapping_add(1);
        let encrypted = self.seal(&header, &[])?;
        self.transport.send(&encrypted).await?;
        self.retransmit = Some(Retransmit::new(
            encrypted,
            self.config.dpd.timeout,
            self.config.dpd.retries.max(1),
        ));
        self.dpd_failures = self.dpd_failures.saturating_add(1);
        self.dpd_deadline = Some(
            tokio::time::Instant::now()
                + self.config.dpd.interval
                + self.config.dpd.timeout,
        );
        Ok(())
    }

    async fn shutdown_connection(&mut self) {
        if self.phase == Phase::Established
            && let Some(ike) = self.ike.as_ref()
        {
            let header = self.header_for(
                ExchangeType::Informational,
                self.next_message_id,
                true,
            );
            let payload = ike.child.as_ref().map(|child| Payload::Delete {
                protocol: codec::protocol_id::ESP,
                spi_size: 4,
                spis: vec![child.handle.local_spi],
            });
            if let Some(payload) = payload
                && let Ok(encrypted) = self.seal(&header, &[payload])
            {
                let _ = self.transport.send(&encrypted).await;
            }
        }
        self.set_state(IpsecState::Closed).await;
    }

    fn header_for(
        &self,
        exchange: ExchangeType,
        message_id: u32,
        request: bool,
    ) -> IkeHeader {
        let (spi_i, spi_r, initiator) = self
            .ike
            .as_ref()
            .map(|ike| {
                if ike.role == Role::Initiator {
                    (ike.local_spi, ike.remote_spi, true)
                } else {
                    (ike.remote_spi, ike.local_spi, false)
                }
            })
            .unwrap_or((0, 0, self.pending_sa_init.is_some()));
        let mut flags = if initiator { FLAG_INITIATOR } else { 0 };
        if !request {
            flags |= FLAG_RESPONSE;
        }
        IkeHeader::new(spi_i, spi_r, exchange, flags, message_id)
    }

    fn seal(
        &self,
        header: &IkeHeader,
        payloads: &[Payload],
    ) -> Result<Vec<u8>, IpsecError> {
        let ike = self
            .ike
            .as_ref()
            .ok_or_else(|| IpsecError::internal("no IKE SA"))?;
        sa::seal_message(
            header,
            payloads,
            ike.suite.encryption,
            ike.suite.integrity,
            ike.keys.outbound_encryption(ike.role),
            ike.keys.outbound_integrity(ike.role),
        )
    }

    fn open_encrypted(
        &self,
        message: &codec::Message,
    ) -> Result<Vec<Payload>, IpsecError> {
        let ike = self.ike.as_ref().ok_or_else(|| {
            IpsecError::ike("encrypted message before IKE SA was created")
        })?;
        let payload = message
            .payloads
            .first()
            .ok_or_else(|| IpsecError::ike("empty encrypted IKE message"))?;
        sa::open_message(
            &message.header,
            payload,
            ike.suite.encryption,
            ike.suite.integrity,
            ike.keys.inbound_encryption(ike.role),
            ike.keys.inbound_integrity(ike.role),
        )
    }

    fn local_id_payload(&self, initiator: bool) -> Payload {
        let identity = &self.config.local.identity;
        match identity {
            crate::identity::Identity::Any => Payload::Id {
                initiator,
                id_type: 2,
                data: b"localhost".to_vec(),
            },
            _ => Payload::Id {
                initiator,
                id_type: identity.id_type().unwrap_or(2),
                data: identity.encode().unwrap_or_default(),
            },
        }
    }

    fn local_id_body(&self) -> Result<Vec<u8>, IpsecError> {
        let identity = &self.config.local.identity;
        let id_type = identity.id_type().unwrap_or(2);
        let data = if identity.is_wildcard() {
            b"localhost".to_vec()
        } else {
            identity.encode()?
        };
        let mut body = Vec::with_capacity(4 + data.len());
        body.push(id_type);
        body.extend_from_slice(&[0, 0, 0]);
        body.extend_from_slice(&data);
        Ok(body)
    }

    async fn send_plain_notify(
        &mut self,
        initiator_spi: u64,
        responder_spi: u64,
        message_id: u32,
        notify_type: u16,
        data: &[u8],
    ) -> Result<(), IpsecError> {
        let header = IkeHeader::new(
            initiator_spi,
            responder_spi,
            ExchangeType::IkeSaInit,
            FLAG_RESPONSE,
            message_id,
        );
        let message = codec::Message::new(
            header,
            vec![Payload::Notify {
                protocol: codec::protocol_id::IKE,
                spi: Vec::new(),
                notify_type,
                data: data.to_vec(),
            }],
        )
        .encode()?;
        self.transport.send(&message).await
    }

    async fn set_state(&mut self, state: IpsecState) {
        self.states
            .lock()
            .await
            .insert(self.config.name.clone(), state);
        let _ = self.events.send(IpsecEvent::State {
            connection: self.config.name.clone(),
            state,
        });
    }

    fn report_error(&self, error: IpsecError) {
        log::warn!("{}: {error}", self.config.name);
        let _ = self.events.send(error_event(&self.config.name, error));
    }
}

async fn wait_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn parse_config_payload(payloads: &[Payload]) -> (Vec<IpNet>, Vec<IpAddr>) {
    let mut addresses = Vec::new();
    let mut dns = Vec::new();
    for payload in payloads {
        let Payload::Config(attributes) = payload else {
            continue;
        };
        for attribute in attributes {
            match (attribute.type_, attribute.value.len()) {
                (1, 4) => {
                    let address = IpAddr::V4(std::net::Ipv4Addr::new(
                        attribute.value[0],
                        attribute.value[1],
                        attribute.value[2],
                        attribute.value[3],
                    ));
                    if let Ok(network) = IpNet::new(address, 32) {
                        addresses.push(network);
                    }
                }
                (8, len) if len >= 16 => {
                    let octets: [u8; 16] =
                        attribute.value[..16].try_into().unwrap();
                    let address = IpAddr::V6(std::net::Ipv6Addr::from(octets));
                    if let Ok(network) = IpNet::new(address, 128) {
                        addresses.push(network);
                    }
                }
                (3, 4) => dns.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    attribute.value[0],
                    attribute.value[1],
                    attribute.value[2],
                    attribute.value[3],
                ))),
                (10, len) if len >= 16 => {
                    dns.push(IpAddr::V6(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(&attribute.value[..16]).unwrap(),
                    )))
                }
                _ => {}
            }
        }
    }
    (addresses, dns)
}

fn ts_wire(selector: &TrafficSelector) -> TsSelector {
    TsSelector {
        ts_type: if selector.start.is_ipv4() { 7 } else { 8 },
        protocol: selector.protocol,
        start_port: selector.start_port,
        end_port: selector.end_port,
        start: selector.start,
        end: selector.end,
    }
}

fn ts_from_wire(selector: &TsSelector) -> Result<TrafficSelector, IpsecError> {
    Ok(TrafficSelector {
        start: selector.start,
        end: selector.end,
        protocol: selector.protocol,
        start_port: selector.start_port,
        end_port: selector.end_port,
    })
}

fn selector_to_net(selector: &TrafficSelector) -> Option<IpNet> {
    if selector.start.is_ipv4() {
        let start = u32::from(match selector.start {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => return None,
        });
        let end = u32::from(match selector.end {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => return None,
        });
        let prefix = (start ^ end).leading_zeros() as u8;
        IpNet::new(selector.start, prefix).ok()
    } else {
        let start = u128::from(match selector.start {
            IpAddr::V6(address) => address,
            IpAddr::V4(_) => return None,
        });
        let end = u128::from(match selector.end {
            IpAddr::V6(address) => address,
            IpAddr::V4(_) => return None,
        });
        let prefix = (start ^ end).leading_zeros() as u8;
        IpNet::new(selector.start, prefix).ok()
    }
}

fn find_id(payloads: &[Payload], initiator: bool) -> Option<&Payload> {
    payloads.iter().find(|payload| {
        matches!(
            payload,
            Payload::Id {
                initiator: is_initiator,
                ..
            } if *is_initiator == initiator
        )
    })
}

fn initiator_id_identity(
    payload: &Payload,
) -> Result<crate::identity::Identity, IpsecError> {
    match payload {
        Payload::Id { id_type, data, .. } => {
            crate::identity::Identity::decode(*id_type, data)
        }
        _ => Err(IpsecError::ike("expected an identification payload")),
    }
}

fn id_payload_body(payload: &Payload) -> Vec<u8> {
    match payload {
        Payload::Id { id_type, data, .. } => {
            let mut body = Vec::with_capacity(4 + data.len());
            body.push(*id_type);
            body.extend_from_slice(&[0, 0, 0]);
            body.extend_from_slice(data);
            body
        }
        _ => Vec::new(),
    }
}

fn certificate_chain(payloads: &[Payload]) -> Vec<Vec<u8>> {
    payloads
        .iter()
        .filter_map(|payload| match payload {
            Payload::Cert {
                encoding: 4, data, ..
            } => Some(data.clone()),
            _ => None,
        })
        .collect()
}

fn narrow_request_selectors(
    configured: &TrafficSelectorPair,
    payloads: &[Payload],
) -> Result<(Vec<TrafficSelector>, Vec<TrafficSelector>), IpsecError> {
    // TSi is the peer's local selector, which is our remote selector.
    let (peer_local, peer_remote) = ts_from_payloads(payloads)?;
    let local = narrow(&peer_remote, &configured.local)?;
    let remote = narrow(&peer_local, &configured.remote)?;
    Ok((local, remote))
}

fn narrow_response_selectors(
    configured: &TrafficSelectorPair,
    payloads: &[Payload],
) -> Result<(Vec<TrafficSelector>, Vec<TrafficSelector>), IpsecError> {
    let (selected_local, selected_remote) = ts_from_payloads(payloads)?;
    let local = narrow(&selected_local, &configured.local)?;
    let remote = narrow(&selected_remote, &configured.remote)?;
    Ok((local, remote))
}

fn ts_from_payloads(
    payloads: &[Payload],
) -> Result<(Vec<TrafficSelector>, Vec<TrafficSelector>), IpsecError> {
    let mut local = Vec::new();
    let mut remote = Vec::new();
    for payload in payloads {
        if let Payload::Ts {
            initiator,
            selectors,
        } = payload
        {
            for selector in selectors {
                let selector = ts_from_wire(selector)?;
                if *initiator {
                    local.push(selector);
                } else {
                    remote.push(selector);
                }
            }
        }
    }
    if local.is_empty() || remote.is_empty() {
        return Err(IpsecError::ike("IKE_AUTH is missing traffic selectors"));
    }
    Ok((local, remote))
}

fn narrow(
    requested: &[TrafficSelector],
    configured: &[TrafficSelector],
) -> Result<Vec<TrafficSelector>, IpsecError> {
    let mut selected = Vec::new();
    for selector in requested {
        for allowed in configured {
            if let Some(intersection) = selector.intersection(allowed)
                && !selected.contains(&intersection)
            {
                selected.push(intersection);
            }
        }
    }
    if selected.is_empty() {
        return Err(IpsecError::new(
            IpsecErrorKind::Proposal,
            "traffic selectors do not overlap with the configured selectors",
        ));
    }
    Ok(selected)
}

fn clone_handle(handle: &ChildSaHandle) -> ChildSaHandle {
    ChildSaHandle {
        local_spi: handle.local_spi,
        remote_spi: handle.remote_spi,
        encryption: handle.encryption,
        integrity: handle.integrity,
        esn: handle.esn,
        mode: handle.mode,
        local_selectors: handle.local_selectors.clone(),
        remote_selectors: handle.remote_selectors.clone(),
        outbound_key: handle.outbound_key.clone(),
        outbound_integrity_key: handle.outbound_integrity_key.clone(),
        inbound_key: handle.inbound_key.clone(),
        inbound_integrity_key: handle.inbound_integrity_key.clone(),
    }
}

fn stable_id(name: &str) -> u32 {
    let mut hash = 2_166_136_261u32;
    for byte in name.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash.max(1)
}
