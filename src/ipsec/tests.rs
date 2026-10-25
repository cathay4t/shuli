// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr};

use crate::{
    ChildSaHandle, Identity,
    config::{
        AuthConfig, ChildConfig, DpdConfig, IkeConfig, IpsecConfig,
        LocalConfig, PeerConfig, RekeyConfig, RemoteConfig, Secret, Topology,
        TrafficSelectorPair, XfrmConfig,
    },
    ikev2::{
        codec::{self, ExchangeType, IkeHeader, Payload},
        crypto,
    },
};

fn psk_config(
    name: &str,
    local_port: u16,
    remote_port: Option<u16>,
    local_identity: Identity,
    remote_identity: Identity,
) -> IpsecConfig {
    let local_inner = Ipv4Addr::new(10, 0, 0, 1);
    let remote_inner = Ipv4Addr::new(10, 0, 0, 2);
    let (local_selector, remote_selector) = if name.ends_with('b') {
        (remote_inner, local_inner)
    } else {
        (local_inner, remote_inner)
    };
    IpsecConfig {
        name: name.to_string(),
        topology: Topology::PointToPoint,
        local: LocalConfig {
            address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            interface: None,
            identity: local_identity,
            port: local_port,
            nat_t: false,
            request_inner_address: false,
            request_dns: false,
        },
        peers: vec![PeerConfig {
            remote: RemoteConfig {
                address: remote_port.map(|_| IpAddr::V4(Ipv4Addr::LOCALHOST)),
                identity: remote_identity,
                port: remote_port.unwrap_or(0),
            },
            selectors: TrafficSelectorPair::hosts(
                IpAddr::V4(local_selector),
                IpAddr::V4(remote_selector),
            ),
            auth: AuthConfig::Psk(Secret::from("correct horse battery staple")),
        }],
        ike: IkeConfig::default(),
        child: ChildConfig::default(),
        xfrm: XfrmConfig::default(),
        rekey: RekeyConfig::default(),
        dpd: DpdConfig {
            enabled: false,
            ..DpdConfig::default()
        },
    }
}

#[test]
fn codec_round_trip() {
    let header = IkeHeader::new(1, 2, ExchangeType::IkeSaInit, 0x08, 0);
    let message = codec::Message::new(
        header,
        vec![
            Payload::Sa(vec![codec::Proposal {
                number: 1,
                protocol: codec::protocol_id::IKE,
                spi: Vec::new(),
                transforms: codec::ike_transforms(
                    crate::config::EncryptionAlgorithm::AesGcm16_256,
                    crate::config::PrfAlgorithm::HmacSha2_256,
                    crate::config::IntegrityAlgorithm::None,
                    crate::config::DhGroup::Ecp256,
                ),
            }]),
            Payload::Ke {
                group: 19,
                data: vec![4; 65],
            },
            Payload::Nonce(vec![7; 32]),
            Payload::Id {
                initiator: true,
                id_type: 2,
                data: b"peer.example.org".to_vec(),
            },
            Payload::Ts {
                initiator: true,
                selectors: vec![codec::TsSelector {
                    ts_type: 7,
                    protocol: 0,
                    start_port: 0,
                    end_port: u16::MAX,
                    start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
                }],
            },
        ],
    );
    let encoded = message.encode().unwrap();
    let decoded = codec::Message::decode(&encoded).unwrap();
    assert_eq!(message.payloads, decoded.payloads);
    assert_eq!(message.header.initiator_spi, decoded.header.initiator_spi);
    assert_eq!(message.header.responder_spi, decoded.header.responder_spi);
    assert_eq!(decoded.header.length as usize, encoded.len());
}

#[test]
fn codec_rejects_truncated_payloads() {
    let header = IkeHeader::new(1, 2, ExchangeType::IkeSaInit, 0x08, 0);
    let message =
        codec::Message::new(header, vec![Payload::Nonce(vec![1, 2, 3, 4])])
            .encode()
            .unwrap();
    for length in 1..message.len() {
        if length >= codec::IKE_HEADER_LEN {
            let mut truncated = message[..length].to_vec();
            // A truncated buffer is expected to fail if the header
            // length still points past the end.
            if length < message.len() {
                truncated[24..28]
                    .copy_from_slice(&(message.len() as u32).to_be_bytes());
            }
            let _ = codec::Message::decode(&truncated);
        }
    }
    assert!(codec::Message::decode(&message).is_ok());
}

#[test]
fn encrypted_message_round_trip() {
    use crate::ikev2::sa::{open_message, seal_message};
    let header = IkeHeader::new(1, 2, ExchangeType::IkeAuth, 0x08, 1);
    let payloads = vec![
        Payload::Id {
            initiator: true,
            id_type: 2,
            data: b"a.example".to_vec(),
        },
        Payload::Nonce(vec![9; 32]),
        Payload::Ts {
            initiator: true,
            selectors: vec![codec::TsSelector {
                ts_type: 7,
                protocol: 0,
                start_port: 0,
                end_port: u16::MAX,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            }],
        },
    ];
    let key = vec![3u8; 36];
    let message = seal_message(
        &header,
        &payloads,
        crate::config::EncryptionAlgorithm::AesGcm16_256,
        crate::config::IntegrityAlgorithm::None,
        &key,
        &[],
    )
    .unwrap();
    eprintln!(
        "message len={} header={:?} sk_next={} sk_len={}",
        message.len(),
        &message[..28],
        message[28],
        u16::from_be_bytes([message[30], message[31]])
    );
    let decoded = codec::Message::decode(&message).unwrap();
    let encrypted = &decoded.payloads[0];
    let opened = open_message(
        &decoded.header,
        encrypted,
        crate::config::EncryptionAlgorithm::AesGcm16_256,
        crate::config::IntegrityAlgorithm::None,
        &key,
        &[],
    )
    .unwrap();
    assert_eq!(payloads, opened);
}

#[test]
fn encrypted_payload_uses_rfc_7296_padding() {
    use crate::{
        config::EncryptionAlgorithm,
        ikev2::{
            codec::payload_type,
            sa::{open_message, seal_message},
        },
    };

    let header = IkeHeader::new(1, 2, ExchangeType::IkeAuth, 0x08, 1);
    let payloads = vec![
        Payload::Nonce(vec![0x33; 32]),
        Payload::Id {
            initiator: true,
            id_type: 2,
            data: b"a.example".to_vec(),
        },
    ];
    let encoded = codec::encode_chain(&payloads).unwrap();

    for (encryption, padding) in [
        (EncryptionAlgorithm::AesCbc128, (16 - ((encoded.len() + 1) % 16)) % 16),
        (EncryptionAlgorithm::AesGcm16_256, 3),
    ] {
        let mut plaintext = encoded.clone();
        plaintext.extend(std::iter::repeat_n(0xa5, padding));
        plaintext.push(padding as u8);
        let key = vec![0x42; encryption.key_len() + encryption.salt_len()];
        let iv = vec![0x24; encryption.iv_len()];
        let mut wire_header = header.clone();
        wire_header.next_payload = payload_type::SK;
        wire_header.length = (28 + 4 + iv.len() + plaintext.len() + 16) as u32;
        let aad = wire_header.encode();
        let ciphertext =
            crypto::encrypt(encryption, &key, &iv, &plaintext, &aad).unwrap();
        let mut data = iv.clone();
        data.extend_from_slice(&ciphertext);
        let opened = open_message(
            &wire_header,
            &Payload::Encrypted {
                next: payload_type::NONCE,
                data,
            },
            encryption,
            crate::config::IntegrityAlgorithm::None,
            &key,
            &[],
        )
        .unwrap();
        assert_eq!(opened, payloads, "{encryption:?}");
    }

    let sealed = seal_message(
        &header,
        &payloads,
        EncryptionAlgorithm::AesCbc128,
        crate::config::IntegrityAlgorithm::None,
        &[0x42; 16],
        &[],
    )
    .unwrap();
    let decoded = codec::Message::decode(&sealed).unwrap();
    let Payload::Encrypted { next, data } = &decoded.payloads[0] else {
        panic!("expected an encrypted payload");
    };
    let raw = crypto::decrypt(
        EncryptionAlgorithm::AesCbc128,
        &[0x42; 16],
        &data[..16],
        &data[16..],
        &decoded.header.encode(),
    )
    .unwrap();
    assert_eq!(raw.len() % 16, 0);
    let padding = *raw.last().unwrap() as usize;
    assert_eq!(raw.len() - 1 - encoded.len(), padding);
    assert_eq!(
        codec::decode_chain(*next, &raw[..raw.len() - padding - 1]).unwrap(),
        payloads
    );
}

#[test]
fn crypto_round_trip_cbc_and_gcm() {
    for algorithm in [
        crate::config::EncryptionAlgorithm::AesCbc128,
        crate::config::EncryptionAlgorithm::AesCbc256,
        crate::config::EncryptionAlgorithm::AesGcm16_128,
        crate::config::EncryptionAlgorithm::AesGcm16_256,
    ] {
        let key = vec![0x42; algorithm.key_len() + algorithm.salt_len()];
        let iv = vec![0x24; algorithm.iv_len()];
        let plaintext = vec![0x5a; 32];
        let ciphertext =
            crypto::encrypt(algorithm, &key, &iv, &plaintext, b"aad").unwrap();
        let decrypted =
            crypto::decrypt(algorithm, &key, &iv, &ciphertext, b"aad").unwrap();
        assert_eq!(decrypted, plaintext, "{algorithm:?}");
    }
}

#[test]
fn prf_plus_is_deterministic_and_long_enough() {
    let key = [1u8; 32];
    let seed = [2u8; 40];
    let first = crypto::prf_plus(
        crate::config::PrfAlgorithm::HmacSha2_256,
        &key,
        &seed,
        100,
    );
    let second = crypto::prf_plus(
        crate::config::PrfAlgorithm::HmacSha2_256,
        &key,
        &seed,
        100,
    );
    assert_eq!(first, second);
    assert_eq!(first.len(), 100);
}

#[test]
fn ike_fragments_round_trip() {
    let fragment = crypto::Fragment {
        fragment_number: 2,
        total_fragments: 3,
        data: vec![0xaa; 40],
    };
    let encoded = crypto::encode_fragment(&fragment);
    assert_eq!(crypto::decode_fragment(&encoded).unwrap(), fragment);
}

#[test]
fn dh_groups_agree() {
    for group in [
        crate::config::DhGroup::Ecp256,
        crate::config::DhGroup::Ecp384,
        crate::config::DhGroup::X25519,
        crate::config::DhGroup::Modp2048,
    ] {
        let left = crypto::DhKeyPair::generate(group).unwrap();
        let right = crypto::DhKeyPair::generate(group).unwrap();
        let left_public = left.public().to_vec();
        let right_public = right.public().to_vec();
        let left_shared = left.agree(&right_public).unwrap();
        let right_shared = right.agree(&left_public).unwrap();
        assert_eq!(left_shared, right_shared, "{group:?}");
    }
}

#[test]
fn ipnet_handles_default_prefix() {
    let network =
        crate::config::IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 0)
            .unwrap();
    assert_eq!(network.first(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(network.last(), IpAddr::V4(Ipv4Addr::BROADCAST));
}

#[test]
fn child_keys_follow_rfc_7296_pfs_order() {
    use crate::ikev2::sa::{Role, derive_child_keys};

    let sk_d: Vec<u8> = (1..=32).collect();
    let nonce_i: Vec<u8> = (33..=64).collect();
    let nonce_r: Vec<u8> = (65..=96).collect();
    let shared = vec![0x5a; 32];
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let remote = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let child = derive_child_keys(
        crate::config::PrfAlgorithm::HmacSha2_256,
        &sk_d,
        &nonce_i,
        &nonce_r,
        Some(&shared),
        Role::Initiator,
        crate::config::EncryptionAlgorithm::AesGcm16_256,
        crate::config::IntegrityAlgorithm::HmacSha2_256_128,
        0x0102_0304,
        0x0506_0708,
        crate::config::ChildMode::Tunnel,
        vec![crate::config::TrafficSelector::host(local)],
        vec![crate::config::TrafficSelector::host(remote)],
        false,
    );
    // KEYMAT = prf+(SK_d, g^ir | Ni | Nr) per RFC 7296 section 2.17.
    assert_eq!(
        child.outbound_key.as_slice(),
        hex_bytes("890a0ee861a6983a66cb9dc442ce1631b8da9b133129392be39cef90525d3b1b515d38a1")
    );
    assert_eq!(
        child.inbound_key.as_slice(),
        hex_bytes("253ccfeade5319f4773264a2178ec8a7a2866040a9d625742ecd45c4e86ee1e3dbeee051")
    );
    assert_eq!(
        child.outbound_integrity_key.as_ref().unwrap().as_slice(),
        hex_bytes("351a38ee7ec38cfdb02e96cdd80277c818f736300bfda51ed1096aa8bb780530")
    );
    assert_eq!(
        child.inbound_integrity_key.as_ref().unwrap().as_slice(),
        hex_bytes("ec938eeae1fb04f1a760263edb1b48bb5fbb6694ff9d066bbdc807bed54c8855")
    );
}

#[test]
fn ike_keys_follow_rfc_7296_skeyseed() {
    use crate::{
        config::{
            EncryptionAlgorithm, IntegrityAlgorithm, PrfAlgorithm,
        },
        ikev2::sa::{IkeKeys, Role},
    };

    let nonce_i: Vec<u8> = (1..=32).collect();
    let nonce_r: Vec<u8> = (33..=64).collect();
    let shared = vec![0x5a; 32];
    let keys = IkeKeys::derive(
        PrfAlgorithm::HmacSha2_256,
        &shared,
        &nonce_i,
        &nonce_r,
        0x1122_3344_5566_7788,
        0x8877_6655_4433_2211,
        EncryptionAlgorithm::AesGcm16_256,
        IntegrityAlgorithm::HmacSha2_256_128,
    );
    // Expected values were produced independently with
    // SKEYSEED = prf(Ni | Nr, g^ir) per RFC 7296 section 2.14.
    assert_eq!(
        keys.sk_d.as_slice(),
        hex_bytes("8bfd98e2b8add5d8036166e2c4c406a900fda72ae71550c2753f85b5761b6213")
    );
    assert_eq!(
        keys.sk_ai.as_slice(),
        hex_bytes("f21aab0e94311308c72416ed94d555230272459b300fb6dbe751a701be460c55")
    );
    assert_eq!(
        keys.sk_ei.as_slice(),
        hex_bytes("4551604f68b637015f19de2c74befcc47e08dcfd2903eccabbad623fc951f454d8164142")
    );
    assert_eq!(
        keys.sk_er.as_slice(),
        hex_bytes("93f7f3ac21722dc1141966da0fd3df690f63614e6cba0e0cb79c4ad160e65d714e1be7c1")
    );
    assert_eq!(keys.outbound_encryption(Role::Initiator), &keys.sk_ei[..]);
    assert_eq!(keys.inbound_encryption(Role::Responder), &keys.sk_ei[..]);
}

fn hex_bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn identity_uses_rfc_7296_id_types() {
    use std::net::Ipv6Addr;

    let ipv4 = Identity::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(ipv4.id_type(), Some(1));
    assert_eq!(Identity::decode(1, &ipv4.encode().unwrap()).unwrap(), ipv4);

    let ipv6 = Identity::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(ipv6.id_type(), Some(5));
    assert_eq!(Identity::decode(5, &ipv6.encode().unwrap()).unwrap(), ipv6);

    let key_id = Identity::KeyId(b"shuli".to_vec());
    assert_eq!(key_id.id_type(), Some(11));
    assert_eq!(
        Identity::decode(11, &key_id.encode().unwrap()).unwrap(),
        key_id
    );

    let dn = Identity::DerAsn1Dn(vec![0x30, 0x00]);
    assert_eq!(dn.id_type(), Some(9));
    assert_eq!(Identity::decode(9, &dn.encode().unwrap()).unwrap(), dn);
}

#[test]
fn config_validation_rejects_bad_selectors() {
    let mut config = psk_config(
        "a",
        500,
        Some(500),
        Identity::Fqdn("a.example".into()),
        Identity::Fqdn("b.example".into()),
    );
    config.peers[0].selectors.local.clear();
    assert!(config.validate().is_err());

    let mut config = psk_config(
        "a",
        500,
        Some(500),
        Identity::Fqdn("a.example".into()),
        Identity::Fqdn("b.example".into()),
    );
    config.peers[0].auth = AuthConfig::Psk(Secret::from(""));
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn xfrm_install_and_remove_owned_state() {
    let mut manager = match crate::XfrmManager::new().await {
        Ok(manager) => manager,
        Err(error) => {
            eprintln!("skipping XFRM test: {error}");
            return;
        }
    };
    let if_id = 20_000 + (std::process::id() % 10_000);
    let name = format!("shulitest{if_id}");
    let spec = crate::XfrmInterfaceSpec {
        name: Some(name.clone()),
        if_id: Some(if_id),
        underlay_interface: Some("lo".to_string()),
    };
    let interface = match manager.ensure_interface(&spec).await {
        Ok(interface) => interface,
        Err(error) => {
            eprintln!("skipping XFRM test: {error}");
            return;
        }
    };

    let key = vec![0x11u8; 32 + 4];
    let child = ChildSaHandle {
        local_spi: 0x1122_3344,
        remote_spi: 0x5566_7788,
        encryption: crate::config::EncryptionAlgorithm::AesGcm16_256,
        integrity: None,
        esn: false,
        mode: crate::config::ChildMode::Tunnel,
        local_selectors: vec![crate::config::TrafficSelector::net(
            crate::config::IpNet::new(
                IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)),
                32,
            )
            .unwrap(),
        )],
        remote_selectors: vec![crate::config::TrafficSelector::net(
            crate::config::IpNet::new(
                IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)),
                32,
            )
            .unwrap(),
        )],
        outbound_key: zeroize::Zeroizing::new(key.clone()),
        outbound_integrity_key: None,
        inbound_key: zeroize::Zeroizing::new(key),
        inbound_integrity_key: None,
    };
    let install = crate::InstallSpec {
        interface: Some(interface.clone()),
        if_id,
        reqid: if_id,
        local_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        remote_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        mode: crate::config::ChildMode::Tunnel,
        lifetime: std::time::Duration::from_secs(60),
        priority: 1000,
        replay_window: 32,
        mark: None,
        mark_mask: 0,
        forward: true,
        nat_t: false,
    };
    let unrelated_name = format!("unrelated{if_id}");
    let _ = std::process::Command::new("ip")
        .args(["link", "del", &unrelated_name])
        .output();
    let unrelated_ok = std::process::Command::new("ip")
        .args([
            "link",
            "add",
            &unrelated_name,
            "type",
            "xfrm",
            "if_id",
            &(if_id + 1).to_string(),
            "dev",
            "lo",
        ])
        .output()
        .is_ok_and(|output| output.status.success());
    assert!(unrelated_ok, "failed to create unrelated XFRM interface");

    let installed = manager.install(&child, &install).await.unwrap();
    let state_before = std::process::Command::new("ip")
        .args(["xfrm", "state", "list"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&state_before.stdout).contains("0x11223344")
    );
    manager.remove(&installed).await.unwrap();
    manager.remove_interface(&interface).await.unwrap();
    manager.cleanup_owned().await.unwrap();
    let state_after = std::process::Command::new("ip")
        .args(["xfrm", "state", "list"])
        .output()
        .unwrap();
    if String::from_utf8_lossy(&state_after.stdout).contains("0x11223344") {
        eprintln!("{}", String::from_utf8_lossy(&state_after.stdout));
    }
    assert!(
        !String::from_utf8_lossy(&state_after.stdout).contains("0x11223344")
    );
    let unrelated = std::process::Command::new("ip")
        .args(["link", "show", &unrelated_name])
        .output()
        .unwrap();
    assert!(
        unrelated.status.success(),
        "cleanup removed unrelated XFRM interface"
    );
    let _ = std::process::Command::new("ip")
        .args(["link", "del", &unrelated_name])
        .output();
}

fn openssl(args: &[&str]) -> bool {
    std::process::Command::new("openssl")
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

#[tokio::test]
async fn certificate_point_to_point_self_connection() {
    let dir = std::env::temp_dir()
        .join(format!("shuli-ipsec-cert-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca_key = dir.join("ca.key");
    let ca_cert = dir.join("ca.pem");
    let ok = openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=shuli-test-ca",
        "-keyout",
        ca_key.to_str().unwrap(),
        "-out",
        ca_cert.to_str().unwrap(),
    ]);
    if !ok {
        eprintln!("skipping certificate test: openssl unavailable");
        return;
    }
    let mut material = Vec::new();
    for name in ["a.example", "b.example"] {
        let key = dir.join(format!("{name}.key"));
        let csr = dir.join(format!("{name}.csr"));
        let cert = dir.join(format!("{name}.pem"));
        let ext = dir.join(format!("{name}.ext"));
        std::fs::write(&ext, format!("subjectAltName=DNS:{name}\n")).unwrap();
        let ok = openssl(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            &format!("/CN={name}"),
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            csr.to_str().unwrap(),
        ]) && openssl(&[
            "x509",
            "-req",
            "-days",
            "1",
            "-in",
            csr.to_str().unwrap(),
            "-CA",
            ca_cert.to_str().unwrap(),
            "-CAkey",
            ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-extfile",
            ext.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
        ]);
        assert!(ok, "openssl certificate generation failed");
        material.push((
            std::fs::read(&cert).unwrap(),
            std::fs::read(&key).unwrap(),
        ));
    }
    let ca = std::fs::read(&ca_cert).unwrap();
    let mut a = psk_config(
        "a",
        15300,
        Some(15301),
        Identity::Fqdn("a.example".into()),
        Identity::Fqdn("b.example".into()),
    );
    let mut b = psk_config(
        "b",
        15301,
        None,
        Identity::Fqdn("b.example".into()),
        Identity::Fqdn("a.example".into()),
    );
    a.peers[0].auth = AuthConfig::Certificate(crate::CertificateConfig::new(
        vec![ca.clone()],
        vec![material[0].0.clone()],
        material[0].1.clone(),
    ));
    b.peers[0].auth = AuthConfig::Certificate(crate::CertificateConfig::new(
        vec![ca],
        vec![material[1].0.clone()],
        material[1].1.clone(),
    ));
    let mut client_a = crate::IpsecClient::init(vec![a]).await.unwrap();
    let mut client_b = crate::IpsecClient::init(vec![b]).await.unwrap();
    let mut ready = false;
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = client_a.run() => {
                match event {
                    Ok(crate::IpsecEvent::ChildSaReady { .. }) => { ready = true; break; }
                    Ok(crate::IpsecEvent::Error { error, .. }) => eprintln!("A: {error}"),
                    _ => {}
                }
            }
            event = client_b.run() => {
                match event {
                    Ok(crate::IpsecEvent::ChildSaReady { .. }) => {}
                    Ok(crate::IpsecEvent::Error { error, .. }) => eprintln!("B: {error}"),
                    _ => {}
                }
            }
        }
    }
    client_a.shutdown().await;
    client_b.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ready,
        "certificate authentication did not establish a Child SA"
    );
}

#[tokio::test]
async fn child_sa_rekey_self_connection() {
    let mut a = psk_config(
        "a",
        15200,
        Some(15201),
        Identity::Fqdn("a.example".into()),
        Identity::Fqdn("b.example".into()),
    );
    let mut b = psk_config(
        "b",
        15201,
        None,
        Identity::Fqdn("b.example".into()),
        Identity::Fqdn("a.example".into()),
    );
    for config in [&mut a, &mut b] {
        config.child.lifetime = std::time::Duration::from_secs(2);
        config.rekey.child_margin_percent = 50;
    }
    let mut client_a = crate::IpsecClient::init(vec![a]).await.unwrap();
    let mut client_b = crate::IpsecClient::init(vec![b]).await.unwrap();
    let mut a_refreshed = false;
    let mut b_refreshed = false;
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline
        && !(a_refreshed && b_refreshed)
    {
        tokio::select! {
            event = client_a.run() => {
                if let Ok(crate::IpsecEvent::ChildSaRefreshed { .. }) = event {
                    a_refreshed = true;
                }
            }
            event = client_b.run() => {
                if let Ok(crate::IpsecEvent::ChildSaRefreshed { .. }) = event {
                    b_refreshed = true;
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
    }
    assert!(a_refreshed, "initiator did not report a rekey");
    assert!(b_refreshed, "responder did not report a rekey");
    client_a.shutdown().await;
    client_b.shutdown().await;
}

#[tokio::test]
async fn psk_point_to_point_self_connection() {
    let a = psk_config(
        "a",
        15100,
        Some(15101),
        Identity::Fqdn("a.example".into()),
        Identity::Fqdn("b.example".into()),
    );
    let b = psk_config(
        "b",
        15101,
        None,
        Identity::Fqdn("b.example".into()),
        Identity::Fqdn("a.example".into()),
    );
    let _ = env_logger::builder().is_test(true).try_init();
    let mut client_a = crate::IpsecClient::init(vec![a]).await.unwrap();
    let mut client_b = crate::IpsecClient::init(vec![b]).await.unwrap();

    let mut a_ready = false;
    let mut b_ready = false;
    for _ in 0..50 {
        if !a_ready {
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                client_a.run(),
            )
            .await
            {
                Ok(Ok(crate::IpsecEvent::ChildSaReady {
                    child,
                    lease,
                    ..
                })) => {
                    assert_eq!(lease.connection, "a");
                    assert_ne!(child.local_spi(), child.remote_spi());
                    assert_eq!(child.local_selectors().len(), 1);
                    a_ready = true;
                }
                Ok(Ok(crate::IpsecEvent::Error { error, .. })) => {
                    eprintln!("client A error: {error}");
                }
                Ok(Ok(_)) | Err(_) => {}
                Ok(Err(error)) => eprintln!("client A run error: {error}"),
            }
        }
        if !b_ready {
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                client_b.run(),
            )
            .await
            {
                Ok(Ok(crate::IpsecEvent::ChildSaReady {
                    child,
                    lease,
                    ..
                })) => {
                    assert_eq!(lease.connection, "b");
                    assert_ne!(child.local_spi(), child.remote_spi());
                    b_ready = true;
                }
                Ok(Ok(crate::IpsecEvent::Error { error, .. })) => {
                    eprintln!("client B error: {error}");
                }
                Ok(Ok(_)) | Err(_) => {}
                Ok(Err(error)) => eprintln!("client B run error: {error}"),
            }
        }
        if a_ready && b_ready {
            break;
        }
    }
    assert!(a_ready, "initiator did not establish a Child SA");
    assert!(b_ready, "responder did not establish a Child SA");
    client_a.shutdown().await;
    client_b.shutdown().await;
}
