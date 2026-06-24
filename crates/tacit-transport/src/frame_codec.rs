//! 协议帧编解码。
//!
//! 将 ControlMsg / DataFrame 编码为 v1.0 规范第 13 节定义的二进制帧格式，
//! 以及从二进制帧解码。
//!
//! 编解码使用 tacit_core::frame 中定义的 DiscoveryFrame / ControlFrame / DataFrameWire。

use tacit_core::{
    ControlFrame, ControlType, DataFrameKind, DataFrameWire, DiscoveryFrame, FrameError, Tlv,
};
use tacit_core::{DocId, PeerId};

use crate::control::{
    IntroducePeer, KeyRotateNotice, NeedRanges, PeerAnnouncement, RelayHints, TransportHints,
    RevokePeer,
};
use crate::ControlMsg as CMsg;

/// 将 ControlMsg 编码为 ControlFrame 二进制格式。
pub fn encode_control(msg: &CMsg, session_id: u64) -> Result<Vec<u8>, FrameError> {
    let (ctrl_type, payload) = control_msg_to_tlv(msg);
    let frame = ControlFrame::new(ctrl_type, session_id, payload);
    Ok(frame.encode())
}

/// 从二进制数据解码 ControlMsg。
pub fn decode_control(data: &[u8]) -> Result<(CMsg, u64), FrameError> {
    let frame = ControlFrame::decode(data)?;
    let msg = tlv_to_control_msg(frame.ctrl_type, &frame.payload)?;
    Ok((msg, frame.session_id))
}

/// 将 DataFrame（领域模型）编码为 DataFrameWire 二进制格式。
pub fn encode_data(
    doc_id: &DocId,
    actor_id: &PeerId,
    seq: u32,
    kind: DataFrameKind,
    payload: &[u8],
    batch_flag: tacit_core::BatchFlag,
    ref_id: [u8; 8],
) -> Vec<u8> {
    let frame = DataFrameWire::new(
        doc_id,
        actor_id,
        seq,
        kind,
        bytes::Bytes::copy_from_slice(payload),
        batch_flag,
        ref_id,
    );
    frame.encode()
}

/// 从二进制数据解码为 DataFrameWire。
pub fn decode_data(data: &[u8]) -> Result<DataFrameWire, FrameError> {
    DataFrameWire::decode(data)
}

/// 编码 DiscoveryFrame 为二进制格式。
pub fn encode_discovery(
    group_id: &str,
    device_id: &str,
    caps: tacit_core::AnchorCapabilities,
) -> Vec<u8> {
    let frame = DiscoveryFrame::from_presence(group_id, device_id, caps);
    frame.encode()
}

/// 从二进制数据解码 DiscoveryFrame。
pub fn decode_discovery(data: &[u8]) -> Result<DiscoveryFrame, FrameError> {
    DiscoveryFrame::decode(data)
}

/// 将 ControlMsg 转为 (ControlType, TLV payload)。
fn control_msg_to_tlv(msg: &CMsg) -> (ControlType, Vec<u8>) {
    match msg {
        CMsg::Capabilities(ann) => {
            let json = serde_json::to_vec(ann).unwrap_or_default();
            (ControlType::Capabilities, Tlv::encode(ControlType::Capabilities as u8, &json))
        }
        CMsg::KnownCheckpoint {
            peer_id,
            doc_id,
            checkpoint,
            frontier,
        } => {
            let json = serde_json::json!({
                "peer_id": peer_id.as_str(),
                "doc_id": doc_id.as_str(),
                "checkpoint": checkpoint.as_ref().map(|c| c.as_str()),
                "frontier": frontier,
            });
            let bytes = serde_json::to_vec(&json).unwrap_or_default();
            (ControlType::KnownCheckpoint, Tlv::encode(ControlType::KnownCheckpoint as u8, &bytes))
        }
        CMsg::AckSummary(ack) => {
            let json = serde_json::to_vec(ack).unwrap_or_default();
            (ControlType::AckSummary, Tlv::encode(ControlType::AckSummary as u8, &json))
        }
        CMsg::NeedRanges(ranges) => {
            let json = serde_json::to_vec(ranges).unwrap_or_default();
            (ControlType::NeedRanges, Tlv::encode(ControlType::NeedRanges as u8, &json))
        }
        CMsg::SyncIntent { peer_id, doc_id } => {
            let json = serde_json::json!({
                "peer_id": peer_id.as_str(),
                "doc_id": doc_id.as_str(),
            });
            let bytes = serde_json::to_vec(&json).unwrap_or_default();
            (ControlType::SyncIntent, Tlv::encode(ControlType::SyncIntent as u8, &bytes))
        }
        CMsg::TransportHints(hints) => {
            let json = serde_json::to_vec(hints).unwrap_or_default();
            (ControlType::TransportHints, Tlv::encode(ControlType::TransportHints as u8, &json))
        }
        CMsg::RelayHints(hints) => {
            let json = serde_json::to_vec(hints).unwrap_or_default();
            (ControlType::RelayHints, Tlv::encode(ControlType::RelayHints as u8, &json))
        }
        CMsg::Introduce(intro) => {
            let json = serde_json::to_vec(intro).unwrap_or_default();
            (ControlType::Introduce, Tlv::encode(ControlType::Introduce as u8, &json))
        }
        CMsg::Revoke(revoke) => {
            let json = serde_json::to_vec(revoke).unwrap_or_default();
            (ControlType::Revoke, Tlv::encode(ControlType::Revoke as u8, &json))
        }
        CMsg::KeyRotate(rotate) => {
            let json = serde_json::to_vec(rotate).unwrap_or_default();
            (ControlType::KeyRotate, Tlv::encode(ControlType::KeyRotate as u8, &json))
        }
    }
}

/// 将 (ControlType, TLV payload) 转为 ControlMsg。
fn tlv_to_control_msg(
    ctrl_type: ControlType,
    payload: &[u8],
) -> Result<CMsg, FrameError> {
    let entries = Tlv::decode_all(payload)?;
    let value = entries
        .first()
        .map(|(_, v)| v.as_slice())
        .unwrap_or(&[]);
    match ctrl_type {
        ControlType::Capabilities => {
            let ann: PeerAnnouncement = serde_json::from_slice(value)
                .map_err(|_| FrameError::UnknownControlType(ControlType::Capabilities as u8))?;
            Ok(CMsg::Capabilities(ann))
        }
        ControlType::KnownCheckpoint => {
            let json: serde_json::Value = serde_json::from_slice(value)
                .map_err(|_| FrameError::UnknownControlType(ControlType::KnownCheckpoint as u8))?;
            let peer_id = PeerId::new(json["peer_id"].as_str().unwrap_or(""));
            let doc_id = DocId::new(json["doc_id"].as_str().unwrap_or(""));
            let checkpoint = json["checkpoint"]
                .as_str()
                .map(tacit_core::CheckpointId::new);
            let frontier: tacit_core::Frontier = serde_json::from_value(json["frontier"].clone())
                .unwrap_or_default();
            Ok(CMsg::KnownCheckpoint {
                peer_id,
                doc_id,
                checkpoint,
                frontier,
            })
        }
        ControlType::AckSummary => {
            let ack: tacit_core::AckSummary = serde_json::from_slice(value)
                .map_err(|_| FrameError::UnknownControlType(ControlType::AckSummary as u8))?;
            Ok(CMsg::AckSummary(ack))
        }
        ControlType::NeedRanges => {
            let ranges: NeedRanges = serde_json::from_slice(value)
                .map_err(|_| FrameError::UnknownControlType(ControlType::NeedRanges as u8))?;
            Ok(CMsg::NeedRanges(ranges))
        }
        ControlType::SyncIntent => {
            let json: serde_json::Value = serde_json::from_slice(value)
                .map_err(|_| FrameError::UnknownControlType(ControlType::SyncIntent as u8))?;
            let peer_id = PeerId::new(json["peer_id"].as_str().unwrap_or(""));
            let doc_id = DocId::new(json["doc_id"].as_str().unwrap_or(""));
            Ok(CMsg::SyncIntent { peer_id, doc_id })
        }
        ControlType::TransportHints => {
            let hints: TransportHints = serde_json::from_slice(value)
                .map_err(|_| FrameError::UnknownControlType(ControlType::TransportHints as u8))?;
            Ok(CMsg::TransportHints(hints))
        }
        ControlType::RelayHints => {
            let hints: RelayHints = serde_json::from_slice(value)
                .map_err(|_| FrameError::UnknownControlType(ControlType::RelayHints as u8))?;
            Ok(CMsg::RelayHints(hints))
        }
        ControlType::Introduce => {
            let intro: IntroducePeer = serde_json::from_slice(value)
                .map_err(|_| FrameError::UnknownControlType(ControlType::Introduce as u8))?;
            Ok(CMsg::Introduce(intro))
        }
        ControlType::Revoke => {
            let revoke: RevokePeer = serde_json::from_slice(value)
                .map_err(|_| FrameError::UnknownControlType(ControlType::Revoke as u8))?;
            Ok(CMsg::Revoke(revoke))
        }
        ControlType::KeyRotate => {
            let rotate: KeyRotateNotice = serde_json::from_slice(value)
                .map_err(|_| FrameError::UnknownControlType(ControlType::KeyRotate as u8))?;
            Ok(CMsg::KeyRotate(rotate))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_core::{AckSummary, AnchorCapabilities, Frontier};

    #[test]
    fn encode_decode_control_ack() {
        let ack = AckSummary {
            peer_id: PeerId::new("1"),
            doc_id: DocId::new("d1"),
            ack_checkpoint: None,
            ack_frontier: Frontier::new(),
            updated_at: std::time::SystemTime::now(),
        };
        let msg = CMsg::AckSummary(ack);
        let encoded = encode_control(&msg, 42).unwrap();
        let (decoded, sid) = decode_control(&encoded).unwrap();
        assert_eq!(sid, 42);
        assert!(matches!(decoded, CMsg::AckSummary(_)));
    }

    #[test]
    fn encode_decode_control_capabilities() {
        let ann = PeerAnnouncement {
            peer_id: PeerId::new("1"),
            capabilities: AnchorCapabilities {
                can_anchor: true,
                ..Default::default()
            },
            frontier: Frontier::new(),
        };
        let msg = CMsg::Capabilities(ann);
        let encoded = encode_control(&msg, 1).unwrap();
        let (decoded, _) = decode_control(&encoded).unwrap();
        assert!(matches!(decoded, CMsg::Capabilities(_)));
    }

    #[test]
    fn encode_decode_data_frame() {
        let doc_id = DocId::new("doc1");
        let actor_id = PeerId::new("42");
        let encoded = encode_data(
            &doc_id,
            &actor_id,
            99,
            DataFrameKind::Delta,
            b"hello",
            tacit_core::BatchFlag::Single,
            [0u8; 8],
        );
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded.seq, 99);
        assert_eq!(decoded.payload.as_ref(), b"hello");
        assert_eq!(decoded.batch_flag(), tacit_core::BatchFlag::Single);
    }

    #[test]
    fn encode_decode_discovery() {
        let caps = AnchorCapabilities {
            can_anchor: true,
            can_relay: true,
            persistent: false,
        };
        let encoded = encode_discovery("group1", "device1", caps);
        let decoded = decode_discovery(&encoded).unwrap();
        assert_eq!(decoded.capabilities(), caps);
    }

    #[test]
    fn encode_decode_transport_hints() {
        let hints = TransportHints {
            peer_id: PeerId::new("1"),
            preferred_path: "lan".to_string(),
            mtu: Some(1200),
        };
        let msg = CMsg::TransportHints(hints);
        let encoded = encode_control(&msg, 7).unwrap();
        let (decoded, sid) = decode_control(&encoded).unwrap();
        assert_eq!(sid, 7);
        match decoded {
            CMsg::TransportHints(h) => {
                assert_eq!(h.preferred_path, "lan");
                assert_eq!(h.mtu, Some(1200));
            }
            _ => panic!("期望 TransportHints"),
        }
    }

    #[test]
    fn encode_decode_relay_hints() {
        let hints = RelayHints {
            peer_id: PeerId::new("1"),
            relay_addr: "relay.example.com:443".to_string(),
            requires_auth: true,
        };
        let msg = CMsg::RelayHints(hints);
        let encoded = encode_control(&msg, 3).unwrap();
        let (decoded, _) = decode_control(&encoded).unwrap();
        match decoded {
            CMsg::RelayHints(h) => {
                assert_eq!(h.relay_addr, "relay.example.com:443");
                assert!(h.requires_auth);
            }
            _ => panic!("期望 RelayHints"),
        }
    }

    #[test]
    fn encode_decode_introduce() {
        let intro = IntroducePeer {
            introducer: PeerId::new("1"),
            introduced_peer: PeerId::new("2"),
            introduced_pubkey_hex: "abcdef0123456789".to_string(),
            endpoint: Some("192.168.1.10:8080".to_string()),
        };
        let msg = CMsg::Introduce(intro);
        let encoded = encode_control(&msg, 5).unwrap();
        let (decoded, _) = decode_control(&encoded).unwrap();
        match decoded {
            CMsg::Introduce(i) => {
                assert_eq!(i.introduced_peer, PeerId::new("2"));
                assert_eq!(i.introduced_pubkey_hex, "abcdef0123456789");
                assert_eq!(i.endpoint, Some("192.168.1.10:8080".to_string()));
            }
            _ => panic!("期望 Introduce"),
        }
    }

    #[test]
    fn encode_decode_revoke() {
        let revoke = RevokePeer {
            revoker: PeerId::new("1"),
            revoked_peer: PeerId::new("2"),
            reason: "compromised".to_string(),
        };
        let msg = CMsg::Revoke(revoke);
        let encoded = encode_control(&msg, 9).unwrap();
        let (decoded, _) = decode_control(&encoded).unwrap();
        match decoded {
            CMsg::Revoke(r) => {
                assert_eq!(r.revoked_peer, PeerId::new("2"));
                assert_eq!(r.reason, "compromised");
            }
            _ => panic!("期望 Revoke"),
        }
    }

    #[test]
    fn encode_decode_key_rotate() {
        let rotate = KeyRotateNotice {
            peer_id: PeerId::new("1"),
            new_pubkey_hex: "deadbeef".to_string(),
            rotation_seq: 42,
        };
        let msg = CMsg::KeyRotate(rotate);
        let encoded = encode_control(&msg, 11).unwrap();
        let (decoded, _) = decode_control(&encoded).unwrap();
        match decoded {
            CMsg::KeyRotate(k) => {
                assert_eq!(k.new_pubkey_hex, "deadbeef");
                assert_eq!(k.rotation_seq, 42);
            }
            _ => panic!("期望 KeyRotate"),
        }
    }
}
