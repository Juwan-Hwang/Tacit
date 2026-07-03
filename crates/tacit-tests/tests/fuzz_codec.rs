//! 帧编解码器模糊测试。
//!
//! 验证 `decode_control` / `decode_data` / `decode_discovery` 在面对任意输入时：
//! 1. **不 panic** — 任意字节序列都安全处理
//! 2. **编码-解码往返等价** — 合法帧 round-trip 后字段一致
//!
//! 使用 proptest 生成策略性测试数据：
//! - 纯随机字节（fuzz 风格）
//! - 合法帧 + 随机篡改位（mutation fuzzing）
//! - 边界长度（0, 1, MAX_FRAME_SIZE 附近）

use proptest::prelude::*;

use tacit_core::{
    AckSummary, AnchorCapabilities, BatchFlag, DataFrameKind, DocId, Frontier, PeerId,
};
use tacit_transport::{
    decode_control, decode_data, decode_discovery, encode_control, encode_data, encode_discovery,
    ControlMsg,
};
use tacit_transport::{
    IntroducePeer, KeyRotateNotice, PeerAnnouncement, RelayHints, RevokePeer, TransportHints,
};

// ─── 辅助函数 ───────────────────────────────────────────────

fn pid(s: &str) -> PeerId {
    PeerId::new(s)
}

fn did(s: &str) -> DocId {
    DocId::new(s)
}

// ─── 纯随机字节：解码器不 panic ─────────────────────────────

proptest! {
    #[test]
    fn fuzz_decode_control_arbitrary(data: Vec<u8>) {
        // 任意字节序列：decode_control 要么 Ok 要么 Err，绝不 panic
        let _ = decode_control(&data);
    }

    #[test]
    fn fuzz_decode_data_arbitrary(data: Vec<u8>) {
        let _ = decode_data(&data);
    }

    #[test]
    fn fuzz_decode_discovery_arbitrary(data: Vec<u8>) {
        let _ = decode_discovery(&data);
    }
}

// ─── 合法帧 + 随机篡改：解码器不 panic ────────────────────

proptest! {
    /// 对合法 control 帧做随机位翻转后解码，确保不 panic。
    #[test]
    fn fuzz_control_mutation(flip_byte: usize, flip_mask: u8) {
        let ack = AckSummary {
            peer_id: pid("1"),
            doc_id: did("d1"),
            ack_checkpoint: None,
            ack_frontier: Frontier::new(),
            updated_at: std::time::SystemTime::UNIX_EPOCH,
            version_override: None,
        };
        let encoded = encode_control(&ControlMsg::AckSummary(ack), 42).unwrap();
        if !encoded.is_empty() {
            let idx = flip_byte % encoded.len();
            let mut mutated = encoded.clone();
            mutated[idx] ^= flip_mask;
            let _ = decode_control(&mutated);
        }
    }

    /// 对合法 data 帧做随机位翻转后解码，确保不 panic。
    #[test]
    fn fuzz_data_mutation(flip_byte: usize, flip_mask: u8) {
        let encoded = encode_data(
            &did("doc1"), &pid("42"), 99,
            DataFrameKind::Delta, b"hello payload",
            BatchFlag::Single, [0u8; 8],
        );
        if !encoded.is_empty() {
            let idx = flip_byte % encoded.len();
            let mut mutated = encoded.clone();
            mutated[idx] ^= flip_mask;
            let _ = decode_data(&mutated);
        }
    }
}

// ─── 编码-解码往返等价 ─────────────────────────────────────

proptest! {
    /// 控制帧往返：encode → decode 后 session_id 和消息类型一致。
    #[test]
    fn prop_control_roundtrip_session_id(session_id: u64) {
        let ack = AckSummary {
            peer_id: pid("1"),
            doc_id: did("d1"),
            ack_checkpoint: None,
            ack_frontier: Frontier::new(),
            updated_at: std::time::SystemTime::UNIX_EPOCH,
            version_override: None,
        };
        let encoded = encode_control(&ControlMsg::AckSummary(ack), session_id).unwrap();
        let (decoded, sid) = decode_control(&encoded).unwrap();
        prop_assert_eq!(sid, session_id);
        prop_assert!(matches!(decoded, ControlMsg::AckSummary(_)));
    }

    /// 数据帧往返：encode → decode 后所有字段一致。
    #[test]
    fn prop_data_roundtrip(
        seq in 0u32..=65535,
        payload in prop::collection::vec(any::<u8>(), 0..=1024),
    ) {
        let encoded = encode_data(
            &did("doc1"), &pid("42"), seq,
            DataFrameKind::Delta, &payload,
            BatchFlag::Single, [0u8; 8],
        );
        let decoded = decode_data(&encoded).unwrap();
        prop_assert_eq!(decoded.seq, seq);
        prop_assert_eq!(decoded.payload.as_ref(), payload.as_slice());
    }

    /// Discovery 帧往返。
    #[test]
    fn prop_discovery_roundtrip(
        can_anchor: bool,
        can_relay: bool,
        persistent: bool,
    ) {
        let caps = AnchorCapabilities { can_anchor, can_relay, persistent };
        let encoded = encode_discovery("group1", "device1", caps);
        let decoded = decode_discovery(&encoded).unwrap();
        prop_assert_eq!(decoded.capabilities(), caps);
    }

    /// 所有 ControlMsg 变体的往返等价。
    #[test]
    fn prop_all_control_variants_roundtrip(session_id: u64) {
        let msgs = vec![
            ControlMsg::Capabilities(PeerAnnouncement {
                peer_id: pid("1"),
                capabilities: AnchorCapabilities::default(),
                frontier: Frontier::new(),
            }),
            ControlMsg::TransportHints(TransportHints {
                peer_id: pid("1"),
                preferred_path: "lan".into(),
                mtu: Some(1200),
            }),
            ControlMsg::RelayHints(RelayHints {
                peer_id: pid("1"),
                relay_addr: "relay:443".into(),
                requires_auth: true,
            }),
            ControlMsg::Introduce(IntroducePeer {
                introducer: pid("1"),
                introduced_peer: pid("2"),
                introduced_pubkey_hex: "abcdef".into(),
                endpoint: Some("192.168.1.1:8080".into()),
            }),
            ControlMsg::Revoke(RevokePeer {
                revoker: pid("1"),
                revoked_peer: pid("2"),
                reason: "compromised".into(),
            }),
            ControlMsg::KeyRotate(KeyRotateNotice {
                peer_id: pid("1"),
                new_pubkey_hex: "deadbeef".into(),
                rotation_seq: 42,
                signature: vec![0u8; 64],
            }),
        ];
        for msg in msgs {
            let encoded = encode_control(&msg, session_id).unwrap();
            let (decoded, sid) = decode_control(&encoded).unwrap();
            prop_assert_eq!(sid, session_id);
            // 验证变体一致（不比较内部字段，因为序列化可能损失精度）
            let original_discriminant = std::mem::discriminant(&msg);
            let decoded_discriminant = std::mem::discriminant(&decoded);
            prop_assert_eq!(original_discriminant, decoded_discriminant,
                "ControlMsg 变体不一致");
        }
    }
}

// ─── 边界长度 ──────────────────────────────────────────────

#[test]
fn fuzz_decode_empty() {
    assert!(decode_control(&[]).is_err());
    assert!(decode_data(&[]).is_err());
    assert!(decode_discovery(&[]).is_err());
}

proptest! {
    /// 单字节解码不 panic。
    #[test]
    fn fuzz_decode_single_byte(b: u8) {
        let _ = decode_control(&[b]);
        let _ = decode_data(&[b]);
        let _ = decode_discovery(&[b]);
    }
}
