//! SMS 分片编解码器模糊测试。
//!
//! 验证 `SmsSegmentCodec` 在面对任意输入时：
//! 1. `parse_header` 对任意字节不 panic
//! 2. `reassemble` 对任意段集合不 panic
//! 3. `segment → reassemble` 往返等价

use proptest::prelude::*;

use tacit_transport_sms::codec::{
    SmsSegmentCodec, FRAME_TYPE_CONTROL, FRAME_TYPE_DATA, MAX_SEGMENT_PAYLOAD_LEN,
};

// ─── parse_header 不 panic ─────────────────────────────────

proptest! {
    #[test]
    fn fuzz_parse_header_arbitrary(data: Vec<u8>) {
        let _ = SmsSegmentCodec::parse_header(&data);
    }
}

// ─── reassemble 不 panic ───────────────────────────────────

proptest! {
    /// 任意段列表的 reassemble 不 panic。
    #[test]
    fn fuzz_reassemble_arbitrary(segments: Vec<Vec<u8>>) {
        let _ = SmsSegmentCodec::reassemble(&segments);
    }

    /// 对合法分段做随机位翻转后 reassemble，不 panic。
    #[test]
    fn fuzz_reassemble_mutation(
        payload_len in 1usize..=4096,
        flip_idx in 0usize..=512,
        flip_mask: u8,
    ) {
        let payload = vec![0xAB; payload_len];
        let segs = SmsSegmentCodec::segment(&payload, 7, FRAME_TYPE_DATA).unwrap();
        let mut mutated = segs.clone();
        if !mutated.is_empty() {
            let seg_idx = flip_idx % mutated.len();
            if !mutated[seg_idx].is_empty() {
                let byte_idx = (flip_idx / mutated.len().max(1)) % mutated[seg_idx].len();
                mutated[seg_idx][byte_idx] ^= flip_mask;
            }
        }
        let _ = SmsSegmentCodec::reassemble(&mutated);
    }
}

// ─── segment → reassemble 往返 ─────────────────────────────

proptest! {
    #[test]
    fn prop_segment_reassemble_roundtrip(
        payload in prop::collection::vec(any::<u8>(), 0..=4096),
        message_id: u8,
        frame_type in 0u8..=1, // 0 → CONTROL, 1 → DATA
    ) {
        let ft = if frame_type == 0 { FRAME_TYPE_CONTROL } else { FRAME_TYPE_DATA };
        let segs = SmsSegmentCodec::segment(&payload, message_id, ft).unwrap();
        let reassembled = SmsSegmentCodec::reassemble(&segs).unwrap();
        prop_assert_eq!(reassembled, payload);
    }

    /// 段数与 payload 长度的关系正确。
    #[test]
    fn prop_segment_count(
        payload_len in 0usize..=MAX_SEGMENT_PAYLOAD_LEN * 255,
    ) {
        let payload = vec![0x42; payload_len];
        let segs = SmsSegmentCodec::segment(&payload, 0, FRAME_TYPE_CONTROL).unwrap();
        let expected = if payload_len == 0 {
            1
        } else {
            payload_len.div_ceil(MAX_SEGMENT_PAYLOAD_LEN)
        };
        prop_assert_eq!(segs.len(), expected);
        for seg in &segs {
            prop_assert!(seg.len() <= 140, "段长度 {} 超过 140", seg.len());
        }
    }

    /// 每段的 header 字段一致。
    #[test]
    fn prop_segment_header_consistency(
        payload in prop::collection::vec(any::<u8>(), 1..=4096),
        message_id: u8,
        frame_type in 0u8..=1,
    ) {
        let ft = if frame_type == 0 { FRAME_TYPE_CONTROL } else { FRAME_TYPE_DATA };
        let segs = SmsSegmentCodec::segment(&payload, message_id, ft).unwrap();
        let total = segs.len() as u8;
        for (i, seg) in segs.iter().enumerate() {
            let hdr = SmsSegmentCodec::parse_header(seg).unwrap();
            prop_assert_eq!(hdr.index, i as u8);
            prop_assert_eq!(hdr.total, total);
            prop_assert_eq!(hdr.message_id, message_id);
            prop_assert_eq!(hdr.frame_type, ft);
        }
    }
}

// ─── SMS Transport 层：任意 segment 不 panic ───────────────

use std::sync::Arc;
use tacit_core::PeerId;
use tacit_transport_sms::backend::{MockSmsBackend, SmsMessage};
use tacit_transport_sms::transport::SmsTransport;

proptest! {
    /// 向 transport 注入任意 payload 的 SMS 消息，poll_incoming 不 panic。
    #[test]
    fn fuzz_transport_arbitrary_payload(
        payload in prop::collection::vec(any::<u8>(), 0..=300),
    ) {
        let backend = Arc::new(MockSmsBackend::new());
        let transport = SmsTransport::new(backend.clone());
        transport.register_peer(PeerId::new("peer1"), "+8613800138000".into());

        backend.inject_incoming(SmsMessage {
            phone: "+8613800138000".into(),
            payload,
        });

        // poll_incoming 应安全处理任意 payload，不 panic
        let _ = transport.poll_incoming();
    }
}
