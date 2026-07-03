//! SMS 分片 / 重组 codec。
//!
//! Data SMS 单条二进制 payload 上限 140 字节（GSM 03.40 TP-UD）。
//!
//! 本 codec 实现自定义的简单分片协议（不依赖 UDH）：
//! - 每段前 4 字节为头：
//!   `segment_index(u8) | total_segments(u8) | message_id(u8) | frame_type(u8)`
//! - 后续为有效载荷切片（每段最多 136 字节）
//! - `message_id` 由发送端分配，用于区分并发分片流
//! - `frame_type` 区分控制帧（0x01）与数据帧（0x02），接收端据此分路重组
//!
//! 接收端按 `(message_id, frame_type, segment_index)` 重组，
//! 收齐 `total_segments` 段后拼接还原。
//!
//! 段数上限 255（u8 范围 1..=255），超过则拒绝。

use tacit_core::{CoreError, CoreResult};

/// 单条 SMS 二进制 payload 最大长度（字节）。
pub const MAX_SMS_PAYLOAD_LEN: usize = 140;

/// 多段 SMS 每段有效载荷最大长度（扣除 4 字节分片头）。
pub const MAX_SEGMENT_PAYLOAD_LEN: usize = MAX_SMS_PAYLOAD_LEN - SEGMENT_HEADER_LEN;

/// 分片头长度。
const SEGMENT_HEADER_LEN: usize = 4;

/// 分片头中 index 的最大值（含）。
const MAX_SEGMENT_INDEX: u8 = 255;

/// 帧类型：控制帧。
pub const FRAME_TYPE_CONTROL: u8 = 0x01;

/// 帧类型：数据帧。
pub const FRAME_TYPE_DATA: u8 = 0x02;

/// 分片头解析结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    pub index: u8,
    pub total: u8,
    pub message_id: u8,
    pub frame_type: u8,
}

/// 分片 codec：将 payload 切分为 SMS 段，或从段重组 payload。
#[derive(Debug, Clone, Default)]
pub struct SmsSegmentCodec;

impl SmsSegmentCodec {
    /// 将 payload 分片为若干 SMS 段。
    ///
    /// - `message_id`：0..=255，由调用端分配，用于区分并发分片流
    /// - `frame_type`：`FRAME_TYPE_CONTROL` 或 `FRAME_TYPE_DATA`
    /// - 返回的每个 `Vec<u8>` 长度 ≤ [`MAX_SMS_PAYLOAD_LEN`]
    ///
    /// 若 payload 为空，返回单个空段（`total=1, index=0`）。
    pub fn segment(payload: &[u8], message_id: u8, frame_type: u8) -> CoreResult<Vec<Vec<u8>>> {
        if payload.is_empty() {
            return Ok(vec![vec![0, 1, message_id, frame_type]]);
        }

        let total = payload.len().div_ceil(MAX_SEGMENT_PAYLOAD_LEN);
        // u8 范围为 0..=255，但 total=0 无意义，total=256 会溢出为 0。
        // 因此最大允许 255 段（index 0..=254）。
        if total > MAX_SEGMENT_INDEX as usize {
            return Err(CoreError::Transport(format!(
                "payload 过大，需 {} 段，超过最大段数 {}",
                total, MAX_SEGMENT_INDEX
            )));
        }
        let total_u8 = total as u8;

        let mut segments = Vec::with_capacity(total);
        for (i, chunk) in payload.chunks(MAX_SEGMENT_PAYLOAD_LEN).enumerate() {
            let mut seg = Vec::with_capacity(SEGMENT_HEADER_LEN + chunk.len());
            seg.push(i as u8); // segment_index
            seg.push(total_u8); // total_segments
            seg.push(message_id); // message_id
            seg.push(frame_type); // frame_type
            seg.extend_from_slice(chunk);
            segments.push(seg);
        }
        Ok(segments)
    }

    /// 解析单段的分片头。
    pub fn parse_header(seg: &[u8]) -> CoreResult<SegmentHeader> {
        if seg.len() < SEGMENT_HEADER_LEN {
            return Err(CoreError::Transport(format!(
                "分片过短: {} 字节 (最少 {})",
                seg.len(),
                SEGMENT_HEADER_LEN
            )));
        }
        Ok(SegmentHeader {
            index: seg[0],
            total: seg[1],
            message_id: seg[2],
            frame_type: seg[3],
        })
    }

    /// 重组 SMS 段为完整 payload。
    ///
    /// - 所有段必须具有相同的 `message_id` 和 `frame_type`
    /// - 段数必须等于 `total_segments`
    /// - 段索引必须 0..total 连续
    ///
    /// 返回重组后的 payload。
    pub fn reassemble(segments: &[Vec<u8>]) -> CoreResult<Vec<u8>> {
        if segments.is_empty() {
            return Err(CoreError::Transport("无分片可重组".into()));
        }

        // 解析头部
        let headers: Vec<SegmentHeader> = segments
            .iter()
            .map(|s| Self::parse_header(s))
            .collect::<CoreResult<Vec<_>>>()?;

        // 校验 message_id + frame_type 一致
        let msg_id = headers[0].message_id;
        let ftype = headers[0].frame_type;
        if !headers
            .iter()
            .all(|h| h.message_id == msg_id && h.frame_type == ftype)
        {
            return Err(CoreError::Transport(
                "分片 message_id 或 frame_type 不一致".into(),
            ));
        }

        let total = headers[0].total;
        if segments.len() != total as usize {
            return Err(CoreError::Transport(format!(
                "分片数不匹配: 期望 {} 段，实际 {} 段",
                total,
                segments.len()
            )));
        }

        // 按 index 排序
        let mut indexed: Vec<(u8, &[u8])> = segments
            .iter()
            .map(|s| (s[0], &s[SEGMENT_HEADER_LEN..]))
            .collect();
        indexed.sort_by_key(|(i, _)| *i);

        // 校验连续性
        for (expected, (actual, _)) in indexed.iter().enumerate() {
            if *actual != expected as u8 {
                return Err(CoreError::Transport(format!(
                    "分片索引不连续: 期望 {}，实际 {}",
                    expected, actual
                )));
            }
        }

        let total_len: usize = indexed.iter().map(|(_, data)| data.len()).sum();
        let mut out = Vec::with_capacity(total_len);
        for (_, data) in indexed {
            out.extend_from_slice(data);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_single_small_payload() {
        let payload = vec![1, 2, 3];
        let segs = SmsSegmentCodec::segment(&payload, 42, FRAME_TYPE_CONTROL).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0][0], 0); // index
        assert_eq!(segs[0][1], 1); // total
        assert_eq!(segs[0][2], 42); // message_id
        assert_eq!(segs[0][3], FRAME_TYPE_CONTROL); // frame_type
        assert_eq!(&segs[0][4..], &[1, 2, 3]);
    }

    #[test]
    fn segment_empty_payload() {
        let segs = SmsSegmentCodec::segment(&[], 0, FRAME_TYPE_DATA).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0][1], 1); // total = 1
        assert_eq!(segs[0][3], FRAME_TYPE_DATA); // frame_type
    }

    #[test]
    fn segment_multi_part() {
        // 136 * 2 + 1 = 273 bytes -> 3 segments
        let payload = vec![0xAB; MAX_SEGMENT_PAYLOAD_LEN * 2 + 1];
        let segs = SmsSegmentCodec::segment(&payload, 7, FRAME_TYPE_DATA).unwrap();
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0][1], 3); // total
        assert_eq!(segs[1][0], 1); // index
        assert_eq!(segs[2][0], 2); // index
                                   // 每段不超过 140 字节
        for seg in &segs {
            assert!(seg.len() <= MAX_SMS_PAYLOAD_LEN);
        }
    }

    #[test]
    fn reassemble_roundtrip() {
        let payload = vec![0x42; 300];
        let segs = SmsSegmentCodec::segment(&payload, 99, FRAME_TYPE_CONTROL).unwrap();
        let reassembled = SmsSegmentCodec::reassemble(&segs).unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn reassemble_single() {
        let payload = vec![1, 2, 3];
        let segs = SmsSegmentCodec::segment(&payload, 0, FRAME_TYPE_CONTROL).unwrap();
        let out = SmsSegmentCodec::reassemble(&segs).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn reassemble_empty() {
        let segs = SmsSegmentCodec::segment(&[], 0, FRAME_TYPE_DATA).unwrap();
        let out = SmsSegmentCodec::reassemble(&segs).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn reassemble_rejects_missing_segment() {
        let payload = vec![0xFF; MAX_SEGMENT_PAYLOAD_LEN * 2 + 1];
        let mut segs = SmsSegmentCodec::segment(&payload, 1, FRAME_TYPE_DATA).unwrap();
        segs.remove(1); // 丢掉中间段
        let result = SmsSegmentCodec::reassemble(&segs);
        assert!(result.is_err());
    }

    #[test]
    fn reassemble_rejects_mixed_message_id() {
        // 需要多段才能检测 message_id 不一致
        let payload = vec![0xAB; MAX_SEGMENT_PAYLOAD_LEN * 2 + 1];
        let mut segs = SmsSegmentCodec::segment(&payload, 1, FRAME_TYPE_CONTROL).unwrap();
        assert!(segs.len() >= 2);
        segs[1][2] = 2; // 篡改第二段的 message_id
        let result = SmsSegmentCodec::reassemble(&segs);
        assert!(result.is_err());
    }

    #[test]
    fn reassemble_rejects_mixed_frame_type() {
        let payload = vec![0xAB; MAX_SEGMENT_PAYLOAD_LEN * 2 + 1];
        let mut segs = SmsSegmentCodec::segment(&payload, 1, FRAME_TYPE_CONTROL).unwrap();
        assert!(segs.len() >= 2);
        segs[1][3] = FRAME_TYPE_DATA; // 篡改第二段的 frame_type
        let result = SmsSegmentCodec::reassemble(&segs);
        assert!(result.is_err());
    }

    #[test]
    fn parse_header_works() {
        let segs = SmsSegmentCodec::segment(&[1, 2, 3], 42, FRAME_TYPE_DATA).unwrap();
        let hdr = SmsSegmentCodec::parse_header(&segs[0]).unwrap();
        assert_eq!(hdr.index, 0);
        assert_eq!(hdr.total, 1);
        assert_eq!(hdr.message_id, 42);
        assert_eq!(hdr.frame_type, FRAME_TYPE_DATA);
    }

    #[test]
    fn segment_rejects_oversized() {
        // 255 段 * 136 = 34680 bytes：允许
        // 256 段会 u8 溢出为 0，现在被拒绝
        // 257 段同样超出
        let payload = vec![0x00; MAX_SEGMENT_PAYLOAD_LEN * 257];
        let result = SmsSegmentCodec::segment(&payload, 0, FRAME_TYPE_DATA);
        assert!(result.is_err());
    }

    #[test]
    fn segment_rejects_exactly_256_segments() {
        // 256 段时 total as u8 = 0，导致接收端永远无法重组
        // 修复后应拒绝 256 段
        let payload = vec![0x00; MAX_SEGMENT_PAYLOAD_LEN * 256];
        let result = SmsSegmentCodec::segment(&payload, 0, FRAME_TYPE_DATA);
        assert!(result.is_err());
    }

    #[test]
    fn segment_allows_exactly_255_segments() {
        // 255 段是最大允许值（index 0..=254）
        let payload = vec![0x00; MAX_SEGMENT_PAYLOAD_LEN * 255];
        let segs = SmsSegmentCodec::segment(&payload, 0, FRAME_TYPE_DATA).unwrap();
        assert_eq!(segs.len(), 255);
        assert_eq!(segs[0][1], 255); // total = 255
        assert_eq!(segs[254][0], 254); // last index = 254
    }
}
