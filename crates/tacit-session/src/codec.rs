//! Session 层 payload 编解码。
//!
//! 在 `DataFrame.payload` 中编码 `block_id` 信息，使接收方知道
//! 这是 block delta 还是 meta delta，以及对应的 block_id。
//!
//! ## 编码格式
//!
//! ```text
//! Byte 0: 0x00 = meta delta（无 block_id）
//!         0x01 = block delta（后跟 block_id）
//! 若 block delta:
//!   Bytes 1-2: block_id 字符串长度（u16 LE）
//!   Bytes 3..3+len: block_id UTF-8 字符串
//!   Bytes 3+len..: delta 字节
//! 若 meta delta:
//!   Bytes 1..: meta delta 字节
//! ```

use tacit_core::BlockId;

/// 编码 payload：将 block_id 前缀与 delta 字节合并。
pub fn encode_payload(block_id: Option<&BlockId>, delta: &[u8]) -> Vec<u8> {
    match block_id {
        None => {
            let mut buf = Vec::with_capacity(1 + delta.len());
            buf.push(0x00);
            buf.extend_from_slice(delta);
            buf
        }
        Some(bid) => {
            let bid_str = bid.as_str().as_bytes();
            let len = u16::try_from(bid_str.len()).expect("block_id 长度不超过 64KB");
            let mut buf = Vec::with_capacity(3 + bid_str.len() + delta.len());
            buf.push(0x01);
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(bid_str);
            buf.extend_from_slice(delta);
            buf
        }
    }
}

/// 解码 payload：提取 block_id（若有）和 delta 字节。
///
/// 返回 `(Option<BlockId>, &[u8])`，其中 `&[u8]` 指向 `payload` 的切片。
pub fn decode_payload(payload: &[u8]) -> tacit_core::CoreResult<(Option<BlockId>, &[u8])> {
    if payload.is_empty() {
        return Err(tacit_core::CoreError::Internal(
            "payload 为空，无法解码 session 帧".into(),
        ));
    }
    match payload[0] {
        0x00 => Ok((None, &payload[1..])),
        0x01 => {
            if payload.len() < 3 {
                return Err(tacit_core::CoreError::Internal(
                    "block delta payload 过短，缺少 block_id 长度".into(),
                ));
            }
            let len = u16::from_le_bytes([payload[1], payload[2]]) as usize;
            if payload.len() < 3 + len {
                return Err(tacit_core::CoreError::Internal(
                    "block delta payload 过短，block_id 被截断".into(),
                ));
            }
            let bid_str = std::str::from_utf8(&payload[3..3 + len]).map_err(|e| {
                tacit_core::CoreError::Internal(format!("block_id 不是有效 UTF-8: {e}"))
            })?;
            let block_id = BlockId::new(bid_str.to_string());
            Ok((Some(block_id), &payload[3 + len..]))
        }
        flag => Err(tacit_core::CoreError::Internal(format!(
            "未知的 session 帧标志: 0x{flag:02x}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_delta_roundtrip() {
        let delta = b"meta delta bytes";
        let encoded = encode_payload(None, delta);
        let (bid, decoded) = decode_payload(&encoded).unwrap();
        assert!(bid.is_none());
        assert_eq!(decoded, delta);
    }

    #[test]
    fn block_delta_roundtrip() {
        let block_id = BlockId::new("block-42");
        let delta = b"block delta bytes";
        let encoded = encode_payload(Some(&block_id), delta);
        let (bid, decoded) = decode_payload(&encoded).unwrap();
        assert_eq!(bid.as_ref().map(|b| b.as_str()), Some("block-42"));
        assert_eq!(decoded, delta);
    }

    #[test]
    fn empty_delta_roundtrip() {
        let block_id = BlockId::new("b1");
        let encoded = encode_payload(Some(&block_id), b"");
        let (bid, decoded) = decode_payload(&encoded).unwrap();
        assert_eq!(bid.as_ref().map(|b| b.as_str()), Some("b1"));
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_empty_payload_errors() {
        let result = decode_payload(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_unknown_flag_errors() {
        let result = decode_payload(&[0xFF]);
        assert!(result.is_err());
    }
}
