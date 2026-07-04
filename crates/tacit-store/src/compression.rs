//! Snapshot 透明压缩（zstd）。
//!
//! 在 DAO 层对 snapshot blob 进行透明 zstd 压缩/解压，
//! 减少存储空间和传输量，尤其有利于 relay / SMS 等窄带宽通道。
//!
//! # 压缩格式
//! 使用 1 字节前缀标记压缩状态：
//! - `0x01`：后续为 zstd 压缩数据
//! - 其他：原始未压缩数据（向后兼容旧数据）
//!
//! # 压缩策略
//! 仅对 ≥ 256 字节的数据压缩——更小的数据压缩后可能反而更大。
//! 压缩级别 3（快速 + 良好压缩比）。

use tacit_core::{CoreError, CoreResult};

/// 压缩前缀标识。
const COMPRESSED_PREFIX: u8 = 0x01;

/// 最小压缩阈值（字节）。小于此值的数据不压缩。
const MIN_COMPRESS_LEN: usize = 256;

/// zstd 压缩级别（0-22，3 = 快速 + 良好压缩比）。
const ZSTD_LEVEL: i32 = 3;

/// 压缩数据。
///
/// 小于 `MIN_COMPRESS_LEN` 的数据原样返回（不加前缀）。
/// 否则用 zstd 压缩并添加 `0x01` 前缀。
pub fn compress(data: &[u8]) -> Vec<u8> {
    if data.len() < MIN_COMPRESS_LEN {
        return data.to_vec();
    }
    let compressed = match zstd::encode_all(data, ZSTD_LEVEL) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "zstd 压缩失败，存储原始数据");
            return data.to_vec();
        }
    };
    // 仅当压缩后更小时使用压缩（含 1 字节前缀开销）
    if compressed.len() + 1 < data.len() {
        let mut buf = Vec::with_capacity(1 + compressed.len());
        buf.push(COMPRESSED_PREFIX);
        buf.extend_from_slice(&compressed);
        buf
    } else {
        data.to_vec()
    }
}

/// 解压数据。
///
/// 以 `0x01` 开头的数据解压 zstd，其他原样返回（向后兼容）。
pub fn decompress(data: &[u8]) -> CoreResult<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data[0] == COMPRESSED_PREFIX {
        zstd::decode_all(&data[1..]).map_err(|e| CoreError::Store(format!("zstd 解压失败: {e}")))
    } else {
        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_decompress_roundtrip_large() {
        let data = b"hello world".repeat(100); // 1100 bytes
        let compressed = compress(&data);
        assert_eq!(compressed[0], COMPRESSED_PREFIX);
        assert!(compressed.len() < data.len());
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn small_data_not_compressed() {
        let data = b"small";
        let result = compress(data);
        // 小数据不加前缀
        assert_ne!(result[0], COMPRESSED_PREFIX);
        assert_eq!(&result, data);
        let decompressed = decompress(&result).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn empty_data_roundtrip() {
        let data = b"";
        let compressed = compress(data);
        assert!(compressed.is_empty());
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn backward_compatible_raw_data() {
        // 模拟旧数据（无前缀，不以 0x01 开头）
        let raw = b"\x02\x03\x04raw data that is long enough to not be confused";
        let decompressed = decompress(raw).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn compress_shrinks_repetitive_data() {
        let data = b"AAAA".repeat(1000); // 4000 bytes of 'A'
        let compressed = compress(&data);
        assert!(compressed.len() < 100, "高度重复数据应大幅压缩");
    }
}
