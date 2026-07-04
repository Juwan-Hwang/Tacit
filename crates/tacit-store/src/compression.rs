//! Snapshot 透明压缩（zstd）。
//!
//! 在 DAO 层对 snapshot blob 进行透明 zstd 压缩/解压，
//! 减少存储空间和传输量，尤其有利于 relay / SMS 等窄带宽通道。
//!
//! # 压缩格式
//! 使用 4 字节 magic 前缀标记压缩状态：
//! - `b"TZSD"`（Tacit Zstd Snapshot Data）：后续为 zstd 压缩数据
//! - 其他：原始未压缩数据（小数据跳过压缩）
//!
//! 使用 4 字节而非 1 字节前缀，消除与原始 Loro 二进制数据碰撞的风险
//! ——原始 payload 理论上可以以任意单字节开头，但以 `TZSD` 开头的概率可忽略。
//!
//! # 压缩策略
//! 仅对 ≥ 256 字节的数据压缩——更小的数据压缩后可能反而更大。
//! 压缩级别 3（快速 + 良好压缩比）。

use tacit_core::{CoreError, CoreResult};

/// 压缩前缀标识（4 字节 magic，避免与原始二进制数据碰撞）。
const COMPRESSED_PREFIX: &[u8; 4] = b"TZSD";

/// 最小压缩阈值（字节）。小于此值的数据不压缩。
const MIN_COMPRESS_LEN: usize = 256;

/// zstd 压缩级别（0-22，3 = 快速 + 良好压缩比）。
const ZSTD_LEVEL: i32 = 3;

/// 最大解压大小（50 MB），防止 zstd 炸弹导致 OOM。
const MAX_DECOMPRESSED_SIZE: u64 = 50 * 1024 * 1024;

/// 压缩数据。
///
/// 小于 `MIN_COMPRESS_LEN` 的数据原样返回（不加前缀）。
/// 否则用 zstd 压缩并添加 4 字节 magic 前缀。
///
/// **例外**：如果原始数据本身以 magic `TZSD` 开头，则**强制**压缩
/// （即使压缩后更大），否则 `decompress` 会误判为压缩数据导致解压失败。
///
/// 返回 `CoreResult`：若原始数据以 magic 开头且压缩失败，返回错误而非 panic，
/// 由调用方决定降级策略（如跳过写入或记录错误）。
pub fn compress(data: &[u8]) -> CoreResult<Vec<u8>> {
    let starts_with_magic = data.len() >= COMPRESSED_PREFIX.len()
        && &data[..COMPRESSED_PREFIX.len()] == COMPRESSED_PREFIX;

    if data.len() < MIN_COMPRESS_LEN && !starts_with_magic {
        return Ok(data.to_vec());
    }
    let compressed = match zstd::encode_all(data, ZSTD_LEVEL) {
        Ok(c) => c,
        Err(e) => {
            if starts_with_magic {
                // 原始数据以 magic 开头但压缩失败：返回原始数据会导致 decompress 误判。
                // 返回错误让调用方决定降级策略，而非 panic 导致整个进程崩溃。
                return Err(CoreError::Store(format!(
                    "以 magic 开头的数据压缩失败，无法安全存储: {e}"
                )));
            }
            tracing::warn!(error = %e, "zstd 压缩失败，存储原始数据");
            return Ok(data.to_vec());
        }
    };
    // 如果原始数据以 magic 开头，必须强制压缩（即使压缩后更大），
    // 否则解压时会误认为它是压缩数据而导致解压失败。
    if starts_with_magic || compressed.len() + COMPRESSED_PREFIX.len() < data.len() {
        let mut buf = Vec::with_capacity(COMPRESSED_PREFIX.len() + compressed.len());
        buf.extend_from_slice(COMPRESSED_PREFIX);
        buf.extend_from_slice(&compressed);
        Ok(buf)
    } else {
        Ok(data.to_vec())
    }
}

/// 解压数据。
///
/// 以 4 字节 magic `TZSD` 开头的数据解压 zstd，其他原样返回（未压缩的小数据）。
pub fn decompress(data: Vec<u8>) -> CoreResult<Vec<u8>> {
    if data.len() >= COMPRESSED_PREFIX.len()
        && &data[..COMPRESSED_PREFIX.len()] == COMPRESSED_PREFIX
    {
        use std::io::Read;
        let decoder = zstd::Decoder::new(&data[COMPRESSED_PREFIX.len()..])
            .map_err(|e| CoreError::Store(format!("创建 zstd 解码器失败: {e}")))?;
        let mut decoded = Vec::new();
        // 读取 MAX + 1 字节：若实际读到的数据超过 MAX，说明超限，必须显式拒绝。
        // 不能直接 take(MAX)——Read::take 达到限制时返回 EOF 而非错误，
        // read_to_end 会静默截断并返回 Ok，导致数据损坏。
        decoder
            .take(MAX_DECOMPRESSED_SIZE + 1)
            .read_to_end(&mut decoded)
            .map_err(|e| CoreError::Store(format!("zstd 解压失败: {e}")))?;
        if decoded.len() > MAX_DECOMPRESSED_SIZE as usize {
            return Err(CoreError::Store(format!(
                "解压数据大小超过限制（最大 {} 字节）",
                MAX_DECOMPRESSED_SIZE
            )));
        }
        Ok(decoded)
    } else {
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_decompress_roundtrip_large() {
        let data = b"hello world".repeat(100); // 1100 bytes
        let compressed = compress(&data).unwrap();
        assert_eq!(&compressed[..4], COMPRESSED_PREFIX);
        assert!(compressed.len() < data.len());
        let decompressed = decompress(compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn small_data_not_compressed() {
        let data = b"small";
        let result = compress(data).unwrap();
        // 小数据不加前缀（不以 b"TZSD" 开头）
        assert!(result.len() < 4 || &result[..4] != COMPRESSED_PREFIX);
        assert_eq!(&result, data);
        let decompressed = decompress(result).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn empty_data_roundtrip() {
        let data = b"";
        let compressed = compress(data).unwrap();
        assert!(compressed.is_empty());
        let decompressed = decompress(compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn uncompressed_small_data_roundtrip() {
        // 小数据不被压缩（无 magic 前缀），decompress 应原样返回
        let raw = b"\x02\x03\x04raw data that is long enough to not be confused";
        let decompressed = decompress(raw.to_vec()).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn raw_data_starting_with_0x01_is_not_misinterpreted() {
        // 原始数据以 0x01 开头不应被误判为压缩数据
        let raw = vec![0x01u8; 500]; // 足够长，以 0x01 开头
        let decompressed = decompress(raw.clone()).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn compress_shrinks_repetitive_data() {
        let data = b"AAAA".repeat(1000); // 4000 bytes of 'A'
        let compressed = compress(&data).unwrap();
        assert!(compressed.len() < 100, "高度重复数据应大幅压缩");
    }

    #[test]
    fn raw_data_starting_with_magic_is_force_compressed() {
        // 原始数据恰好以 b"TZSD" 开头——必须强制压缩，否则 decompress 会误判
        let mut data = b"TZSD".to_vec();
        data.extend_from_slice(&b"raw payload after magic"[..].repeat(20)); // 足够长
        let compressed = compress(&data).unwrap();
        // 应被压缩（以 magic 开头）
        assert_eq!(&compressed[..4], COMPRESSED_PREFIX);
        // 解压后应还原原始数据
        let decompressed = decompress(compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn short_raw_data_starting_with_magic_is_force_compressed() {
        // 即使数据很短（< MIN_COMPRESS_LEN），只要以 magic 开头就必须压缩
        let data = b"TZSD";
        let compressed = compress(data).unwrap();
        assert_eq!(&compressed[..4], COMPRESSED_PREFIX);
        let decompressed = decompress(compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
