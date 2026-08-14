//! Admission proof：HMAC-based 准入证明。
//!
//! 客户端用共享密钥生成 proof，服务端用同一密钥验证。
//! proof 包含 peer_id、timestamp、nonce、HMAC 签名，防止伪造与重放。
//!
//! 防重放机制：每个 proof 包含 16 字节随机 nonce，服务端维护一个
//! TTL = max_age 的 nonce 去重集合，拒绝重复 nonce。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// nonce 在缓存中的最大存活时间（秒）。
///
/// 与 proof 的 max_age_secs 保持一致，确保在 proof TTL 窗口内
/// 重放攻击始终被拒绝。过期 nonce 会被自动清理。
const NONCE_MAX_AGE_SECS: u64 = 300;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tacit_core::{CoreError, CoreResult, PeerId};

type HmacSha256 = Hmac<Sha256>;

/// Nonce 字节数（128 位）。
const NONCE_LEN: usize = 16;

/// Admission proof。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdmissionProof {
    /// 证明的 peer_id。
    pub peer_id: String,
    /// 时间戳（毫秒）。
    pub timestamp_ms: i64,
    /// 随机 nonce（32 字符 hex = 16 字节随机），防重放。
    pub nonce: String,
    /// HMAC-SHA256 签名（32 字节 hex）。
    pub signature: String,
}

/// Nonce 去重缓存：服务端用于检测 proof 重放。
///
/// 在 `verify_proof_with_replay` 中使用。TTL 由 `max_age_secs` 控制，
/// 超过 TTL 的 nonce 在清理时自动移除。
#[derive(Debug)]
pub struct NonceCache {
    /// nonce → 插入时间戳（毫秒）。
    seen: Mutex<HashMap<String, i64>>,
}

impl NonceCache {
    /// 创建空的 nonce 缓存。
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// 检查 nonce 是否已存在，若不存在则插入并返回 true（首次见到）。
    /// 若已存在则返回 false（重放）。
    fn check_and_insert(&self, nonce: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let mut seen = self.seen.lock().unwrap();
        // 先清理过期 nonce，防止 HashMap 无限增长
        let cutoff = now - (NONCE_MAX_AGE_SECS as i64) * 1000;
        seen.retain(|_, ts| *ts > cutoff);
        // 若 nonce 已存在且未过期，则为重放
        if let Some(&ts) = seen.get(nonce) {
            // 已存在——无论是否过期，只要 key 还在 map 里就视为重放
            // （过期的会在 maybe_cleanup 中被清理，清理后才能重新接受）
            if ts > 0 {
                return false;
            }
        }
        seen.insert(nonce.to_string(), now);
        true
    }

    /// 清理过期的 nonce 记录。
    ///
    /// 只清理插入时间超过 `max_age_secs` 的 nonce，确保在 proof TTL 窗口内
    /// 重放攻击始终被拒绝。不会全量清空，避免重放窗口重开。
    fn maybe_cleanup(&self, max_age_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let cutoff = now - (max_age_secs as i64) * 1000;
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, ts| *ts > cutoff);
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// 生成 admission proof。
///
/// `secret`：群组共享密钥。
pub fn generate_proof(peer_id: &PeerId, secret: &[u8]) -> CoreResult<AdmissionProof> {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    // 生成随机 nonce（128 位）
    let nonce_bytes = generate_nonce();
    let nonce = hex::encode(nonce_bytes);

    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| CoreError::Crypto(format!("HMAC 初始化失败: {e}")))?;
    mac.update(peer_id.as_str().as_bytes());
    mac.update(&timestamp_ms.to_be_bytes());
    mac.update(&nonce_bytes);
    let signature = hex::encode(mac.finalize().into_bytes());

    Ok(AdmissionProof {
        peer_id: peer_id.as_str().to_string(),
        timestamp_ms,
        nonce,
        signature,
    })
}

/// 验证 admission proof（不含重放检查）。
///
/// 仅验证签名和时间戳，不检查 nonce 是否重复。
/// 用于测试或不需要重放保护的场景。
///
/// `secret`：群组共享密钥。
/// `max_age_secs`：proof 最大有效时长（秒）。
pub fn verify_proof(proof: &AdmissionProof, secret: &[u8], max_age_secs: u64) -> CoreResult<()> {
    verify_proof_inner(proof, secret, max_age_secs)?;
    Ok(())
}

/// 验证 admission proof（含重放检查）。
///
/// 在签名和时间戳验证通过后，检查 nonce 是否已在 `cache` 中出现过。
/// 若 nonce 已存在，返回错误（重放攻击）。
///
/// # 参数
/// - `proof`：待验证的 admission proof
/// - `secret`：群组共享密钥
/// - `max_age_secs`：proof 最大有效时长（秒）
/// - `cache`：nonce 去重缓存（`Arc<NonceCache>` 或 `&NonceCache`）
pub fn verify_proof_with_replay(
    proof: &AdmissionProof,
    secret: &[u8],
    max_age_secs: u64,
    cache: &NonceCache,
) -> CoreResult<()> {
    verify_proof_inner(proof, secret, max_age_secs)?;

    if !cache.check_and_insert(&proof.nonce) {
        return Err(CoreError::Crypto("proof nonce 重放".into()));
    }
    cache.maybe_cleanup(max_age_secs);
    Ok(())
}

/// 内部验证逻辑：时间戳 + 签名。
fn verify_proof_inner(proof: &AdmissionProof, secret: &[u8], max_age_secs: u64) -> CoreResult<()> {
    // 检查时间戳
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let age = now - proof.timestamp_ms;
    if age < 0 || age as u64 > max_age_secs * 1000 {
        return Err(CoreError::Crypto("proof 已过期".into()));
    }

    // 解码 nonce
    let nonce_bytes = hex::decode(&proof.nonce).unwrap_or_default();
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CoreError::Crypto("proof nonce 长度无效".into()));
    }

    // 重新计算签名
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| CoreError::Crypto(format!("HMAC 初始化失败: {e}")))?;
    mac.update(proof.peer_id.as_bytes());
    mac.update(&proof.timestamp_ms.to_be_bytes());
    mac.update(&nonce_bytes);
    let expected_bytes = mac.finalize().into_bytes();

    // 解码客户端提供的签名为原始字节
    let provided_bytes = hex::decode(&proof.signature).unwrap_or_default();

    // 常量时间比较（防止时序攻击）
    if !constant_time_eq(&expected_bytes, &provided_bytes) {
        return Err(CoreError::Crypto("proof 签名无效".into()));
    }

    Ok(())
}

/// 生成 128 位随机 nonce（CSPRNG via uuid v4）。
fn generate_nonce() -> [u8; NONCE_LEN] {
    let uuid = uuid::Uuid::new_v4();
    let bytes = uuid.as_bytes();
    let mut buf = [0u8; NONCE_LEN];
    buf.copy_from_slice(bytes);
    buf
}

/// 常量时间字节比较，防止时序攻击。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify() {
        let peer_id = PeerId::new("1");
        let secret = b"group_secret_key";
        let proof = generate_proof(&peer_id, secret).unwrap();
        assert!(verify_proof(&proof, secret, 60).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let peer_id = PeerId::new("1");
        let proof = generate_proof(&peer_id, b"correct_secret").unwrap();
        assert!(verify_proof(&proof, b"wrong_secret", 60).is_err());
    }

    #[test]
    fn verify_rejects_expired() {
        let proof = AdmissionProof {
            peer_id: "1".into(),
            timestamp_ms: 0, // 很旧的时间戳
            nonce: "a".repeat(32),
            signature: "fake".into(),
        };
        assert!(verify_proof(&proof, b"secret", 60).is_err());
    }

    #[test]
    fn verify_rejects_tampered() {
        let peer_id = PeerId::new("1");
        let secret = b"secret";
        let mut proof = generate_proof(&peer_id, secret).unwrap();
        proof.peer_id = "2".into(); // 篡改 peer_id
        assert!(verify_proof(&proof, secret, 60).is_err());
    }

    #[test]
    fn replay_proof_rejected() {
        let peer_id = PeerId::new("1");
        let secret = b"replay_secret";
        let proof = generate_proof(&peer_id, secret).unwrap();
        let cache = NonceCache::new();

        // 首次验证应成功
        assert!(verify_proof_with_replay(&proof, secret, 60, &cache).is_ok());
        // 重放同一 proof 应失败
        assert!(verify_proof_with_replay(&proof, secret, 60, &cache).is_err());
    }

    #[test]
    fn different_proofs_no_false_rejection() {
        let peer_id = PeerId::new("1");
        let secret = b"multi_secret";
        let cache = NonceCache::new();

        // 两个不同的 proof 都应通过
        let proof1 = generate_proof(&peer_id, secret).unwrap();
        let proof2 = generate_proof(&peer_id, secret).unwrap();
        assert_ne!(proof1.nonce, proof2.nonce, "不同 proof 应有不同的 nonce");
        assert!(verify_proof_with_replay(&proof1, secret, 60, &cache).is_ok());
        assert!(verify_proof_with_replay(&proof2, secret, 60, &cache).is_ok());
    }
}
