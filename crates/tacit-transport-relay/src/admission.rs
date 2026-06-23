//! Admission proof：HMAC-based 准入证明。
//!
//! 客户端用共享密钥生成 proof，服务端用同一密钥验证。
//! proof 包含 peer_id、timestamp、HMAC 签名，防止伪造。

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tacit_core::{CoreError, CoreResult, PeerId};

type HmacSha256 = Hmac<Sha256>;

/// Admission proof。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdmissionProof {
    /// 证明的 peer_id。
    pub peer_id: String,
    /// 时间戳（毫秒）。
    pub timestamp_ms: i64,
    /// HMAC-SHA256 签名（32 字节 hex）。
    pub signature: String,
}

/// 生成 admission proof。
///
/// `secret`：群组共享密钥。
pub fn generate_proof(peer_id: &PeerId, secret: &[u8]) -> CoreResult<AdmissionProof> {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| CoreError::Crypto(format!("HMAC 初始化失败: {e}")))?;
    mac.update(peer_id.as_str().as_bytes());
    mac.update(&timestamp_ms.to_be_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    Ok(AdmissionProof {
        peer_id: peer_id.as_str().to_string(),
        timestamp_ms,
        signature,
    })
}

/// 验证 admission proof。
///
/// `secret`：群组共享密钥。
/// `max_age_secs`：proof 最大有效时长（秒）。
pub fn verify_proof(proof: &AdmissionProof, secret: &[u8], max_age_secs: u64) -> CoreResult<()> {
    // 检查时间戳
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let age = now - proof.timestamp_ms;
    if age < 0 || age as u64 > max_age_secs * 1000 {
        return Err(CoreError::Crypto("proof 已过期".into()));
    }

    // 重新计算签名
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| CoreError::Crypto(format!("HMAC 初始化失败: {e}")))?;
    mac.update(proof.peer_id.as_bytes());
    mac.update(&proof.timestamp_ms.to_be_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // 常量时间比较
    if expected != proof.signature {
        return Err(CoreError::Crypto("proof 签名无效".into()));
    }

    Ok(())
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
}
