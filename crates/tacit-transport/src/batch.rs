//! 批次签名规则（v1.0 规范第 13.4 节）。
//!
//! 同一 QUIC 流内、同一文档的连续 delta 构成一个签名批次。
//! flags 预留 2 bits 表示：单帧、批次开始、批次中间、批次结束。
//!
//! BatchSigner 管理签名批次的状态机：
//! - 开始批次 → 收集帧 → 结束批次 → 计算签名
//! - 签名覆盖批次内所有帧的 payload hash

use std::collections::HashMap;

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tacit_core::{BatchFlag, DocId, PeerId};

/// 批次状态。
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BatchState {
    /// 累积的 payload hash。
    hasher: Sha256,
    /// 批次内帧数。
    frame_count: u32,
    /// 批次关联的 doc_id。
    doc_id: DocId,
}

/// 批次签名管理器。
///
/// 线程安全，支持多文档并发批次。
pub struct BatchSigner {
    /// 按文档维护活跃批次。
    batches: Mutex<HashMap<(PeerId, DocId), BatchState>>,
}

impl Default for BatchSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchSigner {
    pub fn new() -> Self {
        Self {
            batches: Mutex::new(HashMap::new()),
        }
    }

    /// 处理一帧，返回应使用的 BatchFlag。
    ///
    /// - 首帧（frame_count == 0 时）：BatchStart
    /// - 后续帧：BatchMiddle
    /// - 结束批次需显式调用 [`end_batch`](Self::end_batch)，返回 BatchEnd 由调用方设置
    /// - 单帧（无后续）：Single（由 [`single_frame`](Self::single_frame) 提供）
    pub fn add_frame(&self, peer_id: &PeerId, doc_id: &DocId, payload: &[u8]) -> BatchFlag {
        let mut batches = self.batches.lock();
        let key = (peer_id.clone(), doc_id.clone());
        let is_new = !batches.contains_key(&key);
        let state = batches.entry(key).or_insert_with(|| BatchState {
            hasher: Sha256::new(),
            frame_count: 0,
            doc_id: doc_id.clone(),
        });
        state.hasher.update(payload);
        state.frame_count += 1;
        if is_new {
            BatchFlag::BatchStart
        } else {
            BatchFlag::BatchMiddle
        }
    }

    /// 开始一个新批次。
    pub fn start_batch(&self, peer_id: &PeerId, doc_id: &DocId) {
        let mut batches = self.batches.lock();
        let key = (peer_id.clone(), doc_id.clone());
        batches.insert(
            key,
            BatchState {
                hasher: Sha256::new(),
                frame_count: 0,
                doc_id: doc_id.clone(),
            },
        );
    }

    /// 结束批次，返回签名（payload hash）。
    pub fn end_batch(&self, peer_id: &PeerId, doc_id: &DocId) -> Option<Vec<u8>> {
        let mut batches = self.batches.lock();
        let key = (peer_id.clone(), doc_id.clone());
        let state = batches.remove(&key)?;
        let result = state.hasher.finalize();
        Some(result.to_vec())
    }

    /// 获取批次内帧数。
    pub fn batch_frame_count(&self, peer_id: &PeerId, doc_id: &DocId) -> u32 {
        let batches = self.batches.lock();
        let key = (peer_id.clone(), doc_id.clone());
        batches.get(&key).map(|s| s.frame_count).unwrap_or(0)
    }

    /// 判断是否有活跃批次。
    pub fn has_active_batch(&self, peer_id: &PeerId, doc_id: &DocId) -> bool {
        let batches = self.batches.lock();
        let key = (peer_id.clone(), doc_id.clone());
        batches.contains_key(&key)
    }

    /// 单帧模式：不使用批次，直接返回 Single flag。
    pub fn single_frame() -> BatchFlag {
        BatchFlag::Single
    }
}

/// 批次验证结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchVerifyResult {
    /// 帧已接受，批次仍在进行中（或单帧模式无需验证）。
    Accepted,
    /// 批次结束且签名验证通过。
    Verified,
    /// 批次结束但签名不匹配（可能被篡改）。
    Mismatch,
    /// 收到 BatchMiddle/BatchEnd 但无活跃批次（状态错乱）。
    NoActiveBatch,
    /// 收到 BatchEnd 但未提供签名（安全降级，不再静默接受）。
    MissingSignature,
}

/// 批次验证器：接收端验证批次签名。
pub struct BatchVerifier {
    /// 按文档维护累积 hash。
    hashes: Mutex<HashMap<(PeerId, DocId), Sha256>>,
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchVerifier {
    pub fn new() -> Self {
        Self {
            hashes: Mutex::new(HashMap::new()),
        }
    }

    /// 接收一帧，根据 batch_flag 更新状态。
    ///
    /// `signature`：仅 BatchEnd 帧需要提供（发送方计算的批次签名），
    /// 其他帧传 None。返回验证结果。
    pub fn receive_frame(
        &self,
        peer_id: &PeerId,
        doc_id: &DocId,
        payload: &[u8],
        flag: BatchFlag,
        signature: Option<&[u8]>,
    ) -> BatchVerifyResult {
        let mut hashes = self.hashes.lock();
        let key = (peer_id.clone(), doc_id.clone());
        match flag {
            BatchFlag::Single => {
                // 单帧模式，无需累积验证
                BatchVerifyResult::Accepted
            }
            BatchFlag::BatchStart => {
                let mut hasher = Sha256::new();
                hasher.update(payload);
                hashes.insert(key, hasher);
                BatchVerifyResult::Accepted
            }
            BatchFlag::BatchMiddle => {
                if let Some(hasher) = hashes.get_mut(&key) {
                    hasher.update(payload);
                    BatchVerifyResult::Accepted
                } else {
                    BatchVerifyResult::NoActiveBatch
                }
            }
            BatchFlag::BatchEnd => {
                if let Some(mut hasher) = hashes.remove(&key) {
                    hasher.update(payload);
                    let final_hash = hasher.finalize();
                    match signature {
                        Some(sig) => {
                            // 常量时间比较，防止时序攻击
                            if constant_time_eq(&final_hash, sig) {
                                BatchVerifyResult::Verified
                            } else {
                                BatchVerifyResult::Mismatch
                            }
                        }
                        None => {
                            // 收到 BatchEnd 但未提供签名，安全降级：拒绝而非静默接受
                            BatchVerifyResult::MissingSignature
                        }
                    }
                } else {
                    BatchVerifyResult::NoActiveBatch
                }
            }
        }
    }

    /// 清理指定文档的批次状态。
    pub fn clear(&self, peer_id: &PeerId, doc_id: &DocId) {
        let mut hashes = self.hashes.lock();
        let key = (peer_id.clone(), doc_id.clone());
        hashes.remove(&key);
    }
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
    fn batch_sign_and_verify() {
        let signer = BatchSigner::new();
        let peer = PeerId::new("1");
        let doc = DocId::new("d1");

        // 开始批次
        signer.start_batch(&peer, &doc);
        signer.add_frame(&peer, &doc, b"frame1");
        signer.add_frame(&peer, &doc, b"frame2");
        let sig = signer.end_batch(&peer, &doc).unwrap();

        // 验证签名非空
        assert!(!sig.is_empty());

        // 批次结束后应无活跃批次
        assert!(!signer.has_active_batch(&peer, &doc));
    }

    #[test]
    fn batch_verifier_single_frame() {
        let verifier = BatchVerifier::new();
        let peer = PeerId::new("1");
        let doc = DocId::new("d1");
        // 单帧模式不应累积
        let result = verifier.receive_frame(&peer, &doc, b"data", BatchFlag::Single, None);
        assert_eq!(result, BatchVerifyResult::Accepted);
    }

    #[test]
    fn batch_verifier_full_cycle_verified() {
        let signer = BatchSigner::new();
        let verifier = BatchVerifier::new();
        let peer = PeerId::new("1");
        let doc = DocId::new("d1");

        // 发送方构建批次并签名
        signer.start_batch(&peer, &doc);
        signer.add_frame(&peer, &doc, b"f1");
        signer.add_frame(&peer, &doc, b"f2");
        let sig = signer.end_batch(&peer, &doc).unwrap();

        // 接收方验证
        let r1 = verifier.receive_frame(&peer, &doc, b"f1", BatchFlag::BatchStart, None);
        assert_eq!(r1, BatchVerifyResult::Accepted);
        let r2 = verifier.receive_frame(&peer, &doc, b"f2", BatchFlag::BatchMiddle, None);
        assert_eq!(r2, BatchVerifyResult::Accepted);
        let r3 = verifier.receive_frame(&peer, &doc, b"", BatchFlag::BatchEnd, Some(&sig));
        assert_eq!(r3, BatchVerifyResult::Verified);
    }

    #[test]
    fn batch_verifier_mismatch_detected() {
        let verifier = BatchVerifier::new();
        let peer = PeerId::new("1");
        let doc = DocId::new("d1");

        verifier.receive_frame(&peer, &doc, b"f1", BatchFlag::BatchStart, None);
        verifier.receive_frame(&peer, &doc, b"f2", BatchFlag::BatchMiddle, None);
        // 提供错误的签名
        let wrong_sig = vec![0u8; 32];
        let r = verifier.receive_frame(&peer, &doc, b"f3", BatchFlag::BatchEnd, Some(&wrong_sig));
        assert_eq!(r, BatchVerifyResult::Mismatch);
    }

    #[test]
    fn batch_verifier_no_active_batch() {
        let verifier = BatchVerifier::new();
        let peer = PeerId::new("1");
        let doc = DocId::new("d1");
        // 直接发 BatchEnd 而无活跃批次
        let r = verifier.receive_frame(&peer, &doc, b"data", BatchFlag::BatchEnd, Some(&[0u8; 32]));
        assert_eq!(r, BatchVerifyResult::NoActiveBatch);
    }

    #[test]
    fn batch_verifier_missing_signature_rejected() {
        let verifier = BatchVerifier::new();
        let peer = PeerId::new("1");
        let doc = DocId::new("d1");

        // 构建活跃批次
        verifier.receive_frame(&peer, &doc, b"f1", BatchFlag::BatchStart, None);
        verifier.receive_frame(&peer, &doc, b"f2", BatchFlag::BatchMiddle, None);
        // 收到 BatchEnd 但未提供签名，应返回 MissingSignature 而非 Accepted
        let r = verifier.receive_frame(&peer, &doc, b"f3", BatchFlag::BatchEnd, None);
        assert_eq!(r, BatchVerifyResult::MissingSignature);
    }

    #[test]
    fn single_frame_flag() {
        assert_eq!(BatchSigner::single_frame(), BatchFlag::Single);
    }
}
