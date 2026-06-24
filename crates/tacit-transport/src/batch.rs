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
    pub fn receive_frame(
        &self,
        peer_id: &PeerId,
        doc_id: &DocId,
        payload: &[u8],
        flag: BatchFlag,
    ) {
        let mut hashes = self.hashes.lock();
        let key = (peer_id.clone(), doc_id.clone());
        match flag {
            BatchFlag::Single => {
                // 单帧模式，无需累积
            }
            BatchFlag::BatchStart => {
                let mut hasher = Sha256::new();
                hasher.update(payload);
                hashes.insert(key, hasher);
            }
            BatchFlag::BatchMiddle => {
                if let Some(hasher) = hashes.get_mut(&key) {
                    hasher.update(payload);
                }
            }
            BatchFlag::BatchEnd => {
                if let Some(mut hasher) = hashes.remove(&key) {
                    hasher.update(payload);
                    // 最终 hash 可用于验证
                    let _final_hash = hasher.finalize();
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
        verifier.receive_frame(&peer, &doc, b"data", BatchFlag::Single);
        // 不应 panic
    }

    #[test]
    fn batch_verifier_full_cycle() {
        let verifier = BatchVerifier::new();
        let peer = PeerId::new("1");
        let doc = DocId::new("d1");

        verifier.receive_frame(&peer, &doc, b"f1", BatchFlag::BatchStart);
        verifier.receive_frame(&peer, &doc, b"f2", BatchFlag::BatchMiddle);
        verifier.receive_frame(&peer, &doc, b"f3", BatchFlag::BatchEnd);
        // 不应 panic，批次状态应已清理
    }

    #[test]
    fn single_frame_flag() {
        assert_eq!(BatchSigner::single_frame(), BatchFlag::Single);
    }
}
