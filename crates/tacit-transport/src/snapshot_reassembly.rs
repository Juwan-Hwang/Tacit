//! Snapshot 分片传输与重组。
//!
//! v1.0 规范第 8 节 stale peer 追赶：
//! - 大 snapshot 分片传输，避免单帧过大。
//! - 接收方按 (checkpoint_id, index) 重组。
//! - 收齐所有分片后合并为完整 snapshot。
//!
//! 本模块提供分片重组器，发送方使用 CheckpointManager::chunk_snapshot 生成分片。

use std::collections::HashMap;

use parking_lot::Mutex;
use tacit_core::{CheckpointId, CoreError, CoreResult, SnapshotChunk};
use tracing::{debug, info};

/// 分片重组器：按 checkpoint_id 聚合分片，收齐后合并。
pub struct SnapshotReassembler {
    /// checkpoint_id -> (已收到的分片, 总分片数)
    pending: Mutex<HashMap<String, ReassemblyState>>,
}

#[derive(Debug)]
struct ReassemblyState {
    /// 已收到的分片：index -> chunk。
    chunks: HashMap<u32, SnapshotChunk>,
    /// 总分片数（收到第一个分片后确定）。
    total: Option<u32>,
}

impl SnapshotReassembler {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// 接收一个分片。
    ///
    /// 返回 `Ok(Some(complete_snapshot))` 表示已收齐所有分片并合并完成。
    /// 返回 `Ok(None)` 表示还需要更多分片。
    pub fn receive_chunk(&self, chunk: SnapshotChunk) -> CoreResult<Option<Vec<u8>>> {
        let checkpoint_id_str = chunk.checkpoint_id.as_str().to_string();
        let mut pending = self.pending.lock();

        let state = pending
            .entry(checkpoint_id_str.clone())
            .or_insert_with(|| ReassemblyState {
                chunks: HashMap::new(),
                total: None,
            });

        // 更新总分片数
        if state.total.is_none() {
            state.total = Some(chunk.total);
        } else if state.total != Some(chunk.total) {
            return Err(CoreError::Store(format!(
                "分片总数不匹配: 期望 {:?}, 实际 {}",
                state.total, chunk.total
            )));
        }

        // 检查 index 是否越界
        if chunk.index >= chunk.total {
            return Err(CoreError::Store(format!(
                "分片 index 越界: index={}, total={}",
                chunk.index, chunk.total
            )));
        }

        // 存入分片（幂等：重复分片忽略）
        let is_duplicate = state.chunks.contains_key(&chunk.index);
        state.chunks.insert(chunk.index, chunk);

        if is_duplicate {
            debug!(
                checkpoint_id = %checkpoint_id_str,
                index = state.chunks.len(),
                "收到重复分片，已忽略"
            );
        } else {
            debug!(
                checkpoint_id = %checkpoint_id_str,
                received = state.chunks.len(),
                total = state.total.unwrap(),
                "收到分片"
            );
        }

        // 检查是否收齐
        let total = state.total.unwrap();
        if state.chunks.len() as u32 == total {
            // 收齐，合并
            let mut complete = Vec::new();
            for i in 0..total {
                let chunk = state
                    .chunks
                    .get(&i)
                    .ok_or_else(|| {
                        CoreError::Store(format!("缺少分片: index={}", i))
                    })?;
                complete.extend_from_slice(&chunk.data);
            }
            // 从 pending 移除
            pending.remove(&checkpoint_id_str);
            info!(
                checkpoint_id = %checkpoint_id_str,
                size = complete.len(),
                "snapshot 分片重组完成"
            );
            Ok(Some(complete))
        } else {
            Ok(None)
        }
    }

    /// 获取指定 checkpoint 的重组进度。
    pub fn progress(&self, checkpoint_id: &CheckpointId) -> (u32, u32) {
        let pending = self.pending.lock();
        if let Some(state) = pending.get(checkpoint_id.as_str()) {
            (
                state.chunks.len() as u32,
                state.total.unwrap_or(0),
            )
        } else {
            (0, 0)
        }
    }

    /// 取消指定 checkpoint 的重组（清理已收到的分片）。
    pub fn cancel(&self, checkpoint_id: &CheckpointId) {
        self.pending.lock().remove(checkpoint_id.as_str());
    }

    /// 清理所有未完成的重组。
    pub fn clear(&self) {
        self.pending.lock().clear();
    }
}

impl Default for SnapshotReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn make_chunk(checkpoint_id: &str, index: u32, total: u32, data: &[u8]) -> SnapshotChunk {
        SnapshotChunk {
            checkpoint_id: CheckpointId::new(checkpoint_id),
            index,
            total,
            data: Bytes::copy_from_slice(data),
        }
    }

    #[test]
    fn reassembles_complete_snapshot() {
        let reassembler = SnapshotReassembler::new();
        let data = b"hello world this is a snapshot";
        let chunks = vec![
            make_chunk("ckpt1", 0, 3, &data[0..10]),
            make_chunk("ckpt1", 1, 3, &data[10..20]),
            make_chunk("ckpt1", 2, 3, &data[20..]),
        ];

        // 前两个分片不应完成
        assert!(reassembler.receive_chunk(chunks[0].clone()).unwrap().is_none());
        assert!(reassembler.receive_chunk(chunks[1].clone()).unwrap().is_none());

        // 第三个分片应完成
        let result = reassembler.receive_chunk(chunks[2].clone()).unwrap();
        assert!(result.is_some());
        let snapshot = result.unwrap();
        assert_eq!(snapshot, data);
    }

    #[test]
    fn handles_out_of_order() {
        let reassembler = SnapshotReassembler::new();
        let data = b"0123456789";
        let chunks = vec![
            make_chunk("ckpt1", 0, 3, &data[0..4]),
            make_chunk("ckpt1", 1, 3, &data[4..7]),
            make_chunk("ckpt1", 2, 3, &data[7..]),
        ];

        // 乱序接收
        assert!(reassembler.receive_chunk(chunks[2].clone()).unwrap().is_none());
        assert!(reassembler.receive_chunk(chunks[0].clone()).unwrap().is_none());
        let result = reassembler.receive_chunk(chunks[1].clone()).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn ignores_duplicate_chunks() {
        let reassembler = SnapshotReassembler::new();
        let data = b"hello";
        let chunks = vec![
            make_chunk("ckpt1", 0, 2, &data[0..3]),
            make_chunk("ckpt1", 1, 2, &data[3..]),
        ];

        reassembler.receive_chunk(chunks[0].clone()).unwrap();
        // 重复发送第一个分片
        reassembler.receive_chunk(chunks[0].clone()).unwrap();
        let result = reassembler.receive_chunk(chunks[1].clone()).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn rejects_total_mismatch() {
        let reassembler = SnapshotReassembler::new();
        reassembler
            .receive_chunk(make_chunk("ckpt1", 0, 3, b"abc"))
            .unwrap();
        let result = reassembler.receive_chunk(make_chunk("ckpt1", 1, 2, b"de"));
        assert!(result.is_err());
    }

    #[test]
    fn rejects_out_of_bounds_index() {
        let reassembler = SnapshotReassembler::new();
        let result = reassembler.receive_chunk(make_chunk("ckpt1", 5, 3, b"abc"));
        assert!(result.is_err());
    }

    #[test]
    fn progress_tracking() {
        let reassembler = SnapshotReassembler::new();
        reassembler
            .receive_chunk(make_chunk("ckpt1", 0, 3, b"abc"))
            .unwrap();
        reassembler
            .receive_chunk(make_chunk("ckpt1", 1, 3, b"def"))
            .unwrap();

        let (received, total) = reassembler.progress(&CheckpointId::new("ckpt1"));
        assert_eq!(received, 2);
        assert_eq!(total, 3);
    }

    #[test]
    fn cancel_clears_state() {
        let reassembler = SnapshotReassembler::new();
        reassembler
            .receive_chunk(make_chunk("ckpt1", 0, 3, b"abc"))
            .unwrap();
        assert_eq!(reassembler.progress(&CheckpointId::new("ckpt1")).0, 1);

        reassembler.cancel(&CheckpointId::new("ckpt1"));
        assert_eq!(reassembler.progress(&CheckpointId::new("ckpt1")).0, 0);
    }
}
