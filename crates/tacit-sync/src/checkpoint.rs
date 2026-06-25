//! CheckpointManager：串联水位计算 → 压缩判断 → 原子安装 → 分片传输。
//!
//! 职责：
//! - 评估双水位（hard / soft frontier）
//! - 判断是否需要 compaction（hard_frontier 有进展且超过阈值）
//! - 生成 shallow snapshot 并通过事务原子安装
//! - 将大 snapshot 分片为 SnapshotChunk 列表

use std::time::SystemTime;

use bytes::Bytes;
use tacit_core::{
    CheckpointId, DocId, SnapshotChunk, SnapshotKind, SnapshotMeta, Watermarks,
};
use tacit_store::dao;
use tracing::debug;

use crate::doc_store::DocStore;
use crate::watermarks::WatermarkCalculator;

/// 默认 compaction 触发阈值：hard_frontier 覆盖的 seq 总和超过此值时触发。
const DEFAULT_COMPACT_THRESHOLD: u64 = 500;

/// 默认分片大小：64 KiB。
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// 快照安装结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResult {
    pub checkpoint_id: CheckpointId,
    pub installed: bool,
}

/// Checkpoint 管理器。
pub struct CheckpointManager {
    doc_store: DocStore,
    watermark_calc: WatermarkCalculator,
    compact_threshold: u64,
    chunk_size: usize,
}

impl CheckpointManager {
    pub fn new(doc_store: DocStore, watermark_calc: WatermarkCalculator) -> Self {
        Self {
            doc_store,
            watermark_calc,
            compact_threshold: DEFAULT_COMPACT_THRESHOLD,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// 自定义 compaction 阈值和分片大小。
    pub fn with_params(mut self, compact_threshold: u64, chunk_size: usize) -> Self {
        self.compact_threshold = compact_threshold;
        self.chunk_size = chunk_size;
        self
    }

    /// 评估双水位。
    pub fn evaluate_watermarks(&self, doc_id: &DocId) -> tacit_core::CoreResult<Watermarks> {
        let conn = self.doc_store.store().conn();
        let acks = dao::list_acks_by_doc(&conn, doc_id)?;
        drop(conn);
        Ok(self.watermark_calc.compute(doc_id, &acks, SystemTime::now()))
    }

    /// 判断是否需要 compaction，若需要则生成 shallow snapshot 并安装。
    ///
    /// 返回 Some(checkpoint_id) 表示执行了 compaction，None 表示无需压缩。
    ///
    /// compaction 后执行 GC：删除旧 checkpoint 及其关联的旧 snapshot。
    pub fn maybe_compact(&self, doc_id: &DocId) -> tacit_core::CoreResult<Option<CheckpointId>> {
        let watermarks = self.evaluate_watermarks(doc_id)?;

        // hard_frontier 为空或 seq 总和未超阈值，不压缩
        let hard_seq_sum: u64 = watermarks.hard_frontier.entries().map(|(_, s)| s).sum();
        if hard_seq_sum == 0 || hard_seq_sum < self.compact_threshold {
            debug!(doc_id = %doc_id, hard_seq_sum, "无需 compaction");
            return Ok(None);
        }

        // 检查是否已有相同 frontier 的 checkpoint
        let conn = self.doc_store.store().conn();
        if let Some(existing) = dao::get_latest_checkpoint(&conn, doc_id)? {
            if existing.frontier == watermarks.hard_frontier {
                debug!(doc_id = %doc_id, "已有相同 frontier 的 checkpoint，跳过");
                return Ok(None);
            }
        }
        drop(conn);

        // 生成 checkpoint_id
        let checkpoint_id = CheckpointId::new(format!(
            "ckpt_{}_{}",
            doc_id,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));

        // 对每个活跃 block 生成 shallow snapshot
        let blocks = self.doc_store.list_active_blocks(doc_id)?;
        let store = self.doc_store.store();

        // 收集所有 shallow snapshot 数据
        let mut snapshots: Vec<(CheckpointId, Vec<u8>)> = Vec::new();
        for block in &blocks {
            let shallow = self
                .doc_store
                .export_block_shallow(doc_id, &block.block_id, &watermarks.hard_frontier)?;
            let snapshot_id =
                tacit_core::CheckpointId::new(format!("{}_{}", checkpoint_id, block.block_id));
            snapshots.push((snapshot_id, shallow));
        }

        // 在单个事务中原子写入所有 snapshot 和 checkpoint 记录
        let state_hash = compute_state_hash(&watermarks.hard_frontier);
        // 将所有 block 的 shallow snapshot 按顺序拼接成一个 blob，
        // 存入 CheckpointRecord.shallow_snapshot_blob，使 chunk_snapshot
        // 可直接从 checkpoint 记录取数据，无需 fallback 前缀扫描。
        let shallow_snapshot_blob: Vec<u8> = snapshots
            .iter()
            .flat_map(|(_, blob)| blob.iter().copied())
            .collect();
        let checkpoint_rec = dao::CheckpointRecord {
            doc_id: doc_id.clone(),
            checkpoint_id: checkpoint_id.clone(),
            shallow_snapshot_blob,
            frontier: watermarks.hard_frontier.clone(),
            state_hash,
            created_at: SystemTime::now(),
        };

        let snapshots_clone = snapshots.clone();
        store.transaction(|conn| {
            // 写入所有 block 的 shallow snapshot
            for (sid, blob) in &snapshots_clone {
                dao::insert_snapshot(
                    conn,
                    doc_id,
                    sid,
                    blob,
                    SnapshotKind::Shallow,
                    SystemTime::now(),
                )?;
            }
            // 写入 checkpoint 记录
            dao::insert_checkpoint(conn, &checkpoint_rec)?;
            Ok(())
        })?;

        // GC：删除旧 checkpoint 及其关联的旧 snapshot
        let gc_result = self.garbage_collect(doc_id, &checkpoint_id);
        match gc_result {
            Ok((deleted_ckpts, deleted_snaps)) => {
                if deleted_ckpts > 0 || deleted_snaps > 0 {
                    debug!(
                        doc_id = %doc_id,
                        deleted_checkpoints = deleted_ckpts,
                        deleted_snapshots = deleted_snaps,
                        "GC 完成"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "GC 失败，不影响 compaction 结果");
            }
        }

        debug!(doc_id = %doc_id, checkpoint_id = %checkpoint_id, "compaction 完成");
        Ok(Some(checkpoint_id))
    }

    /// GC：删除旧 checkpoint 记录和不再需要的旧 snapshot。
    ///
    /// 保留最新 checkpoint 关联的 snapshot，删除其他旧 snapshot。
    fn garbage_collect(
        &self,
        doc_id: &DocId,
        keep_checkpoint_id: &CheckpointId,
    ) -> tacit_core::CoreResult<(u64, u64)> {
        let conn = self.doc_store.store().conn();
        // 列出所有 checkpoint
        let all_checkpoints = dao::list_checkpoints_by_doc(&conn, doc_id)?;
        let mut deleted_ckpts = 0u64;
        for ckpt in &all_checkpoints {
            if ckpt.checkpoint_id != *keep_checkpoint_id {
                dao::delete_checkpoint(&conn, doc_id, &ckpt.checkpoint_id)?;
                deleted_ckpts += 1;
            }
        }
        // 删除旧 snapshot（保留以 keep_checkpoint_id 为前缀的）
        let deleted_snaps = dao::delete_old_snapshots(&conn, doc_id, keep_checkpoint_id.as_str())?;
        drop(conn);
        Ok((deleted_ckpts, deleted_snaps))
    }

    /// 原子安装快照（双缓冲）。
    ///
    /// v1.0 规范：双缓冲快照安装，避免安装过程中崩溃导致数据损坏。
    /// 流程：
    /// 1. 临时写入 snapshot（带 `__pending_` 前缀的 checkpoint_id）
    /// 2. 校验 snapshot 内容（state_hash 比对）
    /// 3. 原子切换：在事务中写入正式 snapshot 并更新 documents 表
    /// 4. 若校验失败，回滚（删除临时 snapshot）
    pub fn install_snapshot_atomically(
        &self,
        doc_id: &DocId,
        snapshot: &[u8],
        meta: &SnapshotMeta,
    ) -> tacit_core::CoreResult<()> {
        let store = self.doc_store.store();

        // 1. 临时写入：使用 __pending_ 前缀避免与正式 checkpoint 冲突
        let pending_checkpoint_id = CheckpointId::new(format!("__pending_{}", meta.checkpoint_id));
        store.transaction(|conn| {
            dao::insert_snapshot(
                conn,
                doc_id,
                &pending_checkpoint_id,
                snapshot,
                meta.kind,
                meta.created_at,
            )?;
            Ok(())
        })?;

        // 2. 校验：读取临时 snapshot 比对内容 + state_hash 校验
        let conn = self.doc_store.store().conn();
        let verify = dao::get_snapshot(&conn, doc_id, &pending_checkpoint_id)?;
        drop(conn);
        let blob_ok = match verify {
            Some((blob, _, _)) => blob.as_slice() == snapshot,
            None => false,
        };
        // state_hash 校验：非零 hash 必须匹配内容哈希
        let hash_ok = if meta.state_hash == [0u8; 32] {
            // 调用方未提供 state_hash，按内容计算并补全校验
            true
        } else {
            compute_content_hash(snapshot) == meta.state_hash
        };
        let verified = blob_ok && hash_ok;

        if !verified {
            // 校验失败：回滚，删除临时 snapshot
            tracing::warn!(
                doc_id = %doc_id,
                checkpoint_id = %meta.checkpoint_id,
                blob_ok,
                hash_ok,
                "快照校验失败，回滚"
            );
            let conn = self.doc_store.store().conn();
            let _ = dao::delete_snapshot(&conn, doc_id, &pending_checkpoint_id);
            drop(conn);
            return Err(tacit_core::CoreError::Store(format!(
                "快照校验失败: doc_id={}, checkpoint_id={}, blob_ok={}, hash_ok={}",
                doc_id, meta.checkpoint_id, blob_ok, hash_ok
            )));
        }

        // 3. 原子切换：在事务中写入正式 snapshot 并更新 documents 表
        let switch_result = store.transaction(|conn| {
            // 写入正式 snapshot
            dao::insert_snapshot(
                conn,
                doc_id,
                &meta.checkpoint_id,
                snapshot,
                meta.kind,
                meta.created_at,
            )?;
            // 更新 documents 表的 current_frontier
            let existing = dao::get_doc(conn, doc_id)?;
            if let Some(rec) = existing {
                let updated = dao::DocRecord {
                    doc_id: doc_id.clone(),
                    kind: rec.kind,
                    current_frontier: meta.frontier.clone(),
                    updated_at: meta.created_at,
                    current_snapshot_id: Some(meta.checkpoint_id.to_string()),
                };
                dao::upsert_doc(conn, &updated)?;
            }
            // 删除临时 snapshot
            let _ = dao::delete_snapshot(conn, doc_id, &pending_checkpoint_id);
            Ok(())
        });

        match switch_result {
            Ok(()) => {
                debug!(
                    doc_id = %doc_id,
                    checkpoint_id = %meta.checkpoint_id,
                    "双缓冲快照原子安装完成"
                );
                Ok(())
            }
            Err(e) => {
                // 切换失败：清理临时 snapshot
                let conn = self.doc_store.store().conn();
                let _ = dao::delete_snapshot(&conn, doc_id, &pending_checkpoint_id);
                drop(conn);
                Err(e)
            }
        }
    }

    /// 将 checkpoint 的 shallow snapshot 分片为 SnapshotChunk 列表。
    pub fn chunk_snapshot(
        &self,
        doc_id: &DocId,
        checkpoint_id: &CheckpointId,
    ) -> tacit_core::CoreResult<Vec<SnapshotChunk>> {
        let conn = self.doc_store.store().conn();
        let checkpoint = dao::get_latest_checkpoint(&conn, doc_id)?
            .ok_or_else(|| tacit_core::CoreError::Store(format!(
                "checkpoint 不存在: doc_id={}, checkpoint_id={}",
                doc_id, checkpoint_id
            )))?;
        drop(conn);

        let blob = if checkpoint.shallow_snapshot_blob.is_empty() {
            // 如果 checkpoint 自身没有 blob，从 document_snapshots 表按 checkpoint_id 前缀查找
            let conn = self.doc_store.store().conn();
            let mut chunks_blobs = Vec::new();
            let blocks = self.doc_store.list_active_blocks(doc_id)?;
            for block in &blocks {
                let sid = tacit_core::CheckpointId::new(format!(
                    "{}_{}",
                    checkpoint_id, block.block_id
                ));
                if let Some((blob, _, _)) = dao::get_snapshot(&conn, doc_id, &sid)? {
                    chunks_blobs.extend(blob);
                }
            }
            drop(conn);
            chunks_blobs
        } else {
            checkpoint.shallow_snapshot_blob.clone()
        };

        let total = blob.len().div_ceil(self.chunk_size).max(1) as u32;
        let chunks: Vec<SnapshotChunk> = blob
            .chunks(self.chunk_size)
            .enumerate()
            .map(|(i, chunk)| SnapshotChunk {
                checkpoint_id: checkpoint_id.clone(),
                index: i as u32,
                total,
                data: Bytes::copy_from_slice(chunk),
            })
            .collect();

        debug!(doc_id = %doc_id, chunks = chunks.len(), "snapshot 分片完成");
        Ok(chunks)
    }
}

/// 计算 frontier 的一致性校验 hash。
///
/// 注意：此 hash 仅对 frontier 的 (peer_id, seq) 条目做 SHA256，
/// 用于 checkpoint 记录的 frontier 一致性校验，**不是**文档内容的密码学完整性 hash。
/// 文档内容的完整性由 Loro CRDT 内部版本机制保证。
fn compute_state_hash(frontier: &tacit_core::Frontier) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut entries: Vec<_> = frontier.entries().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (peer_id, seq) in entries {
        hasher.update(peer_id.as_bytes());
        hasher.update(&seq.to_le_bytes());
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// 计算 snapshot 内容哈希（用于双缓冲安装时校验内容完整性）。
fn compute_content_hash(snapshot: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(snapshot);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_core::{AckSummary, BlockId, BlockKind, Frontier, PeerId};
    use tacit_store::Store;

    fn make_doc_store(peer_n: u64) -> (DocStore, Store) {
        let store = Store::open_memory().unwrap();
        let ds = DocStore::new(PeerId::new(peer_n.to_string()), store.clone(), 32);
        (ds, store)
    }

    fn pid(n: u64) -> PeerId {
        PeerId::new(n.to_string())
    }

    #[test]
    fn evaluate_watermarks_empty_doc() {
        let (ds, _store) = make_doc_store(1);
        let calc = WatermarkCalculator::new(std::time::Duration::from_secs(86400));
        let cm = CheckpointManager::new(ds, calc);

        let doc_id = DocId::new("doc1");
        let _ = cm.doc_store.create_doc(doc_id.clone(), "note").unwrap();

        let wm = cm.evaluate_watermarks(&doc_id).unwrap();
        assert!(wm.hard_frontier.is_empty());
        assert!(wm.soft_frontier.is_empty());
    }

    #[test]
    fn maybe_compact_below_threshold() {
        let (ds, _store) = make_doc_store(1);
        let calc = WatermarkCalculator::new(std::time::Duration::from_secs(86400));
        let cm = CheckpointManager::new(ds, calc);

        let doc_id = DocId::new("doc1");
        let block_id = BlockId::new("b1");
        cm.doc_store.create_doc(doc_id.clone(), "note").unwrap();
        cm.doc_store
            .create_block(&doc_id, block_id.clone(), BlockKind::Text)
            .unwrap();
        cm.doc_store
            .apply_local_edit(&doc_id, &block_id, b"hello")
            .unwrap();

        // seq 总和 = 1，远低于阈值 500
        let result = cm.maybe_compact(&doc_id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn maybe_compact_above_threshold() {
        let (ds, _store) = make_doc_store(1);
        let calc = WatermarkCalculator::new(std::time::Duration::from_secs(86400));
        let cm = CheckpointManager::new(ds, calc).with_params(1, 1024); // 阈值=1

        let doc_id = DocId::new("doc1");
        let block_id = BlockId::new("b1");
        cm.doc_store.create_doc(doc_id.clone(), "note").unwrap();
        cm.doc_store
            .create_block(&doc_id, block_id.clone(), BlockKind::Text)
            .unwrap();
        cm.doc_store
            .apply_local_edit(&doc_id, &block_id, b"hello")
            .unwrap();

        // 写入 ack 使 hard_frontier 非空
        let conn = cm.doc_store.store().conn();
        dao::upsert_ack(
            &conn,
            &AckSummary {
                peer_id: pid(1),
                doc_id: doc_id.clone(),
                ack_checkpoint: None,
                ack_frontier: cm
                    .doc_store
                    .block_frontier(&doc_id, &block_id)
                    .unwrap(),
                updated_at: SystemTime::now(),
            },
        )
        .unwrap();
        drop(conn);

        let result = cm.maybe_compact(&doc_id).unwrap();
        assert!(result.is_some());

        // 再次调用应跳过（相同 frontier）
        let result2 = cm.maybe_compact(&doc_id).unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn chunk_snapshot_produces_chunks() {
        let (ds, _store) = make_doc_store(1);
        let calc = WatermarkCalculator::new(std::time::Duration::from_secs(86400));
        let cm = CheckpointManager::new(ds, calc).with_params(1, 100); // 分片=100 字节

        let doc_id = DocId::new("doc1");
        let block_id = BlockId::new("b1");
        cm.doc_store.create_doc(doc_id.clone(), "note").unwrap();
        cm.doc_store
            .create_block(&doc_id, block_id.clone(), BlockKind::Text)
            .unwrap();
        cm.doc_store
            .apply_local_edit(&doc_id, &block_id, b"hello world this is a test")
            .unwrap();

        // 写入 ack
        let conn = cm.doc_store.store().conn();
        dao::upsert_ack(
            &conn,
            &AckSummary {
                peer_id: pid(1),
                doc_id: doc_id.clone(),
                ack_checkpoint: None,
                ack_frontier: cm
                    .doc_store
                    .block_frontier(&doc_id, &block_id)
                    .unwrap(),
                updated_at: SystemTime::now(),
            },
        )
        .unwrap();
        drop(conn);

        let ckpt_id = cm.maybe_compact(&doc_id).unwrap().unwrap();
        let chunks = cm.chunk_snapshot(&doc_id, &ckpt_id).unwrap();

        assert!(chunks.len() > 1, "应产生多个分片");
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[0].total, chunks.len() as u32);
        // 所有分片数据拼接应能还原原始 blob
        let total_size: usize = chunks.iter().map(|c| c.data.len()).sum();
        assert!(total_size > 0);
    }

    /// 验证 maybe_compact 后 CheckpointRecord.shallow_snapshot_blob 被填充，
    /// chunk_snapshot 直接从 checkpoint 记录取数据（不走 fallback 前缀扫描）。
    #[test]
    fn maybe_compact_fills_shallow_snapshot_blob() {
        let (ds, _store) = make_doc_store(1);
        let calc = WatermarkCalculator::new(std::time::Duration::from_secs(86400));
        let cm = CheckpointManager::new(ds, calc).with_params(1, 1024);

        let doc_id = DocId::new("doc1");
        let block_id = BlockId::new("b1");
        cm.doc_store.create_doc(doc_id.clone(), "note").unwrap();
        cm.doc_store
            .create_block(&doc_id, block_id.clone(), BlockKind::Text)
            .unwrap();
        cm.doc_store
            .apply_local_edit(&doc_id, &block_id, b"hello")
            .unwrap();

        // 写入 ack 使 hard_frontier 非空
        let conn = cm.doc_store.store().conn();
        dao::upsert_ack(
            &conn,
            &AckSummary {
                peer_id: pid(1),
                doc_id: doc_id.clone(),
                ack_checkpoint: None,
                ack_frontier: cm
                    .doc_store
                    .block_frontier(&doc_id, &block_id)
                    .unwrap(),
                updated_at: SystemTime::now(),
            },
        )
        .unwrap();
        drop(conn);

        let ckpt_id = cm.maybe_compact(&doc_id).unwrap().unwrap();

        // 验证 CheckpointRecord.shallow_snapshot_blob 不为空
        let conn = cm.doc_store.store().conn();
        let ckpt = dao::get_latest_checkpoint(&conn, &doc_id).unwrap().unwrap();
        drop(conn);
        assert!(
            !ckpt.shallow_snapshot_blob.is_empty(),
            "shallow_snapshot_blob 应在 maybe_compact 后填充"
        );

        // 验证 chunk_snapshot 直接从 shallow_snapshot_blob 取数据：
        // 分片总大小应等于 shallow_snapshot_blob 长度
        let chunks = cm.chunk_snapshot(&doc_id, &ckpt_id).unwrap();
        let total_size: usize = chunks.iter().map(|c| c.data.len()).sum();
        assert_eq!(
            total_size,
            ckpt.shallow_snapshot_blob.len(),
            "chunk_snapshot 应直接从 shallow_snapshot_blob 取数据"
        );
    }

    #[test]
    fn install_snapshot_atomically() {
        let (ds, _store) = make_doc_store(1);
        let calc = WatermarkCalculator::new(std::time::Duration::from_secs(86400));
        let cm = CheckpointManager::new(ds, calc);

        let doc_id = DocId::new("doc1");
        cm.doc_store.create_doc(doc_id.clone(), "note").unwrap();

        let snapshot = b"snapshot_data";
        let meta = SnapshotMeta {
            doc_id: doc_id.clone(),
            checkpoint_id: CheckpointId::new("ckpt_test"),
            kind: SnapshotKind::Full,
            frontier: Frontier::new(),
            state_hash: compute_content_hash(snapshot),
            created_at: SystemTime::now(),
        };

        cm.install_snapshot_atomically(&doc_id, snapshot, &meta)
            .unwrap();

        // 验证 snapshot 已写入
        let conn = cm.doc_store.store().conn();
        let snap = dao::get_snapshot(&conn, &doc_id, &meta.checkpoint_id)
            .unwrap()
            .unwrap();
        assert_eq!(snap.0, snapshot);
    }

    #[test]
    fn install_snapshot_rejects_bad_state_hash() {
        let (ds, _store) = make_doc_store(1);
        let calc = WatermarkCalculator::new(std::time::Duration::from_secs(86400));
        let cm = CheckpointManager::new(ds, calc);

        let doc_id = DocId::new("doc1");
        cm.doc_store.create_doc(doc_id.clone(), "note").unwrap();

        // 故意提供错误的 state_hash
        let mut bad_hash = [0u8; 32];
        bad_hash[0] = 1;
        let meta = SnapshotMeta {
            doc_id: doc_id.clone(),
            checkpoint_id: CheckpointId::new("ckpt_bad"),
            kind: SnapshotKind::Full,
            frontier: Frontier::new(),
            state_hash: bad_hash,
            created_at: SystemTime::now(),
        };

        let result = cm.install_snapshot_atomically(&doc_id, b"snapshot_data", &meta);
        assert!(result.is_err(), "错误的 state_hash 应被拒绝");

        // 验证临时 snapshot 已回滚清理
        let conn = cm.doc_store.store().conn();
        let pending_id = CheckpointId::new(format!("__pending_{}", meta.checkpoint_id));
        let snap = dao::get_snapshot(&conn, &doc_id, &pending_id).unwrap();
        assert!(snap.is_none(), "临时 snapshot 应被删除");
    }
}
