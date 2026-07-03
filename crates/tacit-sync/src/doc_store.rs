//! DocStore：文档状态管理器。
//!
//! 持有 MetaDoc 与 BlockDocCache，协调与 Store 的持久化。
//! SyncEngine 通过 DocStore 操作文档状态，不直接接触 LoroDoc。
//!
//! 职责：
//! - 打开/恢复文档（MetaDoc + BlockDoc）
//! - 应用本地编辑，产生 delta
//! - 导入远端 delta/snapshot
//! - 导出 delta/snapshot 供传输
//! - 与 Store 协调持久化 frontier/snapshot

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::Mutex;
use tacit_core::{
    ApplyResult, BlockId, BlockKind, BlockRecord, CoreError, CoreResult, DocId, Frontier,
    ImportResult, PeerId,
};
use tacit_crdt::{BlockDoc, BlockDocCache, MetaDoc};
use tacit_store::{dao, Store};

use tacit_core::CheckpointId;

/// 文档状态管理器。
///
/// 每个 doc 对应一个 MetaDoc（常驻内存）和若干 BlockDoc（LRU 缓存）。
/// 持久化层通过 [`Store`] 协调，frontier/snapshot 落 SQLite。
pub struct DocStore {
    peer_id: PeerId,
    store: Store,
    cache: BlockDocCache,
    /// doc_id -> MetaDoc。常驻内存。
    metas: Mutex<HashMap<DocId, Arc<MetaDoc>>>,
    /// 脏 block 集合：(doc_id, block_id) — 已编辑但未持久化 snapshot 的 block。
    /// apply_local_edit 时标记，flush_dirty_blocks 时批量写入并清空。
    dirty_blocks: Mutex<HashSet<(DocId, BlockId)>>,
}

impl DocStore {
    /// 创建 DocStore。
    pub fn new(peer_id: PeerId, store: Store, cache_capacity: usize) -> Self {
        Self {
            peer_id,
            store,
            cache: BlockDocCache::new(cache_capacity),
            metas: Mutex::new(HashMap::new()),
            dirty_blocks: Mutex::new(HashSet::new()),
        }
    }

    /// 本设备 PeerId。
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// 底层 Store 引用。
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// 获取文档的 kind（从 documents 表读取，避免硬编码）。
    fn doc_kind(&self, doc_id: &DocId) -> CoreResult<String> {
        let conn = self.store.conn();
        let rec = dao::get_doc(&conn, doc_id)?
            .ok_or_else(|| CoreError::DocNotFound(doc_id.to_string()))?;
        Ok(rec.kind)
    }

    /// 创建新文档。
    pub fn create_doc(&self, doc_id: DocId, kind: &str) -> CoreResult<()> {
        let meta = MetaDoc::new(doc_id.clone(), &self.peer_id)?;
        let frontier = meta.frontier()?;
        self.metas.lock().insert(doc_id.clone(), Arc::new(meta));
        // 持久化 doc 记录
        let conn = self.store.conn();
        dao::upsert_doc(
            &conn,
            &dao::DocRecord {
                doc_id: doc_id.clone(),
                kind: kind.to_string(),
                current_frontier: frontier,
                updated_at: SystemTime::now(),
                current_snapshot_id: None,
            },
        )?;
        Ok(())
    }

    /// 打开文档（从 store 恢复或返回已缓存的 MetaDoc）。
    pub fn open_doc(&self, doc_id: &DocId) -> CoreResult<Arc<MetaDoc>> {
        // 先查内存
        if let Some(meta) = self.metas.lock().get(doc_id) {
            return Ok(meta.clone());
        }
        // 从 store 恢复
        let conn = self.store.conn();
        let _doc_rec = dao::get_doc(&conn, doc_id)?
            .ok_or_else(|| CoreError::DocNotFound(doc_id.to_string()))?;
        // 尝试从最新 snapshot 恢复 MetaDoc
        let meta = if let Some((_, blob, _, _)) = dao::get_latest_snapshot(&conn, doc_id)? {
            MetaDoc::from_snapshot(doc_id.clone(), &self.peer_id, &blob)?
        } else {
            // 无 snapshot，创建空 MetaDoc
            MetaDoc::new(doc_id.clone(), &self.peer_id)?
        };
        let meta = Arc::new(meta);
        self.metas.lock().insert(doc_id.clone(), meta.clone());
        Ok(meta)
    }

    /// 创建新 block。
    ///
    /// 事务边界：先创建并持久化 BlockDoc 初始状态，再更新 MetaDoc 引用。
    /// 这样即便崩溃，最多留下可恢复的悬挂引用，而不会丢掉 block 初始数据。
    pub fn create_block(
        &self,
        doc_id: &DocId,
        block_id: BlockId,
        kind: BlockKind,
    ) -> CoreResult<()> {
        let meta = self.open_doc(doc_id)?;
        // 1. 创建 BlockDoc 并导出初始 snapshot
        let block = BlockDoc::new(block_id.clone(), kind, &self.peer_id)?;
        let snap = block.export_snapshot()?;
        // 2. 更新 MetaDoc（内存操作，不持锁）
        meta.add_block(block_id.clone(), kind)?;
        let meta_snap = meta.export_snapshot()?;
        let frontier = meta.frontier()?;
        // 3. 预取 doc kind（避免在持锁期间再次获取锁导致死锁）
        let doc_kind = self.doc_kind(doc_id)?;
        // 4. 在单事务中原子写入：block snapshot + meta snapshot + doc frontier
        self.store.transaction(|conn| {
            dao::insert_snapshot(
                conn,
                doc_id,
                &CheckpointId::new(block_id.as_str()),
                &snap,
                tacit_core::SnapshotKind::Full,
                SystemTime::now(),
            )?;
            dao::insert_snapshot(
                conn,
                doc_id,
                &CheckpointId::new("meta"),
                &meta_snap,
                tacit_core::SnapshotKind::Full,
                SystemTime::now(),
            )?;
            dao::upsert_doc(
                conn,
                &dao::DocRecord {
                    doc_id: doc_id.clone(),
                    kind: doc_kind,
                    current_frontier: frontier,
                    updated_at: SystemTime::now(),
                    current_snapshot_id: None,
                },
            )?;
            Ok(())
        })?;
        // 5. 放入 cache
        self.cache.insert(block_id, Arc::new(block));
        Ok(())
    }

    /// 获取 block（从 cache 或 store 恢复）。
    pub fn get_block(&self, doc_id: &DocId, block_id: &BlockId) -> CoreResult<Arc<BlockDoc>> {
        // 先查 cache
        if let Some(block) = self.cache.get(block_id) {
            return Ok(block);
        }
        // 从 store 恢复：按 block_id 精确查找 snapshot（避免误读 meta snapshot）
        let conn = self.store.conn();
        let (blob, _, _) = dao::get_snapshot(&conn, doc_id, &CheckpointId::new(block_id.as_str()))?
            .ok_or_else(|| CoreError::BlockNotFound {
                doc_id: doc_id.to_string(),
                block_id: block_id.to_string(),
            })?;
        drop(conn);
        // 从 MetaDoc 查找 block kind
        let meta = self.open_doc(doc_id)?;
        let kind = meta
            .list_blocks()?
            .into_iter()
            .find(|b| b.block_id == *block_id)
            .map(|b| b.kind)
            .unwrap_or(BlockKind::Text);
        let block = BlockDoc::from_snapshot(block_id.clone(), kind, &self.peer_id, &blob)?;
        let block = Arc::new(block);
        self.cache.insert(block_id.clone(), block.clone());
        Ok(block)
    }

    /// 应用本地编辑到 block。
    ///
    /// 写放大优化：仅更新 frontier（轻量 DB 写），block snapshot 延迟到 flush_dirty_blocks 时批量写入。
    /// 调用方应在同步前或定期调用 flush_dirty_blocks 确保持久化。
    pub fn apply_local_edit(
        &self,
        doc_id: &DocId,
        block_id: &BlockId,
        edit_bytes: &[u8],
    ) -> CoreResult<ApplyResult> {
        let block = self.get_block(doc_id, block_id)?;
        let result = block.apply_edit(edit_bytes)?;
        // 更新 doc frontier（轻量 DB 写，仅更新 frontier 记录）
        let meta = self.open_doc(doc_id)?;
        let meta_frontier = meta.frontier()?;
        let mut frontier = meta_frontier;
        frontier.merge(&result.new_frontier);
        // 预取 doc kind（避免在持锁期间再次获取锁导致死锁）
        let doc_kind = self.doc_kind(doc_id)?;
        // 仅更新 frontier，不写 block snapshot（延迟到 flush）
        self.store.transaction(|conn| {
            dao::upsert_doc(
                conn,
                &dao::DocRecord {
                    doc_id: doc_id.clone(),
                    kind: doc_kind,
                    current_frontier: frontier,
                    updated_at: SystemTime::now(),
                    current_snapshot_id: None,
                },
            )?;
            Ok(())
        })?;
        // 标记 block 为脏（待 flush）
        self.dirty_blocks
            .lock()
            .insert((doc_id.clone(), block_id.clone()));
        Ok(result)
    }

    /// 刷新所有脏 block：批量持久化 snapshot 并清空脏标记。
    ///
    /// 应在同步前或定期调用，确保编辑不丢失。
    /// 返回刷新的 block 数量。
    pub fn flush_dirty_blocks(&self) -> CoreResult<usize> {
        let dirty: Vec<(DocId, BlockId)> = {
            let mut dirty = self.dirty_blocks.lock();
            if dirty.is_empty() {
                return Ok(0);
            }
            dirty.drain().collect()
        };

        let count = dirty.len();
        if count == 0 {
            return Ok(0);
        }

        // 批量写入所有脏 block 的 snapshot
        self.store.transaction(|conn| {
            for (doc_id, block_id) in &dirty {
                if let Some(block) = self.cache.get(block_id) {
                    let snap = block.export_snapshot()?;
                    dao::insert_snapshot(
                        conn,
                        doc_id,
                        &CheckpointId::new(block_id.as_str()),
                        &snap,
                        tacit_core::SnapshotKind::Full,
                        SystemTime::now(),
                    )?;
                }
            }
            Ok(())
        })?;

        tracing::debug!(flushed = count, "已刷新脏 block snapshot");
        Ok(count)
    }

    /// 检查是否有未持久化的脏 block。
    pub fn has_dirty_blocks(&self) -> bool {
        !self.dirty_blocks.lock().is_empty()
    }

    /// 导入远端 block delta/snapshot。
    pub fn import_block(
        &self,
        doc_id: &DocId,
        block_id: &BlockId,
        bytes: &[u8],
    ) -> CoreResult<ImportResult> {
        let block = self.get_block(doc_id, block_id)?;
        let result = block.import(bytes)?;
        if result.changed {
            // 持久化更新后的 snapshot
            let snap = block.export_snapshot()?;
            let conn = self.store.conn();
            dao::insert_snapshot(
                &conn,
                doc_id,
                &CheckpointId::new(block_id.as_str()),
                &snap,
                tacit_core::SnapshotKind::Full,
                SystemTime::now(),
            )?;
        }
        Ok(result)
    }

    /// 批量导入多个 block delta/snapshot。
    ///
    /// 在单个事务中持久化所有变更的 block snapshot，减少事务开销。
    /// 适用于大量 block 追赶场景（如长时间离线后恢复）。
    ///
    /// 返回每个 block 的导入结果，顺序与输入一致。
    pub fn import_blocks_batch(
        &self,
        doc_id: &DocId,
        blocks: &[(BlockId, Vec<u8>)],
    ) -> CoreResult<Vec<ImportResult>> {
        // 1. 逐个导入 delta（CRDT 操作，不涉及 I/O）
        //    同时保存旧 snapshot，以便任意阶段失败时回滚内存状态
        //    使用 HashMap 去重：同一 block 在批次中出现多次时，只保留最终 snapshot
        let mut results = Vec::with_capacity(blocks.len());
        let mut changed_blocks: std::collections::HashMap<BlockId, Vec<u8>> =
            std::collections::HashMap::new();
        // rollback_list 记录所有「尝试过导入」的 block 的导入前状态。
        // 即使 import() 成功但 export_snapshot() 失败，该 block 也已被 mutate，
        // 必须用 rollback_list 而非 changed_blocks 才能覆盖此场景。
        let mut rollback_list: Vec<(BlockId, BlockKind, Option<Vec<u8>>)> = Vec::new();

        // 闭包：用旧 snapshot 回滚已变更的 block 内存状态
        let rollback_memory = |targets: &[(BlockId, BlockKind, Option<Vec<u8>>)]| {
            for (block_id, kind, old_snap) in targets {
                let restored = match old_snap {
                    Some(snap) if !snap.is_empty() => {
                        BlockDoc::from_snapshot(block_id.clone(), *kind, &self.peer_id, snap)
                    }
                    _ => BlockDoc::new(block_id.clone(), *kind, &self.peer_id),
                };
                match restored {
                    Ok(r) => {
                        self.cache.insert(block_id.clone(), Arc::new(r));
                        tracing::debug!(block_id = %block_id, "已回滚内存状态");
                    }
                    Err(e) => {
                        // 回滚失败：清除缓存条目，使下次访问时从 DB 重新加载正确状态，
                        // 避免损坏的 BlockDoc 残留在内存中造成状态不一致
                        self.cache.remove(block_id);
                        tracing::error!(
                            block_id = %block_id, error = %e,
                            "回滚内存状态失败，已从缓存中移除该 block，下次访问将从数据库重新加载"
                        );
                    }
                }
            }
        };

        // 内存导入阶段：若中途任一 block 导入或导出失败，回滚所有已尝试的 block
        for (block_id, bytes) in blocks {
            let block = match self.get_block(doc_id, block_id) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(
                        doc_id = %doc_id, error = %e,
                        "批量导入获取 block 失败，正在回滚已变更的内存状态"
                    );
                    rollback_memory(&rollback_list);
                    return Err(e);
                }
            };
            let old_snap = block.export_snapshot().ok();
            let kind = block.kind();
            // 在 import 之前就记录，确保即使 import/export 失败也能回滚
            rollback_list.push((block_id.clone(), kind, old_snap));

            let result = match block.import(bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(
                        doc_id = %doc_id, error = %e,
                        "批量导入 CRDT 内存导入失败，正在回滚已变更的内存状态"
                    );
                    rollback_memory(&rollback_list);
                    return Err(e);
                }
            };
            if result.changed {
                let new_snap = match block.export_snapshot() {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            doc_id = %doc_id, error = %e,
                            "导出 snapshot 失败，正在回滚已变更的内存状态"
                        );
                        rollback_memory(&rollback_list);
                        return Err(e);
                    }
                };
                // 仅保留最新 snapshot（同 block 多次出现时覆盖）
                changed_blocks.insert(block_id.clone(), new_snap);
            }
            results.push(result);
        }

        // 2. 在单个事务中批量持久化所有变更的 snapshot（每个 block 仅写一次）
        if !changed_blocks.is_empty() {
            if let Err(e) = self.store.transaction(|conn| {
                for (block_id, snap) in &changed_blocks {
                    dao::insert_snapshot(
                        conn,
                        doc_id,
                        &CheckpointId::new(block_id.as_str()),
                        snap,
                        tacit_core::SnapshotKind::Full,
                        SystemTime::now(),
                    )?;
                }
                Ok(())
            }) {
                // DB 写入失败：用 rollback_list 回滚所有已导入的 block
                tracing::error!(
                    doc_id = %doc_id, error = %e,
                    "批量导入 DB 写入失败，正在回滚内存状态"
                );
                rollback_memory(&rollback_list);
                return Err(e);
            }
            tracing::debug!(
                doc_id = %doc_id,
                total = blocks.len(),
                changed = changed_blocks.len(),
                "批量导入完成"
            );
        }

        Ok(results)
    }

    /// 导入远端 MetaDoc delta/snapshot。
    pub fn import_meta(&self, doc_id: &DocId, bytes: &[u8]) -> CoreResult<ImportResult> {
        let meta = self.open_doc(doc_id)?;
        let result = meta.import(bytes)?;
        if result.changed {
            // 持久化 meta snapshot
            let snap = meta.export_snapshot()?;
            let frontier = meta.frontier()?;
            // 预取 doc kind（避免在持锁期间再次获取锁导致死锁）
            let doc_kind = self.doc_kind(doc_id)?;
            // 在单事务中原子写入 meta snapshot + doc frontier
            self.store.transaction(|conn| {
                dao::insert_snapshot(
                    conn,
                    doc_id,
                    &CheckpointId::new("meta"),
                    &snap,
                    tacit_core::SnapshotKind::Full,
                    SystemTime::now(),
                )?;
                dao::upsert_doc(
                    conn,
                    &dao::DocRecord {
                        doc_id: doc_id.clone(),
                        kind: doc_kind,
                        current_frontier: frontier,
                        updated_at: SystemTime::now(),
                        current_snapshot_id: None,
                    },
                )?;
                Ok(())
            })?;
        }
        Ok(result)
    }

    /// 导出 block 自指定 frontier 之后的 delta。
    pub fn export_block_delta(
        &self,
        doc_id: &DocId,
        block_id: &BlockId,
        since: &Frontier,
    ) -> CoreResult<Vec<u8>> {
        let block = self.get_block(doc_id, block_id)?;
        block.export_delta_since(since)
    }

    /// 导出 MetaDoc 自指定 frontier 之后的 delta。
    pub fn export_meta_delta(&self, doc_id: &DocId, since: &Frontier) -> CoreResult<Vec<u8>> {
        let meta = self.open_doc(doc_id)?;
        meta.export_delta_since(since)
    }

    /// 导出 block 完整 snapshot。
    pub fn export_block_snapshot(&self, doc_id: &DocId, block_id: &BlockId) -> CoreResult<Vec<u8>> {
        let block = self.get_block(doc_id, block_id)?;
        block.export_snapshot()
    }

    /// 导出 MetaDoc 完整 snapshot。
    pub fn export_meta_snapshot(&self, doc_id: &DocId) -> CoreResult<Vec<u8>> {
        let meta = self.open_doc(doc_id)?;
        meta.export_snapshot()
    }

    /// 导出 block 的 shallow snapshot（用于 stale 追赶）。
    pub fn export_block_shallow(
        &self,
        doc_id: &DocId,
        block_id: &BlockId,
        at: &Frontier,
    ) -> CoreResult<Vec<u8>> {
        let block = self.get_block(doc_id, block_id)?;
        block.export_shallow_snapshot(at)
    }

    /// 获取 MetaDoc 当前 frontier。
    pub fn meta_frontier(&self, doc_id: &DocId) -> CoreResult<Frontier> {
        let meta = self.open_doc(doc_id)?;
        meta.frontier()
    }

    /// 获取 block 当前 frontier。
    pub fn block_frontier(&self, doc_id: &DocId, block_id: &BlockId) -> CoreResult<Frontier> {
        let block = self.get_block(doc_id, block_id)?;
        block.frontier()
    }

    /// 列出文档的所有 block（含已删除）。
    pub fn list_blocks(&self, doc_id: &DocId) -> CoreResult<Vec<BlockRecord>> {
        let meta = self.open_doc(doc_id)?;
        meta.list_blocks()
    }

    /// 列出所有文档的 ID。
    ///
    /// 供首屏恢复冷文档追赶阶段遍历所有文档使用。
    pub fn list_doc_ids(&self) -> CoreResult<Vec<DocId>> {
        let conn = self.store.conn();
        let docs = dao::list_docs(&conn)?;
        Ok(docs.into_iter().map(|d| d.doc_id).collect())
    }

    /// 列出文档的活跃 block（未删除）。
    pub fn list_active_blocks(&self, doc_id: &DocId) -> CoreResult<Vec<BlockRecord>> {
        let meta = self.open_doc(doc_id)?;
        meta.list_active_blocks()
    }

    /// 软删除 block。
    pub fn soft_delete_block(&self, doc_id: &DocId, block_id: &BlockId) -> CoreResult<()> {
        let meta = self.open_doc(doc_id)?;
        meta.soft_delete(block_id)?;
        let frontier = meta.frontier()?;
        // 持久化 MetaDoc snapshot（确保删除状态可恢复）
        let meta_snap = meta.export_snapshot()?;
        // 预取 doc kind（避免在持锁期间再次获取锁导致死锁）
        let doc_kind = self.doc_kind(doc_id)?;
        self.store.transaction(|conn| {
            dao::insert_snapshot(
                conn,
                doc_id,
                &CheckpointId::new("meta"),
                &meta_snap,
                tacit_core::SnapshotKind::Full,
                SystemTime::now(),
            )?;
            dao::upsert_doc(
                conn,
                &dao::DocRecord {
                    doc_id: doc_id.clone(),
                    kind: doc_kind,
                    current_frontier: frontier,
                    updated_at: SystemTime::now(),
                    current_snapshot_id: None,
                },
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// 获取文档渲染模型：返回视口内 block 的渲染数据。
    ///
    /// 若 `viewport` 为 None，返回所有活跃 block。
    /// 用于 UI 层渲染文档内容。
    pub fn get_render_model(
        &self,
        doc_id: &DocId,
        viewport: Option<tacit_core::Viewport>,
    ) -> CoreResult<tacit_core::RenderModel> {
        let blocks = self.list_active_blocks(doc_id)?;
        let selected: Vec<_> = match viewport {
            Some(vp) => blocks
                .into_iter()
                .skip(vp.start_block)
                .take(vp.block_count)
                .collect(),
            None => blocks,
        };
        let mut renders = Vec::with_capacity(selected.len());
        for block_rec in selected {
            let block = self.get_block(doc_id, &block_rec.block_id)?;
            let render_bytes = block.export_render_bytes()?;
            renders.push(tacit_core::BlockRender {
                block_id: block_rec.block_id,
                kind: block_rec.kind,
                render_bytes: bytes::Bytes::from(render_bytes),
            });
        }
        Ok(tacit_core::RenderModel {
            doc_id: doc_id.clone(),
            blocks: renders,
        })
    }
}
