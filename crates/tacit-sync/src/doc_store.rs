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

use std::collections::HashMap;
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
}

impl DocStore {
    /// 创建 DocStore。
    pub fn new(peer_id: PeerId, store: Store, cache_capacity: usize) -> Self {
        Self {
            peer_id,
            store,
            cache: BlockDocCache::new(cache_capacity),
            metas: Mutex::new(HashMap::new()),
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
        let block = BlockDoc::new(block_id.clone(), &self.peer_id)?;
        let snap = block.export_snapshot()?;
        // 2. 持久化 block snapshot（用 block_id 作为 snapshot_id）
        let conn = self.store.conn();
        dao::insert_snapshot(
            &conn,
            doc_id,
            &CheckpointId::new(block_id.as_str()),
            &snap,
            tacit_core::SnapshotKind::Full,
            SystemTime::now(),
        )?;
        // 3. 更新 MetaDoc
        meta.add_block(block_id.clone(), kind)?;
        let frontier = meta.frontier()?;
        // 4. 更新 doc frontier
        dao::upsert_doc(
            &conn,
            &dao::DocRecord {
                doc_id: doc_id.clone(),
                kind: "note".to_string(),
                current_frontier: frontier,
                updated_at: SystemTime::now(),
            },
        )?;
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
        // 从 store 恢复
        let conn = self.store.conn();
        let (_, blob, _, _) = dao::get_latest_snapshot(&conn, doc_id)?
            .ok_or_else(|| CoreError::BlockNotFound {
                doc_id: doc_id.to_string(),
                block_id: block_id.to_string(),
            })?;
        // 注意：snapshot_id 用 block_id，但 get_latest_snapshot 返回的是最新 snapshot
        // 这里需要按 block_id 查找。简化：Phase 0 假设 block_id == snapshot_id。
        let block = BlockDoc::from_snapshot(block_id.clone(), &self.peer_id, &blob)?;
        let block = Arc::new(block);
        self.cache.insert(block_id.clone(), block.clone());
        Ok(block)
    }

    /// 应用本地编辑到 block。
    pub fn apply_local_edit(
        &self,
        doc_id: &DocId,
        block_id: &BlockId,
        edit_bytes: &[u8],
    ) -> CoreResult<ApplyResult> {
        let block = self.get_block(doc_id, block_id)?;
        let result = block.apply_edit(edit_bytes)?;
        // 持久化 block snapshot（写放大防御：Phase 0 简化为每次都写）
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
        // 更新 doc frontier（取 meta 与 block 的并集）
        let meta = self.open_doc(doc_id)?;
        let meta_frontier = meta.frontier()?;
        let mut frontier = meta_frontier;
        frontier.merge(&result.new_frontier);
        dao::upsert_doc(
            &conn,
            &dao::DocRecord {
                doc_id: doc_id.clone(),
                kind: "note".to_string(),
                current_frontier: frontier,
                updated_at: SystemTime::now(),
            },
        )?;
        Ok(result)
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

    /// 导入远端 MetaDoc delta/snapshot。
    pub fn import_meta(&self, doc_id: &DocId, bytes: &[u8]) -> CoreResult<ImportResult> {
        let meta = self.open_doc(doc_id)?;
        let result = meta.import(bytes)?;
        if result.changed {
            // 持久化 meta snapshot
            let snap = meta.export_snapshot()?;
            let conn = self.store.conn();
            dao::insert_snapshot(
                &conn,
                doc_id,
                &CheckpointId::new("meta"),
                &snap,
                tacit_core::SnapshotKind::Full,
                SystemTime::now(),
            )?;
            // 更新 doc frontier
            let frontier = meta.frontier()?;
            dao::upsert_doc(
                &conn,
                &dao::DocRecord {
                    doc_id: doc_id.clone(),
                    kind: "note".to_string(),
                    current_frontier: frontier,
                    updated_at: SystemTime::now(),
                },
            )?;
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
    pub fn export_block_snapshot(
        &self,
        doc_id: &DocId,
        block_id: &BlockId,
    ) -> CoreResult<Vec<u8>> {
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
        let conn = self.store.conn();
        dao::upsert_doc(
            &conn,
            &dao::DocRecord {
                doc_id: doc_id.clone(),
                kind: "note".to_string(),
                current_frontier: frontier,
                updated_at: SystemTime::now(),
            },
        )?;
        Ok(())
    }
}
