//! MetaDoc：Meta-Document 管理。
//!
//! 管理 block 列表、顺序、block 类型、soft-delete 状态。
//! 本身是一个 LoroDoc，根容器为 LoroMovableList，每个元素存储
//! block 元信息的 JSON 字符串。
//!
//! 注意：`expected_frontier` 不属于 MetaDoc，由 sync/store 层维护。

use loro::{LoroDoc, LoroMovableList, LoroValue, ValueOrContainer};
use parking_lot::Mutex;
use serde_json;
use std::collections::HashMap;
use std::time::SystemTime;
use tacit_core::{
    BlockId, BlockKind, BlockRecord, CoreError, CoreResult, DocId, Frontier, ImportResult, PeerId,
};

use crate::converter::{frontiers_to_frontier, LoroExport};

/// 根容器名。
const META_LIST: &str = "blocks";

/// Meta-Document：管理文档的 block 结构。
pub struct MetaDoc {
    doc: LoroDoc,
    doc_id: DocId,
    /// block_id -> list 索引 的内存索引缓存。
    /// 在任何改变 list 结构的操作后失效（设为 None）。
    /// 用于加速 soft_delete / remove_block 的 block 查找，避免 O(n) 线性扫描。
    index: Mutex<Option<HashMap<BlockId, usize>>>,
}

impl MetaDoc {
    /// 创建新的空 MetaDoc。
    pub fn new(doc_id: DocId, peer_id: &PeerId) -> CoreResult<Self> {
        let doc = LoroDoc::new();
        let loro_peer = crate::converter::parse_peer_id(peer_id.as_str())?;
        doc.set_peer_id(loro_peer)
            .map_err(|e| CoreError::Crdt(format!("设置 PeerID 失败: {e}")))?;
        Ok(Self {
            doc,
            doc_id,
            index: Mutex::new(None),
        })
    }

    /// 从 snapshot 字节恢复。
    pub fn from_snapshot(doc_id: DocId, peer_id: &PeerId, bytes: &[u8]) -> CoreResult<Self> {
        let doc = LoroDoc::from_snapshot(bytes)
            .map_err(|e| CoreError::Crdt(format!("MetaDoc 从 snapshot 恢复失败: {e}")))?;
        let loro_peer = crate::converter::parse_peer_id(peer_id.as_str())?;
        doc.set_peer_id(loro_peer)
            .map_err(|e| CoreError::Crdt(format!("设置 PeerID 失败: {e}")))?;
        Ok(Self {
            doc,
            doc_id,
            index: Mutex::new(None),
        })
    }

    pub fn doc_id(&self) -> &DocId {
        &self.doc_id
    }

    /// 获取根 list 容器。
    fn list(&self) -> LoroMovableList {
        self.doc.get_movable_list(META_LIST)
    }

    /// 构建 block_id -> 索引 的内存索引（O(n) 一次性扫描）。
    /// 后续 soft_delete / remove_block 可用索引做 O(1) 查找。
    fn build_index(&self, list: &LoroMovableList) -> HashMap<BlockId, usize> {
        let mut map = HashMap::with_capacity(list.len());
        for i in 0..list.len() {
            if let Some(ValueOrContainer::Value(LoroValue::String(s))) = list.get(i) {
                if let Ok(record) = serde_json::from_str::<BlockRecord>(s.as_str()) {
                    map.insert(record.block_id, i);
                }
            }
        }
        map
    }

    /// 使索引缓存失效。在改变 list 结构的操作后调用。
    fn invalidate_index(&self) {
        *self.index.lock() = None;
    }

    /// 查找 block 在 list 中的索引。
    /// 优先使用内存索引（O(1)），索引不存在时构建（O(n) 一次）。
    fn find_block_index(&self, list: &LoroMovableList, block_id: &BlockId) -> Option<usize> {
        let mut idx_guard = self.index.lock();
        if idx_guard.is_none() {
            *idx_guard = Some(self.build_index(list));
        }
        idx_guard.as_ref().and_then(|m| m.get(block_id).copied())
    }

    /// 当前 frontier。
    pub fn frontier(&self) -> CoreResult<Frontier> {
        frontiers_to_frontier(&self.doc.state_frontiers())
    }

    /// 提交事务。
    pub fn commit(&self) {
        self.doc.commit();
    }

    /// 在末尾追加一个 block 元信息。
    pub fn add_block(&self, block_id: BlockId, kind: BlockKind) -> CoreResult<()> {
        let record = BlockRecord {
            block_id: block_id.clone(),
            kind,
            deleted: false,
            updated_at: SystemTime::now(),
        };
        let json =
            serde_json::to_string(&record).map_err(|e| CoreError::Serialize(e.to_string()))?;
        let list = self.list();
        let pos = list.len();
        list.insert(pos, json)
            .map_err(|e| CoreError::Crdt(format!("MetaDoc 插入失败: {e}")))?;
        self.doc.commit();
        // 新 block 在末尾，索引仍有效，追加新条目
        let mut idx_guard = self.index.lock();
        if let Some(m) = idx_guard.as_mut() {
            m.insert(block_id, pos);
        }
        Ok(())
    }

    /// 标记 block 为 soft-deleted。
    pub fn soft_delete(&self, block_id: &BlockId) -> CoreResult<()> {
        let list = self.list();
        // 使用内存索引查找（O(1)），索引不存在时自动构建（O(n) 一次）
        let idx =
            self.find_block_index(&list, block_id)
                .ok_or_else(|| CoreError::BlockNotFound {
                    doc_id: self.doc_id.to_string(),
                    block_id: block_id.to_string(),
                })?;

        if let Some(ValueOrContainer::Value(LoroValue::String(s))) = list.get(idx) {
            if let Ok(mut record) = serde_json::from_str::<BlockRecord>(s.as_str()) {
                if record.block_id == *block_id {
                    record.deleted = true;
                    record.updated_at = SystemTime::now();
                    let json = serde_json::to_string(&record)
                        .map_err(|e| CoreError::Serialize(e.to_string()))?;
                    list.set(idx, json)
                        .map_err(|e| CoreError::Crdt(format!("MetaDoc 更新失败: {e}")))?;
                    self.doc.commit();
                    // soft_delete 不改变 list 结构，索引仍有效
                    return Ok(());
                }
            }
        }
        // 索引可能过期（远端操作），回退到线性扫描
        self.invalidate_index();
        self.soft_delete_linear(&list, block_id)
    }

    /// 线性扫描回退（索引过期时使用）。
    fn soft_delete_linear(&self, list: &LoroMovableList, block_id: &BlockId) -> CoreResult<()> {
        for i in 0..list.len() {
            if let Some(ValueOrContainer::Value(LoroValue::String(s))) = list.get(i) {
                if let Ok(mut record) = serde_json::from_str::<BlockRecord>(s.as_str()) {
                    if record.block_id == *block_id {
                        record.deleted = true;
                        record.updated_at = SystemTime::now();
                        let json = serde_json::to_string(&record)
                            .map_err(|e| CoreError::Serialize(e.to_string()))?;
                        list.set(i, json)
                            .map_err(|e| CoreError::Crdt(format!("MetaDoc 更新失败: {e}")))?;
                        self.doc.commit();
                        return Ok(());
                    }
                }
            }
        }
        Err(CoreError::BlockNotFound {
            doc_id: self.doc_id.to_string(),
            block_id: block_id.to_string(),
        })
    }

    /// 物理删除 block（从 list 中移除）。
    ///
    /// 注意：通常应使用 `soft_delete` 标记删除，仅在 compaction 确认安全后
    /// 才调用此方法物理移除。
    pub fn remove_block(&self, block_id: &BlockId) -> CoreResult<()> {
        let list = self.list();
        // 使用内存索引查找
        let idx =
            self.find_block_index(&list, block_id)
                .ok_or_else(|| CoreError::BlockNotFound {
                    doc_id: self.doc_id.to_string(),
                    block_id: block_id.to_string(),
                })?;

        if let Some(ValueOrContainer::Value(LoroValue::String(s))) = list.get(idx) {
            if let Ok(record) = serde_json::from_str::<BlockRecord>(s.as_str()) {
                if record.block_id == *block_id {
                    list.delete(idx, 1)
                        .map_err(|e| CoreError::Crdt(format!("MetaDoc 删除失败: {e}")))?;
                    self.doc.commit();
                    // remove 改变 list 结构（位置移动），索引失效
                    self.invalidate_index();
                    return Ok(());
                }
            }
        }
        // 索引可能过期，回退到线性扫描
        self.invalidate_index();
        self.remove_block_linear(&list, block_id)
    }

    /// 线性扫描回退（索引过期时使用）。
    fn remove_block_linear(&self, list: &LoroMovableList, block_id: &BlockId) -> CoreResult<()> {
        for i in 0..list.len() {
            if let Some(ValueOrContainer::Value(LoroValue::String(s))) = list.get(i) {
                if let Ok(record) = serde_json::from_str::<BlockRecord>(s.as_str()) {
                    if record.block_id == *block_id {
                        list.delete(i, 1)
                            .map_err(|e| CoreError::Crdt(format!("MetaDoc 删除失败: {e}")))?;
                        self.doc.commit();
                        return Ok(());
                    }
                }
            }
        }
        Err(CoreError::BlockNotFound {
            doc_id: self.doc_id.to_string(),
            block_id: block_id.to_string(),
        })
    }

    /// 移动 block 到新位置（调整 block 顺序）。
    ///
    /// `from` 和 `to` 是目标位置索引（基于当前 active block 列表）。
    pub fn move_block(&self, from: usize, to: usize) -> CoreResult<()> {
        let list = self.list();
        let len = list.len();
        if from >= len {
            return Err(CoreError::BlockNotFound {
                doc_id: self.doc_id.to_string(),
                block_id: format!("index={from}"),
            });
        }
        if to >= len {
            return Err(CoreError::InvalidFrontier(format!(
                "目标位置越界: to={to}, len={len}"
            )));
        }
        if from == to {
            return Ok(());
        }
        list.mov(from, to)
            .map_err(|e| CoreError::Crdt(format!("MetaDoc move 失败: {e}")))?;
        self.doc.commit();
        // move 改变 list 结构，索引失效
        self.invalidate_index();
        Ok(())
    }

    /// 列出所有 block 元信息（含已 soft-deleted）。
    pub fn list_blocks(&self) -> CoreResult<Vec<BlockRecord>> {
        let list = self.list();
        let mut out = Vec::with_capacity(list.len());
        for i in 0..list.len() {
            if let Some(ValueOrContainer::Value(LoroValue::String(s))) = list.get(i) {
                if let Ok(record) = serde_json::from_str::<BlockRecord>(s.as_str()) {
                    out.push(record);
                }
            }
        }
        Ok(out)
    }

    /// 列出未删除的 block。
    pub fn list_active_blocks(&self) -> CoreResult<Vec<BlockRecord>> {
        Ok(self
            .list_blocks()?
            .into_iter()
            .filter(|b| !b.deleted)
            .collect())
    }

    /// 导出完整 snapshot。
    pub fn export_snapshot(&self) -> CoreResult<Vec<u8>> {
        LoroExport::Snapshot.export(&self.doc)
    }

    /// 导出自指定 frontier 之后的增量。
    pub fn export_delta_since(&self, since: &Frontier) -> CoreResult<Vec<u8>> {
        LoroExport::UpdatesSince(since).export(&self.doc)
    }

    /// 导入远端 delta 或 snapshot。
    pub fn import(&self, bytes: &[u8]) -> CoreResult<ImportResult> {
        let old = self.frontier()?;
        self.doc
            .import(bytes)
            .map_err(|e| CoreError::Crdt(format!("MetaDoc 导入失败: {e}")))?;
        let new_frontier = self.frontier()?;
        let changed = new_frontier != old;
        // 远端操作可能改变 list 结构，索引失效
        if changed {
            self.invalidate_index();
        }
        Ok(ImportResult {
            new_frontier,
            changed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    #[test]
    fn add_and_list_blocks() {
        let meta = MetaDoc::new(DocId::new("d1"), &pid(1)).unwrap();
        meta.add_block(BlockId::new("b1"), BlockKind::Text).unwrap();
        meta.add_block(BlockId::new("b2"), BlockKind::Todo).unwrap();
        let blocks = meta.list_active_blocks().unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].block_id, BlockId::new("b1"));
        assert_eq!(blocks[1].kind, BlockKind::Todo);
    }

    #[test]
    fn soft_delete_hides_block() {
        let meta = MetaDoc::new(DocId::new("d1"), &pid(1)).unwrap();
        meta.add_block(BlockId::new("b1"), BlockKind::Text).unwrap();
        meta.add_block(BlockId::new("b2"), BlockKind::Todo).unwrap();
        meta.soft_delete(&BlockId::new("b1")).unwrap();
        let active = meta.list_active_blocks().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].block_id, BlockId::new("b2"));
        // 全部列表仍含已删除项
        let all = meta.list_blocks().unwrap();
        assert_eq!(all.len(), 2);
        assert!(all
            .iter()
            .any(|b| b.block_id == BlockId::new("b1") && b.deleted));
    }

    #[test]
    fn meta_sync_between_two() {
        let a = MetaDoc::new(DocId::new("d1"), &pid(1)).unwrap();
        a.add_block(BlockId::new("b1"), BlockKind::Text).unwrap();
        let snap = a.export_snapshot().unwrap();

        let b = MetaDoc::new(DocId::new("d1"), &pid(2)).unwrap();
        b.import(&snap).unwrap();
        let blocks = b.list_active_blocks().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_id, BlockId::new("b1"));
    }
}
