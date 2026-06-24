//! MetaDoc：Meta-Document 管理。
//!
//! 管理 block 列表、顺序、block 类型、soft-delete 状态。
//! 本身是一个 LoroDoc，根容器为 LoroMovableList，每个元素存储
//! block 元信息的 JSON 字符串。
//!
//! 注意：`expected_frontier` 不属于 MetaDoc，由 sync/store 层维护。

use loro::{LoroDoc, LoroMovableList, LoroValue, ValueOrContainer};
use serde_json;
use tacit_core::{
    BlockId, BlockKind, BlockRecord, CoreError, CoreResult, DocId, Frontier, ImportResult,
    PeerId,
};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::converter::{frontiers_to_frontier, LoroExport};

/// 根容器名。
const META_LIST: &str = "blocks";

/// Meta-Document：管理文档的 block 结构。
pub struct MetaDoc {
    doc: LoroDoc,
    doc_id: DocId,
}

impl MetaDoc {
    /// 创建新的空 MetaDoc。
    pub fn new(doc_id: DocId, peer_id: &PeerId) -> CoreResult<Self> {
        let doc = LoroDoc::new();
        let loro_peer = crate::converter::parse_peer_id(peer_id.as_str())?;
        doc.set_peer_id(loro_peer)
            .map_err(|e| CoreError::Crdt(format!("设置 PeerID 失败: {e}")))?;
        Ok(Self { doc, doc_id })
    }

    /// 从 snapshot 字节恢复。
    pub fn from_snapshot(doc_id: DocId, peer_id: &PeerId, bytes: &[u8]) -> CoreResult<Self> {
        let doc = LoroDoc::from_snapshot(bytes)
            .map_err(|e| CoreError::Crdt(format!("MetaDoc 从 snapshot 恢复失败: {e}")))?;
        let loro_peer = crate::converter::parse_peer_id(peer_id.as_str())?;
        doc.set_peer_id(loro_peer)
            .map_err(|e| CoreError::Crdt(format!("设置 PeerID 失败: {e}")))?;
        Ok(Self { doc, doc_id })
    }

    pub fn doc_id(&self) -> &DocId {
        &self.doc_id
    }

    #[allow(dead_code)]
    pub(crate) fn loro_doc(&self) -> &LoroDoc {
        &self.doc
    }

    /// 获取根 list 容器。
    fn list(&self) -> LoroMovableList {
        self.doc.get_movable_list(META_LIST)
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
            block_id,
            kind,
            deleted: false,
            updated_at: SystemTime::now(),
        };
        let json = serde_json::to_string(&record)
            .map_err(|e| CoreError::Serialize(e.to_string()))?;
        let list = self.list();
        let pos = list.len();
        list.insert(pos, json)
            .map_err(|e| CoreError::Crdt(format!("MetaDoc 插入失败: {e}")))?;
        self.doc.commit();
        Ok(())
    }

    /// 标记 block 为 soft-deleted。
    pub fn soft_delete(&self, block_id: &BlockId) -> CoreResult<()> {
        let list = self.list();
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
        Ok(self.list_blocks()?.into_iter().filter(|b| !b.deleted).collect())
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
        Ok(ImportResult {
            new_frontier,
            changed,
        })
    }
}

/// 将 SystemTime 转为 Unix 毫秒（用于稳定序列化）。
#[allow(dead_code)]
fn unix_millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
        assert!(all.iter().any(|b| b.block_id == BlockId::new("b1") && b.deleted));
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
