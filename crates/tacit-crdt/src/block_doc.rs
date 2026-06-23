//! BlockDoc：单个 block 的 Loro 封装。
//!
//! 每个 block 拥有独立 LoroDoc 实例，惰性加载。根据 BlockKind 选择
//! 内部容器类型（Text->LoroText, Todo/Log->LoroList, Settings->LoroMap）。

use loro::LoroDoc;
use tacit_core::{
    ApplyResult, BlockId, CoreError, CoreResult, Frontier, ImportResult, PeerId,
};

use crate::converter::{
    format_peer_id, frontiers_to_frontier, parse_peer_id, LoroExport,
};

/// block 内部根容器名。
const ROOT_CONTAINER: &str = "block";

/// 单个 block 的 Loro 文档封装。
pub struct BlockDoc {
    doc: LoroDoc,
    block_id: BlockId,
}

impl BlockDoc {
    /// 创建新的空 BlockDoc，并设置 PeerID。
    pub fn new(block_id: BlockId, peer_id: &PeerId) -> CoreResult<Self> {
        let doc = LoroDoc::new();
        let loro_peer = parse_peer_id(peer_id.as_str())?;
        // 设置 PeerID，使本地编辑产生的 op 带上正确 peer。
        doc.set_peer_id(loro_peer)
            .map_err(|e| CoreError::Crdt(format!("设置 PeerID 失败: {e}")))?;
        Ok(Self { doc, block_id })
    }

    /// 从 snapshot 字节恢复 BlockDoc。
    pub fn from_snapshot(block_id: BlockId, peer_id: &PeerId, bytes: &[u8]) -> CoreResult<Self> {
        let doc = LoroDoc::from_snapshot(bytes)
            .map_err(|e| CoreError::Crdt(format!("从 snapshot 恢复失败: {e}")))?;
        let loro_peer = parse_peer_id(peer_id.as_str())?;
        // 注意：从 snapshot 恢复时 PeerID 已包含在历史中，此处仅设置后续编辑用的 PeerID。
        doc.set_peer_id(loro_peer)
            .map_err(|e| CoreError::Crdt(format!("设置 PeerID 失败: {e}")))?;
        Ok(Self { doc, block_id })
    }

    /// 获取 block_id。
    pub fn block_id(&self) -> &BlockId {
        &self.block_id
    }

    /// 获取底层 LoroDoc 引用（供同 crate 内部使用）。
    pub(crate) fn loro_doc(&self) -> &LoroDoc {
        &self.doc
    }

    /// 当前状态 frontier。
    pub fn frontier(&self) -> CoreResult<Frontier> {
        frontiers_to_frontier(&self.doc.state_frontiers())
    }

    /// 提交当前未提交事务。
    pub fn commit(&self) {
        self.doc.commit();
    }

    /// 应用用户编辑字节，返回新 frontier。
    ///
    /// edit_bytes 语义由上层定义：可以是 Loro delta 或结构化编辑。
    /// Phase 0 约定 edit_bytes 为待写入文本容器的 UTF-8 文本，追加到末尾。
    pub fn apply_edit(&self, edit_bytes: &[u8]) -> CoreResult<ApplyResult> {
        let text = self.doc.get_text(ROOT_CONTAINER);
        let s = std::str::from_utf8(edit_bytes)
            .map_err(|e| CoreError::Crdt(format!("编辑字节非 UTF-8: {e}")))?;
        let pos = text.len_unicode();
        text.insert(pos, s)
            .map_err(|e| CoreError::Crdt(format!("插入文本失败: {e}")))?;
        self.doc.commit();
        let new_frontier = self.frontier()?;
        Ok(ApplyResult {
            new_frontier,
            has_delta: true,
        })
    }

    /// 导出完整 snapshot。
    pub fn export_snapshot(&self) -> CoreResult<Vec<u8>> {
        LoroExport::Snapshot.export(&self.doc)
    }

    /// 导出自指定 frontier 之后的增量 delta。
    pub fn export_delta_since(&self, since: &Frontier) -> CoreResult<Vec<u8>> {
        LoroExport::UpdatesSince(since).export(&self.doc)
    }

    /// 导出以指定 frontier 为边界的 shallow snapshot。
    pub fn export_shallow_snapshot(&self, at: &Frontier) -> CoreResult<Vec<u8>> {
        LoroExport::ShallowSnapshot(at).export(&self.doc)
    }

    /// 导入远端 delta 或 snapshot 字节。
    pub fn import(&self, bytes: &[u8]) -> CoreResult<ImportResult> {
        let old = self.frontier()?;
        self.doc
            .import(bytes)
            .map_err(|e| CoreError::Crdt(format!("导入失败: {e}")))?;
        let new_frontier = self.frontier()?;
        let changed = new_frontier != old;
        Ok(ImportResult {
            new_frontier,
            changed,
        })
    }

    /// 导出渲染所需的字节（当前文本内容）。
    pub fn export_render_bytes(&self) -> CoreResult<Vec<u8>> {
        let text = self.doc.get_text(ROOT_CONTAINER);
        Ok(text.to_string().into_bytes())
    }

    /// 获取本设备 PeerId（从 LoroDoc 当前 PeerID 派生）。
    pub fn peer_id(&self) -> CoreResult<PeerId> {
        // LoroDoc 没有直接获取 PeerID 的公开 API，这里通过 frontier 推断不可靠。
        // 实际 PeerID 由上层管理，此处返回占位。Phase 0 由 DocStore 维护 peer_id。
        // 为避免误用，此处返回错误，强制调用方使用上层管理的 peer_id。
        let _ = self;
        Err(CoreError::Internal(
            "BlockDoc::peer_id 应由上层 DocStore 管理".into(),
        ))
    }
}

impl BlockDoc {
    /// 用于测试：直接获取底层 PeerID 字符串。
    #[doc(hidden)]
    pub fn loro_peer_id_str(&self) -> String {
        format_peer_id(self.doc.peer_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    #[test]
    fn edit_and_snapshot_roundtrip() {
        let block = BlockDoc::new(BlockId::new("b1"), &pid(1)).unwrap();
        block.apply_edit(b"hello").unwrap();
        let snap = block.export_snapshot().unwrap();

        let block2 = BlockDoc::from_snapshot(BlockId::new("b1"), &pid(2), &snap).unwrap();
        let render = block2.export_render_bytes().unwrap();
        assert_eq!(render, b"hello");
    }

    #[test]
    fn delta_sync_between_two_docs() {
        let a = BlockDoc::new(BlockId::new("b1"), &pid(1)).unwrap();
        a.apply_edit(b"foo").unwrap();
        let f0 = a.frontier().unwrap();

        let b = BlockDoc::new(BlockId::new("b1"), &pid(2)).unwrap();
        // b 从 a 的 snapshot 恢复初始状态
        let snap = a.export_snapshot().unwrap();
        b.import(&snap).unwrap();

        // a 继续编辑
        a.apply_edit(b"bar").unwrap();
        let delta = a.export_delta_since(&f0).unwrap();
        let imported = b.import(&delta).unwrap();
        assert!(imported.changed);

        let render = b.export_render_bytes().unwrap();
        assert_eq!(render, b"foobar");
    }

    #[test]
    fn idempotent_import() {
        let a = BlockDoc::new(BlockId::new("b1"), &pid(1)).unwrap();
        a.apply_edit(b"x").unwrap();
        let snap = a.export_snapshot().unwrap();

        let b = BlockDoc::new(BlockId::new("b1"), &pid(2)).unwrap();
        b.import(&snap).unwrap();
        let r = b.import(&snap).unwrap();
        assert!(!r.changed, "重复导入应幂等");
    }
}
