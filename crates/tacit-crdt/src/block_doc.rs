//! BlockDoc：单个 block 的 Loro 封装。
//!
//! 每个 block 拥有独立 LoroDoc 实例，惰性加载。根据 BlockKind 选择
//! 内部容器类型（Text->LoroText, Todo/Log->LoroList, Settings->LoroMap）。

use loro::{LoroDoc, LoroMap, LoroText, LoroValue, ValueOrContainer};
use tacit_core::{
    ApplyResult, BlockId, BlockKind, CoreError, CoreResult, Frontier, ImportResult, PeerId,
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
    kind: BlockKind,
    peer_id: PeerId,
}

impl BlockDoc {
    /// 创建新的空 BlockDoc，并设置 PeerID。
    pub fn new(block_id: BlockId, kind: BlockKind, peer_id: &PeerId) -> CoreResult<Self> {
        let doc = LoroDoc::new();
        let loro_peer = parse_peer_id(peer_id.as_str())?;
        doc.set_peer_id(loro_peer)
            .map_err(|e| CoreError::Crdt(format!("设置 PeerID 失败: {e}")))?;
        Ok(Self {
            doc,
            block_id,
            kind,
            peer_id: peer_id.clone(),
        })
    }

    /// 从 snapshot 字节恢复 BlockDoc。
    pub fn from_snapshot(
        block_id: BlockId,
        kind: BlockKind,
        peer_id: &PeerId,
        bytes: &[u8],
    ) -> CoreResult<Self> {
        let doc = LoroDoc::from_snapshot(bytes)
            .map_err(|e| CoreError::Crdt(format!("从 snapshot 恢复失败: {e}")))?;
        let loro_peer = parse_peer_id(peer_id.as_str())?;
        doc.set_peer_id(loro_peer)
            .map_err(|e| CoreError::Crdt(format!("设置 PeerID 失败: {e}")))?;
        Ok(Self {
            doc,
            block_id,
            kind,
            peer_id: peer_id.clone(),
        })
    }

    /// 获取 block_id。
    pub fn block_id(&self) -> &BlockId {
        &self.block_id
    }

    /// 获取 BlockKind。
    pub fn kind(&self) -> BlockKind {
        self.kind
    }

    /// 获取本设备 PeerId。
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
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
    /// edit_bytes 语义根据 BlockKind 分发：
    /// - Text: edit_bytes 为 UTF-8 文本，追加到 LoroText 末尾
    /// - Todo: edit_bytes 为 JSON 序列化的待办项，追加到 LoroList
    /// - Log: edit_bytes 为 JSON 序列化的日志条目，追加到 LoroList
    /// - Settings: edit_bytes 为 JSON 序列化的 key-value 对，更新到 LoroMap
    pub fn apply_edit(&self, edit_bytes: &[u8]) -> CoreResult<ApplyResult> {
        match self.kind {
            BlockKind::Text => self.apply_text_edit(edit_bytes),
            BlockKind::Todo | BlockKind::Log => self.apply_list_edit(edit_bytes),
            BlockKind::Settings => self.apply_map_edit(edit_bytes),
        }
    }

    /// Text 类型：追加 UTF-8 文本到 LoroText。
    fn apply_text_edit(&self, edit_bytes: &[u8]) -> CoreResult<ApplyResult> {
        let text = self.get_text_container();
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

    /// Todo/Log 类型：追加 JSON 序列化条目到 LoroList。
    fn apply_list_edit(&self, edit_bytes: &[u8]) -> CoreResult<ApplyResult> {
        let list = self.doc.get_list(ROOT_CONTAINER);
        let json_str = std::str::from_utf8(edit_bytes)
            .map_err(|e| CoreError::Crdt(format!("编辑字节非 UTF-8: {e}")))?;
        let value: LoroValue = serde_json::from_str(json_str)
            .map_err(|e| CoreError::Crdt(format!("JSON 解析失败: {e}")))?;
        list.push(value)
            .map_err(|e| CoreError::Crdt(format!("List 插入失败: {e}")))?;
        self.doc.commit();
        let new_frontier = self.frontier()?;
        Ok(ApplyResult {
            new_frontier,
            has_delta: true,
        })
    }

    /// Settings 类型：更新 JSON key-value 到 LoroMap。
    fn apply_map_edit(&self, edit_bytes: &[u8]) -> CoreResult<ApplyResult> {
        let map = self.get_map_container();
        let json_str = std::str::from_utf8(edit_bytes)
            .map_err(|e| CoreError::Crdt(format!("编辑字节非 UTF-8: {e}")))?;
        let kvs: std::collections::HashMap<String, serde_json::Value> = serde_json::from_str(json_str)
            .map_err(|e| CoreError::Crdt(format!("JSON 解析失败: {e}")))?;
        for (k, v) in kvs {
            let value: LoroValue = serde_json::from_str(
                &serde_json::to_string(&v)
                    .map_err(|e| CoreError::Crdt(format!("JSON 序列化失败: {e}")))?,
            )
            .map_err(|e| CoreError::Crdt(format!("JSON 值转换失败: {e}")))?;
            map.insert(&k, value)
                .map_err(|e| CoreError::Crdt(format!("Map 插入失败: {e}")))?;
        }
        self.doc.commit();
        let new_frontier = self.frontier()?;
        Ok(ApplyResult {
            new_frontier,
            has_delta: true,
        })
    }

    /// Todo 块：更新指定索引处待办项的完成状态。
    ///
    /// 将 LoroList 中指定索引的元素反序列化为 JSON 对象，
    /// 更新 `completed` 字段后用 delete + insert 替换原元素
    /// （LoroList 无 set 方法，delete + insert 是等价操作）。
    pub fn apply_todo_update(&self, index: usize, completed: bool) -> CoreResult<()> {
        let list = self.doc.get_list(ROOT_CONTAINER);
        let old = list
            .get(index)
            .ok_or_else(|| CoreError::Crdt(format!("Todo 索引超出范围: {index}")))?;
        let ValueOrContainer::Value(loro_val) = old else {
            return Err(CoreError::Crdt(format!(
                "Todo 索引 {index} 处的元素不是值类型"
            )));
        };
        // LoroValue -> serde_json::Value
        let mut json: serde_json::Value = serde_json::to_value(&loro_val)
            .map_err(|e| CoreError::Crdt(format!("JSON 序列化失败: {e}")))?;
        let obj = json.as_object_mut().ok_or_else(|| {
            CoreError::Crdt(format!("Todo 索引 {index} 处的元素不是 JSON 对象"))
        })?;
        obj.insert(
            "completed".to_string(),
            serde_json::Value::Bool(completed),
        );
        // serde_json::Value -> LoroValue
        let new_val: LoroValue = serde_json::from_str(
            &serde_json::to_string(&json)
                .map_err(|e| CoreError::Crdt(format!("JSON 序列化失败: {e}")))?,
        )
        .map_err(|e| CoreError::Crdt(format!("JSON 值转换失败: {e}")))?;
        // 用 delete + insert 替换原元素
        list.delete(index, 1)
            .map_err(|e| CoreError::Crdt(format!("List 删除失败: {e}")))?;
        list.insert(index, new_val)
            .map_err(|e| CoreError::Crdt(format!("List 插入失败: {e}")))?;
        self.doc.commit();
        Ok(())
    }

    /// 获取 Text 容器。
    fn get_text_container(&self) -> LoroText {
        self.doc.get_text(ROOT_CONTAINER)
    }

    /// 获取 Map 容器。
    fn get_map_container(&self) -> LoroMap {
        self.doc.get_map(ROOT_CONTAINER)
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

    /// 导出渲染所需的字节（根据 BlockKind 返回不同格式）。
    pub fn export_render_bytes(&self) -> CoreResult<Vec<u8>> {
        match self.kind {
            BlockKind::Text => {
                let text = self.get_text_container();
                Ok(text.to_string().into_bytes())
            }
            BlockKind::Todo | BlockKind::Log => {
                let list = self.doc.get_list(ROOT_CONTAINER);
                let mut items: Vec<LoroValue> = Vec::new();
                for i in 0..list.len() {
                    if let Some(ValueOrContainer::Value(v)) = list.get(i) {
                        items.push(v);
                    }
                }
                let json = serde_json::to_string(&items)
                    .map_err(|e| CoreError::Serialize(e.to_string()))?;
                Ok(json.into_bytes())
            }
            BlockKind::Settings => {
                let map = self.get_map_container();
                let json = serde_json::to_string(&map.get_value())
                    .map_err(|e| CoreError::Serialize(e.to_string()))?;
                Ok(json.into_bytes())
            }
        }
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
        let block = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(1)).unwrap();
        block.apply_edit(b"hello").unwrap();
        let snap = block.export_snapshot().unwrap();

        let block2 = BlockDoc::from_snapshot(BlockId::new("b1"), BlockKind::Text, &pid(2), &snap).unwrap();
        let render = block2.export_render_bytes().unwrap();
        assert_eq!(render, b"hello");
    }

    #[test]
    fn delta_sync_between_two_docs() {
        let a = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(1)).unwrap();
        a.apply_edit(b"foo").unwrap();
        let f0 = a.frontier().unwrap();

        let b = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(2)).unwrap();
        let snap = a.export_snapshot().unwrap();
        b.import(&snap).unwrap();

        a.apply_edit(b"bar").unwrap();
        let delta = a.export_delta_since(&f0).unwrap();
        let imported = b.import(&delta).unwrap();
        assert!(imported.changed);

        let render = b.export_render_bytes().unwrap();
        assert_eq!(render, b"foobar");
    }

    #[test]
    fn idempotent_import() {
        let a = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(1)).unwrap();
        a.apply_edit(b"x").unwrap();
        let snap = a.export_snapshot().unwrap();

        let b = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(2)).unwrap();
        b.import(&snap).unwrap();
        let r = b.import(&snap).unwrap();
        assert!(!r.changed, "重复导入应幂等");
    }

    #[test]
    fn todo_block_uses_list_container() {
        let block = BlockDoc::new(BlockId::new("b1"), BlockKind::Todo, &pid(1)).unwrap();
        let item = serde_json::json!({"text": "buy milk", "done": false});
        block.apply_edit(serde_json::to_vec(&item).unwrap().as_slice()).unwrap();
        let render = block.export_render_bytes().unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&render).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["text"], "buy milk");
    }

    #[test]
    fn todo_update_toggles_completed() {
        let block = BlockDoc::new(BlockId::new("b1"), BlockKind::Todo, &pid(1)).unwrap();
        let item = serde_json::json!({"text": "buy milk", "completed": false});
        block
            .apply_edit(serde_json::to_vec(&item).unwrap().as_slice())
            .unwrap();

        // 标记为完成
        block.apply_todo_update(0, true).unwrap();
        let render = block.export_render_bytes().unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&render).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["completed"], true);
        assert_eq!(items[0]["text"], "buy milk");

        // 取消完成
        block.apply_todo_update(0, false).unwrap();
        let render = block.export_render_bytes().unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&render).unwrap();
        assert_eq!(items[0]["completed"], false);
    }

    #[test]
    fn todo_update_out_of_range_errors() {
        let block = BlockDoc::new(BlockId::new("b1"), BlockKind::Todo, &pid(1)).unwrap();
        let item = serde_json::json!({"text": "task", "completed": false});
        block
            .apply_edit(serde_json::to_vec(&item).unwrap().as_slice())
            .unwrap();
        // 索引越界应返回错误
        let result = block.apply_todo_update(5, true);
        assert!(result.is_err());
    }

    #[test]
    fn settings_block_uses_map_container() {
        let block = BlockDoc::new(BlockId::new("b1"), BlockKind::Settings, &pid(1)).unwrap();
        let kvs = serde_json::json!({"theme": "dark", "font_size": 14});
        block.apply_edit(serde_json::to_vec(&kvs).unwrap().as_slice()).unwrap();
        let render = block.export_render_bytes().unwrap();
        let map: serde_json::Value = serde_json::from_slice(&render).unwrap();
        assert_eq!(map["theme"], "dark");
        assert_eq!(map["font_size"], 14);
    }

    #[test]
    fn peer_id_stored_correctly() {
        let block = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(42)).unwrap();
        assert_eq!(block.peer_id(), &pid(42));
    }
}
