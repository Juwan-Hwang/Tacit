//! TacitEngine：FFI 主入口。
//!
//! 同步外观、异步内核：
//! - API 调用同步返回。
//! - 同步动作通过 `drain_actions` 拉取，由集成层异步执行。
//! - 事件通过 `TacitEventListener` 回调。

use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tacit_core::{
    BlockId, ChangeEnvelope, CoreError, CoreResult, DocId, NetworkType, PeerId,
    SyncReason,
};
use tacit_store::Store;
use tacit_sync::{DefaultSyncEngine, DocStore, EngineConfig, SyncEngine};
use tracing::debug;

use crate::listener::EventDispatcher;
use crate::view::{DocumentView, SyncStatus};

/// Tacit 引擎：FFI 主入口。
pub struct TacitEngine {
    doc_store: Arc<DocStore>,
    engine: Arc<DefaultSyncEngine>,
    dispatcher: EventDispatcher,
    /// 在线 peer 集合（简化管理）。
    online_peers: Mutex<Vec<PeerId>>,
    /// 当前网络类型。
    current_net: Mutex<NetworkType>,
}

impl TacitEngine {
    /// 创建引擎。
    ///
    /// `store_path`：SQLite 数据库路径。
    /// `peer_id`：本设备 PeerId。
    pub fn new(store_path: &str, peer_id: &str) -> CoreResult<Self> {
        let store = Store::open(store_path)?;
        let peer_id = PeerId::new(peer_id);
        let doc_store = Arc::new(DocStore::new(peer_id.clone(), store, 64));
        let engine_config = EngineConfig {
            peer_id,
            ..Default::default()
        };
        let engine = Arc::new(DefaultSyncEngine::new(doc_store.clone(), engine_config));
        Ok(Self {
            doc_store,
            engine,
            dispatcher: EventDispatcher::new(),
            online_peers: Mutex::new(Vec::new()),
            current_net: Mutex::new(NetworkType::Offline),
        })
    }

    /// 创建内存引擎（用于测试）。
    pub fn new_memory(peer_id: &str) -> CoreResult<Self> {
        let store = Store::open_memory()?;
        let peer_id = PeerId::new(peer_id);
        let doc_store = Arc::new(DocStore::new(peer_id.clone(), store, 64));
        let engine_config = EngineConfig {
            peer_id,
            ..Default::default()
        };
        let engine = Arc::new(DefaultSyncEngine::new(doc_store.clone(), engine_config));
        Ok(Self {
            doc_store,
            engine,
            dispatcher: EventDispatcher::new(),
            online_peers: Mutex::new(Vec::new()),
            current_net: Mutex::new(NetworkType::Offline),
        })
    }

    /// 创建文档。
    pub fn create_document(&self, doc_id: String, kind: String) -> CoreResult<()> {
        debug!(doc_id = %doc_id, kind = %kind, "创建文档");
        self.doc_store.create_doc(DocId::new(doc_id), &kind)
    }

    /// 打开文档，返回视图。
    pub fn open_document(&self, doc_id: String) -> CoreResult<DocumentView> {
        let doc_id = DocId::new(doc_id);
        // 从 store 获取文档记录
        let conn = self.doc_store.store().conn();
        let doc_rec = tacit_store::dao::get_doc(&conn, &doc_id)?
            .ok_or_else(|| CoreError::Store(format!("文档不存在: {doc_id}")))?;
        let blocks = self.doc_store.list_blocks(&doc_id)?;
        let frontier = self.doc_store.meta_frontier(&doc_id)?;
        Ok(DocumentView {
            doc_id: doc_id.as_str().to_string(),
            kind: doc_rec.kind,
            block_ids: blocks
                .iter()
                .map(|b| b.block_id.as_str().to_string())
                .collect(),
            frontier_json: serde_json::to_string(&frontier)
                .map_err(|e| CoreError::Serialize(e.to_string()))?,
        })
    }

    /// 创建 block。
    pub fn create_block(&self, doc_id: String, block_id: String, kind: String) -> CoreResult<()> {
        use tacit_core::BlockKind;
        let block_kind = match kind.as_str() {
            "text" => BlockKind::Text,
            "todo" => BlockKind::Todo,
            "settings" => BlockKind::Settings,
            "log" => BlockKind::Log,
            _ => BlockKind::Text,
        };
        self.doc_store
            .create_block(&DocId::new(doc_id), BlockId::new(block_id), block_kind)
    }

    /// 应用用户编辑到 block。
    ///
    /// `edit_bytes`：Loro delta 编码。
    pub fn apply_user_edit(
        &self,
        doc_id: String,
        block_id: String,
        edit_bytes: Vec<u8>,
    ) -> CoreResult<()> {
        let doc_id = DocId::new(doc_id);
        let block_id = BlockId::new(block_id);
        let result = self
            .doc_store
            .apply_local_edit(&doc_id, &block_id, &edit_bytes)?;

        // 通知 SyncEngine
        let change = ChangeEnvelope {
            doc_id: doc_id.clone(),
            block_id: Some(block_id.clone()),
            delta: bytes::Bytes::from(edit_bytes),
            frontier: result.new_frontier,
        };
        self.engine.on_local_change(doc_id, change)?;
        Ok(())
    }

    /// 请求 fast-resume。
    pub fn request_fast_resume(&self) -> CoreResult<()> {
        self.engine.fast_resume()
    }

    /// 获取同步状态。
    pub fn get_sync_status(&self) -> CoreResult<SyncStatus> {
        Ok(SyncStatus {
            pending_actions: self.engine.pending_actions() as u32,
            pending_fetches: self.engine.pending_queue().len() as u32,
            online_peers: self.online_peers.lock().len() as u32,
        })
    }

    /// 注册事件监听器。
    pub fn register_listener(&self, listener: Arc<dyn crate::TacitEventListener>) {
        self.dispatcher.register(listener);
    }

    /// 通知网络状态变化。
    ///
    /// 从离线恢复到 LAN/WAN 时自动触发 fast-resume。
    pub fn notify_network_changed(&self, online: bool, net_type: String) -> CoreResult<()> {
        let new_net = match net_type.as_str() {
            "lan" => NetworkType::Lan,
            "wan" => NetworkType::Wan,
            _ => NetworkType::Offline,
        };

        let was_offline = {
            let mut net = self.current_net.lock();
            let prev = *net;
            *net = if online { new_net } else { NetworkType::Offline };
            prev == NetworkType::Offline
        };

        if !online {
            // 离线时清空在线 peer 列表
            self.online_peers.lock().clear();
        } else if was_offline && (new_net == NetworkType::Lan || new_net == NetworkType::Wan) {
            // 从离线恢复到在线，触发 fast-resume
            debug!(net = ?new_net, "网络恢复，触发 fast-resume");
            self.engine.fast_resume()?;
        }

        self.dispatcher.dispatch(&tacit_core::CoreEvent::PeerStatusChanged {
            peer_id: PeerId::new("network"),
            online,
        });
        Ok(())
    }

    /// 通知 peer 上线。
    pub fn on_peer_online(&self, peer_id: String) -> CoreResult<()> {
        let peer_id = PeerId::new(peer_id);
        self.online_peers.lock().push(peer_id.clone());
        // 分发 peer 状态事件
        self.dispatcher.dispatch(&tacit_core::CoreEvent::PeerStatusChanged {
            peer_id: peer_id.clone(),
            online: true,
        });
        // 请求同步
        self.engine.request_sync(peer_id, SyncReason::PeerOnline)?;
        // 分发待执行动作的事件
        self.flush_actions_to_events();
        Ok(())
    }

    /// 拉取并分发待执行的同步动作（由集成层定期调用）。
    ///
    /// 返回未处理的动作数。
    pub fn drain_actions(&self) -> CoreResult<u32> {
        let actions = self.engine.drain_actions();
        for action in &actions {
            use tacit_sync::SyncAction;
            match action {
                SyncAction::EmitEvent(event) => {
                    self.dispatcher.dispatch(event);
                }
                _ => {
                    // 其他动作由集成层处理（发送数据/控制消息）
                    debug!(action = ?action, "待执行同步动作");
                }
            }
        }
        Ok(actions.len() as u32)
    }

    /// 处理依赖等待重试。
    pub fn process_pending(&self) -> CoreResult<()> {
        self.engine.process_pending(Instant::now())
    }

    /// 触发 Hot-Path 模式（Apple 设备短暂唤醒）。
    pub fn trigger_hot_path(&self) {
        self.engine.trigger_hot_path();
    }

    /// 退出 Hot-Path 模式。
    pub fn exit_hot_path(&self) {
        self.engine.exit_hot_path();
    }

    /// 获取 telemetry 快照（JSON 字符串）。
    pub fn get_telemetry_snapshot(&self) -> CoreResult<String> {
        let snap = self.engine.telemetry().snapshot();
        serde_json::to_string(&snap)
            .map_err(|e| CoreError::Serialize(e.to_string()))
    }

    /// 将待执行动作中的事件分发到监听器。
    ///
    /// 仅取出 EmitEvent 动作进行分发，非事件动作（SendData/SendControl/RequestDelta）
    /// 保留在引擎队列中，由集成层通过 `drain_actions` 消费。
    fn flush_actions_to_events(&self) {
        let events = self.engine.drain_events();
        for action in &events {
            if let tacit_sync::SyncAction::EmitEvent(event) = action {
                self.dispatcher.dispatch(event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener::TacitEventListener;
    use parking_lot::Mutex;
    use tacit_core::CoreEvent;

    struct MockListener {
        events: Mutex<Vec<CoreEvent>>,
    }

    impl MockListener {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
            })
        }

        fn count(&self) -> usize {
            self.events.lock().len()
        }
    }

    impl TacitEventListener for MockListener {
        fn on_event(&self, event: CoreEvent) {
            self.events.lock().push(event);
        }
    }

    #[test]
    fn create_and_open_document() {
        let engine = TacitEngine::new_memory("1").unwrap();
        engine.create_document("doc1".into(), "note".into()).unwrap();
        let view = engine.open_document("doc1".into()).unwrap();
        assert_eq!(view.doc_id, "doc1");
        assert_eq!(view.kind, "note");
        assert!(view.block_ids.is_empty());
    }

    #[test]
    fn create_block_and_edit() {
        let engine = TacitEngine::new_memory("1").unwrap();
        engine.create_document("doc1".into(), "note".into()).unwrap();
        engine
            .create_block("doc1".into(), "block1".into(), "text".into())
            .unwrap();

        // 应用编辑（空 delta，仅测试流程）
        let edit_bytes = vec![];
        let result = engine.apply_user_edit("doc1".into(), "block1".into(), edit_bytes);
        // 空 delta 可能成功或失败，取决于 Loro 实现
        // 这里只测试不 panic
        let _ = result;
    }

    #[test]
    fn sync_status() {
        let engine = TacitEngine::new_memory("1").unwrap();
        let status = engine.get_sync_status().unwrap();
        assert_eq!(status.pending_actions, 0);
        assert_eq!(status.online_peers, 0);
    }

    #[test]
    fn register_listener_and_dispatch() {
        let engine = TacitEngine::new_memory("1").unwrap();
        let listener = MockListener::new();
        engine.register_listener(listener.clone());

        // 触发网络变化事件
        engine
            .notify_network_changed(false, "offline".into())
            .unwrap();

        assert!(listener.count() > 0);
    }

    #[test]
    fn peer_online_triggers_sync() {
        let engine = TacitEngine::new_memory("1").unwrap();
        engine.create_document("doc1".into(), "note".into()).unwrap();
        engine.on_peer_online("2".into()).unwrap();
        let status = engine.get_sync_status().unwrap();
        assert_eq!(status.online_peers, 1);
    }
}
