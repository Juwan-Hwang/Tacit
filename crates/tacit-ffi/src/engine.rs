//! TacitEngine：FFI 主入口。
//!
//! 同步外观、异步内核：
//! - API 调用同步返回。
//! - 同步动作通过 `drain_actions` 拉取，由集成层异步执行。
//! - 事件通过 `TacitEventListener` 回调，同时发布到 `EventBus` 供过滤订阅。
//! - UI 线程可通过 `CommandBus` 发送命令，由 `RuntimeSupervisor` 异步消费。

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use parking_lot::Mutex;
use tacit_core::{
    BlockId, ChangeEnvelope, CoreError, CoreResult, DocId, NetworkType, PeerId, SyncReason,
};
use tacit_crypto::{DeviceIdentity, StaticKeypair};
use tacit_store::Store;
use tacit_sync::{DefaultSyncEngine, DocStore, EngineConfig, SyncEngine};
use tracing::debug;

use crate::command_bus::{Command, CommandBus};
use crate::doc_executor::DocExecutorRegistry;
use crate::event_bus::EventBus;
use crate::listener::{EventDispatcher, ForeignEventListener, ForeignListenerAdapter};
use crate::view::{
    DocumentView, FfiRequestDeltaAction, FfiSendControlAction, FfiSendDataAction, FfiSyncAction,
    SyncStatus,
};

/// Tacit 引擎：FFI 主入口。
#[derive(uniffi::Object)]
pub struct TacitEngine {
    doc_store: Arc<DocStore>,
    engine: Arc<DefaultSyncEngine>,
    dispatcher: EventDispatcher,
    /// 命令总线：UI 线程发送命令到后台消费循环。
    command_bus: CommandBus,
    /// 事件总线：支持过滤订阅 CoreEvent。
    event_bus: Arc<EventBus>,
    /// per-doc 执行器：串行处理同一文档的操作，避免并发 CRDT 损坏。
    doc_executor: Arc<DocExecutorRegistry>,
    /// 在线 peer 集合。
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
            command_bus: CommandBus::new(),
            event_bus: Arc::new(EventBus::new()),
            doc_executor: Arc::new(DocExecutorRegistry::new()),
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
            command_bus: CommandBus::new(),
            event_bus: Arc::new(EventBus::new()),
            doc_executor: Arc::new(DocExecutorRegistry::new()),
            online_peers: Mutex::new(Vec::new()),
            current_net: Mutex::new(NetworkType::Offline),
        })
    }

    /// 获取命令总线引用（UI 线程通过它发送命令）。
    pub fn command_bus(&self) -> &CommandBus {
        &self.command_bus
    }

    /// 获取事件总线引用（订阅 CoreEvent）。
    pub fn event_bus(&self) -> &Arc<EventBus> {
        &self.event_bus
    }

    /// 获取 per-doc 执行器引用。
    pub fn doc_executor(&self) -> &Arc<DocExecutorRegistry> {
        &self.doc_executor
    }

    /// 发送命令到命令总线（非阻塞）。
    ///
    /// UI 线程通过此方法将操作入队，由 RuntimeSupervisor 在后台异步执行。
    /// 队列满时返回错误，UI 可据此提示用户或丢弃。
    pub fn send_command(&self, cmd: Command) -> Result<(), crate::command_bus::CommandBusError> {
        self.command_bus.try_send(cmd)
    }

    /// 创建文档。
    pub fn create_document(&self, doc_id: String, kind: String) -> CoreResult<()> {
        debug!(doc_id = %doc_id, kind = %kind, "创建文档");
        self.doc_store.create_doc(DocId::new(doc_id), &kind)
    }

    /// #4: 保存设备身份到数据库（持久化）。
    ///
    /// 将 Ed25519 签名密钥、X25519 静态密钥对和绑定证明写入 `device_identity` 表。
    /// 应用启动时调用 `load_device_identity` 恢复身份，避免每次重启生成新身份。
    pub fn save_device_identity(&self, identity: &DeviceIdentity) -> CoreResult<()> {
        let conn = self.doc_store.store().conn();
        let rec = tacit_store::dao::DeviceIdentityRecord {
            signing_key: identity.signing_key_bytes().to_vec(),
            static_private: identity.static_keypair().private.to_vec(),
            static_public: identity.static_keypair().public.to_vec(),
            binding_proof: identity.binding_proof().to_vec(),
            created_at: SystemTime::now(),
        };
        tacit_store::dao::save_device_identity(&conn, &rec)
    }

    /// #4: 从数据库加载设备身份。
    ///
    /// 返回 `Ok(Some(identity))` 表示数据库中已有身份；
    /// 返回 `Ok(None)` 表示首次启动，需要调用 `DeviceIdentity::generate()` 生成新身份。
    pub fn load_device_identity(&self) -> CoreResult<Option<DeviceIdentity>> {
        let conn = self.doc_store.store().conn();
        let rec = match tacit_store::dao::load_device_identity(&conn)? {
            Some(r) => r,
            None => return Ok(None),
        };
        let static_kp = StaticKeypair {
            private: rec.static_private.as_slice().try_into().map_err(|_| {
                CoreError::Crypto("数据库中存储的静态私钥长度不正确".into())
            })?,
            public: rec.static_public.as_slice().try_into().map_err(|_| {
                CoreError::Crypto("数据库中存储的静态公钥长度不正确".into())
            })?,
        };
        let identity = DeviceIdentity::from_keys(
            &rec.signing_key,
            static_kp,
            &rec.binding_proof,
        )?;
        Ok(Some(identity))
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

    /// 获取 block 的渲染内容（字节数组）。
    ///
    /// 返回 block 的 `render_bytes`，格式取决于 block 类型：
    /// - Text: UTF-8 文本
    /// - Todo/Log: JSON 数组
    ///
    /// 用于移动端 UI 渲染文档内容。
    pub fn get_block_content(
        &self,
        doc_id: String,
        block_id: String,
    ) -> CoreResult<Vec<u8>> {
        let doc_id_obj = DocId::new(doc_id);
        let block_id_obj = BlockId::new(block_id);
        let block = self.doc_store.get_block(&doc_id_obj, &block_id_obj)?;
        block.export_render_bytes()
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
    ///
    /// # 大导入限制
    ///
    /// 此方法为**同步 API**，仅适用于小编辑（< 1MB）。
    /// 超过 1MB 的编辑会被拒绝并返回 `Error`，调用方应改用异步路径：
    /// ```ignore
    /// engine.send_command(Command::ApplyUserEdit { doc_id, block_id, edit_bytes })?;
    /// ```
    /// 异步路径通过 per-doc actor 串行处理，不阻塞 UI 线程。
    pub fn apply_user_edit(
        &self,
        doc_id: String,
        block_id: String,
        edit_bytes: Vec<u8>,
    ) -> CoreResult<()> {
        // #19/#9: 大导入检测——同步 API 拒绝 >1MB 的编辑，引导使用异步路径
        const SYNC_EDIT_MAX_BYTES: usize = 1024 * 1024;
        if edit_bytes.len() > SYNC_EDIT_MAX_BYTES {
            return Err(CoreError::Store(format!(
                "同步 API 拒绝大导入（{} 字节 > {} 字节），请使用 send_command(Command::ApplyUserEdit) 异步路径",
                edit_bytes.len(),
                SYNC_EDIT_MAX_BYTES
            )));
        }
        let doc_id_obj = DocId::new(doc_id);
        let block_id_obj = BlockId::new(block_id);
        let result = self
            .doc_store
            .apply_local_edit(&doc_id_obj, &block_id_obj, &edit_bytes)?;

        // 通知 SyncEngine
        let change = ChangeEnvelope {
            doc_id: doc_id_obj.clone(),
            block_id: Some(block_id_obj.clone()),
            delta: bytes::Bytes::from(edit_bytes),
            frontier: result.new_frontier,
        };
        self.engine.on_local_change(doc_id_obj, change)?;
        Ok(())
    }

    /// 请求 fast-resume。
    ///
    /// `viewport` 为视口信息（可见 block 范围），传入后首屏恢复会优先加载
    /// 视口内 block；传 None 则跳过"可见 block 优先"阶段。
    pub fn request_fast_resume(&self) -> CoreResult<()> {
        self.engine.fast_resume(None)
    }

    /// 请求 fast-resume（带视口）。
    pub fn request_fast_resume_with_viewport(
        &self,
        viewport: tacit_core::Viewport,
    ) -> CoreResult<()> {
        self.engine.fast_resume(Some(viewport))
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
            *net = if online {
                new_net
            } else {
                NetworkType::Offline
            };
            prev == NetworkType::Offline
        };

        if !online {
            // 离线时清空在线 peer 列表
            self.online_peers.lock().clear();
        } else if was_offline && (new_net == NetworkType::Lan || new_net == NetworkType::Wan) {
            // 从离线恢复到在线，触发 fast-resume
            debug!(net = ?new_net, "网络恢复，触发 fast-resume");
            self.engine.fast_resume(None)?;
        }

        self.dispatch_event(&tacit_core::CoreEvent::PeerStatusChanged {
            peer_id: PeerId::new("network"),
            online,
        });
        Ok(())
    }

    /// 通知 peer 上线。
    pub fn on_peer_online(&self, peer_id: String) -> CoreResult<()> {
        let peer_id = PeerId::new(peer_id);
        // 去重：避免重复上线导致多次入队
        let mut peers = self.online_peers.lock();
        if !peers.contains(&peer_id) {
            peers.push(peer_id.clone());
        }
        drop(peers);
        // 分发 peer 状态事件
        self.dispatch_event(&tacit_core::CoreEvent::PeerStatusChanged {
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
    /// 返回 FFI 友好的动作列表，集成层根据动作类型执行实际网络发送。
    /// EmitEvent 动作已在内部完成事件分发，集成层无需再处理。
    pub fn drain_actions(&self) -> CoreResult<Vec<FfiSyncAction>> {
        let actions = self.engine.drain_actions();
        let mut result = Vec::with_capacity(actions.len());
        for action in &actions {
            use tacit_sync::SyncAction;
            match action {
                SyncAction::EmitEvent(event) => {
                    // 事件在内部完成分发
                    self.dispatch_event(event);
                    // 同时返回事件 JSON 供集成层记录日志
                    let event_json = serde_json::to_string(event).unwrap_or_else(|_| "{}".into());
                    result.push(FfiSyncAction::EmitEvent { event_json });
                }
                SyncAction::SendData {
                    peer_id,
                    doc_id,
                    block_id,
                    bytes,
                    priority,
                    path,
                } => {
                    result.push(FfiSyncAction::SendData {
                        action: FfiSendDataAction {
                            peer_id: peer_id.as_str().to_string(),
                            doc_id: doc_id.as_str().to_string(),
                            block_id: block_id.as_ref().map(|b| b.as_str().to_string()),
                            data: bytes.clone(),
                            priority: priority_to_u8(*priority),
                            path: path_to_str(*path).to_string(),
                        },
                    });
                }
                SyncAction::SendControl {
                    peer_id,
                    msg,
                    priority,
                } => {
                    let msg_json = serde_json::to_string(msg)
                        .map_err(|e| CoreError::Serialize(e.to_string()))?;
                    result.push(FfiSyncAction::SendControl {
                        action: FfiSendControlAction {
                            peer_id: peer_id.as_str().to_string(),
                            msg_json,
                            priority: priority_to_u8(*priority),
                        },
                    });
                }
                SyncAction::RequestDelta {
                    peer_id,
                    doc_id,
                    block_id,
                    since,
                    priority,
                } => {
                    let since_json = serde_json::to_string(since)
                        .map_err(|e| CoreError::Serialize(e.to_string()))?;
                    result.push(FfiSyncAction::RequestDelta {
                        action: FfiRequestDeltaAction {
                            peer_id: peer_id.as_str().to_string(),
                            doc_id: doc_id.as_str().to_string(),
                            block_id: block_id.as_ref().map(|b| b.as_str().to_string()),
                            since_json,
                            priority: priority_to_u8(*priority),
                        },
                    });
                }
            }
        }
        Ok(result)
    }

    /// 处理依赖等待重试。
    pub fn process_pending(&self) -> CoreResult<()> {
        self.engine.process_pending(Instant::now())
    }

    /// 检查所有文档是否需要 compaction，按需执行。
    ///
    /// 由 RuntimeSupervisor 周期调用，自动维护文档压缩。
    /// 返回执行了 compaction 的文档数量。
    pub fn maybe_compact_all(&self) -> CoreResult<usize> {
        let doc_ids = self.doc_store.list_doc_ids()?;
        let watermark_calc =
            tacit_sync::WatermarkCalculator::new(std::time::Duration::from_secs(60 * 60 * 24 * 3));
        let cp_mgr =
            tacit_sync::CheckpointManager::new_ref(self.doc_store.as_ref(), watermark_calc);
        let mut compacted = 0;
        for doc_id in &doc_ids {
            match cp_mgr.maybe_compact(doc_id) {
                Ok(Some(_)) => compacted += 1,
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(doc_id = %doc_id, error = %e, "文档 compaction 失败，跳过并继续");
                }
            }
        }
        Ok(compacted)
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
        serde_json::to_string(&snap).map_err(|e| CoreError::Serialize(e.to_string()))
    }

    /// 将待执行动作中的事件分发到监听器。
    ///
    /// 仅取出 EmitEvent 动作进行分发，非事件动作（SendData/SendControl/RequestDelta）
    /// 保留在引擎队列中，由集成层通过 `drain_actions` 消费。
    fn flush_actions_to_events(&self) {
        let events = self.engine.drain_events();
        for action in &events {
            if let tacit_sync::SyncAction::EmitEvent(event) = action {
                self.dispatch_event(event);
            }
        }
    }

    /// 统一事件分发：同时通知 EventDispatcher（同步监听器）和 EventBus（过滤订阅）。
    fn dispatch_event(&self, event: &tacit_core::CoreEvent) {
        self.dispatcher.dispatch(event);
        self.event_bus.publish(event);
    }
}

/// Priority 转换为 u8：High=0, Medium=1, Low=2。
fn priority_to_u8(p: tacit_core::Priority) -> u8 {
    use tacit_core::Priority;
    match p {
        Priority::High => 0,
        Priority::Medium => 1,
        Priority::Low => 2,
    }
}

/// PathPreference 转换为字符串。
fn path_to_str(p: tacit_transport::PathPreference) -> &'static str {
    use tacit_transport::PathPreference;
    match p {
        PathPreference::Any => "any",
        PathPreference::Ble => "ble",
        PathPreference::LanQuic => "lan_quic",
        PathPreference::WanQuic => "wan_quic",
        PathPreference::Relay => "relay",
    }
}

/// UniFFI 导出的 API 方法。
///
/// 这些方法返回 `Result<T, TacitFfiError>`，供 Kotlin/Swift 直接调用。
/// 内部委托给 `TacitEngine` 的强类型方法，错误自动转换为 `TacitFfiError`。
#[uniffi::export]
impl TacitEngine {
    /// 创建引擎（UniFFI 构造函数）。
    ///
    /// `store_path`：SQLite 数据库路径。传空字符串使用内存数据库（仅测试）。
    /// `peer_id`：本设备 PeerId。
    #[uniffi::constructor]
    pub fn open(
        store_path: String,
        peer_id: String,
    ) -> Result<Arc<Self>, crate::error::TacitFfiError> {
        if store_path.is_empty() {
            let engine = Self::new_memory(&peer_id)?;
            Ok(Arc::new(engine))
        } else {
            let engine = Self::new(&store_path, &peer_id)?;
            Ok(Arc::new(engine))
        }
    }

    /// 创建文档。
    pub fn ffi_create_document(
        &self,
        doc_id: String,
        kind: String,
    ) -> Result<(), crate::error::TacitFfiError> {
        Ok(self.create_document(doc_id, kind)?)
    }

    /// 打开文档，返回视图。
    pub fn ffi_open_document(
        &self,
        doc_id: String,
    ) -> Result<DocumentView, crate::error::TacitFfiError> {
        Ok(self.open_document(doc_id)?)
    }

    /// 获取 block 的渲染内容。
    ///
    /// 返回 `render_bytes`（Text 为 UTF-8 文本，Todo/Log 为 JSON 数组）。
    pub fn ffi_get_block_content(
        &self,
        doc_id: String,
        block_id: String,
    ) -> Result<Vec<u8>, crate::error::TacitFfiError> {
        Ok(self.get_block_content(doc_id, block_id)?)
    }

    /// 创建 block。
    pub fn ffi_create_block(
        &self,
        doc_id: String,
        block_id: String,
        kind: String,
    ) -> Result<(), crate::error::TacitFfiError> {
        Ok(self.create_block(doc_id, block_id, kind)?)
    }

    /// 应用用户编辑到 block。
    ///
    /// `edit_bytes`：Loro delta 编码。
    pub fn ffi_apply_user_edit(
        &self,
        doc_id: String,
        block_id: String,
        edit_bytes: Vec<u8>,
    ) -> Result<(), crate::error::TacitFfiError> {
        Ok(self.apply_user_edit(doc_id, block_id, edit_bytes)?)
    }

    /// 请求 fast-resume。
    pub fn ffi_request_fast_resume(&self) -> Result<(), crate::error::TacitFfiError> {
        Ok(self.request_fast_resume()?)
    }

    /// 获取同步状态。
    pub fn ffi_get_sync_status(&self) -> Result<SyncStatus, crate::error::TacitFfiError> {
        Ok(self.get_sync_status()?)
    }

    /// 通知网络状态变化。
    ///
    /// `net_type`：`"lan"`、`"wan"` 或 `"offline"`。
    /// 从离线恢复到 LAN/WAN 时自动触发 fast-resume。
    pub fn ffi_notify_network_changed(
        &self,
        online: bool,
        net_type: String,
    ) -> Result<(), crate::error::TacitFfiError> {
        Ok(self.notify_network_changed(online, net_type)?)
    }

    /// 通知 peer 上线。
    pub fn ffi_on_peer_online(&self, peer_id: String) -> Result<(), crate::error::TacitFfiError> {
        Ok(self.on_peer_online(peer_id)?)
    }

    /// 拉取并分发待执行的同步动作。
    ///
    /// 返回 FFI 友好的动作列表，集成层根据动作类型执行实际网络发送。
    /// 集成层应定期调用此方法（如每 50ms）。
    pub fn ffi_drain_actions(&self) -> Result<Vec<FfiSyncAction>, crate::error::TacitFfiError> {
        Ok(self.drain_actions()?)
    }

    /// 处理依赖等待重试。
    ///
    /// 集成层应定期调用此方法（如每 1s）。
    pub fn ffi_process_pending(&self) -> Result<(), crate::error::TacitFfiError> {
        Ok(self.process_pending()?)
    }

    /// 触发 Hot-Path 模式（Apple 设备短暂唤醒）。
    pub fn ffi_trigger_hot_path(&self) {
        self.trigger_hot_path();
    }

    /// 退出 Hot-Path 模式。
    pub fn ffi_exit_hot_path(&self) {
        self.exit_hot_path();
    }

    /// 获取 telemetry 快照（JSON 字符串）。
    pub fn ffi_get_telemetry_snapshot(&self) -> Result<String, crate::error::TacitFfiError> {
        Ok(self.get_telemetry_snapshot()?)
    }

    /// 注册外部队听器（UniFFI 回调接口）。
    ///
    /// 平台层实现 `ForeignEventListener` trait，通过此方法注册。
    /// 事件以 JSON 字符串形式传递。
    pub fn register_foreign_listener(&self, listener: Arc<dyn ForeignEventListener>) {
        let adapter = ForeignListenerAdapter::new(listener);
        self.dispatcher.register(adapter);
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
        engine
            .create_document("doc1".into(), "note".into())
            .unwrap();
        let view = engine.open_document("doc1".into()).unwrap();
        assert_eq!(view.doc_id, "doc1");
        assert_eq!(view.kind, "note");
        assert!(view.block_ids.is_empty());
    }

    #[test]
    fn create_block_and_edit() {
        let engine = TacitEngine::new_memory("1").unwrap();
        engine
            .create_document("doc1".into(), "note".into())
            .unwrap();
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
        engine
            .create_document("doc1".into(), "note".into())
            .unwrap();
        engine.on_peer_online("2".into()).unwrap();
        let status = engine.get_sync_status().unwrap();
        assert_eq!(status.online_peers, 1);
    }
}
