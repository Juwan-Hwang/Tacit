# Tacit crate 级实现蓝图 FINAL

## 概述

本蓝图把 Tacit v1.0 FINAL 拆成可编码的 Rust workspace、trait 边界、线程模型、数据流与模块职责。核心原则是：**单一真相层、命令式 FFI、受控异步、状态与传输解耦。**[code_file:179]

## Workspace

| crate | 职责 |
|---|---|
| `Tacit-core` | 领域模型、错误、配置、共享类型 |
| `Tacit-crdt` | Loro 封装、Meta-Document、BlockDoc、Frontier/Diff/Snapshot 接口、BlockDocCache |
| `Tacit-store` | SQLite、peer/ack/snapshot/checkpoint 持久化、WAL/双缓冲快照 |
| `Tacit-crypto` | 设备身份、签名、Noise 握手、session key 管理 |
| `Tacit-transport` | Transport trait、通道抽象、事件定义、preferred_path hint |
| `Tacit-transport-ble` | BLE Presence 适配 |
| `Tacit-transport-quic` | LAN/WAN QUIC 适配、连接状态、fast-resume |
| `Tacit-transport-relay` | Relay 协议客户端/服务端、admission gate |
| `Tacit-sync` | 调度器、push/pull、依赖等待、GC、stale 追赶 |
| `Tacit-ffi` | UniFFI API、命令总线、回调事件桥接 |

## 依赖与版本策略

- `Tacit-crdt` 应精确锁定 Loro 版本，并通过 thin wrapper 隔离上游 API 变化。[web:139][web:166]
- `Tacit-transport-quic` 建议使用 Quinn 的 Tokio runtime 能力，因为 Quinn 是面向 Rust async/Tokio 的 QUIC 实现。[web:127][web:171]
- `Tacit-crypto` 建议使用 snow 作为 Noise 实现。[web:128][web:137]
- `Tacit-store` 建议使用 `rusqlite` 单连接 + 专用线程模型，并开启 SQLite WAL，避免无收益的连接池复杂度。
- 全 workspace 用 `thiserror` 定义库内精确错误；FFI 边界可统一转换为字符串或错误码。
- 全 workspace 用 `tracing` 做结构化日志。

## 线程模型

### 原则
- UI 线程只发命令，不直接做 CRDT 合并或网络 IO。
- Rust 内部存在一个主工作线程组和一个 Tokio runtime。
- 所有持久化写入、Loro 导入、网络发送都通过受控队列进入 runtime。

### 推荐结构
- `CommandBus`：来自 FFI/UI 的命令入口。
- `EventBus`：向 UI 回传状态变化、同步进度、错误，支持按 `doc_id`、事件类型过滤订阅。
- `RuntimeSupervisor`：持有 Tokio runtime，负责启动各服务。
- `DocExecutorRegistry`：维护 per-doc actor，而不是全局串行执行器。

### per-doc Actor
每个活跃文档拥有一个轻量 actor：
- 串行处理该 doc 的 Meta-Document 与 block 级变更。
- 不同文档间可并发执行。
- 冷文档 actor 可自动休眠并释放内存。

## 核心服务

### `DocStore`
职责：
- 管理 `DocMeta` 与 `BlockDoc` 生命周期。
- 惰性加载 block。
- 导出 delta/snapshot。
- 导入远端 delta/snapshot。
- 提供只读查询给 UI。

建议接口：
```rust
trait DocStore {
    fn apply_local_edit(&self, doc_id: DocId, edit: UserEdit) -> Result<ApplyResult>;
    fn import_remote_delta(&self, doc_id: DocId, delta: Bytes) -> Result<ImportResult>;
    fn import_snapshot(&self, doc_id: DocId, snapshot: Bytes) -> Result<ImportResult>;
    fn export_delta_since(&self, doc_id: DocId, frontier: Frontier) -> Result<Bytes>;
    fn export_shallow_snapshot(&self, doc_id: DocId, frontier: Frontier) -> Result<Bytes>;
    fn get_render_model(&self, doc_id: DocId, viewport: Option<Viewport>) -> Result<RenderModel>;
}
```

### `BlockDocCache`
`Tacit-crdt` 内部增加 `BlockDocCache`：
- LRU 策略。
- 热 block 常驻内存。
- 冷 block 仅保留 snapshot/blob。
- 超出阈值自动回收实例，仅保留可恢复状态。

### `PeerRegistry`
职责：
- 管理 `known_peers`、Anchor 候选、relay hint、NAT 能力。
- 计算主 Anchor。
- 跟踪 peer liveness、trust_state、success_ema。

建议接口：
```rust
trait PeerRegistry {
    fn upsert_peer(&self, peer: PeerRecord) -> Result<()>;
    fn mark_seen(&self, peer_id: PeerId, endpoint: Endpoint) -> Result<()>;
    fn best_anchor(&self) -> Result<Option<PeerId>>;
    fn relay_candidates(&self) -> Result<Vec<PeerId>>;
    fn revoke_peer(&self, peer_id: PeerId) -> Result<()>;
}
```

### `CheckpointManager`
职责：
- 计算强安全/软安全水位。
- 生成 shallow snapshot。
- 执行双缓冲原子替换。
- 执行 snapshot chunking 与安装。
- 触发文档压实。

建议接口：
```rust
trait CheckpointManager {
    fn evaluate_watermarks(&self, doc_id: DocId) -> Result<Watermarks>;
    fn maybe_compact(&self, doc_id: DocId) -> Result<Option<CheckpointId>>;
    fn install_snapshot_atomically(&self, doc_id: DocId, snapshot: Bytes, meta: SnapshotMeta) -> Result<()>;
    fn chunk_snapshot(&self, doc_id: DocId, checkpoint_id: CheckpointId) -> Result<Vec<SnapshotChunk>>;
}
```

### `TransportManager`
职责：
- 统一管理 BLE、QUIC、relay 通道。
- 根据优先级与 `preferred_path` 选择发送路径。
- 监听网络变化并触发 fast-resume。
- 维护每条通道健康度。

建议接口：
```rust
trait TransportManager {
    fn send_control(&self, peer_id: PeerId, msg: ControlMsg, priority: Priority) -> Result<()>;
    fn send_data(&self, peer_id: PeerId, frame: DataFrame, priority: Priority, preferred_path: Option<PathHint>) -> Result<()>;
    fn broadcast_presence(&self, hint: PresenceHint) -> Result<()>;
    fn reconnect_peer(&self, peer_id: PeerId) -> Result<()>;
    fn notify_network_changed(&self, online: bool, net_type: NetworkType) -> Result<()>;
}
```

### `SyncEngine`
职责：
- 处理 push/pull 会话。
- 维护 block 级 `expected_frontier` 依赖等待。
- 调度 Meta-Document 优先同步。
- 处理 stale peer、手术式重入、恢复流程。

建议接口：
```rust
trait SyncEngine {
    fn on_local_change(&self, doc_id: DocId, change: ChangeEnvelope) -> Result<()>;
    fn on_peer_summary(&self, peer_id: PeerId, summary: PeerSummary) -> Result<()>;
    fn request_sync(&self, peer_id: PeerId, reason: SyncReason) -> Result<()>;
    fn fast_resume(&self) -> Result<()>;
}
```

## 文档模型

### `DocMeta`
`DocMeta` 只表示内容级真相：
- block 顺序
- block 类型
- soft-delete 状态
- 更新时间与可选渲染 hint

`expected_frontier` 不写入 `DocMeta`。

### `BlockSyncState`
同步层单独维护：
```rust
struct BlockSyncState {
    doc_id: DocId,
    block_id: BlockId,
    peer_id: PeerId,
    expected_frontier: Frontier,
    observed_frontier: Frontier,
    retry_at: Instant,
    retries: u32,
}
```

### `BlockDoc`
每个 block 一个独立 Loro 实例，采用惰性加载。

## 同步调度状态机

### 高层流程
1. 发现 peer。
2. 建立会话。
3. 交换 `AckSummary` / frontier。
4. 优先同步 `DocMeta`。
5. 按需拉 block。
6. 若 block frontier < `expected_frontier`，进入依赖等待队列。
7. 退避重试，直至满足预期或会话结束。
8. 达到条件时更新 ack 并评估 compaction。

### 依赖等待队列
建议结构：
```rust
struct PendingBlockFetch {
    doc_id: DocId,
    block_id: BlockId,
    expected_frontier: Frontier,
    peer_id: PeerId,
    retry_at: Instant,
    retries: u32,
}
```

策略：
- 初始退避约 200ms。
- 指数回退到上限，例如 2s。
- 到达上限后不报致命错误，降级为后台静默拉取。

### 创建事务边界
新建 block 时，先创建并持久化 `BlockDoc` 初始状态，再更新 `DocMeta` 引用该 block。这样即便崩溃，最多留下可恢复的悬挂引用，而不会丢掉 block 初始数据。

## FFI 设计

### 原则
- 不返回 LoroDoc 指针。
- 不让平台层持有 Rust 内部对象生命周期。
- API 尽量同步外观、异步内核。
- 事件回传优先使用线程安全回调注册，而不是跨语言异步 stream。

### 推荐 API
```rust
fn apply_user_edit(doc_id: String, block_id: String, edit_bytes: Vec<u8>) -> Result<()>;
fn open_document(doc_id: String) -> Result<DocumentView>;
fn request_fast_resume() -> Result<()>;
fn get_sync_status() -> Result<SyncStatus>;
fn register_listener(listener: Box<dyn TacitEventListener>) -> Result<()>;
fn notify_network_changed(online: bool, net_type: NetworkType) -> Result<()>;
```

## 传输模块细节

### `Tacit-transport-quic`
- 管理 endpoint、peer 连接池、health check。
- network path 变化时主动断开并 fast-resume。
- 支持高优消息抢占发送。
- 不把 QUIC 被动迁移当可靠前提。[web:127][web:171]

### `Tacit-transport-relay`
- 客户端：注册 peer、建立会话级临时 ID、提交 admission proof。
- 服务端：校验 proof、映射 `session_id -> peer_id`、转发控制与数据流。
- 不做长期存储；可预留小 TTL 缓存扩展位。

### `Tacit-transport-ble`
- 仅广播/扫描 presence。
- 支持最小 rendezvous hint。
- 后台能力差异由平台层处理，不向上承诺数据面能力。

## 存储模块细节

### `Tacit-store`
建议子组件：
- `PeerDao`
- `AckDao`
- `SnapshotDao`
- `BlockSyncStateDao`
- `TransportStatsDao`
- `TxnExecutor`

快照安装必须通过事务或双缓冲：
1. 写入临时 snapshot。
2. 校验 hash/frontier。
3. 原子切换 `documents.current_frontier` 与 snapshot 指针。
4. 提交事务。

## GC 与恢复

### 双水位计算
`CheckpointManager` 根据 `acks` 计算：
- `hard_frontier`
- `soft_frontier`

### stale peer 恢复
- 若 peer frontier 落在 shallow snapshot 剪裁点之前，直接进入恢复模式。
- 优先安装 shallow snapshot。
- 再导入 tail delta。
- 若仍有本地旧改动，则走手术式重入。

### 手术式重入边界
v1.0 保守处理 block 内复杂文本分叉：优先保留当前主状态，把旧设备残留修改作为副本或冲突提示重新提交，而不承诺完整重建旧局部编辑历史。

## 事件模型

建议统一事件：
```rust
enum CoreEvent {
    SyncStarted { peer_id: PeerId, reason: SyncReason },
    SyncProgress { doc_id: DocId, stage: SyncStage, progress: f32 },
    SyncBlockedOnDependency { doc_id: DocId, block_id: BlockId },
    SyncCompleted { peer_id: PeerId },
    PeerStatusChanged { peer_id: PeerId, online: bool },
    AnchorChanged { old: Option<PeerId>, new: Option<PeerId> },
    ConflictMerged { doc_id: DocId, block_id: Option<BlockId> },
    ErrorRaised { scope: ErrorScope, message: String },
}
```

平台层收到 `ConflictMerged` 后，优先使用差量渲染或列表 diff 动画，而不是整页重载。

## 日志与错误

- 库内部错误类型使用 `thiserror`。
- FFI 边界统一转换为平台可消费的错误码或字符串。
- 使用 `tracing` span，例如：`sync_engine::push_pull`、`transport::quic::send`、`checkpoint::compact`。

## 测试落点

### 单元测试
- Frontier 比较
- Meta-Document 排序与 soft-delete
- Peer 选举确定性
- admission proof 验证
- `preferred_path` 选择策略

### 属性测试
- delta 乱序/重复导入后字节一致
- Meta-Document 与 BlockDoc 最终收敛
- 手术式重入后文档可重建

### 集成测试
- 3 节点 LAN 同步
- Anchor 离线切换
- stale device 追赶
- relay 兜底
- UI 前台 fast-resume 首屏可渲染

## Phase 0 / 1 编码顺序

1. `Tacit-core`
2. `Tacit-crdt`
3. `Tacit-store`
4. `Tacit-sync` 最小单机回放
5. `Tacit-transport-quic`
6. `Tacit-transport-ble`
7. `Tacit-crypto`
8. `Tacit-ffi`
9. `Tacit-transport-relay`
10. 混沌与跨平台测试

## 里程碑验收

### Phase 0
- 单机 block 编辑、Meta-Document 收敛、本地 checkpoint 与恢复跑通。

### Phase 1A
- Desktop ↔ Desktop 通过 QUIC 同步 block 与 Meta-Document。

### Phase 1B
- Mobile ↔ Desktop 前台同步与 fast-resume 跑通。

### Phase 1C
- stale device 通过 shallow snapshot + tail delta 追赶成功。

### Phase 1D
- relay 兜底与 Anchor 切换完成。
