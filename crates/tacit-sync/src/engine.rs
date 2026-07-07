//! SyncEngine：同步调度引擎。
//!
//! 实现 [`SyncEngine`] trait，处理 push/pull 会话、依赖等待、双水位计算。
//!
//! 设计要点：
//! - 同步外观、异步内核：trait 方法同步，内部产生 [`SyncAction`] 通过 channel 输出。
//! - 上层（ffi/集成层）消费 SyncAction，转换为实际传输调用。
//! - 不直接接触网络，便于单机回放测试。
//!
//! 调度流程（蓝图 177-187 行）：
//! 1. 发现 peer → on_peer_summary
//! 2. 交换 frontier → request_sync
//! 3. 优先同步 MetaDoc
//! 4. 按需拉 block
//! 5. 若 block frontier < expected_frontier，进入依赖等待队列
//! 6. 退避重试，直至满足预期或会话结束
//! 7. 达到条件时更新 ack 并评估 compaction

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use parking_lot::Mutex;
use tacit_core::{
    AckSummary, BlockId, ChangeEnvelope, CoreResult, DocId, Frontier, FrontierOps, PeerId,
    PeerSummary, Priority, SyncReason, TelemetryCollector, Viewport,
};
use tacit_transport::{ControlMsg, PathPreference, StoreAndForward};
use tracing::{debug, info};

use crate::doc_store::DocStore;
use crate::hot_path::HotPathController;
use crate::pending::{PendingBlockFetch, PendingFetchQueue};
use crate::priority_queue::PriorityQueue;
use crate::watermarks::WatermarkCalculator;

/// 解析 `host:port` 或 IPv6 端点字符串为 [`tacit_core::Endpoint`]。
///
/// 纯字符串解析，**不执行 DNS 查询**（避免阻塞异步线程 + 保留主机名供 TLS/SNI）。
///
/// 1. 尝试 `SocketAddr` 解析（覆盖 `IPv4:port` 和 `[IPv6]:port`）
/// 2. 尝试 `IpAddr` 解析（覆盖裸 IP，端口 0）
/// 3. 回退 `rfind(':')` 分割（覆盖 `hostname:port`，保留主机名）
/// 4. 纯主机名（端口 0）
fn parse_endpoint(addr: &str) -> tacit_core::Endpoint {
    // 1. SocketAddr：IPv4:port / [IPv6]:port
    if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
        return tacit_core::Endpoint::new(socket_addr.ip().to_string(), socket_addr.port());
    }
    // 2. 裸 IpAddr（无端口）
    if let Ok(ip_addr) = addr.parse::<std::net::IpAddr>() {
        return tacit_core::Endpoint::new(ip_addr.to_string(), 0);
    }
    // 3. hostname:port — 保留原始主机名供 TLS/SNI
    //    对于带方括号的 IPv6（如 [2001:db8::1]:port），仅在 ']' 之后查找端口冒号
    let colon_idx = if let Some(bracket_idx) = addr.rfind(']') {
        addr[bracket_idx..].rfind(':').map(|i| bracket_idx + i)
    } else {
        addr.rfind(':')
    };

    if let Some(idx) = colon_idx {
        let host = &addr[..idx];
        let port: u16 = addr[idx + 1..].parse().unwrap_or(0);
        // 去除 IPv6 方括号 [::1]:port → ::1
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        tacit_core::Endpoint::new(host, port)
    } else {
        // 4. 纯主机名或带方括号的裸 IPv6（如 [2001:db8::1]）
        let host = addr
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(addr);
        tacit_core::Endpoint::new(host, 0)
    }
}

/// 同步动作：SyncEngine 产生的待执行动作。
///
/// 上层消费这些动作并转换为实际传输调用。
#[derive(Debug, Clone)]
pub enum SyncAction {
    /// 发送数据帧。
    SendData {
        peer_id: PeerId,
        doc_id: DocId,
        block_id: Option<BlockId>,
        bytes: Vec<u8>,
        priority: Priority,
        path: PathPreference,
    },
    /// 发送控制消息。
    SendControl {
        peer_id: PeerId,
        msg: ControlMsg,
        priority: Priority,
    },
    /// 请求对端发送自 since 之后的 delta。
    ///
    /// `priority` 由调用方按场景指定：活跃文档同步用 High，
    /// 冷文档追赶/后台补齐用 Low。
    RequestDelta {
        peer_id: PeerId,
        doc_id: DocId,
        block_id: Option<BlockId>,
        since: Frontier,
        priority: Priority,
    },
    /// 事件通知（供 UI/日志）。
    EmitEvent(tacit_core::CoreEvent),
}

/// peer 同步状态。
#[derive(Debug, Clone)]
struct PeerSyncState {
    /// peer 已知的 frontier（按 doc 聚合）。
    known_frontier: Frontier,
    /// 最后一次在线时间（用于 stale 判定）。
    last_seen: SystemTime,
    /// 是否在线。
    online: bool,
}

/// SyncEngine trait（蓝图定义）。
pub trait SyncEngine: Send + Sync {
    /// 本地变更通知。
    fn on_local_change(&self, doc_id: DocId, change: ChangeEnvelope) -> CoreResult<()>;
    /// peer 摘要通知。
    fn on_peer_summary(&self, peer_id: PeerId, summary: PeerSummary) -> CoreResult<()>;
    /// 请求同步。
    fn request_sync(&self, peer_id: PeerId, reason: SyncReason) -> CoreResult<()>;
    /// fast-resume。
    ///
    /// `viewport` 为视口信息（可见 block 范围），传入后首屏恢复会优先加载
    /// 视口内 block；传 None 则跳过"可见 block 优先"阶段，直接加载全部活跃 block。
    fn fast_resume(&self, viewport: Option<Viewport>) -> CoreResult<()>;
}

/// 默认 SyncEngine 实现。
pub struct DefaultSyncEngine {
    doc_store: Arc<DocStore>,
    pending: Arc<PendingFetchQueue>,
    /// Store-and-forward：离线消息持久化与重发。
    store_forward: StoreAndForward,
    watermarks: WatermarkCalculator,
    peer_states: Mutex<std::collections::HashMap<PeerId, PeerSyncState>>,
    actions: PriorityQueue,
    telemetry: Arc<TelemetryCollector>,
    hot_path: HotPathController,
    config: EngineConfig,
}

/// 引擎配置。
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub peer_id: PeerId,
    pub soft_watermark_timeout: Duration,
    pub backoff_init: Duration,
    pub backoff_max: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            peer_id: PeerId::new("0"),
            soft_watermark_timeout: Duration::from_secs(60 * 60 * 24 * 3),
            backoff_init: Duration::from_millis(200),
            backoff_max: Duration::from_secs(2),
        }
    }
}

impl DefaultSyncEngine {
    /// 创建引擎。
    pub fn new(doc_store: Arc<DocStore>, config: EngineConfig) -> Self {
        let pending = Arc::new(PendingFetchQueue::new(
            config.backoff_init,
            config.backoff_max,
        ));
        let store_forward = StoreAndForward::new(Arc::new(doc_store.store().clone()));
        let watermarks = WatermarkCalculator::new(config.soft_watermark_timeout);

        // 预加载：从 DB 读取所有已知 peer 到内存，初始状态为离线
        // 避免在 push_local_change 热路径上同步查询 DB
        let peer_states = {
            let conn = doc_store.store().conn();
            let mut map = std::collections::HashMap::new();
            if let Ok(peers) = tacit_store::dao::list_peers(&conn) {
                let my_id = doc_store.peer_id();
                for peer in peers {
                    if peer.peer_id != *my_id {
                        map.insert(
                            peer.peer_id,
                            PeerSyncState {
                                known_frontier: Frontier::new(),
                                last_seen: SystemTime::now(),
                                online: false,
                            },
                        );
                    }
                }
            }
            Mutex::new(map)
        };

        Self {
            doc_store,
            pending,
            store_forward,
            watermarks,
            peer_states,
            actions: PriorityQueue::new(),
            telemetry: Arc::new(TelemetryCollector::default()),
            hot_path: HotPathController::default(),
            config,
        }
    }

    /// Store-and-forward 引用。
    pub fn store_forward(&self) -> &StoreAndForward {
        &self.store_forward
    }

    /// 取出所有待执行的 SyncAction（按优先级排序）。
    ///
    /// Hot-Path 模式下仅返回控制类动作，数据类动作延后。
    pub fn drain_actions(&self) -> Vec<SyncAction> {
        let all = self.actions.drain();
        let (processable, deferred) = self.hot_path.partition(all);
        // 延后的动作重新入队，等 Normal 模式时再处理
        for a in deferred {
            self.actions.push(a);
        }
        // 更新 telemetry backlog
        self.telemetry
            .set_backlog(self.actions.len() as u32, self.pending.len() as u32);
        processable
    }

    /// 仅取出 EmitEvent 类型的动作，非事件动作保留在队列中。
    ///
    /// 用于 FFI 层在触发同步后立即分发事件给 UI 监听器，
    /// 同时保留 SendData/SendControl/RequestDelta 等动作供集成层通过 drain_actions 消费。
    pub fn drain_events(&self) -> Vec<SyncAction> {
        let all = self.actions.drain();
        let mut events = Vec::new();
        for action in all {
            if matches!(action, SyncAction::EmitEvent(_)) {
                events.push(action);
            } else {
                // 非事件动作重新入队
                self.actions.push(action);
            }
        }
        // 更新 telemetry backlog
        self.telemetry
            .set_backlog(self.actions.len() as u32, self.pending.len() as u32);
        events
    }

    /// 待执行动作数量。
    pub fn pending_actions(&self) -> usize {
        self.actions.len()
    }

    /// 依赖等待队列引用。
    pub fn pending_queue(&self) -> &Arc<PendingFetchQueue> {
        &self.pending
    }

    /// Telemetry 采集器引用。
    pub fn telemetry(&self) -> &Arc<TelemetryCollector> {
        &self.telemetry
    }

    /// Hot-Path 控制器引用。
    pub fn hot_path(&self) -> &HotPathController {
        &self.hot_path
    }

    /// 触发 Hot-Path 模式（设备短暂唤醒）。
    pub fn trigger_hot_path(&self) {
        debug!("触发 Hot-Path 模式");
        self.hot_path.trigger_hot();
    }

    /// 退出 Hot-Path 模式，恢复正常处理。
    pub fn exit_hot_path(&self) {
        debug!("退出 Hot-Path 模式");
        self.hot_path.enter_normal();
    }

    /// 清理 stale peer：移除超过 `max_age` 未活跃的 peer 状态。
    ///
    /// 返回被移除的 peer 列表。调用方可据此通知 PeerRegistry 撤销 peer。
    /// 此方法利用 `PeerSyncState.last_seen` 字段进行判定。
    pub fn cleanup_stale_peers(&self, max_age: std::time::Duration) -> Vec<PeerId> {
        let mut states = self.peer_states.lock();
        let now = SystemTime::now();
        let mut removed = Vec::new();
        states.retain(|peer_id, state| {
            let stale = now
                .duration_since(state.last_seen)
                .map(|d| d > max_age)
                .unwrap_or(false);
            if stale {
                removed.push(peer_id.clone());
                false
            } else {
                true
            }
        });
        if !removed.is_empty() {
            debug!(count = removed.len(), "清理 stale peer 状态");
        }
        removed
    }

    /// 处理依赖等待重试。
    ///
    /// 取出到期的等待条目，从 observed_frontier 增量拉取（而非从头拉取）。
    pub fn process_pending(&self, now: Instant) -> CoreResult<()> {
        let ready = self.pending.drain_ready(now);
        for fetch in ready {
            // 从 observed_frontier 增量拉取，避免每次从头拉取完整 delta
            self.push_action(SyncAction::RequestDelta {
                peer_id: fetch.peer_id.clone(),
                doc_id: fetch.doc_id.clone(),
                block_id: Some(fetch.block_id.clone()),
                since: fetch.observed_frontier.clone(),
                priority: Priority::High,
            });
            // 重新入队等待下次重试
            self.pending.requeue(fetch, now);
        }
        Ok(())
    }

    /// 计算指定文档的双水位。
    pub fn compute_watermarks(&self, doc_id: &DocId) -> CoreResult<tacit_core::Watermarks> {
        let conn = self.doc_store.store().conn();
        let acks = tacit_store::dao::list_acks_by_doc(&conn, doc_id)?;
        Ok(self.watermarks.compute(doc_id, &acks, SystemTime::now()))
    }

    /// stale 追赶：导出 shallow snapshot + tail delta 供远端追赶。
    ///
    /// 返回 (shallow_snapshot_bytes, tail_delta_bytes)。
    pub fn stale_catchup_export(
        &self,
        doc_id: &DocId,
        block_id: &BlockId,
        at: &Frontier,
        since: &Frontier,
    ) -> CoreResult<(Vec<u8>, Vec<u8>)> {
        let shallow = self.doc_store.export_block_shallow(doc_id, block_id, at)?;
        let tail = self.doc_store.export_block_delta(doc_id, block_id, since)?;
        Ok((shallow, tail))
    }

    /// 应用远端 block delta（传输层收到数据后调用）。
    pub fn apply_remote_block_delta(
        &self,
        doc_id: &DocId,
        block_id: &BlockId,
        bytes: &[u8],
        peer_id: &PeerId,
    ) -> CoreResult<()> {
        let result = self.doc_store.import_block(doc_id, block_id, bytes)?;
        if result.changed {
            // 更新 observed_frontier，移除依赖等待
            self.pending.remove(doc_id, block_id, peer_id);
            // 更新 ack
            let frontier = self.doc_store.block_frontier(doc_id, block_id)?;
            let conn = self.doc_store.store().conn();
            tacit_store::dao::upsert_ack(
                &conn,
                &AckSummary {
                    peer_id: peer_id.clone(),
                    doc_id: doc_id.clone(),
                    ack_checkpoint: None,
                    ack_frontier: frontier,
                    updated_at: SystemTime::now(),
                    version_override: None,
                },
            )?;
        }
        Ok(())
    }

    /// #8 接入点：peer 侧接收 anchor 发来的 shallow snapshot 并执行手术式重入。
    ///
    /// 当 anchor 检测到 peer 处于 stale 状态时，anchor 调用 `stale_catchup_export`
    /// 导出 shallow snapshot + tail delta 并发送给 peer。peer 收到后调用此方法：
    ///
    /// 1. 检测本地是否有自 `stale_frontier` 以来的独有变更
    /// 2. 如果有冲突，调用 `surgical_reentry` 执行手术式重入（备份→提取本地增量→重建→重放）
    /// 3. 如果无冲突，直接导入 snapshot
    /// 4. 冲突合并后发射 `ConflictMerged` 事件通知 UI
    pub fn apply_recovery_snapshot(
        &self,
        doc_id: &DocId,
        block_id: &BlockId,
        remote_snapshot: &[u8],
        stale_frontier: &Frontier,
    ) -> CoreResult<()> {
        use crate::recovery::surgical_reentry;
        use tacit_core::FrontierOps;

        // 检测本地是否有独有变更（local_frontier 未被 stale_frontier 覆盖）
        // 如果本地不存在该 block（BlockNotFound），则视为无本地独有变更，直接导入。
        // 其他错误（DB I/O 等）必须向上传播，否则恢复时可能静默覆盖本地更改。
        let local_frontier = self.doc_store.block_frontier(doc_id, block_id);
        let has_local_changes = match local_frontier {
            Ok(lf) => !stale_frontier.covers(&lf),
            Err(tacit_core::CoreError::BlockNotFound { .. }) => false,
            Err(e) => return Err(e),
        };

        if has_local_changes {
            debug!(
                doc_id = %doc_id,
                block_id = %block_id,
                "检测到本地独有变更，执行手术式重入"
            );
            let result = surgical_reentry(
                &self.doc_store,
                doc_id,
                block_id,
                remote_snapshot,
                stale_frontier,
            )?;

            if result.had_conflict {
                self.push_action(SyncAction::EmitEvent(
                    tacit_core::CoreEvent::ConflictMerged {
                        doc_id: doc_id.clone(),
                        block_id: Some(block_id.clone()),
                    },
                ));
            }
        } else {
            debug!(
                doc_id = %doc_id,
                block_id = %block_id,
                "无本地独有变更，直接导入 shallow snapshot"
            );
            self.doc_store
                .import_block(doc_id, block_id, remote_snapshot)?;
        }

        Ok(())
    }

    /// 应用远端 MetaDoc delta。
    pub fn apply_remote_meta_delta(
        &self,
        doc_id: &DocId,
        bytes: &[u8],
        peer_id: &PeerId,
    ) -> CoreResult<()> {
        let result = self.doc_store.import_meta(doc_id, bytes)?;
        if result.changed {
            // 获取 peer 已知的 meta frontier，作为 block 的 expected_frontier
            // （peer 的 meta 到此 frontier 时引用的 block 应可拉取到此版本）
            let peer_known_frontier = {
                let states = self.peer_states.lock();
                states
                    .get(peer_id)
                    .map(|s| s.known_frontier.clone())
                    .unwrap_or_default()
            };

            // 检查是否有新 block 需要拉取
            let blocks = self.doc_store.list_active_blocks(doc_id)?;
            for block in blocks {
                let local_frontier = self.doc_store.block_frontier(doc_id, &block.block_id);
                // 入队条件：block 完全缺失，或本地 block frontier 落后于 peer 已知 frontier
                let need_fetch = match &local_frontier {
                    Err(_) => true,
                    Ok(local) => !local.covers(&peer_known_frontier),
                };
                if need_fetch {
                    let observed = local_frontier.unwrap_or_default();
                    self.pending.enqueue(PendingBlockFetch {
                        doc_id: doc_id.clone(),
                        block_id: block.block_id.clone(),
                        expected_frontier: peer_known_frontier.clone(),
                        observed_frontier: observed,
                        peer_id: peer_id.clone(),
                        retry_at: Instant::now(),
                        retries: 0,
                        phase: crate::pending::BackoffPhase::Normal,
                    });
                    self.push_action(SyncAction::EmitEvent(
                        tacit_core::CoreEvent::SyncBlockedOnDependency {
                            doc_id: doc_id.clone(),
                            block_id: block.block_id.clone(),
                        },
                    ));
                }
            }
        }
        Ok(())
    }

    /// 推送本地变更给所有在线 peer，并为离线 peer 记录待发消息。
    ///
    /// 锁粒度优化：先在锁内 clone peer ID 列表并释放锁，
    /// 然后在锁外执行 delta 导出（可能触发 I/O）。
    /// 避免在持有 `peer_states` Mutex 期间阻塞于 store 操作。
    fn push_local_change(&self, doc_id: &DocId, change: &ChangeEnvelope) -> CoreResult<()> {
        // 1. 锁内：分离在线/离线 peer ID，立刻释放锁
        let (online_peer_ids, offline_peer_ids): (Vec<PeerId>, Vec<PeerId>) = {
            let peers = self.peer_states.lock();
            let mut online = Vec::new();
            let mut offline = Vec::new();
            for (peer_id, state) in peers.iter() {
                if state.online {
                    online.push(peer_id.clone());
                } else {
                    offline.push(peer_id.clone());
                }
            }
            (online, offline)
        };

        // peer_states 已在 new() 中预加载所有 DB 中的已知 peer，
        // handle_introduce/handle_revoke 会同步更新内存状态，
        // 因此此处完全依赖内存，无需查询 DB。

        // 2. 锁外：对每个在线 peer 导出 delta 并推送
        for peer_id in &online_peer_ids {
            let bytes = if let Some(block_id) = &change.block_id {
                self.doc_store
                    .export_block_delta(doc_id, block_id, &change.frontier)?
            } else {
                self.doc_store.export_meta_delta(doc_id, &change.frontier)?
            };
            self.push_action(SyncAction::SendData {
                peer_id: peer_id.clone(),
                doc_id: doc_id.clone(),
                block_id: change.block_id.clone(),
                bytes,
                priority: Priority::High,
                path: PathPreference::Any,
            });
        }

        // 3. 对每个离线 peer 记录待发 delta（store-and-forward）
        if !offline_peer_ids.is_empty() {
            for peer_id in &offline_peer_ids {
                let (entry_id, delta_id) = if let Some(block_id) = &change.block_id {
                    (
                        format!("{doc_id}:{block_id}:{:?}", change.frontier),
                        format!("block_delta:{block_id}"),
                    )
                } else {
                    (
                        format!("{doc_id}:meta:{:?}", change.frontier),
                        "meta_delta".to_string(),
                    )
                };
                if let Err(e) = self
                    .store_forward
                    .record_pending(&entry_id, doc_id, &delta_id, peer_id, "quic")
                {
                    debug!(
                        peer_id = %peer_id,
                        doc_id = %doc_id,
                        error = %e,
                        "store-and-forward 记录待发失败"
                    );
                }
            }
            debug!(
                online = online_peer_ids.len(),
                offline = offline_peer_ids.len(),
                "本地变更推送完成（离线 peer 已记录待发）"
            );
        }

        Ok(())
    }

    /// 处理远端撤销消息：移除 peer 状态并发射事件。
    ///
    /// 收到 `RevokePeer` 后：
    /// 1. 从 `peer_states` 中移除被撤销的 peer
    /// 2. 清理该 peer 的依赖等待条目
    /// 3. 发射 `PeerRevoked` 事件供上层（PeerRegistry / UI）处理
    pub fn handle_revoke(&self, revoked_peer: &PeerId, _reason: &str) -> CoreResult<()> {
        // 1. 移除 peer 同步状态
        let was_known = {
            let mut states = self.peer_states.lock();
            states.remove(revoked_peer).is_some()
        };

        // 即使 peer_states 中不存在（例如 peer 仅在 DB 中注册但未在线），
        // 也需要持久化撤销状态到数据库，防止重启后恢复信任。
        // 2. 持久化撤销状态到数据库
        {
            let conn = self.doc_store.store().conn();
            tacit_store::dao::revoke_peer(&conn, revoked_peer)?;
        }

        if was_known {
            // 3. 清理该 peer 的依赖等待条目
            self.pending.remove_peer(revoked_peer);
        }

        // 4. 发射事件，确保上层（PeerRegistry / UI）能感知到该 peer 被撤销，即使其当前不在线
        self.push_action(SyncAction::EmitEvent(tacit_core::CoreEvent::PeerRevoked {
            peer_id: revoked_peer.clone(),
        }));

        debug!(
            peer = %revoked_peer,
            was_known,
            "peer 已被撤销，状态已清理并持久化"
        );

        Ok(())
    }

    /// 处理远程信任链引入消息（§12.2 Introduce）。
    ///
    /// 收到 `IntroducePeer` 后：
    /// 1. 校验介绍人是否为已信任的 peer（防止未知 peer 随意引入）
    /// 2. 将被介绍的 peer 写入 `peers` 表（`TrustState::Pending`），供后续直接连接验证
    /// 3. 发射 `PeerIntroduced` 事件，供上层（PeerRegistry / UI）感知新 peer
    /// 4. 若被介绍的 peer 携带 endpoint，可选触发连接尝试（由上层决策）
    ///
    /// 安全模型：
    /// - 介绍人必须是当前已知的在线 peer（`peer_states` 中存在）
    /// - 被介绍的 peer 初始为 `Pending` 状态，不自动信任
    /// - 后续需通过 Noise 握手完成身份验证后升级为 `Trusted`
    pub fn handle_introduce(
        &self,
        msg: &tacit_transport::IntroducePeer,
        sender_peer_id: &PeerId,
    ) -> CoreResult<()> {
        // 0. 拒绝引入本地 peer 自身：本地节点不应被注册为自身的 Pending 节点
        if msg.introduced_peer == *self.doc_store.peer_id() {
            return Err(tacit_core::CoreError::Sync("不能引入本地 peer 自身".into()));
        }

        // 1. 校验发送者 == 介绍人（防止第三方冒充介绍人发起引入）
        if sender_peer_id != &msg.introducer {
            return Err(tacit_core::CoreError::Sync(format!(
                "介绍消息发送者 {sender_peer_id} 与介绍人 {} 不匹配，拒绝引入",
                msg.introducer
            )));
        }

        // 2. 校验介绍人是否已知且已被信任（Pending peer 不得引入他人）
        let introducer_trusted = {
            let conn = self.doc_store.store().conn();
            match tacit_store::dao::get_peer(&conn, &msg.introducer) {
                Ok(Some(record)) => record.trust_state == tacit_core::TrustState::Trusted,
                _ => false,
            }
        };

        if !introducer_trusted {
            return Err(tacit_core::CoreError::Sync(format!(
                "介绍人 {} 未被信任，拒绝引入未知信任链",
                msg.introducer
            )));
        }

        // 3. 校验被介绍 peer 的公钥 hex 格式（必须是 64 字符 hex，解码为 32 字节）
        if msg.introduced_pubkey_hex.len() != 64 || hex::decode(&msg.introduced_pubkey_hex).is_err()
        {
            return Err(tacit_core::CoreError::Sync(format!(
                "被介绍的 peer 公钥 hex 格式不合法: {}",
                msg.introduced_pubkey_hex
            )));
        }

        // 4. 将被介绍的 peer 写入 peers 表（Pending 状态）
        {
            let conn = self.doc_store.store().conn();
            let existing = tacit_store::dao::get_peer(&conn, &msg.introduced_peer)?;

            // 已存在的 peer：
            // - Trusted peer：不覆盖公钥/信任状态/endpoint，防止劫持
            // - Pending peer：允许更新公钥和 endpoint（介绍人已验证为 Trusted）。
            //   这防止恶意 peer 预注册假公钥锁定 victim peer ID 的攻击。
            if let Some(mut record) = existing {
                if record.trust_state == tacit_core::TrustState::Pending {
                    let mut updated = false;
                    if record.device_pubkey != msg.introduced_pubkey_hex {
                        record.device_pubkey = msg.introduced_pubkey_hex.clone();
                        updated = true;
                    }
                    if let Some(addr) = &msg.endpoint {
                        let parsed = parse_endpoint(addr);
                        if record.last_endpoint.as_ref() != Some(&parsed) {
                            record.last_endpoint = Some(parsed);
                            updated = true;
                        }
                    }
                    if updated {
                        tacit_store::dao::upsert_peer(&conn, &record)?;
                        debug!(
                            introduced = %msg.introduced_peer,
                            "远程信任链引入：更新 Pending peer 的公钥/endpoint"
                        );
                    }
                } else {
                    debug!(
                        introduced = %msg.introduced_peer,
                        "远程信任链引入：忽略对已信任 peer 的 endpoint 更新以防劫持"
                    );
                }
            } else {
                let record = tacit_core::PeerRecord {
                    peer_id: msg.introduced_peer.clone(),
                    device_pubkey: msg.introduced_pubkey_hex.clone(),
                    capabilities: Default::default(),
                    trust_state: tacit_core::TrustState::Pending,
                    anchor_priority: 0,
                    last_seen_at: SystemTime::now(),
                    last_endpoint: msg.endpoint.as_ref().map(|addr| parse_endpoint(addr)),
                    nat_capability: tacit_core::NatCapability::Unknown,
                    relay_hint: None,
                    success_ema: 0.0,
                    rotation_seq: 0,
                };
                tacit_store::dao::upsert_peer(&conn, &record)?;
                debug!(
                    introducer = %msg.introducer,
                    introduced = %msg.introduced_peer,
                    "远程信任链引入：新 peer 已注册为 Pending"
                );
            }
        }

        // 3. 发射事件
        self.push_action(SyncAction::EmitEvent(
            tacit_core::CoreEvent::PeerIntroduced {
                introducer: msg.introducer.clone(),
                introduced_peer: msg.introduced_peer.clone(),
                introduced_pubkey_hex: msg.introduced_pubkey_hex.clone(),
                endpoint: msg.endpoint.clone(),
            },
        ));

        // 4. 同步更新内存中的 peer_states（仅在不存在时初始化，避免覆盖已在线状态）
        self.peer_states
            .lock()
            .entry(msg.introduced_peer.clone())
            .or_insert_with(|| PeerSyncState {
                known_frontier: Frontier::new(),
                last_seen: SystemTime::now(),
                online: false,
            });

        Ok(())
    }

    /// 处理密钥轮换通知（§12.2 KeyRotate）。
    ///
    /// 收到 `KeyRotateNotice` 后：
    /// 1. 校验 peer 是否已知（未知的 peer 不允许轮换密钥）
    /// 2. 校验 `rotation_seq` 单调递增（防止重放攻击）
    /// 3. 更新 `peers` 表中该 peer 的 `device_pubkey`
    /// 4. 发射 `PeerKeyRotated` 事件，供上层（Crypto 层 / PeerRegistry）更新密钥缓存
    ///
    /// 安全模型：
    /// - `rotation_seq` 必须大于已存储的序号（从 0 开始，首次轮换为 1）
    /// - 新公钥写入后，旧公钥立即失效，后续握手使用新公钥验证
    /// - 轮换不改变 `TrustState`（已信任的 peer 轮换密钥后仍为 Trusted）
    pub fn handle_key_rotate(&self, msg: &tacit_transport::KeyRotateNotice) -> CoreResult<()> {
        // 拒绝为本地 peer 执行密钥轮换：本地密钥由本地安全管理，不响应网络端轮换通知
        if msg.peer_id == *self.doc_store.peer_id() {
            return Err(tacit_core::CoreError::Crypto(
                "不能为本地 peer 执行密钥轮换".into(),
            ));
        }

        // 0. 校验新公钥 hex 格式（必须是 64 字符 hex，解码为 32 字节）
        if msg.new_pubkey_hex.len() != 64 || hex::decode(&msg.new_pubkey_hex).is_err() {
            return Err(tacit_core::CoreError::Crypto(format!(
                "新公钥 hex 格式不合法: {}",
                msg.new_pubkey_hex
            )));
        }

        // 1. 校验 peer 是否已知
        let conn = self.doc_store.store().conn();
        let existing = tacit_store::dao::get_peer(&conn, &msg.peer_id)?;

        let mut record = existing.ok_or_else(|| {
            tacit_core::CoreError::PeerNotFound(format!(
                "密钥轮换失败：peer {} 不在已知列表中",
                msg.peer_id
            ))
        })?;

        // 2. 校验 rotation_seq 单调递增（使用 peers 表中独立的 rotation_seq 列）
        let current_seq = record.rotation_seq;
        if msg.rotation_seq <= current_seq {
            return Err(tacit_core::CoreError::Crypto(format!(
                "密钥轮换序号不递增：当前 {}，收到 {}（可能是重放攻击）",
                current_seq, msg.rotation_seq
            )));
        }

        // 3. 验证轮换签名：用旧公钥验证，防止第三方伪造轮换通知
        let sign_message = format!(
            "{}:{}:{}",
            msg.peer_id, msg.new_pubkey_hex, msg.rotation_seq
        );
        let old_pubkey_bytes = hex::decode(&record.device_pubkey)
            .map_err(|e| tacit_core::CoreError::Crypto(format!("旧公钥 hex 解码失败: {e}")))?;
        let old_pubkey_arr: [u8; 32] = old_pubkey_bytes.as_slice().try_into().map_err(|_| {
            tacit_core::CoreError::Crypto("旧公钥长度不合法（期望 32 字节）".into())
        })?;
        tacit_crypto::verify(sign_message.as_bytes(), &msg.signature, &old_pubkey_arr)?;

        // 4. 更新公钥与序号
        let old_pubkey = record.device_pubkey.clone();
        record.device_pubkey = msg.new_pubkey_hex.clone();
        record.rotation_seq = msg.rotation_seq;
        tacit_store::dao::upsert_peer(&conn, &record)?;

        debug!(
            peer = %msg.peer_id,
            old_pubkey = %old_pubkey,
            new_pubkey = %msg.new_pubkey_hex,
            seq = msg.rotation_seq,
            "密钥轮换完成"
        );

        // 4. 发射事件
        self.push_action(SyncAction::EmitEvent(
            tacit_core::CoreEvent::PeerKeyRotated {
                peer_id: msg.peer_id.clone(),
                new_pubkey_hex: msg.new_pubkey_hex.clone(),
                rotation_seq: msg.rotation_seq,
            },
        ));

        Ok(())
    }

    /// 执行 push/pull 会话。
    fn run_push_pull(&self, peer_id: &PeerId, doc_id: &DocId) -> CoreResult<()> {
        let local_meta_frontier = self.doc_store.meta_frontier(doc_id)?;
        let peer_state = self.peer_states.lock();
        let peer_frontier = peer_state
            .get(peer_id)
            .map(|s| s.known_frontier.clone())
            .unwrap_or_default();
        drop(peer_state);

        // 1. 优先同步 MetaDoc：如果本地 meta frontier 不被 peer 覆盖，推送
        if !peer_frontier.covers(&local_meta_frontier) {
            let delta = self.doc_store.export_meta_delta(doc_id, &peer_frontier)?;
            self.push_action(SyncAction::SendData {
                peer_id: peer_id.clone(),
                doc_id: doc_id.clone(),
                block_id: None,
                bytes: delta,
                priority: Priority::High,
                path: PathPreference::Any,
            });
        }
        // 2. 如果 peer 的 meta frontier 比本地新，请求拉取
        if !local_meta_frontier.covers(&peer_frontier) {
            self.push_action(SyncAction::RequestDelta {
                peer_id: peer_id.clone(),
                doc_id: doc_id.clone(),
                block_id: None,
                since: local_meta_frontier.clone(),
                priority: Priority::High,
            });
        }

        // 3. 检查各 block 的缺口
        let blocks = self.doc_store.list_active_blocks(doc_id)?;
        for block in blocks {
            let local_block_frontier = self.doc_store.block_frontier(doc_id, &block.block_id)?;
            if !peer_frontier.covers(&local_block_frontier) {
                // 本地有 peer 没有的 block 数据，推送
                let delta =
                    self.doc_store
                        .export_block_delta(doc_id, &block.block_id, &peer_frontier)?;
                self.push_action(SyncAction::SendData {
                    peer_id: peer_id.clone(),
                    doc_id: doc_id.clone(),
                    block_id: Some(block.block_id.clone()),
                    bytes: delta,
                    priority: Priority::High,
                    path: PathPreference::Any,
                });
            }
            if !local_block_frontier.covers(&peer_frontier) {
                // peer 有本地没有的 block 数据，请求拉取
                self.push_action(SyncAction::RequestDelta {
                    peer_id: peer_id.clone(),
                    doc_id: doc_id.clone(),
                    block_id: Some(block.block_id.clone()),
                    since: local_block_frontier.clone(),
                    priority: Priority::High,
                });
            }
        }
        Ok(())
    }

    /// 推送动作到优先级队列。
    pub(crate) fn push_action(&self, action: SyncAction) {
        self.actions.push(action);
    }

    /// 返回当前所有在线 peer 的 ID 列表。
    ///
    /// 供 recovery 编排器在冷文档追赶阶段为每个在线 peer 生成低优 RequestDelta。
    pub fn online_peers(&self) -> Vec<PeerId> {
        let states = self.peer_states.lock();
        states
            .iter()
            .filter(|(_, s)| s.online)
            .map(|(p, _)| p.clone())
            .collect()
    }
}

impl SyncEngine for DefaultSyncEngine {
    fn on_local_change(&self, doc_id: DocId, change: ChangeEnvelope) -> CoreResult<()> {
        // 推送给所有在线 peer
        self.push_local_change(&doc_id, &change)?;
        Ok(())
    }

    fn on_peer_summary(&self, peer_id: PeerId, summary: PeerSummary) -> CoreResult<()> {
        // 更新 peer 状态，检测从离线→在线的转换
        let was_offline = {
            let mut states = self.peer_states.lock();
            let was_offline = states.get(&peer_id).map(|s| !s.online).unwrap_or(true);
            states.insert(
                peer_id.clone(),
                PeerSyncState {
                    known_frontier: summary.frontier.clone(),
                    last_seen: SystemTime::now(),
                    online: summary.online,
                },
            );
            was_offline
        };

        // peer 从离线变为在线：重发未投递的待发消息
        if summary.online && was_offline {
            match self.store_forward.list_undelivered(&peer_id) {
                Ok(records) => {
                    if !records.is_empty() {
                        info!(
                            peer_id = %peer_id,
                            count = records.len(),
                            "peer 上线，重发未投递消息"
                        );
                        // 去重：同一 (doc_id, block_id) 只导出/发送一次最新 delta
                        // 逆序遍历（最新优先），确保发送最新记录的 entry_id
                        let mut sent_deltas: std::collections::HashSet<(DocId, Option<BlockId>)> =
                            std::collections::HashSet::new();
                        for rec in records.iter().rev() {
                            // 从 delta_id 解析出 block_id（格式: "block_delta:{id}" 或 "meta_delta"）
                            let block_id = if rec.delta_id == "meta_delta" {
                                None
                            } else {
                                rec.delta_id.strip_prefix("block_delta:").map(BlockId::new)
                            };

                            // 去重：已成功发送过该 (doc_id, block_id) 的最新 delta，标记已投递+已确认并跳过
                            let key = (rec.doc_id.clone(), block_id.clone());
                            if sent_deltas.contains(&key) {
                                let _ = self.store_forward.mark_delivered(&rec.entry_id);
                                let _ = self.store_forward.mark_acknowledged(&rec.entry_id);
                                continue;
                            }

                            // 查询该 peer 对此文档的最后确认 frontier，确保增量导出正确
                            let peer_ack_frontier = {
                                let conn = self.doc_store.store().conn();
                                match tacit_store::dao::get_ack(&conn, &peer_id, &rec.doc_id) {
                                    Ok(Some(ack)) => ack.ack_frontier,
                                    _ => Frontier::new(),
                                }
                            };

                            let bytes_res = if let Some(ref bid) = block_id {
                                self.doc_store.export_block_delta(
                                    &rec.doc_id,
                                    bid,
                                    &peer_ack_frontier,
                                )
                            } else {
                                self.doc_store
                                    .export_meta_delta(&rec.doc_id, &peer_ack_frontier)
                            };

                            let bytes = match bytes_res {
                                Ok(b) => b,
                                Err(e) => {
                                    debug!(
                                        peer_id = %peer_id,
                                        doc_id = %rec.doc_id,
                                        error = %e,
                                        "重发：导出 delta 失败，跳过"
                                    );
                                    continue;
                                }
                            };

                            self.push_action(SyncAction::SendData {
                                peer_id: peer_id.clone(),
                                doc_id: rec.doc_id.clone(),
                                block_id,
                                bytes,
                                priority: Priority::High,
                                path: PathPreference::Any,
                            });

                            // 标记已投递，并记录到已发送集合（仅在成功导出后）
                            let _ = self.store_forward.mark_delivered(&rec.entry_id);
                            sent_deltas.insert(key);
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        peer_id = %peer_id,
                        error = %e,
                        "重发未投递消息失败"
                    );
                }
            }
        }

        // 对所有已知 doc 发送 ack 摘要给 peer。
        // AckSummary 表示"本设备对该 doc 已确认到哪个 frontier"，
        // 因此 ack_frontier 应为本地 meta frontier，而非 peer 报告的 frontier。
        let docs = {
            let conn = self.doc_store.store().conn();
            tacit_store::dao::list_docs(&conn)?
        };
        for doc in docs {
            // 读取本地 meta frontier；若 doc 尚无 meta（刚创建），用空 frontier 兜底
            let local_frontier = self
                .doc_store
                .meta_frontier(&doc.doc_id)
                .unwrap_or_default();
            self.push_action(SyncAction::SendControl {
                peer_id: peer_id.clone(),
                msg: ControlMsg::AckSummary(AckSummary {
                    peer_id: self.config.peer_id.clone(),
                    doc_id: doc.doc_id.clone(),
                    ack_checkpoint: None,
                    ack_frontier: local_frontier,
                    updated_at: SystemTime::now(),
                    version_override: None,
                }),
                priority: Priority::Medium,
            });
        }
        Ok(())
    }

    fn request_sync(&self, peer_id: PeerId, reason: SyncReason) -> CoreResult<()> {
        self.push_action(SyncAction::EmitEvent(tacit_core::CoreEvent::SyncStarted {
            peer_id: peer_id.clone(),
            reason,
        }));
        // 同步前先刷新脏 block，确保最新编辑已持久化
        self.doc_store.flush_dirty_blocks()?;
        // 先收集 doc 列表再释放 conn 锁，避免 run_push_pull 内部再次获取 conn 导致死锁
        let docs = {
            let conn = self.doc_store.store().conn();
            tacit_store::dao::list_docs(&conn)?
        };
        for doc in docs {
            self.run_push_pull(&peer_id, &doc.doc_id)?;
        }
        self.push_action(SyncAction::EmitEvent(
            tacit_core::CoreEvent::SyncCompleted { peer_id },
        ));
        Ok(())
    }

    fn fast_resume(&self, viewport: Option<Viewport>) -> CoreResult<()> {
        // 首屏恢复策略：Meta-Document 骨架 → 可见 block → 活跃文档剩余 block → 冷文档追赶
        let coord = crate::recovery::RecoveryCoordinator::new(self.doc_store.clone());
        coord.first_screen_recovery(self, viewport)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_store::Store;

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    fn make_engine() -> (DefaultSyncEngine, Arc<DocStore>) {
        let store = Store::open_memory().unwrap();
        let doc_store = Arc::new(DocStore::new(pid(1), store, 32));
        doc_store.create_doc(DocId::new("d1"), "note").unwrap();
        let engine = DefaultSyncEngine::new(
            doc_store.clone(),
            EngineConfig {
                peer_id: pid(1),
                ..Default::default()
            },
        );
        (engine, doc_store)
    }

    #[test]
    fn local_change_pushes_to_online_peer() {
        let (engine, doc_store) = make_engine();
        // 创建 block
        doc_store
            .create_block(
                &DocId::new("d1"),
                BlockId::new("b1"),
                tacit_core::BlockKind::Text,
            )
            .unwrap();
        // 标记 peer 在线
        engine
            .on_peer_summary(
                pid(2),
                PeerSummary {
                    peer_id: pid(2),
                    online: true,
                    frontier: Frontier::new(),
                    capabilities: Default::default(),
                },
            )
            .unwrap();
        // 本地编辑
        doc_store
            .apply_local_edit(&DocId::new("d1"), &BlockId::new("b1"), b"hello")
            .unwrap();
        let frontier = doc_store
            .block_frontier(&DocId::new("d1"), &BlockId::new("b1"))
            .unwrap();
        engine
            .on_local_change(
                DocId::new("d1"),
                ChangeEnvelope {
                    doc_id: DocId::new("d1"),
                    block_id: Some(BlockId::new("b1")),
                    delta: bytes::Bytes::new(),
                    frontier,
                },
            )
            .unwrap();
        let actions = engine.drain_actions();
        // 应该有 SendData 动作
        assert!(actions
            .iter()
            .any(|a| matches!(a, SyncAction::SendData { .. })));
    }

    #[test]
    fn request_sync_generates_push_pull() {
        let (engine, doc_store) = make_engine();
        doc_store
            .create_block(
                &DocId::new("d1"),
                BlockId::new("b1"),
                tacit_core::BlockKind::Text,
            )
            .unwrap();
        doc_store
            .apply_local_edit(&DocId::new("d1"), &BlockId::new("b1"), b"data")
            .unwrap();
        engine
            .request_sync(pid(2), SyncReason::UserForeground)
            .unwrap();
        let actions = engine.drain_actions();
        // 应该有 SyncStarted 和 SyncCompleted 事件
        assert!(actions.iter().any(|a| matches!(
            a,
            SyncAction::EmitEvent(tacit_core::CoreEvent::SyncStarted { .. })
        )));
        assert!(actions.iter().any(|a| matches!(
            a,
            SyncAction::EmitEvent(tacit_core::CoreEvent::SyncCompleted { .. })
        )));
    }

    #[test]
    fn watermarks_computation() {
        let (engine, doc_store) = make_engine();
        // 注意：必须先释放 conn 锁，否则 compute_watermarks 内部再次获取会死锁。
        {
            let conn = doc_store.store().conn();
            // 插入两个 peer 的 ack
            tacit_store::dao::upsert_ack(
                &conn,
                &AckSummary {
                    peer_id: pid(2),
                    doc_id: DocId::new("d1"),
                    ack_checkpoint: None,
                    ack_frontier: Frontier::from_iter([(pid(1), 5)]),
                    updated_at: SystemTime::now(),
                    version_override: None,
                },
            )
            .unwrap();
            tacit_store::dao::upsert_ack(
                &conn,
                &AckSummary {
                    peer_id: pid(3),
                    doc_id: DocId::new("d1"),
                    ack_checkpoint: None,
                    ack_frontier: Frontier::from_iter([(pid(1), 3)]),
                    updated_at: SystemTime::now(),
                    version_override: None,
                },
            )
            .unwrap();
        } // conn 在此 drop
        let w = engine.compute_watermarks(&DocId::new("d1")).unwrap();
        // hard = min(5,3) = 3
        assert_eq!(w.hard_frontier.get(&pid(1)), Some(3));
        // soft = max(5,3) = 5
        assert_eq!(w.soft_frontier.get(&pid(1)), Some(5));
    }

    #[test]
    fn fast_resume_opens_all_docs() {
        let (engine, doc_store) = make_engine();
        doc_store
            .create_block(
                &DocId::new("d1"),
                BlockId::new("b1"),
                tacit_core::BlockKind::Text,
            )
            .unwrap();
        // fast_resume 不应报错
        engine.fast_resume(None).unwrap();
    }

    #[test]
    fn pending_queue_backoff() {
        let (engine, _doc_store) = make_engine();
        let now = Instant::now();
        // 入队一个依赖等待
        engine.pending_queue().enqueue(PendingBlockFetch {
            doc_id: DocId::new("d1"),
            block_id: BlockId::new("b1"),
            expected_frontier: Frontier::new(),
            observed_frontier: Frontier::new(),
            peer_id: pid(2),
            retry_at: now,
            retries: 0,
            phase: crate::pending::BackoffPhase::Normal,
        });
        // 处理到期条目
        engine.process_pending(now).unwrap();
        // 应该产生 RequestDelta 动作并重新入队
        let actions = engine.drain_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, SyncAction::RequestDelta { .. })));
        assert_eq!(engine.pending_queue().len(), 1);
    }

    #[test]
    fn handle_revoke_removes_peer_and_emits_event() {
        let (engine, _doc_store) = make_engine();
        // 注册 peer
        engine
            .on_peer_summary(
                pid(2),
                PeerSummary {
                    peer_id: pid(2),
                    online: true,
                    frontier: Frontier::new(),
                    capabilities: Default::default(),
                },
            )
            .unwrap();
        // 确认 peer 已注册
        assert_eq!(engine.online_peers().len(), 1);

        // 撤销 peer
        engine.handle_revoke(&pid(2), "test revocation").unwrap();

        // peer 应已移除
        assert_eq!(engine.online_peers().len(), 0);

        // 应发射 PeerRevoked 事件
        let actions = engine.drain_actions();
        assert!(actions.iter().any(|a| matches!(
            a,
            SyncAction::EmitEvent(tacit_core::CoreEvent::PeerRevoked { .. })
        )));
    }

    #[test]
    fn handle_revoke_cleans_pending_queue() {
        let (engine, _doc_store) = make_engine();
        // 注册 peer
        engine
            .on_peer_summary(
                pid(2),
                PeerSummary {
                    peer_id: pid(2),
                    online: true,
                    frontier: Frontier::new(),
                    capabilities: Default::default(),
                },
            )
            .unwrap();
        // 入队依赖等待
        let now = Instant::now();
        engine.pending_queue().enqueue(PendingBlockFetch {
            doc_id: DocId::new("d1"),
            block_id: BlockId::new("b1"),
            expected_frontier: Frontier::new(),
            observed_frontier: Frontier::new(),
            peer_id: pid(2),
            retry_at: now,
            retries: 0,
            phase: crate::pending::BackoffPhase::Normal,
        });
        assert_eq!(engine.pending_queue().len(), 1);

        // 撤销 peer
        engine.handle_revoke(&pid(2), "test").unwrap();

        // 依赖等待应被清理
        assert_eq!(engine.pending_queue().len(), 0);
    }

    // ===== handle_introduce 测试 =====

    /// 辅助：注册在线 peer。
    fn register_online_peer(engine: &DefaultSyncEngine, peer_id: PeerId) {
        let summary = PeerSummary {
            peer_id: peer_id.clone(),
            online: true,
            frontier: Frontier::new(),
            capabilities: Default::default(),
        };
        engine.on_peer_summary(peer_id, summary).unwrap();
    }

    /// 辅助：注册已信任的在线 peer（内存 + DB）。
    fn register_trusted_peer(engine: &DefaultSyncEngine, doc_store: &DocStore, peer_id: PeerId) {
        register_online_peer(engine, peer_id.clone());
        let conn = doc_store.store().conn();
        tacit_store::dao::upsert_peer(
            &conn,
            &tacit_core::PeerRecord {
                peer_id,
                device_pubkey: "trusted".to_string(),
                capabilities: Default::default(),
                trust_state: tacit_core::TrustState::Trusted,
                anchor_priority: 0,
                last_seen_at: SystemTime::now(),
                last_endpoint: None,
                nat_capability: tacit_core::NatCapability::Unknown,
                relay_hint: None,
                success_ema: 1.0,
                rotation_seq: 0,
            },
        )
        .unwrap();
    }

    #[test]
    fn handle_introduce_registers_new_peer_as_pending() {
        let (engine, doc_store) = make_engine();
        register_trusted_peer(&engine, &doc_store, pid(2));

        let pubkey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let msg = tacit_transport::IntroducePeer {
            introducer: pid(2),
            introduced_peer: pid(3),
            introduced_pubkey_hex: pubkey.to_string(),
            endpoint: Some("192.168.1.100:8080".to_string()),
        };
        engine.handle_introduce(&msg, &pid(2)).unwrap();

        let conn = doc_store.store().conn();
        let peer = tacit_store::dao::get_peer(&conn, &pid(3)).unwrap();
        assert!(peer.is_some());
        let peer = peer.unwrap();
        assert_eq!(peer.trust_state, tacit_core::TrustState::Pending);
        assert_eq!(peer.device_pubkey, pubkey);
        assert!(peer.last_endpoint.is_some());
    }

    #[test]
    fn handle_introduce_emits_peer_introduced_event() {
        let (engine, doc_store) = make_engine();
        register_trusted_peer(&engine, &doc_store, pid(2));

        let pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let msg = tacit_transport::IntroducePeer {
            introducer: pid(2),
            introduced_peer: pid(3),
            introduced_pubkey_hex: pubkey.to_string(),
            endpoint: None,
        };
        engine.handle_introduce(&msg, &pid(2)).unwrap();

        let actions = engine.drain_actions();
        assert!(actions.iter().any(|a| matches!(
            a,
            SyncAction::EmitEvent(tacit_core::CoreEvent::PeerIntroduced {
                introduced_peer,
                ..
            }) if introduced_peer == &pid(3)
        )));
    }

    #[test]
    fn handle_introduce_rejects_unknown_introducer() {
        let (engine, _doc_store) = make_engine();

        let msg = tacit_transport::IntroducePeer {
            introducer: pid(99),
            introduced_peer: pid(3),
            introduced_pubkey_hex:
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            endpoint: None,
        };
        let result = engine.handle_introduce(&msg, &pid(99));
        assert!(result.is_err());
    }

    #[test]
    fn handle_introduce_rejects_mismatched_sender() {
        let (engine, doc_store) = make_engine();
        register_trusted_peer(&engine, &doc_store, pid(2));
        register_online_peer(&engine, pid(5));

        // pid(5) 试图冒充 pid(2) 发起引入
        let msg = tacit_transport::IntroducePeer {
            introducer: pid(2),
            introduced_peer: pid(3),
            introduced_pubkey_hex:
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            endpoint: None,
        };
        let result = engine.handle_introduce(&msg, &pid(5));
        assert!(result.is_err());
    }

    #[test]
    fn handle_introduce_does_not_overwrite_existing_peer() {
        let (engine, doc_store) = make_engine();
        register_trusted_peer(&engine, &doc_store, pid(2));

        {
            let conn = doc_store.store().conn();
            tacit_store::dao::upsert_peer(
                &conn,
                &tacit_core::PeerRecord {
                    peer_id: pid(3),
                    device_pubkey:
                        "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
                            .to_string(),
                    capabilities: Default::default(),
                    trust_state: tacit_core::TrustState::Trusted,
                    anchor_priority: 5,
                    last_seen_at: SystemTime::now(),
                    last_endpoint: None,
                    nat_capability: tacit_core::NatCapability::Unknown,
                    relay_hint: None,
                    success_ema: 0.9,
                    rotation_seq: 0,
                },
            )
            .unwrap();
        }

        let msg = tacit_transport::IntroducePeer {
            introducer: pid(2),
            introduced_peer: pid(3),
            introduced_pubkey_hex:
                "1122334455667788112233445566778811223344556677881122334455667788".to_string(),
            endpoint: None,
        };
        engine.handle_introduce(&msg, &pid(2)).unwrap();

        let conn = doc_store.store().conn();
        let peer = tacit_store::dao::get_peer(&conn, &pid(3)).unwrap().unwrap();
        assert_eq!(peer.trust_state, tacit_core::TrustState::Trusted);
        assert_eq!(
            peer.device_pubkey,
            "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
        );
    }

    // ===== handle_key_rotate 测试 =====

    /// 辅助：生成 DeviceIdentity 并返回 (identity, pubkey_hex)。
    fn make_identity() -> (tacit_crypto::identity::DeviceIdentity, String) {
        let id = tacit_crypto::identity::DeviceIdentity::generate().unwrap();
        let pubkey_hex = hex::encode(id.public_key());
        (id, pubkey_hex)
    }

    /// 辅助：用旧身份签发 KeyRotateNotice。
    fn sign_rotation(
        identity: &tacit_crypto::identity::DeviceIdentity,
        peer_id: &PeerId,
        new_pubkey_hex: &str,
        rotation_seq: u64,
    ) -> tacit_transport::KeyRotateNotice {
        let message = format!("{}:{}:{}", peer_id, new_pubkey_hex, rotation_seq);
        let sig = tacit_crypto::sign(identity, message.as_bytes());
        tacit_transport::KeyRotateNotice {
            peer_id: peer_id.clone(),
            new_pubkey_hex: new_pubkey_hex.to_string(),
            rotation_seq,
            signature: sig.to_vec(),
        }
    }

    #[test]
    fn handle_key_rotate_updates_pubkey_and_seq() {
        let (engine, doc_store) = make_engine();
        register_online_peer(&engine, pid(2));

        let (old_id, old_pubkey_hex) = make_identity();
        let (_, new_pubkey_hex) = make_identity();

        {
            let conn = doc_store.store().conn();
            tacit_store::dao::upsert_peer(
                &conn,
                &tacit_core::PeerRecord {
                    peer_id: pid(2),
                    device_pubkey: old_pubkey_hex,
                    capabilities: Default::default(),
                    trust_state: tacit_core::TrustState::Trusted,
                    anchor_priority: 0,
                    last_seen_at: SystemTime::now(),
                    last_endpoint: None,
                    nat_capability: tacit_core::NatCapability::Unknown,
                    relay_hint: None,
                    success_ema: 1.0,
                    rotation_seq: 0,
                },
            )
            .unwrap();
        }

        let msg = sign_rotation(&old_id, &pid(2), &new_pubkey_hex, 1);
        engine.handle_key_rotate(&msg).unwrap();

        let conn = doc_store.store().conn();
        let peer = tacit_store::dao::get_peer(&conn, &pid(2)).unwrap().unwrap();
        assert_eq!(peer.device_pubkey, new_pubkey_hex);
        assert_eq!(peer.rotation_seq, 1);
        assert_eq!(peer.trust_state, tacit_core::TrustState::Trusted);
    }

    #[test]
    fn handle_key_rotate_emits_event() {
        let (engine, doc_store) = make_engine();
        register_online_peer(&engine, pid(2));

        let (old_id, old_pubkey_hex) = make_identity();
        let (_, new_pubkey_hex) = make_identity();

        {
            let conn = doc_store.store().conn();
            tacit_store::dao::upsert_peer(
                &conn,
                &tacit_core::PeerRecord {
                    peer_id: pid(2),
                    device_pubkey: old_pubkey_hex,
                    capabilities: Default::default(),
                    trust_state: tacit_core::TrustState::Trusted,
                    anchor_priority: 0,
                    last_seen_at: SystemTime::now(),
                    last_endpoint: None,
                    nat_capability: tacit_core::NatCapability::Unknown,
                    relay_hint: None,
                    success_ema: 1.0,
                    rotation_seq: 0,
                },
            )
            .unwrap();
        }

        let msg = sign_rotation(&old_id, &pid(2), &new_pubkey_hex, 1);
        engine.handle_key_rotate(&msg).unwrap();

        let actions = engine.drain_actions();
        assert!(actions.iter().any(|a| matches!(
            a,
            SyncAction::EmitEvent(tacit_core::CoreEvent::PeerKeyRotated {
                peer_id,
                rotation_seq: 1,
                ..
            }) if peer_id == &pid(2)
        )));
    }

    #[test]
    fn handle_key_rotate_rejects_unknown_peer() {
        let (engine, _doc_store) = make_engine();

        let msg = tacit_transport::KeyRotateNotice {
            peer_id: pid(99),
            new_pubkey_hex: "newkey".to_string(),
            rotation_seq: 1,
            signature: vec![0u8; 64],
        };
        let result = engine.handle_key_rotate(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn handle_key_rotate_rejects_non_incrementing_seq() {
        let (engine, doc_store) = make_engine();
        register_online_peer(&engine, pid(2));

        let (_, pubkey_hex) = make_identity();
        let pubkey_hex_check = pubkey_hex.clone();

        {
            let conn = doc_store.store().conn();
            tacit_store::dao::upsert_peer(
                &conn,
                &tacit_core::PeerRecord {
                    peer_id: pid(2),
                    device_pubkey: pubkey_hex,
                    capabilities: Default::default(),
                    trust_state: tacit_core::TrustState::Trusted,
                    anchor_priority: 0,
                    last_seen_at: SystemTime::now(),
                    last_endpoint: None,
                    nat_capability: tacit_core::NatCapability::Unknown,
                    relay_hint: None,
                    success_ema: 1.0,
                    rotation_seq: 3,
                },
            )
            .unwrap();
        }

        // seq=3 不递增
        let msg = tacit_transport::KeyRotateNotice {
            peer_id: pid(2),
            new_pubkey_hex: "00".repeat(32),
            rotation_seq: 3,
            signature: vec![0u8; 64],
        };
        assert!(engine.handle_key_rotate(&msg).is_err());

        // seq=2 回退
        let msg = tacit_transport::KeyRotateNotice {
            peer_id: pid(2),
            new_pubkey_hex: "00".repeat(32),
            rotation_seq: 2,
            signature: vec![0u8; 64],
        };
        assert!(engine.handle_key_rotate(&msg).is_err());

        // 公钥不变
        let conn = doc_store.store().conn();
        let peer = tacit_store::dao::get_peer(&conn, &pid(2)).unwrap().unwrap();
        assert_eq!(peer.device_pubkey, pubkey_hex_check);
    }

    #[test]
    fn handle_key_rotate_rejects_invalid_signature() {
        let (engine, doc_store) = make_engine();
        register_online_peer(&engine, pid(2));

        let (_, old_pubkey_hex) = make_identity();
        let old_pubkey_hex_check = old_pubkey_hex.clone();

        {
            let conn = doc_store.store().conn();
            tacit_store::dao::upsert_peer(
                &conn,
                &tacit_core::PeerRecord {
                    peer_id: pid(2),
                    device_pubkey: old_pubkey_hex,
                    capabilities: Default::default(),
                    trust_state: tacit_core::TrustState::Trusted,
                    anchor_priority: 0,
                    last_seen_at: SystemTime::now(),
                    last_endpoint: None,
                    nat_capability: tacit_core::NatCapability::Unknown,
                    relay_hint: None,
                    success_ema: 1.0,
                    rotation_seq: 0,
                },
            )
            .unwrap();
        }

        // 用无效签名
        let msg = tacit_transport::KeyRotateNotice {
            peer_id: pid(2),
            new_pubkey_hex: "00".repeat(32),
            rotation_seq: 1,
            signature: vec![0u8; 64],
        };
        assert!(engine.handle_key_rotate(&msg).is_err());

        // 公钥不变
        let conn = doc_store.store().conn();
        let peer = tacit_store::dao::get_peer(&conn, &pid(2)).unwrap().unwrap();
        assert_eq!(peer.device_pubkey, old_pubkey_hex_check);
    }

    #[test]
    fn handle_key_rotate_chained_rotations() {
        let (engine, doc_store) = make_engine();
        register_online_peer(&engine, pid(2));

        let (id_v0, pubkey_v0) = make_identity();
        let (id_v1, pubkey_v1) = make_identity();
        let (id_v2, pubkey_v2) = make_identity();
        let (_id_v3, pubkey_v3) = make_identity();

        {
            let conn = doc_store.store().conn();
            tacit_store::dao::upsert_peer(
                &conn,
                &tacit_core::PeerRecord {
                    peer_id: pid(2),
                    device_pubkey: pubkey_v0,
                    capabilities: Default::default(),
                    trust_state: tacit_core::TrustState::Trusted,
                    anchor_priority: 0,
                    last_seen_at: SystemTime::now(),
                    last_endpoint: None,
                    nat_capability: tacit_core::NatCapability::Unknown,
                    relay_hint: None,
                    success_ema: 1.0,
                    rotation_seq: 0,
                },
            )
            .unwrap();
        }

        // seq=1: 用 id_v0 签名，轮换到 pubkey_v1
        let msg = sign_rotation(&id_v0, &pid(2), &pubkey_v1, 1);
        engine.handle_key_rotate(&msg).unwrap();

        // seq=2: 用 id_v1 签名，轮换到 pubkey_v2
        let msg = sign_rotation(&id_v1, &pid(2), &pubkey_v2, 2);
        engine.handle_key_rotate(&msg).unwrap();

        // seq=3: 用 id_v2 签名，轮换到 pubkey_v3
        let msg = sign_rotation(&id_v2, &pid(2), &pubkey_v3, 3);
        engine.handle_key_rotate(&msg).unwrap();

        let conn = doc_store.store().conn();
        let peer = tacit_store::dao::get_peer(&conn, &pid(2)).unwrap().unwrap();
        assert_eq!(peer.device_pubkey, pubkey_v3);
        assert_eq!(peer.rotation_seq, 3);
    }

    // ===== Store-and-forward 接入测试 =====

    #[test]
    fn local_change_records_pending_for_offline_peer() {
        let (engine, doc_store) = make_engine();
        doc_store
            .create_block(
                &DocId::new("d1"),
                BlockId::new("b1"),
                tacit_core::BlockKind::Text,
            )
            .unwrap();
        doc_store
            .apply_local_edit(&DocId::new("d1"), &BlockId::new("b1"), b"hello")
            .unwrap();
        let frontier = doc_store
            .block_frontier(&DocId::new("d1"), &BlockId::new("b1"))
            .unwrap();

        // 注册离线 peer
        engine
            .on_peer_summary(
                pid(2),
                PeerSummary {
                    peer_id: pid(2),
                    online: false,
                    frontier: Frontier::new(),
                    capabilities: Default::default(),
                },
            )
            .unwrap();

        // 本地编辑 → 应记录待发
        engine
            .on_local_change(
                DocId::new("d1"),
                ChangeEnvelope {
                    doc_id: DocId::new("d1"),
                    block_id: Some(BlockId::new("b1")),
                    delta: bytes::Bytes::new(),
                    frontier,
                },
            )
            .unwrap();

        // drain_actions 不应有 SendData（离线 peer 不推送）
        let actions = engine.drain_actions();
        assert!(!actions
            .iter()
            .any(|a| matches!(a, SyncAction::SendData { .. })));

        // sync_log 中应有一条未投递记录
        let undelivered = engine.store_forward().list_undelivered(&pid(2)).unwrap();
        assert_eq!(undelivered.len(), 1);
    }

    #[test]
    fn peer_online_triggers_resend_undelivered() {
        let (engine, doc_store) = make_engine();
        doc_store
            .create_block(
                &DocId::new("d1"),
                BlockId::new("b1"),
                tacit_core::BlockKind::Text,
            )
            .unwrap();
        doc_store
            .apply_local_edit(&DocId::new("d1"), &BlockId::new("b1"), b"data")
            .unwrap();
        let frontier = doc_store
            .block_frontier(&DocId::new("d1"), &BlockId::new("b1"))
            .unwrap();

        // 1. 注册离线 peer
        engine
            .on_peer_summary(
                pid(2),
                PeerSummary {
                    peer_id: pid(2),
                    online: false,
                    frontier: Frontier::new(),
                    capabilities: Default::default(),
                },
            )
            .unwrap();

        // 2. 本地编辑 → 记录待发
        engine
            .on_local_change(
                DocId::new("d1"),
                ChangeEnvelope {
                    doc_id: DocId::new("d1"),
                    block_id: Some(BlockId::new("b1")),
                    delta: bytes::Bytes::new(),
                    frontier,
                },
            )
            .unwrap();

        // 3. peer 上线 → 应触发重发
        engine
            .on_peer_summary(
                pid(2),
                PeerSummary {
                    peer_id: pid(2),
                    online: true,
                    frontier: Frontier::new(),
                    capabilities: Default::default(),
                },
            )
            .unwrap();

        // 应有 SendData 动作（重发的消息）
        let actions = engine.drain_actions();
        assert!(actions
            .iter()
            .any(|a| matches!(a, SyncAction::SendData { peer_id, .. } if peer_id == &pid(2))));
    }
}
