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
    AckSummary, BlockId, ChangeEnvelope, CoreResult, DocId, Frontier, FrontierOps,
    PeerId, PeerSummary, Priority, SyncReason, TelemetryCollector, Viewport,
};
use tacit_transport::{ControlMsg, PathPreference};
use tracing::debug;

use crate::doc_store::DocStore;
use crate::hot_path::HotPathController;
use crate::pending::{PendingBlockFetch, PendingFetchQueue};
use crate::priority_queue::PriorityQueue;
use crate::watermarks::WatermarkCalculator;

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
        let watermarks = WatermarkCalculator::new(config.soft_watermark_timeout);
        Self {
            doc_store,
            pending,
            watermarks,
            peer_states: Mutex::new(std::collections::HashMap::new()),
            actions: PriorityQueue::new(),
            telemetry: Arc::new(TelemetryCollector::default()),
            hot_path: HotPathController::default(),
            config,
        }
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
                },
            )?;
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

    /// 推送本地变更给所有在线 peer。
    fn push_local_change(&self, doc_id: &DocId, change: &ChangeEnvelope) -> CoreResult<()> {
        let peers = self.peer_states.lock();
        for (peer_id, state) in peers.iter() {
            if state.online {
                let bytes = if let Some(block_id) = &change.block_id {
                    self.doc_store.export_block_delta(doc_id, block_id, &change.frontier)?
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
        }
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
                let delta = self.doc_store.export_block_delta(doc_id, &block.block_id, &peer_frontier)?;
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
        // 更新 peer 状态
        {
            let mut states = self.peer_states.lock();
            states.insert(
                peer_id.clone(),
                PeerSyncState {
                    known_frontier: summary.frontier.clone(),
                    last_seen: SystemTime::now(),
                    online: summary.online,
                },
            );
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
        self.push_action(SyncAction::EmitEvent(tacit_core::CoreEvent::SyncCompleted {
            peer_id,
        }));
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
        let doc_store = Arc::new(DocStore::new(
            pid(1),
            store,
            32,
        ));
        let _ = doc_store.create_doc(DocId::new("d1"), "note").unwrap();
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
            .create_block(&DocId::new("d1"), BlockId::new("b1"), tacit_core::BlockKind::Text)
            .unwrap();
        // 标记 peer 在线
        engine.on_peer_summary(
            pid(2),
            PeerSummary {
                peer_id: pid(2),
                online: true,
                frontier: Frontier::new(),
                capabilities: Default::default(),
            },
        ).unwrap();
        // 本地编辑
        doc_store
            .apply_local_edit(&DocId::new("d1"), &BlockId::new("b1"), b"hello")
            .unwrap();
        let frontier = doc_store.block_frontier(&DocId::new("d1"), &BlockId::new("b1")).unwrap();
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
        assert!(actions.iter().any(|a| matches!(a, SyncAction::SendData { .. })));
    }

    #[test]
    fn request_sync_generates_push_pull() {
        let (engine, doc_store) = make_engine();
        doc_store
            .create_block(&DocId::new("d1"), BlockId::new("b1"), tacit_core::BlockKind::Text)
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
                },
            ).unwrap();
            tacit_store::dao::upsert_ack(
                &conn,
                &AckSummary {
                    peer_id: pid(3),
                    doc_id: DocId::new("d1"),
                    ack_checkpoint: None,
                    ack_frontier: Frontier::from_iter([(pid(1), 3)]),
                    updated_at: SystemTime::now(),
                },
            ).unwrap();
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
            .create_block(&DocId::new("d1"), BlockId::new("b1"), tacit_core::BlockKind::Text)
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
        assert!(actions.iter().any(|a| matches!(a, SyncAction::RequestDelta { .. })));
        assert_eq!(engine.pending_queue().len(), 1);
    }
}
