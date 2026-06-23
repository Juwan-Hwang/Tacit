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
    PeerId, PeerSummary, Priority, SyncReason,
};
use tacit_transport::{ControlMsg, PathPreference};

use crate::doc_store::DocStore;
use crate::pending::{PendingBlockFetch, PendingFetchQueue};
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
    RequestDelta {
        peer_id: PeerId,
        doc_id: DocId,
        block_id: Option<BlockId>,
        since: Frontier,
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
    #[allow(dead_code)]
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
    fn fast_resume(&self) -> CoreResult<()>;
}

/// 默认 SyncEngine 实现。
pub struct DefaultSyncEngine {
    doc_store: Arc<DocStore>,
    pending: Arc<PendingFetchQueue>,
    watermarks: WatermarkCalculator,
    peer_states: Mutex<std::collections::HashMap<PeerId, PeerSyncState>>,
    actions: Mutex<Vec<SyncAction>>,
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
            actions: Mutex::new(Vec::new()),
            config,
        }
    }

    /// 取出所有待执行的 SyncAction。
    pub fn drain_actions(&self) -> Vec<SyncAction> {
        std::mem::take(&mut *self.actions.lock())
    }

    /// 待执行动作数量。
    pub fn pending_actions(&self) -> usize {
        self.actions.lock().len()
    }

    /// 依赖等待队列引用。
    pub fn pending_queue(&self) -> &Arc<PendingFetchQueue> {
        &self.pending
    }

    /// 处理依赖等待重试。
    ///
    /// 取出到期的等待条目，重新发起拉取请求。
    pub fn process_pending(&self, now: Instant) -> CoreResult<()> {
        let ready = self.pending.drain_ready(now);
        for fetch in ready {
            // 重新发起拉取请求
            self.push_action(SyncAction::RequestDelta {
                peer_id: fetch.peer_id.clone(),
                doc_id: fetch.doc_id.clone(),
                block_id: Some(fetch.block_id.clone()),
                since: Frontier::new(), // 从头拉（简化：实际应从 observed_frontier 拉）
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
            // 检查是否有新 block 需要拉取
            let blocks = self.doc_store.list_active_blocks(doc_id)?;
            for block in blocks {
                // 如果本地没有该 block 的 snapshot，加入依赖等待
                let local_frontier = self.doc_store.block_frontier(doc_id, &block.block_id);
                if local_frontier.is_err() {
                    self.pending.enqueue(PendingBlockFetch {
                        doc_id: doc_id.clone(),
                        block_id: block.block_id.clone(),
                        expected_frontier: Frontier::new(),
                        peer_id: peer_id.clone(),
                        retry_at: Instant::now(),
                        retries: 0,
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
                });
            }
        }
        Ok(())
    }

    fn push_action(&self, action: SyncAction) {
        self.actions.lock().push(action);
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
        // 发送 ack 摘要给 peer
        self.push_action(SyncAction::SendControl {
            peer_id: peer_id.clone(),
            msg: ControlMsg::AckSummary(AckSummary {
                peer_id: self.config.peer_id.clone(),
                doc_id: DocId::new(""), // 由调用方填充
                ack_checkpoint: None,
                ack_frontier: summary.frontier,
                updated_at: SystemTime::now(),
            }),
            priority: Priority::Medium,
        });
        Ok(())
    }

    fn request_sync(&self, peer_id: PeerId, reason: SyncReason) -> CoreResult<()> {
        self.push_action(SyncAction::EmitEvent(tacit_core::CoreEvent::SyncStarted {
            peer_id: peer_id.clone(),
            reason,
        }));
        // 对所有已知 doc 执行 push/pull
        let conn = self.doc_store.store().conn();
        let docs = tacit_store::dao::list_docs(&conn)?;
        for doc in docs {
            self.run_push_pull(&peer_id, &doc.doc_id)?;
        }
        self.push_action(SyncAction::EmitEvent(tacit_core::CoreEvent::SyncCompleted {
            peer_id,
        }));
        Ok(())
    }

    fn fast_resume(&self) -> CoreResult<()> {
        // 从 store 恢复所有 doc 状态
        let conn = self.doc_store.store().conn();
        let docs = tacit_store::dao::list_docs(&conn)?;
        for doc in docs {
            // 打开 doc 触发恢复
            self.doc_store.open_doc(&doc.doc_id)?;
            // 列出 block，恢复 cache
            if let Ok(blocks) = self.doc_store.list_active_blocks(&doc.doc_id) {
                for block in blocks {
                    // 触发 block 加载（从 store 恢复到 cache）
                    let _ = self.doc_store.get_block(&doc.doc_id, &block.block_id);
                }
            }
        }
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
        engine.fast_resume().unwrap();
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
            peer_id: pid(2),
            retry_at: now,
            retries: 0,
        });
        // 处理到期条目
        engine.process_pending(now).unwrap();
        // 应该产生 RequestDelta 动作并重新入队
        let actions = engine.drain_actions();
        assert!(actions.iter().any(|a| matches!(a, SyncAction::RequestDelta { .. })));
        assert_eq!(engine.pending_queue().len(), 1);
    }
}
