//! 恢复编排：stale peer 恢复、手术式重入、首屏恢复策略。
//!
//! v1.0 规范第 8 节 stale peer 追赶与第 11 节首屏恢复策略。
//!
//! ## stale peer 恢复
//! 当检测到 peer 的 frontier 落在 shallow snapshot 剪裁点之前（即 peer 已"过期"），
//! 不能仅靠增量 delta 追赶，需要：
//! 1. 进入恢复模式
//! 2. 安装 shallow snapshot（重建基线）
//! 3. 导入 tail delta（追赶 snapshot 之后的增量）
//! 4. 若仍有旧改动未合并，走手术式重入
//!
//! ## 手术式重入
//! 当 peer 的本地修改与 shallow snapshot 冲突时：
//! 1. 备份旧本地状态
//! 2. 拉取最新 shallow snapshot 重建
//! 3. 将旧 block 修改重新映射到新基线上
//!
//! ## 首屏恢复策略
//! fast-resume 时按优先级恢复文档：
//! 1. Meta-Document 骨架（必须最先，提供 block 列表）
//! 2. 可见 block（视口内的 block）
//! 3. 活跃文档剩余 block
//! 4. 冷文档追赶（后台低优先级）

use std::sync::Arc;

use tacit_core::{
    BlockId, CoreResult, DocId, Frontier, FrontierOps, PeerId, Priority,
};
use tracing::{debug, info, warn};

use crate::doc_store::DocStore;
use crate::engine::{DefaultSyncEngine, SyncAction};

/// stale peer 恢复阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStage {
    /// 检测 peer 是否 stale。
    Detect,
    /// 安装 shallow snapshot 重建基线。
    InstallSnapshot,
    /// 导入 tail delta 追赶增量。
    ImportTailDelta,
    /// 手术式重入：重新映射旧本地修改。
    SurgicalReentry,
    /// 恢复完成。
    Done,
}

/// stale peer 恢复状态。
#[derive(Debug, Clone)]
pub struct RecoveryState {
    pub peer_id: PeerId,
    pub doc_id: DocId,
    pub stage: RecoveryStage,
    /// peer 报告的旧 frontier（落在剪裁点之前）。
    pub stale_frontier: Frontier,
    /// 本地 shallow snapshot 的 frontier（恢复基线）。
    pub baseline_frontier: Frontier,
    /// 备份的旧本地状态（手术式重入用）。
    pub backup: Option<Vec<u8>>,
}

/// 首屏恢复阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstScreenStage {
    /// 恢复 Meta-Document 骨架。
    MetaSkeleton,
    /// 恢复可见 block（视口内）。
    VisibleBlocks,
    /// 恢复活跃文档剩余 block。
    ActiveDocRemaining,
    /// 冷文档追赶（后台）。
    ColdDocCatchup,
    /// 完成。
    Done,
}

/// 恢复编排器：协调 stale peer 恢复与首屏恢复。
pub struct RecoveryCoordinator {
    doc_store: Arc<DocStore>,
}

impl RecoveryCoordinator {
    pub fn new(doc_store: Arc<DocStore>) -> Self {
        Self { doc_store }
    }

    /// 检测 peer 是否 stale：peer frontier 是否落在本地 shallow snapshot 剪裁点之前。
    ///
    /// 简化判定：若 peer frontier 为空或本地 meta frontier 不覆盖 peer frontier，
    /// 则认为 peer stale。
    pub fn is_peer_stale(
        &self,
        doc_id: &DocId,
        peer_frontier: &Frontier,
    ) -> CoreResult<bool> {
        if peer_frontier.is_empty() {
            // 空 frontier 视为全新 peer，需要完整恢复
            return Ok(true);
        }
        let local_meta = self.doc_store.meta_frontier(doc_id)?;
        // 若本地 meta 不覆盖 peer frontier，说明 peer 有本地没有的旧数据
        // 但更准确的判定应基于 shallow snapshot 的剪裁点
        // 这里简化：若 peer 的任意 seq 比本地小，则可能 stale
        Ok(!local_meta.covers(peer_frontier))
    }

    /// 执行 stale peer 恢复流程。
    ///
    /// 返回产生的 SyncAction 列表（供上层执行传输）。
    pub fn recover_stale_peer(
        &self,
        engine: &DefaultSyncEngine,
        peer_id: &PeerId,
        doc_id: &DocId,
        stale_frontier: &Frontier,
    ) -> CoreResult<RecoveryState> {
        let mut state = RecoveryState {
            peer_id: peer_id.clone(),
            doc_id: doc_id.clone(),
            stage: RecoveryStage::Detect,
            stale_frontier: stale_frontier.clone(),
            baseline_frontier: Frontier::new(),
            backup: None,
        };

        info!(
            peer_id = %peer_id,
            doc_id = %doc_id,
            "开始 stale peer 恢复"
        );

        // 1. 安装 shallow snapshot：导出本地 shallow snapshot 推送给 peer
        state.stage = RecoveryStage::InstallSnapshot;
        let baseline = self.doc_store.meta_frontier(doc_id)?;
        state.baseline_frontier = baseline.clone();

        let blocks = self.doc_store.list_active_blocks(doc_id)?;
        for block in &blocks {
            let shallow = self.doc_store.export_block_shallow(
                doc_id,
                &block.block_id,
                &baseline,
            )?;
            engine.push_action(SyncAction::SendData {
                peer_id: peer_id.clone(),
                doc_id: doc_id.clone(),
                block_id: Some(block.block_id.clone()),
                bytes: shallow,
                priority: Priority::High,
                path: tacit_transport::PathPreference::Any,
            });
        }

        // 2. 导入 tail delta：请求 peer 发送 stale_frontier 之后的增量
        state.stage = RecoveryStage::ImportTailDelta;
        for block in &blocks {
            engine.push_action(SyncAction::RequestDelta {
                peer_id: peer_id.clone(),
                doc_id: doc_id.clone(),
                block_id: Some(block.block_id.clone()),
                since: stale_frontier.clone(),
            });
        }

        // 3. 手术式重入阶段：此阶段在 peer 侧执行。
        // anchor 已发送 shallow snapshot 并请求 tail delta，
        // peer 收到后会自行检测冲突并执行 surgical_reentry。
        // anchor 侧无需额外动作，标记阶段后进入 Done。
        state.stage = RecoveryStage::SurgicalReentry;
        debug!(
            peer_id = %peer_id,
            doc_id = %doc_id,
            "已发送 shallow snapshot 并请求 tail delta，等待 peer 侧完成手术式重入"
        );

        state.stage = RecoveryStage::Done;
        Ok(state)
    }

    /// 手术式重入：备份旧本地状态 → 提取本地增量 → 拉取最新 shallow snapshot 重建 → 重新应用本地增量。
    ///
    /// 当 peer 发来的 delta 与本地状态冲突时调用。
    /// `stale_frontier`：本地最后一次与远端同步的 frontier，用于提取本地独有增量。
    pub fn surgical_reentry(
        &self,
        doc_id: &DocId,
        block_id: &BlockId,
        remote_snapshot: &[u8],
        stale_frontier: &Frontier,
    ) -> CoreResult<Vec<u8>> {
        info!(
            doc_id = %doc_id,
            block_id = %block_id,
            "执行手术式重入"
        );

        // 1. 备份旧本地状态
        let backup = self.doc_store.export_block_snapshot(doc_id, block_id)?;
        warn!(
            doc_id = %doc_id,
            block_id = %block_id,
            backup_size = backup.len(),
            "已备份旧本地状态"
        );

        // 2. 提取本地自 stale_frontier 以来的独有增量（local-only delta）
        let local_delta = self.doc_store.export_block_delta(doc_id, block_id, stale_frontier)?;

        // 3. 用远端 shallow snapshot 重建本地 block（CRDT import 会合并而非覆盖）
        self.doc_store.import_block(doc_id, block_id, remote_snapshot)?;

        // 4. 将本地独有增量重新应用到新基线（CRDT 合并语义自动处理冲突）
        if !local_delta.is_empty() {
            debug!(
                doc_id = %doc_id,
                block_id = %block_id,
                local_delta_size = local_delta.len(),
                "重新应用本地增量到新基线"
            );
            self.doc_store.import_block(doc_id, block_id, &local_delta)?;
        }

        // 5. 返回备份供审计/回滚
        Ok(backup)
    }

    /// 首屏恢复策略：按优先级恢复文档状态。
    ///
    /// 返回恢复阶段序列，上层按顺序执行。
    pub fn first_screen_recovery(
        &self,
        engine: &DefaultSyncEngine,
        viewport: Option<tacit_core::Viewport>,
    ) -> CoreResult<Vec<FirstScreenStage>> {
        let mut stages = Vec::new();

        // 1. Meta-Document 骨架
        stages.push(FirstScreenStage::MetaSkeleton);
        let conn = self.doc_store.store().conn();
        let docs = tacit_store::dao::list_docs(&conn)?;
        drop(conn);

        for doc in &docs {
            // 打开 doc 触发 MetaDoc 恢复
            self.doc_store.open_doc(&doc.doc_id)?;
            engine.push_action(SyncAction::EmitEvent(
                tacit_core::CoreEvent::SyncProgress {
                    doc_id: doc.doc_id.clone(),
                    stage: tacit_core::SyncStage::MetaDoc,
                    progress: 0.1,
                },
            ));
        }

        // 2. 可见 block（视口内）
        stages.push(FirstScreenStage::VisibleBlocks);
        if let Some(vp) = viewport {
            for doc in &docs {
                let blocks = self.doc_store.list_active_blocks(&doc.doc_id)?;
                let visible: Vec<_> = blocks
                    .into_iter()
                    .skip(vp.start_block)
                    .take(vp.block_count)
                    .collect();
                for block in visible {
                    // 触发 block 加载
                    let _ = self.doc_store.get_block(&doc.doc_id, &block.block_id);
                }
                engine.push_action(SyncAction::EmitEvent(
                    tacit_core::CoreEvent::SyncProgress {
                        doc_id: doc.doc_id.clone(),
                        stage: tacit_core::SyncStage::PullBlocks,
                        progress: 0.5,
                    },
                ));
            }
        } else {
            // 无视口信息，加载所有活跃 block
            for doc in &docs {
                let blocks = self.doc_store.list_active_blocks(&doc.doc_id)?;
                for block in blocks {
                    let _ = self.doc_store.get_block(&doc.doc_id, &block.block_id);
                }
            }
        }

        // 3. 活跃文档剩余 block（已在视口加载之外）
        stages.push(FirstScreenStage::ActiveDocRemaining);
        for doc in &docs {
            let blocks = self.doc_store.list_active_blocks(&doc.doc_id)?;
            for block in blocks {
                let _ = self.doc_store.get_block(&doc.doc_id, &block.block_id);
            }
            engine.push_action(SyncAction::EmitEvent(
                tacit_core::CoreEvent::SyncProgress {
                    doc_id: doc.doc_id.clone(),
                    stage: tacit_core::SyncStage::PullBlocks,
                    progress: 0.8,
                },
            ));
        }

        // 4. 冷文档追赶（后台低优先级）
        stages.push(FirstScreenStage::ColdDocCatchup);
        // 冷文档追赶通过定期 sync 触发，这里仅标记阶段

        stages.push(FirstScreenStage::Done);
        for doc in &docs {
            engine.push_action(SyncAction::EmitEvent(
                tacit_core::CoreEvent::SyncProgress {
                    doc_id: doc.doc_id.clone(),
                    stage: tacit_core::SyncStage::Done,
                    progress: 1.0,
                },
            ));
        }

        debug!(docs = docs.len(), "首屏恢复完成");
        Ok(stages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use tacit_store::Store;

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    fn make_env() -> (RecoveryCoordinator, DefaultSyncEngine, Arc<DocStore>) {
        let store = Store::open_memory().unwrap();
        let doc_store = Arc::new(DocStore::new(pid(1), store, 32));
        let _ = doc_store.create_doc(DocId::new("d1"), "note").unwrap();
        let engine = DefaultSyncEngine::new(
            doc_store.clone(),
            EngineConfig {
                peer_id: pid(1),
                ..Default::default()
            },
        );
        let coord = RecoveryCoordinator::new(doc_store.clone());
        (coord, engine, doc_store)
    }

    #[test]
    fn empty_frontier_is_stale() {
        let (coord, _, _) = make_env();
        let stale = coord
            .is_peer_stale(&DocId::new("d1"), &Frontier::new())
            .unwrap();
        assert!(stale);
    }

    #[test]
    fn recover_stale_peer_generates_actions() {
        let (coord, engine, doc_store) = make_env();
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

        let state = coord
            .recover_stale_peer(
                &engine,
                &pid(2),
                &DocId::new("d1"),
                &Frontier::new(),
            )
            .unwrap();

        assert_eq!(state.stage, RecoveryStage::Done);
        let actions = engine.drain_actions();
        // 应有 SendData（shallow snapshot）和 RequestDelta（tail delta）
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, SyncAction::SendData { .. }))
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, SyncAction::RequestDelta { .. }))
        );
    }

    #[test]
    fn first_screen_recovery_progresses() {
        let (coord, engine, doc_store) = make_env();
        doc_store
            .create_block(
                &DocId::new("d1"),
                BlockId::new("b1"),
                tacit_core::BlockKind::Text,
            )
            .unwrap();

        let stages = coord
            .first_screen_recovery(&engine, None)
            .unwrap();

        assert_eq!(stages.len(), 5);
        assert_eq!(stages[0], FirstScreenStage::MetaSkeleton);
        assert_eq!(stages.last(), Some(&FirstScreenStage::Done));

        let actions = engine.drain_actions();
        // 应有 SyncProgress 事件
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, SyncAction::EmitEvent(_)))
        );
    }

    #[test]
    fn surgical_reentry_backups_and_restores() {
        let (coord, _engine, doc_store) = make_env();
        let block_id = BlockId::new("b1");
        doc_store
            .create_block(&DocId::new("d1"), block_id.clone(), tacit_core::BlockKind::Text)
            .unwrap();
        doc_store
            .apply_local_edit(&DocId::new("d1"), &block_id, b"old data")
            .unwrap();

        // 获取当前 block frontier 作为 stale_frontier（模拟最后一次同步点）
        let stale_frontier = doc_store
            .block_frontier(&DocId::new("d1"), &block_id)
            .unwrap();

        // 模拟远端 snapshot
        let remote_snap = doc_store
            .export_block_snapshot(&DocId::new("d1"), &block_id)
            .unwrap();

        let backup = coord
            .surgical_reentry(&DocId::new("d1"), &block_id, &remote_snap, &stale_frontier)
            .unwrap();
        assert!(!backup.is_empty());
    }
}
