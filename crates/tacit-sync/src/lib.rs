//! Tacit-sync：同步调度引擎。
//!
//! 职责：
//! - 处理 push/pull 会话。
//! - 维护 block 级 expected_frontier 依赖等待。
//! - 调度 Meta-Document 优先同步。
//! - 处理 stale peer、手术式重入、恢复流程。
//! - 双水位 GC 计算。
//! - peer 管理业务语义（PeerRegistry）。
//! - checkpoint 压缩与分片（CheckpointManager）。
//! - 优先级队列（PriorityQueue）。
//! - Hot-Path Control（Apple 设备短暂唤醒）。
//! - telemetry 采集集成。
//!
//! 模块：
//! - [`doc_store`]：文档状态管理（MetaDoc + BlockDocCache + 持久化协调）
//! - [`pending`]：依赖等待队列
//! - [`watermarks`]：双水位计算
//! - [`engine`]：SyncEngine 实现
//! - [`peer_registry`]：peer 管理注册表
//! - [`checkpoint`]：checkpoint 压缩与分片管理
//! - [`priority_queue`]：按 Priority 排序的 SyncAction 队列
//! - [`hot_path`]：Hot-Path Control
//! - [`recovery`]：stale peer 恢复、手术式重入、首屏恢复

pub mod checkpoint;
pub mod doc_store;
pub mod engine;
pub mod hot_path;
pub mod peer_registry;
pub mod pending;
pub mod priority_queue;
pub mod recovery;
pub mod watermarks;

pub use checkpoint::CheckpointManager;
pub use doc_store::DocStore;
pub use engine::{DefaultSyncEngine, EngineConfig, SyncAction, SyncEngine};
pub use hot_path::{HotPathConfig, HotPathController, HotPathMode};
pub use peer_registry::PeerRegistry;
pub use pending::{BackoffPhase, PendingBlockFetch, PendingFetchQueue};
pub use priority_queue::PriorityQueue;
pub use recovery::{
    FirstScreenStage, RecoveryCoordinator, RecoveryStage, RecoveryState,
};
pub use watermarks::WatermarkCalculator;
