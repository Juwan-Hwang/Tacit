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
//!
//! 模块：
//! - [`doc_store`]：文档状态管理（MetaDoc + BlockDocCache + 持久化协调）
//! - [`pending`]：依赖等待队列
//! - [`watermarks`]：双水位计算
//! - [`engine`]：SyncEngine 实现
//! - [`peer_registry`]：peer 管理注册表
//! - [`checkpoint`]：checkpoint 压缩与分片管理

pub mod checkpoint;
pub mod doc_store;
pub mod engine;
pub mod peer_registry;
pub mod pending;
pub mod watermarks;

pub use checkpoint::CheckpointManager;
pub use doc_store::DocStore;
pub use engine::{DefaultSyncEngine, EngineConfig, SyncAction, SyncEngine};
pub use peer_registry::PeerRegistry;
pub use pending::{PendingBlockFetch, PendingFetchQueue};
pub use watermarks::WatermarkCalculator;
