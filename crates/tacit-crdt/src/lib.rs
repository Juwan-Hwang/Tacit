//! Tacit-crdt：Loro 封装与文档模型。
//!
//! 职责：
//! - 封装 Loro，隔离上游 API 变化。
//! - 提供 Meta-Document 管理 block 列表、顺序、软删除。
//! - 每个 block 一个独立 Loro 实例（BlockDoc），惰性加载。
//! - 提供 Frontier/Diff/Snapshot 接口。
//! - 内部维护 BlockDocCache（LRU）。
//!
//! Phase 0 占位：实际实现见后续 commit。
