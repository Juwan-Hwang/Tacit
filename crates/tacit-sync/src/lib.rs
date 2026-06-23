//! Tacit-sync：同步调度引擎。
//!
//! 职责：
//! - 处理 push/pull 会话。
//! - 维护 block 级 expected_frontier 依赖等待。
//! - 调度 Meta-Document 优先同步。
//! - 处理 stale peer、手术式重入、恢复流程。
//!
//! Phase 0 占位：实际实现见后续 commit。
