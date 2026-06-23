//! Tacit-store：SQLite 持久化层。
//!
//! 职责：
//! - 单连接 + 专用线程模型，开启 WAL。
//! - 提供 PeerDao/AckDao/SnapshotDao/BlockSyncStateDao/TransportStatsDao/TxnExecutor。
//! - 快照安装通过事务或双缓冲原子替换。
//!
//! Phase 0 占位：实际实现见后续 commit。
