//! Tacit-store：SQLite 持久化层。
//!
//! 职责：
//! - 单连接 + Mutex 模型，开启 WAL。
//! - 提供 peer/ack/snapshot/checkpoint/block_sync_state/transport_stats 等 DAO。
//! - 快照安装通过事务保证原子性（双缓冲由调用方配合临时行 + 原子切换实现）。

pub mod dao;
pub mod store;

pub use dao::{
    best_anchor, get_ack, get_doc, get_latest_checkpoint, get_latest_snapshot, get_peer,
    insert_checkpoint, insert_snapshot, list_docs, list_peers, list_pending_blocks,
    upsert_ack, upsert_block_sync_state, upsert_doc, upsert_peer, upsert_transport_stats,
    BlockSyncStateRecord, CheckpointRecord, DocRecord, TransportStatsRecord,
};
pub use store::Store;
