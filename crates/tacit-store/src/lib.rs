//! Tacit-store：SQLite 持久化层。
//!
//! 职责：
//! - 单连接 + Mutex 模型，开启 WAL。
//! - 提供 peer/ack/snapshot/checkpoint/block_sync_state/transport_stats 等 DAO。
//! - 快照安装通过事务保证原子性（双缓冲由调用方配合临时行 + 原子切换实现）。

pub mod dao;
pub mod store;

pub use dao::{
    best_anchor, cleanup_acknowledged, delete_checkpoint, delete_old_snapshots, delete_snapshot,
    get_ack, get_doc, get_latest_checkpoint, get_latest_snapshot, get_peer, get_snapshot,
    get_transport_stats, insert_checkpoint, insert_snapshot, insert_sync_log, list_acks_by_doc,
    list_checkpoints_by_doc, list_docs, list_peers, list_pending_blocks, list_relay_candidates,
    list_transport_stats, list_unacknowledged, list_undelivered, mark_acknowledged, mark_delivered,
    mark_peer_seen, revoke_peer, update_transport_ema, upsert_ack, upsert_block_sync_state,
    upsert_doc, upsert_peer, upsert_transport_stats, BlockSyncStateRecord, CheckpointRecord,
    DocRecord, SyncLogRecord, TransportStatsRecord,
};
pub use store::{Store, TxnExecutor};
