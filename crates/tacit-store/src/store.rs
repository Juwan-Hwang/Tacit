//! Tacit-store：SQLite 持久化层。
//!
//! 采用单连接 + Mutex 模型，开启 WAL。所有 DAO 通过 [`Store::conn`]
//! 获取连接后操作。快照安装通过事务保证原子性。

use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::Connection;
use tacit_core::CoreResult;

/// SQLite 持久化存储。
#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

struct Inner {
    conn: Mutex<Connection>,
}

impl Store {
    /// 打开数据库并初始化 schema。
    pub fn open(path: &str) -> CoreResult<Self> {
        let conn = Connection::open(path)
            .map_err(|e| tacit_core::CoreError::Store(format!("打开数据库失败: {e}")))?;
        // 开启 WAL 与外键约束，提升并发与数据完整性。
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| tacit_core::CoreError::Store(format!("设置 PRAGMA 失败: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| tacit_core::CoreError::Store(format!("建表失败: {e}")))?;
        Ok(Self {
            inner: Arc::new(Inner {
                conn: Mutex::new(conn),
            }),
        })
    }

    /// 内存数据库（用于测试）。
    pub fn open_memory() -> CoreResult<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| tacit_core::CoreError::Store(format!("打开内存数据库失败: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| tacit_core::CoreError::Store(format!("建表失败: {e}")))?;
        Ok(Self {
            inner: Arc::new(Inner {
                conn: Mutex::new(conn),
            }),
        })
    }

    /// 获取连接锁。所有 DAO 操作通过此方法获取连接。
    pub fn conn(&self) -> parking_lot::MutexGuard<'_, Connection> {
        self.inner.conn.lock()
    }

    /// 在事务中执行操作。
    pub fn transaction<F, T>(&self, f: F) -> CoreResult<T>
    where
        F: FnOnce(&Connection) -> CoreResult<T>,
    {
        let conn = self.conn();
        conn.execute_batch("BEGIN")
            .map_err(|e| tacit_core::CoreError::Store(format!("BEGIN 失败: {e}")))?;
        match f(&conn) {
            Ok(v) => {
                conn.execute_batch("COMMIT")
                    .map_err(|e| tacit_core::CoreError::Store(format!("COMMIT 失败: {e}")))?;
                Ok(v)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }
}

/// 建表 SQL。对应蓝图 7.1 推荐表结构。
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS documents (
    doc_id            TEXT PRIMARY KEY,
    kind              TEXT NOT NULL,
    current_frontier  TEXT NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS document_snapshots (
    doc_id        TEXT NOT NULL,
    snapshot_id   TEXT NOT NULL,
    snapshot_blob BLOB NOT NULL,
    snapshot_kind TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (doc_id, snapshot_id)
);

CREATE TABLE IF NOT EXISTS sync_log (
    entry_id           TEXT PRIMARY KEY,
    doc_id             TEXT NOT NULL,
    delta_id           TEXT NOT NULL,
    recipient_peer_id  TEXT NOT NULL,
    delivered_at       INTEGER,
    acknowledged_at    INTEGER,
    channel            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoint_log (
    doc_id                 TEXT NOT NULL,
    checkpoint_id          TEXT NOT NULL,
    shallow_snapshot_blob BLOB NOT NULL,
    frontier               TEXT NOT NULL,
    state_hash             BLOB NOT NULL,
    created_at             INTEGER NOT NULL,
    PRIMARY KEY (doc_id, checkpoint_id)
);

CREATE TABLE IF NOT EXISTS peers (
    peer_id          TEXT PRIMARY KEY,
    device_pubkey    TEXT NOT NULL,
    capabilities     TEXT NOT NULL,
    trust_state      TEXT NOT NULL,
    anchor_priority  INTEGER NOT NULL,
    last_seen_at     INTEGER NOT NULL,
    last_endpoint    TEXT,
    nat_capability   TEXT NOT NULL,
    relay_hint       TEXT
);

CREATE TABLE IF NOT EXISTS acks (
    peer_id        TEXT NOT NULL,
    doc_id         TEXT NOT NULL,
    ack_checkpoint TEXT,
    ack_frontier   TEXT NOT NULL,
    updated_at     INTEGER NOT NULL,
    PRIMARY KEY (peer_id, doc_id)
);

CREATE TABLE IF NOT EXISTS block_sync_state (
    doc_id            TEXT NOT NULL,
    block_id          TEXT NOT NULL,
    peer_id           TEXT NOT NULL,
    expected_frontier TEXT NOT NULL,
    observed_frontier TEXT NOT NULL,
    retry_after_ms    INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    PRIMARY KEY (doc_id, block_id, peer_id)
);

CREATE TABLE IF NOT EXISTS transport_stats (
    peer_id       TEXT NOT NULL,
    channel       TEXT NOT NULL,
    success_ema   REAL NOT NULL,
    avg_latency_ms INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    PRIMARY KEY (peer_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_doc ON document_snapshots(doc_id, created_at);
CREATE INDEX IF NOT EXISTS idx_checkpoint_doc ON checkpoint_log(doc_id, created_at);
CREATE INDEX IF NOT EXISTS idx_acks_doc ON acks(doc_id);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao;
    use tacit_core::{
        AnchorCapabilities, Frontier, NatCapability, PeerId, SnapshotKind, TrustState,
    };
    use std::time::SystemTime;

    fn pid(s: &str) -> PeerId {
        PeerId(s.into())
    }

    #[test]
    fn doc_crud() {
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let rec = dao::DocRecord {
            doc_id: tacit_core::DocId::new("d1"),
            kind: "note".into(),
            current_frontier: Frontier::from_iter([(pid("1"), 5)]),
            updated_at: SystemTime::now(),
        };
        dao::upsert_doc(&conn, &rec).unwrap();
        let got = dao::get_doc(&conn, &tacit_core::DocId::new("d1")).unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().kind, "note");
        let docs = dao::list_docs(&conn).unwrap();
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn peer_and_anchor() {
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let peer = tacit_core::PeerRecord {
            peer_id: pid("1"),
            device_pubkey: "pk1".into(),
            capabilities: AnchorCapabilities {
                can_anchor: true,
                can_relay: false,
                persistent: true,
            },
            trust_state: TrustState::Trusted,
            anchor_priority: 10,
            last_seen_at: SystemTime::now(),
            last_endpoint: Some(tacit_core::Endpoint::new("127.0.0.1", 8080)),
            nat_capability: NatCapability::Direct,
            relay_hint: None,
        };
        dao::upsert_peer(&conn, &peer).unwrap();
        let got = dao::get_peer(&conn, &pid("1")).unwrap().unwrap();
        assert_eq!(got.device_pubkey, "pk1");
        assert!(got.capabilities.can_anchor);
        let anchor = dao::best_anchor(&conn).unwrap();
        assert_eq!(anchor, Some(pid("1")));
    }

    #[test]
    fn snapshot_and_checkpoint() {
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let doc = tacit_core::DocId::new("d1");
        let cp = tacit_core::CheckpointId::new("cp1");
        dao::insert_snapshot(&conn, &doc, &cp, b"snap-bytes", SnapshotKind::Shallow, SystemTime::now())
            .unwrap();
        let snap = dao::get_latest_snapshot(&conn, &doc).unwrap().unwrap();
        assert_eq!(snap.1, b"snap-bytes");

        let cp_rec = dao::CheckpointRecord {
            doc_id: doc.clone(),
            checkpoint_id: cp.clone(),
            shallow_snapshot_blob: b"shallow".to_vec(),
            frontier: Frontier::from_iter([(pid("1"), 3)]),
            state_hash: [0u8; 32],
            created_at: SystemTime::now(),
        };
        dao::insert_checkpoint(&conn, &cp_rec).unwrap();
        let got = dao::get_latest_checkpoint(&conn, &doc).unwrap().unwrap();
        assert_eq!(got.shallow_snapshot_blob, b"shallow");
    }

    #[test]
    fn transaction_rollback() {
        let store = Store::open_memory().unwrap();
        let result: CoreResult<()> = store.transaction(|conn| {
            dao::upsert_doc(
                conn,
                &dao::DocRecord {
                    doc_id: tacit_core::DocId::new("d1"),
                    kind: "note".into(),
                    current_frontier: Frontier::new(),
                    updated_at: SystemTime::now(),
                },
            )?;
            Err(tacit_core::CoreError::Internal("模拟失败".into()))
        });
        assert!(result.is_err());
        // 回滚后不应存在
        let conn = store.conn();
        let got = dao::get_doc(&conn, &tacit_core::DocId::new("d1")).unwrap();
        assert!(got.is_none());
    }
}
