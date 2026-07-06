//! Tacit-store：SQLite 持久化层。
//!
//! 采用单连接 + Mutex 模型，开启 WAL。所有 DAO 通过 [`Store::conn`]
//! 获取连接后操作。快照安装通过事务保证原子性。

use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::Mutex;
use rusqlite::Connection;
use tacit_core::{CheckpointId, CoreError, CoreResult, DocId, Frontier, SnapshotKind};

use crate::dao;
use sha2::Digest;

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
        // busy_timeout=5000 避免多进程访问时立即报 locked。
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| tacit_core::CoreError::Store(format!("设置 PRAGMA 失败: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| tacit_core::CoreError::Store(format!("建表失败: {e}")))?;
        run_migrations(&conn)?;
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
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| tacit_core::CoreError::Store(format!("设置 PRAGMA 失败: {e}")))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| tacit_core::CoreError::Store(format!("建表失败: {e}")))?;
        run_migrations(&conn)?;
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
    ///
    /// # 警告：死锁风险
    /// `parking_lot::Mutex` 不可重入。**禁止**在已通过 [`conn`](Self::conn) 持有锁时
    /// 调用本方法，否则会死锁。如需在已持有锁时执行事务，请使用
    /// [`transaction_with_conn`](Self::transaction_with_conn)。
    ///
    /// 本方法使用 `try_lock` 检测重入：如果锁已被占用（可能是当前线程已持有），
    /// 立即返回错误而非阻塞，从而避免死锁。
    pub fn transaction<F, T>(&self, f: F) -> CoreResult<T>
    where
        F: FnOnce(&Connection) -> CoreResult<T>,
    {
        // 死锁检测：parking_lot::Mutex 不可重入。
        // try_lock 在锁已被占用时（含当前线程重入）返回 None，借此提前失败而非死锁。
        let conn = self.inner.conn.try_lock().ok_or_else(|| {
            CoreError::Store(
                "transaction() 锁已被占用：可能当前线程已持有 conn() 锁（会死锁）。请改用 transaction_with_conn()".into(),
            )
        })?;
        conn.execute_batch("BEGIN")
            .map_err(|e| CoreError::Store(format!("BEGIN 失败: {e}")))?;
        match f(&conn) {
            Ok(v) => {
                conn.execute_batch("COMMIT")
                    .map_err(|e| CoreError::Store(format!("COMMIT 失败: {e}")))?;
                Ok(v)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// 在外部传入的连接上执行事务。
    ///
    /// 适用于调用方已通过 [`conn`](Self::conn) 持有锁的场景，避免
    /// [`transaction`](Self::transaction) 的重入死锁。调用方负责锁的生命周期。
    ///
    /// # 参数
    /// - `conn`: 外部持有的连接引用（调用方负责锁的生命周期）
    /// - `f`: 事务体，接收同一连接引用
    ///
    /// # 示例
    /// ```ignore
    /// let conn = store.conn();
    /// store.transaction_with_conn(&conn, |conn| {
    ///     dao::upsert_doc(conn, &rec)?;
    ///     Ok(())
    /// })?;
    /// ```
    pub fn transaction_with_conn<F, T>(&self, conn: &Connection, f: F) -> CoreResult<T>
    where
        F: FnOnce(&Connection) -> CoreResult<T>,
    {
        conn.execute_batch("BEGIN")
            .map_err(|e| CoreError::Store(format!("BEGIN 失败: {e}")))?;
        match f(conn) {
            Ok(v) => {
                conn.execute_batch("COMMIT")
                    .map_err(|e| CoreError::Store(format!("COMMIT 失败: {e}")))?;
                Ok(v)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// 原子安装快照（双缓冲便捷方法）。
    ///
    /// 封装蓝图要求的双缓冲 4 步流程，保证快照安装的原子性与崩溃安全性：
    /// 1. 在事务中写入临时 snapshot（snapshot_id 带 `__pending_` 前缀）
    /// 2. 校验 snapshot 内容的 SHA256 与 state_hash 字节一致
    /// 3. 原子切换：更新 `documents.current_frontier` + 删除旧的 pending snapshot
    /// 4. 提交事务
    ///
    /// 使用现有的 dao 函数（[`dao::insert_snapshot`], [`dao::upsert_doc`], [`dao::delete_snapshot`]）。
    ///
    /// # 参数
    /// - `doc_id`: 文档 ID
    /// - `snapshot`: 快照二进制内容（不能为空）
    /// - `state_hash`: 状态哈希（32 字节 SHA256，同时用作 pending snapshot_id 的唯一后缀）
    /// - `frontier`: 新的版本向量，写入 `documents.current_frontier`
    /// - `snapshot_kind`: 快照类型字符串（`"Full"` 或 `"Shallow"`，其他值按 `Full` 处理）
    pub fn install_snapshot_atomically(
        &self,
        doc_id: &str,
        snapshot: &[u8],
        state_hash: &str,
        frontier: &Frontier,
        snapshot_kind: &str,
    ) -> CoreResult<()> {
        // 前置校验：snapshot 不能为空
        if snapshot.is_empty() {
            return Err(CoreError::Store(
                "install_snapshot_atomically: snapshot 不能为空".into(),
            ));
        }

        let doc_id = DocId::new(doc_id);
        // 解析 snapshot_kind 字符串为枚举
        let kind = match snapshot_kind {
            "Shallow" | "shallow" => SnapshotKind::Shallow,
            _ => SnapshotKind::Full,
        };
        let hash_hex = if state_hash.is_empty() {
            hex::encode(sha2::Sha256::digest(snapshot))
        } else {
            state_hash.to_string()
        };
        // 临时 snapshot_id 带 __pending_ 前缀，用于双缓冲标记
        let pending_id = CheckpointId::new(format!("__pending_{}", hash_hex));
        let now = SystemTime::now();

        // 获取连接锁，通过 transaction_with_conn 执行事务（避免 transaction 重入检测）
        let conn = self.conn();
        let result = self.transaction_with_conn(&conn, |conn| {
            // 1. 查找旧 pending snapshot
            let old_pending = dao::get_latest_snapshot(conn, &doc_id)?
                .map(|(id, _, _, _)| id)
                .filter(|id| id.as_str().starts_with("__pending_"));

            // 2. 写入临时 pending snapshot
            dao::insert_snapshot(conn, &doc_id, &pending_id, snapshot, kind, now)?;

            // 3. 校验 snapshot 内容完整性：计算 SHA256 并与 state_hash 比对
            let stored = dao::get_snapshot(conn, &doc_id, &pending_id)?;
            let blob_ok = stored
                .as_ref()
                .map(|(blob, _, _)| blob.as_slice() == snapshot)
                .unwrap_or(false);
            let hash_ok = if state_hash.is_empty() {
                true
            } else {
                let computed_hash = {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(snapshot);
                    let result = hasher.finalize();
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&result);
                    hash
                };
                let expected_hash: Option<[u8; 32]> = hex::decode(state_hash)
                    .ok()
                    .filter(|v| v.len() == 32)
                    .map(|v| {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&v);
                        arr
                    });
                if let Some(expected) = expected_hash {
                    computed_hash == expected
                } else {
                    false
                }
            };
            if !blob_ok || !hash_ok {
                // 校验失败：删除临时 snapshot 并回滚（事务会自动回滚）
                let _ = dao::delete_snapshot(conn, &doc_id, &pending_id);
                return Err(CoreError::Store(format!(
                    "快照校验失败: blob_ok={}, hash_ok={}",
                    blob_ok, hash_ok
                )));
            }

            // 4. 原子切换：更新 documents.current_frontier + current_snapshot_id
            let existing = dao::get_doc(conn, &doc_id)?;
            let doc_kind = existing
                .as_ref()
                .map(|d| d.kind.clone())
                .unwrap_or_else(|| "note".to_string());
            let current_snapshot_id = Some(pending_id.as_str().to_string());
            dao::upsert_doc(
                conn,
                &dao::DocRecord {
                    doc_id: doc_id.clone(),
                    kind: doc_kind,
                    current_frontier: frontier.clone(),
                    current_snapshot_id,
                    updated_at: now,
                },
            )?;

            // 5. 删除旧 pending snapshot
            if let Some(old_id) = old_pending {
                dao::delete_snapshot(conn, &doc_id, &old_id)?;
            }

            Ok(())
        });

        // #40: 事务成功后强制 WAL checkpoint，确保 snapshot 持久化到磁盘。
        // WAL 模式下默认 synchronous=NORMAL，崩溃时可能丢最近的 WAL 帧。
        // 对 snapshot 这种关键操作，wal_checkpoint(FULL) 确保数据落盘。
        if result.is_ok() {
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(FULL)");
        }
        result
    }
}

/// 事务执行器：封装 Store::transaction，提供批量操作接口。
///
/// 蓝图第 255 行要求 TxnExecutor 组件。
/// 用于需要原子性的多步操作（如双缓冲快照安装、checkpoint + snapshot 联合写入）。
#[derive(Clone)]
pub struct TxnExecutor {
    store: Store,
}

impl TxnExecutor {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// 在事务中执行操作。
    ///
    /// 事务内所有操作要么全部成功，要么全部回滚。
    pub fn execute<F, T>(&self, f: F) -> CoreResult<T>
    where
        F: FnOnce(&Connection) -> CoreResult<T>,
    {
        self.store.transaction(f)
    }

    /// 批量写入：在单个事务中执行多个写入操作。
    pub fn batch_write<F>(&self, f: F) -> CoreResult<()>
    where
        F: FnOnce(&Connection) -> CoreResult<()>,
    {
        self.store.transaction(f)
    }

    /// 获取底层 Store 引用。
    pub fn store(&self) -> &Store {
        &self.store
    }
}

/// 执行增量迁移：为已有数据库补充新增列。
///
/// SQLite 的 `CREATE TABLE IF NOT EXISTS` 不会为已存在的表添加新列，
/// 因此需要通过 `ALTER TABLE ... ADD COLUMN` 补充。
/// 使用 `PRAGMA table_info` 检测列是否已存在，避免重复添加报错。
fn run_migrations(conn: &Connection) -> CoreResult<()> {
    // 迁移 1：acks 表添加 version_override 列
    let has_version_override: bool = conn
        .prepare("PRAGMA table_info(acks)")
        .map_err(|e| CoreError::Store(format!("PRAGMA table_info 失败: {e}")))?
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| CoreError::Store(format!("查询 table_info 失败: {e}")))?
        .filter_map(|r| r.ok())
        .any(|name| name == "version_override");

    if !has_version_override {
        conn.execute_batch("ALTER TABLE acks ADD COLUMN version_override INTEGER")
            .map_err(|e| CoreError::Store(format!("迁移 acks.version_override 失败: {e}")))?;
        tracing::info!("迁移完成：acks 表新增 version_override 列");
    }

    // 迁移 2：peers 表添加 rotation_seq 列
    let has_rotation_seq: bool = conn
        .prepare("PRAGMA table_info(peers)")
        .map_err(|e| CoreError::Store(format!("PRAGMA table_info 失败: {e}")))?
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| CoreError::Store(format!("查询 table_info 失败: {e}")))?
        .filter_map(|r| r.ok())
        .any(|name| name == "rotation_seq");

    if !has_rotation_seq {
        conn.execute_batch("ALTER TABLE peers ADD COLUMN rotation_seq INTEGER NOT NULL DEFAULT 0")
            .map_err(|e| CoreError::Store(format!("迁移 peers.rotation_seq 失败: {e}")))?;
        tracing::info!("迁移完成：peers 表新增 rotation_seq 列");
    }

    Ok(())
}

/// 建表 SQL。对应蓝图 7.1 推荐表结构。
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS documents (
    doc_id               TEXT PRIMARY KEY,
    kind                 TEXT NOT NULL,
    current_frontier     TEXT NOT NULL,
    current_snapshot_id  TEXT,
    updated_at           INTEGER NOT NULL
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
    relay_hint       TEXT,
    success_ema      REAL NOT NULL DEFAULT 1.0,
    rotation_seq     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS acks (
    peer_id          TEXT NOT NULL,
    doc_id           TEXT NOT NULL,
    ack_checkpoint   TEXT,
    ack_frontier     TEXT NOT NULL,
    updated_at       INTEGER NOT NULL,
    version_override INTEGER,
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
CREATE INDEX IF NOT EXISTS idx_transport_stats_peer ON transport_stats(peer_id, channel);
CREATE INDEX IF NOT EXISTS idx_sync_log_recipient ON sync_log(recipient_peer_id, delivered_at);
CREATE INDEX IF NOT EXISTS idx_sync_log_ack ON sync_log(acknowledged_at);

-- #4: 设备身份持久化表（单行表，id 固定为 'default'）
CREATE TABLE IF NOT EXISTS device_identity (
    id              TEXT PRIMARY KEY DEFAULT 'default',
    signing_key     BLOB NOT NULL,
    static_private  BLOB NOT NULL,
    static_public   BLOB NOT NULL,
    binding_proof   BLOB NOT NULL,
    created_at      INTEGER NOT NULL
);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao;
    use sha2::{Digest, Sha256};
    use std::time::SystemTime;
    use tacit_core::{
        AnchorCapabilities, Frontier, NatCapability, PeerId, SnapshotKind, TrustState,
    };

    fn pid(s: &str) -> PeerId {
        PeerId(s.into())
    }

    /// 计算内容的 SHA256 哈希。
    fn content_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        hex::encode(result)
    }

    #[test]
    fn doc_crud() {
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let rec = dao::DocRecord {
            doc_id: tacit_core::DocId::new("d1"),
            kind: "note".into(),
            current_frontier: Frontier::from_iter([(pid("1"), 5)]),
            current_snapshot_id: None,
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
            success_ema: 1.0,
            rotation_seq: 0,
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
        dao::insert_snapshot(
            &conn,
            &doc,
            &cp,
            b"snap-bytes",
            SnapshotKind::Shallow,
            SystemTime::now(),
        )
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
                    current_snapshot_id: None,
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

    #[test]
    fn transaction_with_conn_works() {
        // 验证 transaction_with_conn 能在外部持有锁时正常执行事务
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let r: CoreResult<()> = store.transaction_with_conn(&conn, |conn| {
            dao::upsert_doc(
                conn,
                &dao::DocRecord {
                    doc_id: tacit_core::DocId::new("d1"),
                    kind: "note".into(),
                    current_frontier: Frontier::new(),
                    current_snapshot_id: None,
                    updated_at: SystemTime::now(),
                },
            )?;
            Ok(())
        });
        assert!(r.is_ok());
        // 验证写入成功
        let got = dao::get_doc(&conn, &tacit_core::DocId::new("d1")).unwrap();
        assert!(got.is_some());
    }

    #[test]
    fn transaction_with_conn_rollback() {
        // 验证 transaction_with_conn 在失败时正确回滚
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let r: CoreResult<()> = store.transaction_with_conn(&conn, |conn| {
            dao::upsert_doc(
                conn,
                &dao::DocRecord {
                    doc_id: tacit_core::DocId::new("d1"),
                    kind: "note".into(),
                    current_frontier: Frontier::new(),
                    current_snapshot_id: None,
                    updated_at: SystemTime::now(),
                },
            )?;
            Err(tacit_core::CoreError::Internal("模拟失败".into()))
        });
        assert!(r.is_err());
        // 回滚后不应存在
        let got = dao::get_doc(&conn, &tacit_core::DocId::new("d1")).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn transaction_detects_reentrant_deadlock() {
        // 验证 transaction() 在已持有 conn() 锁时返回错误而非死锁
        let store = Store::open_memory().unwrap();
        let _conn = store.conn(); // 持有锁
        let result: CoreResult<()> = store.transaction(|_| Ok(()));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("transaction_with_conn"),
            "错误信息应引导使用 transaction_with_conn: {msg}"
        );
    }

    #[test]
    fn install_snapshot_atomically_basic() {
        // 验证完整的双缓冲安装流程
        let store = Store::open_memory().unwrap();
        // 先创建文档
        {
            let conn = store.conn();
            dao::upsert_doc(
                &conn,
                &dao::DocRecord {
                    doc_id: tacit_core::DocId::new("doc1"),
                    kind: "note".into(),
                    current_frontier: Frontier::new(),
                    updated_at: SystemTime::now(),
                    current_snapshot_id: None,
                },
            )
            .unwrap();
        }

        let snapshot = b"snapshot_payload";
        let hash = content_hash(snapshot);
        let frontier = Frontier::from_iter([(pid("1"), 10)]);
        store
            .install_snapshot_atomically("doc1", snapshot, &hash, &frontier, "Full")
            .unwrap();

        // 验证 pending snapshot 已写入
        let conn = store.conn();
        let pending_id = tacit_core::CheckpointId::new(format!("__pending_{}", hash));
        let snap = dao::get_snapshot(&conn, &tacit_core::DocId::new("doc1"), &pending_id)
            .unwrap()
            .unwrap();
        assert_eq!(snap.0, snapshot);

        // 验证 documents.current_frontier 已更新
        let doc = dao::get_doc(&conn, &tacit_core::DocId::new("doc1"))
            .unwrap()
            .unwrap();
        assert_eq!(doc.current_frontier, frontier);
    }

    #[test]
    fn install_snapshot_atomically_rejects_empty() {
        // 验证空 snapshot 被拒绝
        let store = Store::open_memory().unwrap();
        let hash = content_hash(b"unused");
        let r = store.install_snapshot_atomically("doc1", b"", &hash, &Frontier::new(), "Full");
        assert!(r.is_err());
    }

    #[test]
    fn install_snapshot_atomically_cleans_old_pending() {
        // 验证安装新快照时清理旧的 pending snapshot
        let store = Store::open_memory().unwrap();
        // 先创建文档
        {
            let conn = store.conn();
            dao::upsert_doc(
                &conn,
                &dao::DocRecord {
                    doc_id: tacit_core::DocId::new("doc1"),
                    kind: "note".into(),
                    current_frontier: Frontier::new(),
                    updated_at: SystemTime::now(),
                    current_snapshot_id: None,
                },
            )
            .unwrap();
        }

        // 第一次安装
        let hash1 = content_hash(b"snap1");
        store
            .install_snapshot_atomically("doc1", b"snap1", &hash1, &Frontier::new(), "Full")
            .unwrap();
        // 第二次安装（应清理第一次的 pending）
        let hash2 = content_hash(b"snap2");
        store
            .install_snapshot_atomically("doc1", b"snap2", &hash2, &Frontier::new(), "Full")
            .unwrap();

        let conn = store.conn();
        // 旧的 pending 应被删除
        let old_pending = dao::get_snapshot(
            &conn,
            &tacit_core::DocId::new("doc1"),
            &tacit_core::CheckpointId::new(format!("__pending_{}", hash1)),
        )
        .unwrap();
        assert!(old_pending.is_none(), "旧 pending snapshot 应被删除");
        // 新的 pending 应存在
        let new_pending = dao::get_snapshot(
            &conn,
            &tacit_core::DocId::new("doc1"),
            &tacit_core::CheckpointId::new(format!("__pending_{}", hash2)),
        )
        .unwrap()
        .unwrap();
        assert_eq!(new_pending.0, b"snap2");
    }

    // ===== #47: DAO 边界/错误路径测试 =====

    #[test]
    fn dao_sql_injection_in_doc_id() {
        // SQL 注入 payload 作为 doc_id：验证参数化查询防止注入
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let malicious_ids = [
            "'; DROP TABLE documents;--",
            "doc1' OR '1'='1",
            "doc1\u{0000}", // null byte
        ];
        for &id in &malicious_ids {
            let rec = dao::DocRecord {
                doc_id: tacit_core::DocId::new(id),
                kind: "note".into(),
                current_frontier: Frontier::new(),
                current_snapshot_id: None,
                updated_at: SystemTime::now(),
            };
            assert!(dao::upsert_doc(&conn, &rec).is_ok(), "upsert 应成功（参数化查询）");
            let got = dao::get_doc(&conn, &tacit_core::DocId::new(id)).unwrap();
            assert!(got.is_some(), "应能读回 doc_id={}", id);
        }
        // 验证 documents 表未被删除
        let docs = dao::list_docs(&conn).unwrap();
        assert_eq!(docs.len(), malicious_ids.len(), "所有 doc 应存在，表未被注入破坏");
    }

    #[test]
    fn dao_empty_and_long_strings() {
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        // 空字符串 doc_id
        let rec = dao::DocRecord {
            doc_id: tacit_core::DocId::new(""),
            kind: "note".into(),
            current_frontier: Frontier::new(),
            current_snapshot_id: None,
            updated_at: SystemTime::now(),
        };
        assert!(dao::upsert_doc(&conn, &rec).is_ok());
        let got = dao::get_doc(&conn, &tacit_core::DocId::new("")).unwrap();
        assert!(got.is_some(), "空字符串 doc_id 应可读写");

        // 非常长的 doc_id（10KB）
        let long_id = "x".repeat(10_000);
        let rec = dao::DocRecord {
            doc_id: tacit_core::DocId::new(&long_id),
            kind: "note".into(),
            current_frontier: Frontier::new(),
            current_snapshot_id: None,
            updated_at: SystemTime::now(),
        };
        assert!(dao::upsert_doc(&conn, &rec).is_ok());
        let got = dao::get_doc(&conn, &tacit_core::DocId::new(&long_id)).unwrap();
        assert!(got.is_some(), "10KB doc_id 应可读写");
    }

    #[test]
    fn dao_snapshot_with_null_bytes() {
        // 验证包含 null byte 的二进制数据能正确存取
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let doc_id = tacit_core::DocId::new("d1");
        dao::upsert_doc(
            &conn,
            &dao::DocRecord {
                doc_id: doc_id.clone(),
                kind: "note".into(),
                current_frontier: Frontier::new(),
                current_snapshot_id: None,
                updated_at: SystemTime::now(),
            },
        )
        .unwrap();

        let payload = vec![0x00, 0xFF, 0x00, 0x42, 0x00, 0x00, 0x01];
        let snap_id = tacit_core::CheckpointId::new("snap1");
        dao::insert_snapshot(
            &conn,
            &doc_id,
            &snap_id,
            &payload,
            tacit_core::SnapshotKind::Full,
            SystemTime::now(),
        )
        .unwrap();

        let got = dao::get_snapshot(&conn, &doc_id, &snap_id).unwrap().unwrap();
        assert_eq!(got.0, payload, "含 null byte 的二进制数据应完整存取");
    }

    #[test]
    fn dao_duplicate_key_upsert() {
        // 验证 upsert 在重复 key 时更新而非报错
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let doc_id = tacit_core::DocId::new("d1");

        for &kind in &["note", "log", "todo"] {
            dao::upsert_doc(
                &conn,
                &dao::DocRecord {
                    doc_id: doc_id.clone(),
                    kind: kind.to_string(),
                    current_frontier: Frontier::new(),
                    current_snapshot_id: None,
                    updated_at: SystemTime::now(),
                },
            )
            .unwrap();
        }

        let got = dao::get_doc(&conn, &doc_id).unwrap().unwrap();
        assert_eq!(got.kind, "todo", "upsert 应更新为最后一次写入");
    }

    #[test]
    fn dao_device_identity_roundtrip() {
        // #4: 设备身份持久化 roundtrip
        let store = Store::open_memory().unwrap();
        let conn = store.conn();

        // 首次加载应为 None
        assert!(dao::load_device_identity(&conn).unwrap().is_none());

        // 保存
        let rec = dao::DeviceIdentityRecord {
            signing_key: vec![0x01; 32],
            static_private: vec![0x02; 32],
            static_public: vec![0x03; 32],
            binding_proof: vec![0x04; 64],
            created_at: SystemTime::now(),
        };
        dao::save_device_identity(&conn, &rec).unwrap();

        // 加载并验证
        let loaded = dao::load_device_identity(&conn).unwrap().unwrap();
        assert_eq!(loaded.signing_key, rec.signing_key);
        assert_eq!(loaded.static_private, rec.static_private);
        assert_eq!(loaded.static_public, rec.static_public);
        assert_eq!(loaded.binding_proof, rec.binding_proof);

        // 覆盖写入
        let rec2 = dao::DeviceIdentityRecord {
            signing_key: vec![0xAA; 32],
            static_private: vec![0xBB; 32],
            static_public: vec![0xCC; 32],
            binding_proof: vec![0xDD; 64],
            created_at: SystemTime::now(),
        };
        dao::save_device_identity(&conn, &rec2).unwrap();

        let loaded2 = dao::load_device_identity(&conn).unwrap().unwrap();
        assert_eq!(loaded2.signing_key, rec2.signing_key, "覆盖后应加载新身份");
        assert_ne!(loaded2.signing_key, rec.signing_key, "旧身份应被覆盖");
    }

    #[test]
    fn dao_transaction_rollback_preserves_data() {
        // 验证事务失败时数据不被部分写入
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let doc_id = tacit_core::DocId::new("d1");

        // 先写入一条数据
        dao::upsert_doc(
            &conn,
            &dao::DocRecord {
                doc_id: doc_id.clone(),
                kind: "note".into(),
                current_frontier: Frontier::new(),
                current_snapshot_id: None,
                updated_at: SystemTime::now(),
            },
        )
        .unwrap();

        // 事务中写入第二条数据后失败
        let result: CoreResult<()> = store.transaction_with_conn(&conn, |conn| {
            dao::upsert_doc(
                conn,
                &dao::DocRecord {
                    doc_id: tacit_core::DocId::new("d2"),
                    kind: "note".into(),
                    current_frontier: Frontier::new(),
                    current_snapshot_id: None,
                    updated_at: SystemTime::now(),
                },
            )?;
            // 模拟失败
            Err(CoreError::Store("故意失败".into()))
        });
        assert!(result.is_err());

        // d2 不应存在（事务回滚）
        let d2 = dao::get_doc(&conn, &tacit_core::DocId::new("d2")).unwrap();
        assert!(d2.is_none(), "事务失败后 d2 不应存在");

        // d1 仍应存在（事务前已提交）
        let d1 = dao::get_doc(&conn, &doc_id).unwrap();
        assert!(d1.is_some(), "d1 应仍存在（事务前已提交）");
    }

    #[test]
    fn dao_large_snapshot_blob() {
        // 验证大 blob（1MB）能正确存取
        let store = Store::open_memory().unwrap();
        let conn = store.conn();
        let doc_id = tacit_core::DocId::new("d1");
        dao::upsert_doc(
            &conn,
            &dao::DocRecord {
                doc_id: doc_id.clone(),
                kind: "note".into(),
                current_frontier: Frontier::new(),
                current_snapshot_id: None,
                updated_at: SystemTime::now(),
            },
        )
        .unwrap();

        let large_payload = vec![0xAB; 1024 * 1024]; // 1MB
        let snap_id = tacit_core::CheckpointId::new("large_snap");
        dao::insert_snapshot(
            &conn,
            &doc_id,
            &snap_id,
            &large_payload,
            tacit_core::SnapshotKind::Full,
            SystemTime::now(),
        )
        .unwrap();

        let got = dao::get_snapshot(&conn, &doc_id, &snap_id).unwrap().unwrap();
        assert_eq!(got.0.len(), large_payload.len());
        assert_eq!(got.0, large_payload, "1MB blob 应完整存取");
    }
}
