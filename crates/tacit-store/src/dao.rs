//! 数据访问对象（DAO）。
//!
//! 所有函数接受 `&Connection`，由调用方通过 `Store::conn()` 或
//! `Store::transaction()` 获取。复杂类型（Frontier/枚举）序列化为 JSON TEXT。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use tacit_core::{
    AckSummary, BlockId, CheckpointId, CoreError, CoreResult, DocId, Endpoint, Frontier,
    NatCapability, PeerId, PeerRecord, SnapshotKind, TrustState,
};

// ===== 序列化辅助 =====

fn ser_frontier(f: &Frontier) -> String {
    serde_json::to_string(f).unwrap_or_else(|_| "{}".into())
}

fn de_frontier(s: &str) -> Frontier {
    serde_json::from_str(s).unwrap_or_default()
}

fn ser_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".into())
}

fn de_json<T: serde::de::DeserializeOwned>(s: &str) -> Option<T> {
    serde_json::from_str(s).ok()
}

fn to_millis(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn from_millis(ms: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms.max(0) as u64)
}

// ===== 文档表 =====

/// documents 表对应记录。
#[derive(Debug, Clone)]
pub struct DocRecord {
    pub doc_id: DocId,
    pub kind: String,
    pub current_frontier: Frontier,
    pub updated_at: SystemTime,
}

pub fn upsert_doc(conn: &Connection, rec: &DocRecord) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO documents (doc_id, kind, current_frontier, updated_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            rec.doc_id.as_str(),
            rec.kind,
            ser_frontier(&rec.current_frontier),
            to_millis(rec.updated_at),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

pub fn get_doc(conn: &Connection, doc_id: &DocId) -> CoreResult<Option<DocRecord>> {
    let mut stmt = conn
        .prepare("SELECT doc_id, kind, current_frontier, updated_at FROM documents WHERE doc_id = ?1")
        .map_err(store_err)?;
    let row = stmt
        .query_row(params![doc_id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .optional()
        .map_err(store_err)?;
    match row {
        Some((id, kind, frontier, updated)) => Ok(Some(DocRecord {
            doc_id: DocId::new(id),
            kind,
            current_frontier: de_frontier(&frontier),
            updated_at: from_millis(updated),
        })),
        None => Ok(None),
    }
}

pub fn list_docs(conn: &Connection) -> CoreResult<Vec<DocRecord>> {
    let mut stmt = conn
        .prepare("SELECT doc_id, kind, current_frontier, updated_at FROM documents ORDER BY updated_at DESC")
        .map_err(store_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(DocRecord {
                doc_id: DocId::new(r.get::<_, String>(0)?),
                kind: r.get::<_, String>(1)?,
                current_frontier: de_frontier(&r.get::<_, String>(2)?),
                updated_at: from_millis(r.get::<_, i64>(3)?),
            })
        })
        .map_err(store_err)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(store_err)?);
    }
    Ok(out)
}

// ===== 快照表 =====

pub fn insert_snapshot(
    conn: &Connection,
    doc_id: &DocId,
    snapshot_id: &CheckpointId,
    blob: &[u8],
    kind: SnapshotKind,
    created_at: SystemTime,
) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO document_snapshots (doc_id, snapshot_id, snapshot_blob, snapshot_kind, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            doc_id.as_str(),
            snapshot_id.as_str(),
            blob,
            ser_json(&kind),
            to_millis(created_at),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

pub fn get_latest_snapshot(
    conn: &Connection,
    doc_id: &DocId,
) -> CoreResult<Option<(CheckpointId, Vec<u8>, SnapshotKind, SystemTime)>> {
    let mut stmt = conn
        .prepare("SELECT snapshot_id, snapshot_blob, snapshot_kind, created_at FROM document_snapshots WHERE doc_id = ?1 ORDER BY created_at DESC LIMIT 1")
        .map_err(store_err)?;
    let row = stmt
        .query_row(params![doc_id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .optional()
        .map_err(store_err)?;
    match row {
        Some((id, blob, kind, created)) => Ok(Some((
            CheckpointId::new(id),
            blob,
            de_json(&kind).unwrap_or(SnapshotKind::Full),
            from_millis(created),
        ))),
        None => Ok(None),
    }
}

// ===== peer 表 =====

pub fn upsert_peer(conn: &Connection, peer: &PeerRecord) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO peers
         (peer_id, device_pubkey, capabilities, trust_state, anchor_priority, last_seen_at, last_endpoint, nat_capability, relay_hint)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            peer.peer_id.as_str(),
            peer.device_pubkey,
            ser_json(&peer.capabilities),
            ser_json(&peer.trust_state),
            peer.anchor_priority,
            to_millis(peer.last_seen_at),
            peer.last_endpoint.as_ref().map(ser_json).as_deref(),
            ser_json(&peer.nat_capability),
            peer.relay_hint.as_ref().map(|p| p.as_str()),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

pub fn get_peer(conn: &Connection, peer_id: &PeerId) -> CoreResult<Option<PeerRecord>> {
    let mut stmt = conn
        .prepare("SELECT peer_id, device_pubkey, capabilities, trust_state, anchor_priority, last_seen_at, last_endpoint, nat_capability, relay_hint FROM peers WHERE peer_id = ?1")
        .map_err(store_err)?;
    let row = stmt
        .query_row(params![peer_id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i32>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })
        .optional()
        .map_err(store_err)?;
    match row {
        Some((id, pubkey, caps, trust, prio, seen, endpoint, nat, relay)) => Ok(Some(PeerRecord {
            peer_id: PeerId::new(id),
            device_pubkey: pubkey,
            capabilities: de_json(&caps).unwrap_or_default(),
            trust_state: de_json(&trust).unwrap_or(TrustState::Pending),
            anchor_priority: prio,
            last_seen_at: from_millis(seen),
            last_endpoint: endpoint.and_then(|s| de_json(&s)),
            nat_capability: de_json(&nat).unwrap_or(NatCapability::Unknown),
            relay_hint: relay.map(PeerId::new),
        })),
        None => Ok(None),
    }
}

pub fn list_peers(conn: &Connection) -> CoreResult<Vec<PeerRecord>> {
    let mut stmt = conn
        .prepare("SELECT peer_id, device_pubkey, capabilities, trust_state, anchor_priority, last_seen_at, last_endpoint, nat_capability, relay_hint FROM peers")
        .map_err(store_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i32>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })
        .map_err(store_err)?;
    let mut out = Vec::new();
    for r in rows {
        let (id, pubkey, caps, trust, prio, seen, endpoint, nat, relay) = r.map_err(store_err)?;
        out.push(PeerRecord {
            peer_id: PeerId::new(id),
            device_pubkey: pubkey,
            capabilities: de_json(&caps).unwrap_or_default(),
            trust_state: de_json(&trust).unwrap_or(TrustState::Pending),
            anchor_priority: prio,
            last_seen_at: from_millis(seen),
            last_endpoint: endpoint.and_then(|s| de_json::<Endpoint>(&s)),
            nat_capability: de_json(&nat).unwrap_or(NatCapability::Unknown),
            relay_hint: relay.map(PeerId::new),
        });
    }
    Ok(out)
}

/// 选举最佳 Anchor。排序键：anchor_priority desc, last_seen_at desc, peer_id asc。
/// 仅返回 trusted 且 can_anchor 的 peer。
pub fn best_anchor(conn: &Connection) -> CoreResult<Option<PeerId>> {
    let peers = list_peers(conn)?;
    let anchor = peers
        .into_iter()
        .filter(|p| p.trust_state == TrustState::Trusted && p.capabilities.can_anchor)
        .max_by(|a, b| {
            (a.anchor_priority, a.last_seen_at)
                .cmp(&(b.anchor_priority, b.last_seen_at))
        });
    Ok(anchor.map(|p| p.peer_id))
}

// ===== ack 表 =====

pub fn upsert_ack(conn: &Connection, ack: &AckSummary) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO acks (peer_id, doc_id, ack_checkpoint, ack_frontier, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            ack.peer_id.as_str(),
            ack.doc_id.as_str(),
            ack.ack_checkpoint.as_ref().map(|c| c.as_str()),
            ser_frontier(&ack.ack_frontier),
            to_millis(ack.updated_at),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

pub fn get_ack(conn: &Connection, peer_id: &PeerId, doc_id: &DocId) -> CoreResult<Option<AckSummary>> {
    let mut stmt = conn
        .prepare("SELECT peer_id, doc_id, ack_checkpoint, ack_frontier, updated_at FROM acks WHERE peer_id = ?1 AND doc_id = ?2")
        .map_err(store_err)?;
    let row = stmt
        .query_row(params![peer_id.as_str(), doc_id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .optional()
        .map_err(store_err)?;
    match row {
        Some((pid, did, cp, frontier, updated)) => Ok(Some(AckSummary {
            peer_id: PeerId::new(pid),
            doc_id: DocId::new(did),
            ack_checkpoint: cp.map(CheckpointId::new),
            ack_frontier: de_frontier(&frontier),
            updated_at: from_millis(updated),
        })),
        None => Ok(None),
    }
}

// ===== block_sync_state 表 =====

/// block 同步状态记录。
#[derive(Debug, Clone)]
pub struct BlockSyncStateRecord {
    pub doc_id: DocId,
    pub block_id: BlockId,
    pub peer_id: PeerId,
    pub expected_frontier: Frontier,
    pub observed_frontier: Frontier,
    pub retry_after_ms: i64,
    pub updated_at: SystemTime,
}

pub fn upsert_block_sync_state(conn: &Connection, rec: &BlockSyncStateRecord) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO block_sync_state
         (doc_id, block_id, peer_id, expected_frontier, observed_frontier, retry_after_ms, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            rec.doc_id.as_str(),
            rec.block_id.as_str(),
            rec.peer_id.as_str(),
            ser_frontier(&rec.expected_frontier),
            ser_frontier(&rec.observed_frontier),
            rec.retry_after_ms,
            to_millis(rec.updated_at),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

pub fn list_pending_blocks(conn: &Connection, now_ms: i64) -> CoreResult<Vec<BlockSyncStateRecord>> {
    let mut stmt = conn
        .prepare("SELECT doc_id, block_id, peer_id, expected_frontier, observed_frontier, retry_after_ms, updated_at FROM block_sync_state WHERE retry_after_ms <= ?1")
        .map_err(store_err)?;
    let rows = stmt
        .query_map(params![now_ms], |r| {
            Ok(BlockSyncStateRecord {
                doc_id: DocId::new(r.get::<_, String>(0)?),
                block_id: BlockId::new(r.get::<_, String>(1)?),
                peer_id: PeerId::new(r.get::<_, String>(2)?),
                expected_frontier: de_frontier(&r.get::<_, String>(3)?),
                observed_frontier: de_frontier(&r.get::<_, String>(4)?),
                retry_after_ms: r.get::<_, i64>(5)?,
                updated_at: from_millis(r.get::<_, i64>(6)?),
            })
        })
        .map_err(store_err)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(store_err)?);
    }
    Ok(out)
}

// ===== transport_stats 表 =====

#[derive(Debug, Clone)]
pub struct TransportStatsRecord {
    pub peer_id: PeerId,
    pub channel: String,
    pub success_ema: f64,
    pub avg_latency_ms: i64,
    pub updated_at: SystemTime,
}

pub fn upsert_transport_stats(conn: &Connection, rec: &TransportStatsRecord) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO transport_stats (peer_id, channel, success_ema, avg_latency_ms, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            rec.peer_id.as_str(),
            rec.channel,
            rec.success_ema,
            rec.avg_latency_ms,
            to_millis(rec.updated_at),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

// ===== checkpoint 表 =====

#[derive(Debug, Clone)]
pub struct CheckpointRecord {
    pub doc_id: DocId,
    pub checkpoint_id: CheckpointId,
    pub shallow_snapshot_blob: Vec<u8>,
    pub frontier: Frontier,
    pub state_hash: [u8; 32],
    pub created_at: SystemTime,
}

pub fn insert_checkpoint(conn: &Connection, rec: &CheckpointRecord) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO checkpoint_log (doc_id, checkpoint_id, shallow_snapshot_blob, frontier, state_hash, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            rec.doc_id.as_str(),
            rec.checkpoint_id.as_str(),
            &rec.shallow_snapshot_blob,
            ser_frontier(&rec.frontier),
            rec.state_hash.as_slice(),
            to_millis(rec.created_at),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

pub fn get_latest_checkpoint(conn: &Connection, doc_id: &DocId) -> CoreResult<Option<CheckpointRecord>> {
    let mut stmt = conn
        .prepare("SELECT doc_id, checkpoint_id, shallow_snapshot_blob, frontier, state_hash, created_at FROM checkpoint_log WHERE doc_id = ?1 ORDER BY created_at DESC LIMIT 1")
        .map_err(store_err)?;
    let row = stmt
        .query_row(params![doc_id.as_str()], |r| {
            let hash: Vec<u8> = r.get(4)?;
            let mut state_hash = [0u8; 32];
            if hash.len() == 32 {
                state_hash.copy_from_slice(&hash);
            }
            Ok(CheckpointRecord {
                doc_id: DocId::new(r.get::<_, String>(0)?),
                checkpoint_id: CheckpointId::new(r.get::<_, String>(1)?),
                shallow_snapshot_blob: r.get::<_, Vec<u8>>(2)?,
                frontier: de_frontier(&r.get::<_, String>(3)?),
                state_hash,
                created_at: from_millis(r.get::<_, i64>(5)?),
            })
        })
        .optional()
        .map_err(store_err)?;
    Ok(row)
}

// ===== 辅助 =====

fn store_err(e: rusqlite::Error) -> CoreError {
    CoreError::Store(e.to_string())
}
