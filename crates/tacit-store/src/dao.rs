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

use crate::compression;

// ===== 序列化辅助 =====

fn ser_frontier(f: &Frontier) -> String {
    serde_json::to_string(f).expect("Frontier 序列化不应失败")
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
    pub current_snapshot_id: Option<String>,
    pub updated_at: SystemTime,
}

pub fn upsert_doc(conn: &Connection, rec: &DocRecord) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO documents (doc_id, kind, current_frontier, current_snapshot_id, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            rec.doc_id.as_str(),
            rec.kind,
            ser_frontier(&rec.current_frontier),
            rec.current_snapshot_id.as_deref(),
            to_millis(rec.updated_at),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

pub fn get_doc(conn: &Connection, doc_id: &DocId) -> CoreResult<Option<DocRecord>> {
    let mut stmt = conn
        .prepare("SELECT doc_id, kind, current_frontier, current_snapshot_id, updated_at FROM documents WHERE doc_id = ?1")
        .map_err(store_err)?;
    let row = stmt
        .query_row(params![doc_id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .optional()
        .map_err(store_err)?;
    match row {
        Some((id, kind, frontier, snap_id, updated)) => Ok(Some(DocRecord {
            doc_id: DocId::new(id),
            kind,
            current_frontier: de_frontier(&frontier),
            current_snapshot_id: snap_id,
            updated_at: from_millis(updated),
        })),
        None => Ok(None),
    }
}

pub fn list_docs(conn: &Connection) -> CoreResult<Vec<DocRecord>> {
    let mut stmt = conn
        .prepare("SELECT doc_id, kind, current_frontier, current_snapshot_id, updated_at FROM documents ORDER BY updated_at DESC")
        .map_err(store_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(DocRecord {
                doc_id: DocId::new(r.get::<_, String>(0)?),
                kind: r.get::<_, String>(1)?,
                current_frontier: de_frontier(&r.get::<_, String>(2)?),
                current_snapshot_id: r.get::<_, Option<String>>(3)?,
                updated_at: from_millis(r.get::<_, i64>(4)?),
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
    let compressed = compression::compress(blob)?;
    conn.execute(
        "INSERT OR REPLACE INTO document_snapshots (doc_id, snapshot_id, snapshot_blob, snapshot_kind, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            doc_id.as_str(),
            snapshot_id.as_str(),
            &compressed,
            ser_json(&kind),
            to_millis(created_at),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

#[allow(clippy::type_complexity)]
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
            compression::decompress(blob)?,
            de_json(&kind).unwrap_or(SnapshotKind::Full),
            from_millis(created),
        ))),
        None => Ok(None),
    }
}

/// 按 doc_id + snapshot_id 精确查找快照。
pub fn get_snapshot(
    conn: &Connection,
    doc_id: &DocId,
    snapshot_id: &CheckpointId,
) -> CoreResult<Option<(Vec<u8>, SnapshotKind, SystemTime)>> {
    let mut stmt = conn
        .prepare("SELECT snapshot_blob, snapshot_kind, created_at FROM document_snapshots WHERE doc_id = ?1 AND snapshot_id = ?2 ORDER BY created_at DESC LIMIT 1")
        .map_err(store_err)?;
    let row = stmt
        .query_row(params![doc_id.as_str(), snapshot_id.as_str()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .optional()
        .map_err(store_err)?;
    match row {
        Some((blob, kind, created)) => Ok(Some((
            compression::decompress(blob)?,
            de_json(&kind).unwrap_or(SnapshotKind::Full),
            from_millis(created),
        ))),
        None => Ok(None),
    }
}

/// 按 doc_id + snapshot_id 删除快照（用于双缓冲安装的回滚）。
pub fn delete_snapshot(
    conn: &Connection,
    doc_id: &DocId,
    snapshot_id: &CheckpointId,
) -> CoreResult<()> {
    conn.execute(
        "DELETE FROM document_snapshots WHERE doc_id = ?1 AND snapshot_id = ?2",
        params![doc_id.as_str(), snapshot_id.as_str()],
    )
    .map_err(store_err)?;
    Ok(())
}

// ===== peer 表 =====

pub fn upsert_peer(conn: &Connection, peer: &PeerRecord) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO peers
         (peer_id, device_pubkey, capabilities, trust_state, anchor_priority, last_seen_at, last_endpoint, nat_capability, relay_hint, success_ema, rotation_seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
            peer.success_ema,
            peer.rotation_seq as i64,
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

pub fn get_peer(conn: &Connection, peer_id: &PeerId) -> CoreResult<Option<PeerRecord>> {
    let mut stmt = conn
        .prepare("SELECT peer_id, device_pubkey, capabilities, trust_state, anchor_priority, last_seen_at, last_endpoint, nat_capability, relay_hint, success_ema, rotation_seq FROM peers WHERE peer_id = ?1")
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
                r.get::<_, f64>(9)?,
                r.get::<_, i64>(10)?,
            ))
        })
        .optional()
        .map_err(store_err)?;
    match row {
        Some((id, pubkey, caps, trust, prio, seen, endpoint, nat, relay, ema, rot_seq)) => {
            Ok(Some(PeerRecord {
                peer_id: PeerId::new(id),
                device_pubkey: pubkey,
                capabilities: de_json(&caps).unwrap_or_default(),
                trust_state: de_json(&trust).unwrap_or(TrustState::Pending),
                anchor_priority: prio,
                last_seen_at: from_millis(seen),
                last_endpoint: endpoint.and_then(|s| de_json(&s)),
                nat_capability: de_json(&nat).unwrap_or(NatCapability::Unknown),
                relay_hint: relay.map(PeerId::new),
                success_ema: ema,
                rotation_seq: rot_seq as u64,
            }))
        }
        None => Ok(None),
    }
}

pub fn list_peers(conn: &Connection) -> CoreResult<Vec<PeerRecord>> {
    let mut stmt = conn
        .prepare("SELECT peer_id, device_pubkey, capabilities, trust_state, anchor_priority, last_seen_at, last_endpoint, nat_capability, relay_hint, success_ema, rotation_seq FROM peers")
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
                r.get::<_, f64>(9)?,
                r.get::<_, i64>(10)?,
            ))
        })
        .map_err(store_err)?;
    let mut out = Vec::new();
    for r in rows {
        let (id, pubkey, caps, trust, prio, seen, endpoint, nat, relay, ema, rot_seq) =
            r.map_err(store_err)?;
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
            success_ema: ema,
            rotation_seq: rot_seq as u64,
        });
    }
    Ok(out)
}

/// NAT 能力排序权重（值越大越优）。
fn nat_rank(nat: &NatCapability) -> u8 {
    match nat {
        NatCapability::Direct => 3,
        NatCapability::Cone => 2,
        NatCapability::Symmetric => 1,
        NatCapability::Unknown => 0,
    }
}

/// 选举最佳 Anchor。排序键：anchor_priority desc, nat_capability desc, success_ema desc, last_seen_at desc, peer_id asc。
/// 仅返回 trusted 且 can_anchor 的 peer。
pub fn best_anchor(conn: &Connection) -> CoreResult<Option<PeerId>> {
    let peers = list_peers(conn)?;
    let anchor = peers
        .into_iter()
        .filter(|p| p.trust_state == TrustState::Trusted && p.capabilities.can_anchor)
        .max_by(|a, b| {
            // 5 键排序：anchor_priority desc, nat_capability desc, success_ema desc, last_seen_at desc, peer_id asc
            // max_by 中 a.cmp(&b) = Greater 表示 a > b，即 a 更优
            a.anchor_priority
                .cmp(&b.anchor_priority)
                .then(nat_rank(&a.nat_capability).cmp(&nat_rank(&b.nat_capability)))
                .then(
                    a.success_ema
                        .partial_cmp(&b.success_ema)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then(a.last_seen_at.cmp(&b.last_seen_at))
                .then(b.peer_id.as_str().cmp(a.peer_id.as_str()))
        });
    Ok(anchor.map(|p| p.peer_id))
}

/// 更新 peer 的 last_seen_at 和 last_endpoint（轻量更新，不需要整体 upsert）。
pub fn mark_peer_seen(
    conn: &Connection,
    peer_id: &PeerId,
    endpoint: Option<&Endpoint>,
    now: SystemTime,
) -> CoreResult<()> {
    conn.execute(
        "UPDATE peers SET last_seen_at = ?1, last_endpoint = ?2 WHERE peer_id = ?3",
        params![
            to_millis(now),
            endpoint.map(ser_json).as_deref(),
            peer_id.as_str(),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

/// 列出所有可作为 relay 的 trusted peer。
pub fn list_relay_candidates(conn: &Connection) -> CoreResult<Vec<PeerId>> {
    let peers = list_peers(conn)?;
    Ok(peers
        .into_iter()
        .filter(|p| p.trust_state == TrustState::Trusted && p.capabilities.can_relay)
        .map(|p| p.peer_id)
        .collect())
}

/// 将 peer 信任状态降级为 Revoked。
pub fn revoke_peer(conn: &Connection, peer_id: &PeerId) -> CoreResult<()> {
    conn.execute(
        "UPDATE peers SET trust_state = ?1 WHERE peer_id = ?2",
        params![ser_json(&TrustState::Revoked), peer_id.as_str()],
    )
    .map_err(store_err)?;
    Ok(())
}

// ===== ack 表 =====

pub fn upsert_ack(conn: &Connection, ack: &AckSummary) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO acks (peer_id, doc_id, ack_checkpoint, ack_frontier, updated_at, version_override)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            ack.peer_id.as_str(),
            ack.doc_id.as_str(),
            ack.ack_checkpoint.as_ref().map(|c| c.as_str()),
            ser_frontier(&ack.ack_frontier),
            to_millis(ack.updated_at),
            ack.version_override.map(|v| v as i64),
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

pub fn get_ack(
    conn: &Connection,
    peer_id: &PeerId,
    doc_id: &DocId,
) -> CoreResult<Option<AckSummary>> {
    let mut stmt = conn
        .prepare("SELECT peer_id, doc_id, ack_checkpoint, ack_frontier, updated_at, version_override FROM acks WHERE peer_id = ?1 AND doc_id = ?2")
        .map_err(store_err)?;
    let row = stmt
        .query_row(params![peer_id.as_str(), doc_id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<i64>>(5)?,
            ))
        })
        .optional()
        .map_err(store_err)?;
    match row {
        Some((pid, did, cp, frontier, updated, ver_override)) => Ok(Some(AckSummary {
            peer_id: PeerId::new(pid),
            doc_id: DocId::new(did),
            ack_checkpoint: cp.map(CheckpointId::new),
            ack_frontier: de_frontier(&frontier),
            updated_at: from_millis(updated),
            version_override: ver_override.map(|v| v as u32),
        })),
        None => Ok(None),
    }
}

/// 列出指定文档的所有 ack 摘要。
pub fn list_acks_by_doc(conn: &Connection, doc_id: &DocId) -> CoreResult<Vec<AckSummary>> {
    let mut stmt = conn
        .prepare("SELECT peer_id, doc_id, ack_checkpoint, ack_frontier, updated_at, version_override FROM acks WHERE doc_id = ?1")
        .map_err(store_err)?;
    let rows = stmt
        .query_map(params![doc_id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<i64>>(5)?,
            ))
        })
        .map_err(store_err)?;
    let mut out = Vec::new();
    for r in rows {
        let (pid, did, cp, frontier, updated, ver_override) = r.map_err(store_err)?;
        out.push(AckSummary {
            peer_id: PeerId::new(pid),
            doc_id: DocId::new(did),
            ack_checkpoint: cp.map(CheckpointId::new),
            ack_frontier: de_frontier(&frontier),
            updated_at: from_millis(updated),
            version_override: ver_override.map(|v| v as u32),
        });
    }
    Ok(out)
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

pub fn list_pending_blocks(
    conn: &Connection,
    now_ms: i64,
) -> CoreResult<Vec<BlockSyncStateRecord>> {
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

pub fn get_latest_checkpoint(
    conn: &Connection,
    doc_id: &DocId,
) -> CoreResult<Option<CheckpointRecord>> {
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

/// 列出指定 doc 的所有 checkpoint（按创建时间降序）。
pub fn list_checkpoints_by_doc(
    conn: &Connection,
    doc_id: &DocId,
) -> CoreResult<Vec<CheckpointRecord>> {
    let mut stmt = conn
        .prepare("SELECT doc_id, checkpoint_id, shallow_snapshot_blob, frontier, state_hash, created_at FROM checkpoint_log WHERE doc_id = ?1 ORDER BY created_at DESC")
        .map_err(store_err)?;
    let rows = stmt
        .query_map(params![doc_id.as_str()], |r| {
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
        .map_err(store_err)?;
    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(store_err)?);
    }
    Ok(result)
}

/// 删除指定 checkpoint 记录（用于 GC）。
pub fn delete_checkpoint(
    conn: &Connection,
    doc_id: &DocId,
    checkpoint_id: &CheckpointId,
) -> CoreResult<()> {
    conn.execute(
        "DELETE FROM checkpoint_log WHERE doc_id = ?1 AND checkpoint_id = ?2",
        params![doc_id.as_str(), checkpoint_id.as_str()],
    )
    .map_err(store_err)?;
    Ok(())
}

/// 删除指定 doc 下所有早于 keep_checkpoint_id 的 snapshot（用于 GC）。
///
/// 保留与 keep_checkpoint_id 关联的 snapshot，删除其他旧 snapshot。
///
/// 注意：keep_prefix 中的 LIKE 通配符（`%`、`_`、`\`）会被转义，
/// 避免前缀中含特殊字符时误匹配。
pub fn delete_old_snapshots(
    conn: &Connection,
    doc_id: &DocId,
    keep_prefix: &str,
) -> CoreResult<u64> {
    // 对 keep_prefix 中的 LIKE 通配符进行反斜杠转义：
    //   % → \%   （匹配字面百分号）
    //   _ → \_   （匹配字面下划线）
    //   \ → \\   （转义符自身先转义，避免影响后续转义）
    let escaped = keep_prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    // 删除 snapshot_id 不以 keep_prefix 开头的 snapshot
    // 使用 ESCAPE '\' 子句启用反斜杠作为转义字符
    let deleted = conn.execute(
        "DELETE FROM document_snapshots WHERE doc_id = ?1 AND snapshot_id NOT LIKE ?2 ESCAPE '\\'",
        params![doc_id.as_str(), format!("{}%", escaped)],
    )
    .map_err(store_err)?;
    Ok(deleted as u64)
}

// ===== sync_log 表 =====

/// sync_log 记录。对应 store-and-forward 的传输日志。
#[derive(Debug, Clone)]
pub struct SyncLogRecord {
    pub entry_id: String,
    pub doc_id: DocId,
    pub delta_id: String,
    pub recipient_peer_id: PeerId,
    pub delivered_at: Option<SystemTime>,
    pub acknowledged_at: Option<SystemTime>,
    pub channel: String,
}

/// 插入 sync_log 记录。
pub fn insert_sync_log(conn: &Connection, rec: &SyncLogRecord) -> CoreResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO sync_log
         (entry_id, doc_id, delta_id, recipient_peer_id, delivered_at, acknowledged_at, channel)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            rec.entry_id,
            rec.doc_id.as_str(),
            rec.delta_id,
            rec.recipient_peer_id.as_str(),
            rec.delivered_at.map(to_millis),
            rec.acknowledged_at.map(to_millis),
            rec.channel,
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

/// 标记已投递。
pub fn mark_delivered(conn: &Connection, entry_id: &str, at: SystemTime) -> CoreResult<()> {
    conn.execute(
        "UPDATE sync_log SET delivered_at = ?1 WHERE entry_id = ?2",
        params![to_millis(at), entry_id],
    )
    .map_err(store_err)?;
    Ok(())
}

/// 标记已确认。
pub fn mark_acknowledged(conn: &Connection, entry_id: &str, at: SystemTime) -> CoreResult<()> {
    conn.execute(
        "UPDATE sync_log SET acknowledged_at = ?1 WHERE entry_id = ?2",
        params![to_millis(at), entry_id],
    )
    .map_err(store_err)?;
    Ok(())
}

/// 列出未投递的 sync_log（store-and-forward 重发）。
pub fn list_undelivered(conn: &Connection, peer_id: &PeerId) -> CoreResult<Vec<SyncLogRecord>> {
    let mut stmt = conn
        .prepare("SELECT entry_id, doc_id, delta_id, recipient_peer_id, delivered_at, acknowledged_at, channel FROM sync_log WHERE recipient_peer_id = ?1 AND delivered_at IS NULL")
        .map_err(store_err)?;
    let rows = stmt
        .query_map(params![peer_id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, String>(6)?,
            ))
        })
        .map_err(store_err)?;
    let mut out = Vec::new();
    for r in rows {
        let (eid, did, delta, rid, deliv, ack, chan) = r.map_err(store_err)?;
        out.push(SyncLogRecord {
            entry_id: eid,
            doc_id: DocId::new(did),
            delta_id: delta,
            recipient_peer_id: PeerId::new(rid),
            delivered_at: deliv.map(from_millis),
            acknowledged_at: ack.map(from_millis),
            channel: chan,
        });
    }
    Ok(out)
}

/// 列出未确认的 sync_log。
pub fn list_unacknowledged(conn: &Connection, peer_id: &PeerId) -> CoreResult<Vec<SyncLogRecord>> {
    let mut stmt = conn
        .prepare("SELECT entry_id, doc_id, delta_id, recipient_peer_id, delivered_at, acknowledged_at, channel FROM sync_log WHERE recipient_peer_id = ?1 AND acknowledged_at IS NULL")
        .map_err(store_err)?;
    let rows = stmt
        .query_map(params![peer_id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, String>(6)?,
            ))
        })
        .map_err(store_err)?;
    let mut out = Vec::new();
    for r in rows {
        let (eid, did, delta, rid, deliv, ack, chan) = r.map_err(store_err)?;
        out.push(SyncLogRecord {
            entry_id: eid,
            doc_id: DocId::new(did),
            delta_id: delta,
            recipient_peer_id: PeerId::new(rid),
            delivered_at: deliv.map(from_millis),
            acknowledged_at: ack.map(from_millis),
            channel: chan,
        });
    }
    Ok(out)
}

/// 清理已确认的 sync_log（GC）。
pub fn cleanup_acknowledged(conn: &Connection, older_than_ms: i64) -> CoreResult<()> {
    conn.execute(
        "DELETE FROM sync_log WHERE acknowledged_at IS NOT NULL AND acknowledged_at < ?1",
        params![older_than_ms],
    )
    .map_err(store_err)?;
    Ok(())
}

// ===== transport_stats 查询 + EMA 更新 =====

/// 查询单条 transport_stats。
pub fn get_transport_stats(
    conn: &Connection,
    peer_id: &PeerId,
    channel: &str,
) -> CoreResult<Option<TransportStatsRecord>> {
    let mut stmt = conn
        .prepare("SELECT peer_id, channel, success_ema, avg_latency_ms, updated_at FROM transport_stats WHERE peer_id = ?1 AND channel = ?2")
        .map_err(store_err)?;
    let row = stmt
        .query_row(params![peer_id.as_str(), channel], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, f64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .optional()
        .map_err(store_err)?;
    match row {
        Some((pid, chan, ema, lat, updated)) => Ok(Some(TransportStatsRecord {
            peer_id: PeerId::new(pid),
            channel: chan,
            success_ema: ema,
            avg_latency_ms: lat,
            updated_at: from_millis(updated),
        })),
        None => Ok(None),
    }
}

/// 列出所有 transport_stats。
pub fn list_transport_stats(conn: &Connection) -> CoreResult<Vec<TransportStatsRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT peer_id, channel, success_ema, avg_latency_ms, updated_at FROM transport_stats",
        )
        .map_err(store_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(TransportStatsRecord {
                peer_id: PeerId::new(r.get::<_, String>(0)?),
                channel: r.get::<_, String>(1)?,
                success_ema: r.get::<_, f64>(2)?,
                avg_latency_ms: r.get::<_, i64>(3)?,
                updated_at: from_millis(r.get::<_, i64>(4)?),
            })
        })
        .map_err(store_err)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(store_err)?);
    }
    Ok(out)
}

/// EMA 更新：读取现有值，计算指数移动平均，写入新值。
///
/// `success`：true=1.0, false=0.0
/// `latency_ms`：本次延迟
/// `alpha`：平滑系数（0.0 ~ 1.0）
pub fn update_transport_ema(
    conn: &Connection,
    peer_id: &PeerId,
    channel: &str,
    success: bool,
    latency_ms: i64,
    alpha: f64,
) -> CoreResult<()> {
    let existing = get_transport_stats(conn, peer_id, channel)?;
    let (old_ema, old_latency) = match existing {
        Some(r) => (r.success_ema, r.avg_latency_ms as f64),
        None => (0.0, 0.0),
    };
    let success_val = if success { 1.0 } else { 0.0 };
    let new_ema = alpha * success_val + (1.0 - alpha) * old_ema;
    let new_latency = alpha * latency_ms as f64 + (1.0 - alpha) * old_latency;
    let rec = TransportStatsRecord {
        peer_id: peer_id.clone(),
        channel: channel.to_string(),
        success_ema: new_ema,
        avg_latency_ms: new_latency as i64,
        updated_at: SystemTime::now(),
    };
    upsert_transport_stats(conn, &rec)?;
    Ok(())
}

// ===== 设备身份持久化（#4）=====

/// 设备身份记录（对应 `device_identity` 表）。
///
/// 包含高敏感私钥，使用 `Zeroizing` 包装以在 drop 时自动擦除内存。
/// 私钥为固定 32 字节，使用 `Zeroizing<[u8; 32]>` 而非 `Zeroizing<Vec<u8>>`
/// 以避免堆分配器在 realloc 时残留副本，确保栈分配 + 可靠擦除。
pub struct DeviceIdentityRecord {
    pub signing_key: zeroize::Zeroizing<[u8; 32]>,
    pub static_private: zeroize::Zeroizing<[u8; 32]>,
    pub static_public: Vec<u8>,
    pub binding_proof: Vec<u8>,
    pub created_at: SystemTime,
}

/// 保存设备身份（INSERT，单行表）。
///
/// 使用 `INSERT` 而非 `INSERT OR REPLACE`——如果 `id='default'` 行已存在，
/// SQLite PRIMARY KEY 约束会返回错误，从数据库层面防止静默覆盖。
/// 调用方应先调用 `load_device_identity` 检查是否已有身份。
pub fn save_device_identity(conn: &Connection, rec: &DeviceIdentityRecord) -> CoreResult<()> {
    let now = rec
        .created_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    conn.execute(
        "INSERT INTO device_identity (id, signing_key, static_private, static_public, binding_proof, created_at)
         VALUES ('default', ?1, ?2, ?3, ?4, ?5)",
        params![
            &rec.signing_key[..],
            &rec.static_private[..],
            rec.static_public,
            rec.binding_proof,
            now
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

/// 加载设备身份。
pub fn load_device_identity(conn: &Connection) -> CoreResult<Option<DeviceIdentityRecord>> {
    let row = conn
        .query_row(
            "SELECT signing_key, static_private, static_public, binding_proof, created_at
             FROM device_identity WHERE id = 'default'",
            [],
            |row| {
                // #17: 使用 Zeroizing 包装敏感私钥，部分列读取失败时也能自动擦除。
                // 读取为 Vec<u8> 后立即转换为 [u8; 32]，避免堆分配残留。
                let signing_key_vec: zeroize::Zeroizing<Vec<u8>> =
                    zeroize::Zeroizing::new(row.get(0)?);
                let static_private_vec: zeroize::Zeroizing<Vec<u8>> =
                    zeroize::Zeroizing::new(row.get(1)?);
                let static_public: Vec<u8> = row.get(2)?;
                let binding_proof: Vec<u8> = row.get(3)?;
                let created_at_ms: i64 = row.get(4)?;
                Ok((
                    signing_key_vec,
                    static_private_vec,
                    static_public,
                    binding_proof,
                    created_at_ms,
                ))
            },
        )
        .optional()
        .map_err(store_err)?;

    match row {
        Some((
            signing_key_vec,
            static_private_vec,
            static_public,
            binding_proof,
            created_at_ms,
        )) => {
            // Vec<u8> → [u8; 32]：长度不匹配时返回错误，Zeroizing 自动擦除临时 Vec
            let signing_key: zeroize::Zeroizing<[u8; 32]> =
                zeroize::Zeroizing::new(signing_key_vec.as_slice().try_into().map_err(|_| {
                    store_err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "signing_key 长度不为 32 字节",
                        )),
                    ))
                })?);
            let static_private: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
                static_private_vec.as_slice().try_into().map_err(|_| {
                    store_err(rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "static_private 长度不为 32 字节",
                        )),
                    ))
                })?,
            );
            Ok(Some(DeviceIdentityRecord {
                signing_key,
                static_private,
                static_public,
                binding_proof,
                created_at: from_millis(created_at_ms),
            }))
        }
        None => Ok(None),
    }
}

// ===== 辅助 =====

fn store_err(e: rusqlite::Error) -> CoreError {
    CoreError::Store(e.to_string())
}
