//! 控制消息定义。
//!
//! 对应协议层 Control Frame 的 TLV payload 类型（v1.0 规范 13.2）。
//! sync 层通过这些消息与对端协调 frontier、缺口、能力。

use serde::{Deserialize, Serialize};
use tacit_core::{AckSummary, AnchorCapabilities, CheckpointId, DocId, Frontier, PeerId};

/// 控制消息。对应 Control Frame payload 的 TLV 类型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMsg {
    /// 能力公告。会话建立后交换。
    Capabilities(PeerAnnouncement),
    /// 已知 checkpoint 摘要，用于协调压缩边界。
    KnownCheckpoint {
        peer_id: PeerId,
        doc_id: DocId,
        checkpoint: Option<CheckpointId>,
        frontier: Frontier,
    },
    /// ack 摘要。
    AckSummary(AckSummary),
    /// 缺口请求：请求对端发送自 `since` 之后的 delta。
    NeedRanges(NeedRanges),
    /// 同步意图：表明本端希望开始同步。
    SyncIntent {
        peer_id: PeerId,
        doc_id: DocId,
    },
}

/// peer 公告信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    pub peer_id: PeerId,
    pub capabilities: AnchorCapabilities,
    /// 当前已知 frontier（按 doc 聚合，可选）。
    pub frontier: Frontier,
}

/// 缺口请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeedRanges {
    pub doc_id: DocId,
    /// None 表示请求 Meta-Document；Some(block_id) 表示请求指定 block。
    pub block_id: Option<String>,
    /// 请求自该 frontier 之后的增量。
    pub since: Frontier,
}
