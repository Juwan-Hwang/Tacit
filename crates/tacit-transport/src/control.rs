//! 控制消息定义。
//!
//! 对应协议层 Control Frame 的 TLV payload 类型（v1.0 规范 13.2）。
//! sync 层通过这些消息与对端协调 frontier、缺口、能力。
//!
//! v1.0 规范定义的 TLV 类型包括：
//! Capabilities、KnownCheckpoint、AckSummary、NeedRanges、
//! TransportHints、RelayHints、Introduce、Revoke、KeyRotate。

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
    SyncIntent { peer_id: PeerId, doc_id: DocId },
    /// 传输提示：告知对端本端偏好的传输路径与参数。
    TransportHints(TransportHints),
    /// 中继提示：告知对端可用的中继服务器信息。
    RelayHints(RelayHints),
    /// 介绍消息：向对端介绍另一个已知 peer（用于 NAT 穿透场景）。
    Introduce(IntroducePeer),
    /// 撤销消息：撤销某个 peer 的访问权限。
    Revoke(RevokePeer),
    /// 密钥轮换通知：告知对端已轮换会话密钥。
    KeyRotate(KeyRotateNotice),
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

/// 传输提示：告知对端本端偏好的传输路径与参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportHints {
    pub peer_id: PeerId,
    /// 偏好路径类型：如 "lan"、"wan"、"relay"。
    pub preferred_path: String,
    /// 建议的最大传输单元。
    pub mtu: Option<u16>,
}

/// 中继提示：告知对端可用的中继服务器信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayHints {
    pub peer_id: PeerId,
    /// 中继服务器地址（host:port）。
    pub relay_addr: String,
    /// 中继服务器是否需要认证。
    pub requires_auth: bool,
}

/// 介绍消息：向对端介绍另一个已知 peer。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntroducePeer {
    pub introducer: PeerId,
    /// 被介绍的 peer 的 PeerId。
    pub introduced_peer: PeerId,
    /// 被介绍的 peer 的公钥（Ed25519 验证密钥，hex 编码）。
    pub introduced_pubkey_hex: String,
    /// 被介绍的 peer 的可达地址（如 host:port），可选。
    pub endpoint: Option<String>,
}

/// 撤销消息：撤销某个 peer 的访问权限。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokePeer {
    pub revoker: PeerId,
    /// 被撤销的 peer 的 PeerId。
    pub revoked_peer: PeerId,
    /// 撤销原因。
    pub reason: String,
}

/// 密钥轮换通知。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotateNotice {
    pub peer_id: PeerId,
    /// 新公钥的 hex 编码（轮换后的 Ed25519 验证密钥）。
    pub new_pubkey_hex: String,
    /// 轮换序号，单调递增。
    pub rotation_seq: u64,
    /// 轮换签名：用**旧**私钥对 `peer_id:new_pubkey_hex:rotation_seq` 的 Ed25519 签名（64 字节）。
    ///
    /// 接收方用旧公钥验证，防止第三方伪造轮换通知劫持身份。
    pub signature: Vec<u8>,
}
