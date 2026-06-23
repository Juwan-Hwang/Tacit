//! 统一事件模型。
//!
//! 平台层订阅这些事件以驱动 UI 更新。收到 `ConflictMerged` 后，
//! 优先使用差量渲染或列表 diff 动画，而不是整页重载。

use serde::{Deserialize, Serialize};

use crate::ids::{BlockId, DocId, PeerId};

/// 同步触发原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyncReason {
    /// 用户前台触发。
    UserForeground,
    /// 网络恢复后 fast-resume。
    FastResume,
    /// peer 上线。
    PeerOnline,
    /// 定时心跳。
    Heartbeat,
    /// 检测到缺口。
    GapDetected,
}

/// 同步阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyncStage {
    /// 交换 frontier。
    Negotiate,
    /// 同步 Meta-Document。
    MetaDoc,
    /// 拉取 block。
    PullBlocks,
    /// 依赖等待。
    WaitDependency,
    /// 完成。
    Done,
}

/// 错误作用域，用于事件分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorScope {
    Store,
    Crdt,
    Transport,
    Crypto,
    Sync,
    Config,
}

/// 核心事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoreEvent {
    SyncStarted {
        peer_id: PeerId,
        reason: SyncReason,
    },
    SyncProgress {
        doc_id: DocId,
        stage: SyncStage,
        progress: f32,
    },
    SyncBlockedOnDependency {
        doc_id: DocId,
        block_id: BlockId,
    },
    SyncCompleted {
        peer_id: PeerId,
    },
    PeerStatusChanged {
        peer_id: PeerId,
        online: bool,
    },
    AnchorChanged {
        old: Option<PeerId>,
        new: Option<PeerId>,
    },
    ConflictMerged {
        doc_id: DocId,
        block_id: Option<BlockId>,
    },
    ErrorRaised {
        scope: ErrorScope,
        message: String,
    },
}
