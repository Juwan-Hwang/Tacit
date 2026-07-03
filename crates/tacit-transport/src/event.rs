//! 传输层事件。
//!
//! 传输层向 sync 层上报的事件。sync 层订阅这些事件以驱动状态机。

use serde::{Deserialize, Serialize};
use tacit_core::{DataFrame, DocId, PeerId};

/// 传输层事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportEvent {
    /// peer 上线。
    PeerOnline { peer_id: PeerId },
    /// peer 离线。
    PeerOffline { peer_id: PeerId },
    /// 收到对端控制消息。
    Control {
        peer_id: PeerId,
        msg: super::ControlMsg,
    },
    /// 收到对端数据帧。
    Data { peer_id: PeerId, frame: DataFrame },
    /// 网络状态变化。
    NetworkChanged { online: bool },
    /// 文档同步完成通知（传输层视角）。
    DocSynced { peer_id: PeerId, doc_id: DocId },
}
