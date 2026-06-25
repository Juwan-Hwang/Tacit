//! FFI 视图类型。
//!
//! 不暴露 Rust 内部类型，只传递简单类型给平台层。

/// 文档视图。
#[derive(Debug, Clone, uniffi::Record)]
pub struct DocumentView {
    /// 文档 ID。
    pub doc_id: String,
    /// 文档类型。
    pub kind: String,
    /// 所有 block ID 列表。
    pub block_ids: Vec<String>,
    /// 当前 frontier（JSON 字符串）。
    pub frontier_json: String,
}

/// 同步状态。
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncStatus {
    /// 待执行的同步动作数。
    pub pending_actions: u32,
    /// 依赖等待队列长度。
    pub pending_fetches: u32,
    /// 在线 peer 数。
    pub online_peers: u32,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            pending_actions: 0,
            pending_fetches: 0,
            online_peers: 0,
        }
    }
}

/// 发送数据动作（对应 SyncAction::SendData）。
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSendDataAction {
    pub peer_id: String,
    pub doc_id: String,
    pub block_id: Option<String>,
    pub data: Vec<u8>,
    /// 优先级：0=High, 1=Medium, 2=Low。
    pub priority: u8,
    /// 路径偏好："any"/"ble"/"lan_quic"/"wan_quic"/"relay"。
    pub path: String,
}

/// 发送控制消息动作（对应 SyncAction::SendControl）。
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSendControlAction {
    pub peer_id: String,
    /// 控制消息的 JSON 序列化。
    pub msg_json: String,
    /// 优先级：0=High, 1=Medium, 2=Low。
    pub priority: u8,
}

/// 请求 delta 动作（对应 SyncAction::RequestDelta）。
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRequestDeltaAction {
    pub peer_id: String,
    pub doc_id: String,
    pub block_id: Option<String>,
    /// since frontier 的 JSON 序列化。
    pub since_json: String,
    /// 优先级：0=High, 1=Medium, 2=Low。
    pub priority: u8,
}

/// FFI 友好的同步动作枚举。
///
/// 集成层通过 `ffi_drain_actions` 获取动作列表后，
/// 根据动作类型执行实际的网络发送。
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiSyncAction {
    /// 发送数据帧。
    SendData { action: FfiSendDataAction },
    /// 发送控制消息。
    SendControl { action: FfiSendControlAction },
    /// 请求对端发送 delta。
    RequestDelta { action: FfiRequestDeltaAction },
    /// 事件通知（JSON 序列化的 CoreEvent）。
    EmitEvent { event_json: String },
}
