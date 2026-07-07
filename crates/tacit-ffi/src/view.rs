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

/// 单个 block 的渲染内容（FFI 友好）。
///
/// 用于 `DocumentViewWithContent`，移动端无需再逐个调用 `ffi_get_block_content`。
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiBlockContent {
    /// Block ID。
    pub block_id: String,
    /// Block 类型：`"text"`/`"todo"`/`"settings"`/`"log"`。
    pub kind: String,
    /// 渲染字节（Text 为 UTF-8 文本，Todo/Log 为 JSON 数组）。
    pub render_bytes: Vec<u8>,
}

/// 文档视图（含 block 渲染内容）。
///
/// 与 `DocumentView` 不同，此结构包含所有 block 的渲染数据，
/// 移动端无需再逐个调用 `ffi_get_block_content`，减少 FFI 调用开销。
#[derive(Debug, Clone, uniffi::Record)]
pub struct DocumentViewWithContent {
    /// 文档 ID。
    pub doc_id: String,
    /// 文档类型。
    pub kind: String,
    /// 所有 block ID 列表。
    pub block_ids: Vec<String>,
    /// 当前 frontier（JSON 字符串）。
    pub frontier_json: String,
    /// 所有 block 的渲染内容。
    pub blocks: Vec<FfiBlockContent>,
}

/// 同步状态。
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct SyncStatus {
    /// 待执行的同步动作数。
    pub pending_actions: u32,
    /// 依赖等待队列长度。
    pub pending_fetches: u32,
    /// 在线 peer 数。
    pub online_peers: u32,
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
    /// Store-and-forward 条目 ID（仅离线重发时有值）。
    /// FFI 宿主端在成功发送后应调用 `ffi_mark_delivered` 标记投递完成，
    /// 否则离线消息会在每次 peer 上线时无限重发。
    pub entry_id: Option<String>,
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

/// 设备身份的公开信息（FFI 友好）。
///
/// 只包含公钥和 PeerId，不暴露任何私钥。
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiDevicePublicInfo {
    /// Ed25519 验证公钥（32 字节）。
    pub verifying_key: Vec<u8>,
    /// X25519 静态公钥（32 字节）。
    pub static_public: Vec<u8>,
    /// 设备 PeerId（Ed25519 公钥的 hex）。
    pub peer_id: String,
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
