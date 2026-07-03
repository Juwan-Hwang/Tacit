//! 领域模型：枚举与结构定义。
//!
//! 本模块集中定义 Tacit 跨 crate 共享的领域类型。所有类型尽量保持
//! 纯数据形态，行为逻辑放在各自的服务 crate 中。

use std::time::SystemTime;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::frontier::Frontier;
use crate::ids::{BlockId, CheckpointId, DocId, PeerId, SessionId};

/// v1.0 支持的 block 类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockKind {
    /// 文本块。
    Text,
    /// 待办列表。
    Todo,
    /// 设置项。
    Settings,
    /// 追加式日志。
    Log,
}

/// peer 信任状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustState {
    /// 已配对信任。
    Trusted,
    /// 待确认（配对流程中）。
    Pending,
    /// 已吊销。
    Revoked,
}

/// 网络类型，影响传输策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkType {
    /// 无网络。
    Offline,
    /// 局域网/Wi-Fi。
    Lan,
    /// 广域网（移动网络/远程）。
    Wan,
}

/// 消息优先级。高优消息优先发送，必要时允许多通道竞速。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Priority {
    /// 用户前台实时输入、活跃 block 小增量、Meta-Document。
    High,
    /// ack、控制帧、设置变更。
    Medium,
    /// checkpoint、冷文档追赶、压缩任务。
    Low,
}

/// NAT 能力，影响 Anchor 选举与 relay 选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NatCapability {
    /// 可直连（公网可达或端口可映射）。
    Direct,
    /// 仅能出站连接。
    Cone,
    /// 对称 NAT，需 relay。
    Symmetric,
    /// 未知。
    Unknown,
}

/// Anchor 能力位。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorCapabilities {
    /// 是否可作为 Anchor。
    pub can_anchor: bool,
    /// 是否可作为 relay。
    pub can_relay: bool,
    /// 是否常驻（桌面设备）。
    pub persistent: bool,
}

/// 端点描述。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// 主机（IP 或主机名）。
    pub host: String,
    /// 端口。
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// 端口范围提示，用于 QUIC/relay 端口协商。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// 端口提示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortHint {
    /// 固定端口。
    Exact(u16),
    /// 端口范围。
    Range(PortRange),
}

/// 路径提示，指导 TransportManager 选择发送路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathHint {
    /// 优先 BLE。
    Ble,
    /// 优先 LAN QUIC。
    LanQuic,
    /// 优先 WAN QUIC。
    WanQuic,
    /// 优先 relay。
    Relay,
}

/// presence 广播提示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceHint {
    /// group_id。
    pub group_id: String,
    /// 广播设备自身的标识（用于 DiscoveryFrame 的 device_id 字段）。
    pub device_id: String,
    /// 设备能力位。
    pub capabilities: AnchorCapabilities,
    /// 可达端点（可选）。
    pub endpoint: Option<Endpoint>,
}

/// peer 记录，对应 `peers` 表。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub peer_id: PeerId,
    /// 设备公钥（hex 或 base64）。
    pub device_pubkey: String,
    pub capabilities: AnchorCapabilities,
    pub trust_state: TrustState,
    pub anchor_priority: i32,
    pub last_seen_at: SystemTime,
    pub last_endpoint: Option<Endpoint>,
    pub nat_capability: NatCapability,
    /// relay hint：建议使用的 relay peer。
    pub relay_hint: Option<PeerId>,
    /// 成功率指数移动平均（0.0 ~ 1.0），用于 Anchor 选举排序。
    pub success_ema: f64,
    /// 密钥轮换序号（单调递增，防止重放攻击）。
    ///
    /// 初始为 0，每次密钥轮换后 +1。与 `anchor_priority` 独立存储，
    /// 避免污染 Anchor 选举权重。
    #[serde(default)]
    pub rotation_seq: u64,
}

/// peer 在线状态摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSummary {
    pub peer_id: PeerId,
    pub online: bool,
    pub frontier: Frontier,
    pub capabilities: AnchorCapabilities,
}

/// ack 摘要。控制帧携带，用于 checkpoint 协调。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckSummary {
    pub peer_id: PeerId,
    pub doc_id: DocId,
    /// 最近确认的 checkpoint。
    pub ack_checkpoint: Option<CheckpointId>,
    /// 当前 ack frontier。
    pub ack_frontier: Frontier,
    pub updated_at: SystemTime,
    /// 可选版本覆盖信息（§13.2）。
    ///
    /// 当 peer 声明的协议/格式版本与本地不同时，携带此字段覆盖默认版本协商结果。
    /// v1.0 中通常为 `None`；后续多版本能力协商时启用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_override: Option<u32>,
}

/// 双水位：强安全与软安全。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Watermarks {
    /// 所有 active 设备都覆盖的 frontier。
    pub hard_frontier: Frontier,
    /// 超过阈值未上线设备移出 active 后可推进的 frontier。
    pub soft_frontier: Frontier,
}

/// 用户编辑输入。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserEdit {
    pub doc_id: DocId,
    pub block_id: BlockId,
    /// 编辑内容（Loro delta 字节或结构化编辑）。
    pub edit_bytes: Vec<u8>,
}

/// 本地应用编辑的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyResult {
    /// 应用后的新 frontier。
    pub new_frontier: Frontier,
    /// 是否产生了需要推送的 delta。
    pub has_delta: bool,
}

/// 导入远端数据的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportResult {
    pub new_frontier: Frontier,
    /// 是否实际改变了状态（幂等导入返回 false）。
    pub changed: bool,
}

/// 变更信封，用于 SyncEngine。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeEnvelope {
    pub doc_id: DocId,
    pub block_id: Option<BlockId>,
    pub delta: Bytes,
    pub frontier: Frontier,
}

/// 数据帧类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataFrameKind {
    /// 普通增量。
    Delta,
    /// shallow snapshot 分片。
    SnapshotChunk,
    /// 批次签名中的中间帧。
    BatchMiddle,
}

/// 数据帧，对应协议层数据帧。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFrame {
    pub doc_id: DocId,
    pub actor_id: PeerId,
    pub seq: u32,
    pub kind: DataFrameKind,
    pub payload: Bytes,
    pub session_id: SessionId,
}

/// 快照类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnapshotKind {
    /// 普通 checkpoint。
    Full,
    /// shallow snapshot，用于 GC/压缩与新设备追赶。
    Shallow,
}

/// 快照元数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub doc_id: DocId,
    pub checkpoint_id: CheckpointId,
    pub kind: SnapshotKind,
    pub frontier: Frontier,
    /// 内容哈希（用于校验）。
    pub state_hash: [u8; 32],
    pub created_at: SystemTime,
}

/// 快照分片，用于大 snapshot 分片传输。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunk {
    pub checkpoint_id: CheckpointId,
    /// 分片序号。
    pub index: u32,
    /// 总分片数。
    pub total: u32,
    pub data: Bytes,
}

/// 视口，用于只读查询时限定范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Viewport {
    pub start_block: usize,
    pub block_count: usize,
}

/// block 记录（Meta-Document 中的条目）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRecord {
    pub block_id: BlockId,
    pub kind: BlockKind,
    pub deleted: bool,
    pub updated_at: SystemTime,
}

/// 文档视图，返回给 UI 的只读快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentView {
    pub doc_id: DocId,
    pub blocks: Vec<BlockRecord>,
    pub frontier: Frontier,
}

/// 渲染模型，UI 渲染所需的最小数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderModel {
    pub doc_id: DocId,
    /// 视口内 block 的渲染数据。
    pub blocks: Vec<BlockRender>,
}

/// 单个 block 的渲染数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRender {
    pub block_id: BlockId,
    pub kind: BlockKind,
    /// 渲染所需的二进制（由平台层解码）。
    pub render_bytes: Bytes,
}
