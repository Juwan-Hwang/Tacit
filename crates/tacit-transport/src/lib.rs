//! Tacit-transport：传输抽象层。
//!
//! 定义 Transport trait、控制消息、传输事件与 preferred_path hint。
//! 本 crate 只定义抽象接口，具体实现见 tacit-transport-quic / -ble / -relay。
//!
//! 设计原则：
//! - SyncEngine 通过 [`SyncTransport`] trait 发送数据/控制消息，不直接接触网络。
//! - 传输层实现 [`SyncTransport`]，并把收到的事件通过回调或 channel 上报给 sync。
//! - preferred_path 仅作提示，传输层可自行决策。
//! - 协议帧编解码使用 [`frame_codec`] 模块（v1.0 规范第 13 节二进制帧格式）。
//! - 批次签名使用 [`batch`] 模块（v1.0 规范第 13.4 节）。
//! - 能力协商使用 [`negotiation`] 模块（v1.0 规范第 14 节）。
//! - mDNS 发现使用 [`mdns`] 模块（v1.0 规范第 12 节）。
//! - Store-and-forward 使用 [`store_forward`] 模块（v1.0 规范第 15 节）。
//! - Snapshot 分片重组使用 [`snapshot_reassembly`] 模块（v1.0 规范第 8 节）。

pub mod batch;
pub mod control;
pub mod event;
pub mod frame_codec;
pub mod mdns;
pub mod multiplexer;
pub mod negotiation;
pub mod snapshot_reassembly;
pub mod store_forward;
pub mod transport;

pub use batch::{BatchSigner, BatchVerifier};
pub use control::{
    ControlMsg, IntroducePeer, KeyRotateNotice, NeedRanges, PeerAnnouncement, RelayHints,
    RevokePeer, TransportHints,
};
pub use event::TransportEvent;
pub use frame_codec::{
    decode_control, decode_data, decode_discovery, encode_control, encode_data, encode_discovery,
    MAX_FRAME_SIZE,
};
pub use mdns::{DiscoveredPeer, MdnsDiscovery, MDNS_SERVICE_TYPE};
pub use multiplexer::{ChannelKind, TransportMultiplexer};
pub use negotiation::CapabilityNegotiator;
pub use snapshot_reassembly::SnapshotReassembler;
pub use store_forward::StoreAndForward;
pub use transport::{PathPreference, SyncTransport, TransportManager};
