//! Tacit-transport：传输抽象层。
//!
//! 定义 Transport trait、控制消息、传输事件与 preferred_path hint。
//! 本 crate 只定义抽象接口，具体实现见 tacit-transport-quic / -ble / -relay。
//!
//! 设计原则：
//! - SyncEngine 通过 [`SyncTransport`] trait 发送数据/控制消息，不直接接触网络。
//! - 传输层实现 [`SyncTransport`]，并把收到的事件通过回调或 channel 上报给 sync。
//! - preferred_path 仅作提示，传输层可自行决策。

pub mod control;
pub mod event;
pub mod transport;

pub use control::{ControlMsg, NeedRanges, PeerAnnouncement};
pub use event::TransportEvent;
pub use transport::{PathPreference, SyncTransport, TransportManager};
