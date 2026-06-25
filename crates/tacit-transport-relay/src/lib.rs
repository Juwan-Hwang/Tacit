//! Tacit-transport-relay：Relay 协议实现。
//!
//! 职责：
//! - 客户端：注册 peer、建立会话级临时 ID、提交 admission proof。
//! - 服务端：校验 proof、映射 session_id -> peer_id、转发控制与数据流。
//! - 不做长期存储；可预留小 TTL 缓存扩展位。
//! - 网络传输闭环：[`relay_transport`] 模块注入 QUIC 连接，实现端到端转发。
//!
//! Phase 0/1：实现协议逻辑 + 内存 mock + QUIC 网络传输闭环。

pub mod admission;
pub mod client;
pub mod protocol;
pub mod relay_transport;
pub mod server;

pub use admission::{generate_proof, verify_proof, AdmissionProof};
pub use client::RelayClient;
pub use protocol::{ForwardRequest, RegisterRequest, RelayMessage, RelayTier};
pub use relay_transport::{RelayClientTransport, RelayPushEvent, RelayServerRunner};
pub use server::RelayServer;
