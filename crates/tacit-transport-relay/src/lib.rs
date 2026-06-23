//! Tacit-transport-relay：Relay 协议实现。
//!
//! 职责：
//! - 客户端：注册 peer、建立会话级临时 ID、提交 admission proof。
//! - 服务端：校验 proof、映射 session_id -> peer_id、转发控制与数据流。
//! - 不做长期存储；可预留小 TTL 缓存扩展位。
//!
//! Phase 0/1：实现协议逻辑 + 内存 mock，实际网络传输由集成层注入。

pub mod admission;
pub mod client;
pub mod protocol;
pub mod server;

pub use admission::{generate_proof, verify_proof, AdmissionProof};
pub use client::RelayClient;
pub use protocol::{ForwardRequest, RegisterRequest, RelayMessage};
pub use server::RelayServer;
