//! Tacit-transport-quic：QUIC 传输适配。
//!
//! 职责：
//! - 基于 Quinn 的 LAN/WAN QUIC 适配。
//! - 管理 endpoint、peer 连接池、health check。
//! - network path 变化时主动断开并 fast-resume。
//! - 支持高优消息抢占发送。
//!
//! Phase 0/1：使用自签名证书 + rustls 跳过验证（开发阶段）。
//! 生产环境由 tacit-crypto 提供 Noise 握手后的 session key。

pub mod config;
pub mod transport;

pub use config::{generate_self_signed_cert, make_client_config, make_server_config};
pub use transport::{QuicTransport, QuicTransportConfig};
