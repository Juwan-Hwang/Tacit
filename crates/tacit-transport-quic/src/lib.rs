//! Tacit-transport-quic：QUIC 传输适配。
//!
//! 职责：
//! - 基于 Quinn 的 LAN/WAN QUIC 适配。
//! - 管理 endpoint、peer 连接池、health check。
//! - network path 变化时主动断开并 fast-resume。
//! - 支持高优消息抢占发送。
//!
//! Phase 0 占位：实际实现见后续 commit。
