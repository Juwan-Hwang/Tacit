//! Tacit-transport-relay：Relay 协议实现。
//!
//! 职责：
//! - 客户端：注册 peer、建立会话级临时 ID、提交 admission proof。
//! - 服务端：校验 proof、映射 session_id -> peer_id、转发控制与数据流。
//! - 不做长期存储；可预留小 TTL 缓存扩展位。
//!
//! Phase 0 占位：实际实现见后续 commit。
