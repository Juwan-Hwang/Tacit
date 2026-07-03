//! Tacit-transport-sms：Data SMS 实验性传输适配器。
//!
//! 实现 Tacit-v1.0-FINAL.md §2.2 / §11.1 的 Data SMS 实验性适配器。
//!
//! ## 定位
//!
//! Data SMS **不进入核心路径**，作为极端离线场景（无 IP 连接但 GSM 可用）的兜底通道：
//! - 传输控制帧（AckSummary、NeedRanges 等）
//! - 传输小型数据帧（≤ 10 KB 的文本 delta），让同步可以真正完成
//! - 超过 10 KB 的帧被拒绝，等待 IP 恢复后走 QUIC
//!
//! ## SMS 数据面可行性
//!
//! | 场景 | delta 大小 | SMS 条数 | 传输时间 |
//! |------|-----------|---------|---------|
//! | 待办勾选 | ~50 B | 1 条 | <0.1s |
//! | 短文本编辑 | ~200 B | 2 条 | ~0.2s |
//! | 段落修改 | ~1 KB | 8 条 | ~0.8s |
//! | 大 delta（上限）| ~10 KB | ~75 条 | ~7.5s |
//! | snapshot 分片 | ~64 KB | 拒绝 | N/A |
//!
//! 小型文本编辑通过 SMS 同步是可行的。大对象等待 IP 恢复。
//!
//! ## 设计
//!
//! 与 BLE 适配器对齐：
//! - [`SmsBackend`] trait：平台无关的 SMS 收发接口
//! - [`MockSmsBackend`]：内存 mock，用于测试与单机回放
//! - [`SmsTransport`]：实现 [`SyncTransport`]，控制面 + 小型数据面
//! - [`codec`]：SMS 分片 / 重组 codec（4 字节头：index/total/msg_id/frame_type）
//!
//! 平台后端通过 FFI 注入（与 BLE 的 `set_platform_backend` 模式一致）。

pub mod backend;
pub mod codec;
pub mod transport;

pub use backend::{MockSmsBackend, SmsBackend, SmsMessage};
pub use codec::{
    SmsSegmentCodec, FRAME_TYPE_CONTROL, FRAME_TYPE_DATA, MAX_SEGMENT_PAYLOAD_LEN,
    MAX_SMS_PAYLOAD_LEN,
};
pub use transport::{SmsTransport, MAX_SMS_DATA_PAYLOAD};
