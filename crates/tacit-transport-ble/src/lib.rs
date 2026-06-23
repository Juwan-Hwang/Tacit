//! Tacit-transport-ble：BLE Presence 适配。
//!
//! 职责：
//! - 仅广播/扫描 presence。
//! - 支持最小 rendezvous hint。
//! - 后台能力差异由平台层处理，不向上承诺数据面能力。
//!
//! Phase 0/1：提供抽象后端 trait + mock 实现，实际平台绑定（bluez/CoreBluetooth/WinRT）
//! 由 ffi 层注入。

pub mod backend;
pub mod presence;
pub mod transport;

pub use backend::{DiscoveryEvent, MockPresenceBackend, PresenceBackend};
pub use presence::BlePresence;
pub use transport::BleTransport;
