//! Tacit-transport-ble：BLE Presence 适配。
//!
//! 职责：
//! - 仅广播/扫描 presence。
//! - 支持最小 rendezvous hint。
//! - 后台能力差异由平台层处理，不向上承诺数据面能力。
//!
//! 平台后端：
//! - [`MockPresenceBackend`]：内存 mock，用于测试与单机回放。
//! - [`BluerBackend`]（feature `linux-bluez`）：Linux bluez 真实 BLE 后端。

pub mod backend;
pub mod platform;
pub mod presence;
pub mod transport;

#[cfg(feature = "linux-bluez")]
pub mod bluer_backend;

pub use backend::{DiscoveryEvent, MockPresenceBackend, PresenceBackend};
pub use platform::{
    clear_platform_backend, get_platform_backend, has_platform_backend, require_platform_backend,
    set_platform_backend, PlatformBackendFactory,
};
pub use presence::BlePresence;
pub use transport::BleTransport;

#[cfg(feature = "linux-bluez")]
pub use bluer_backend::BluerBackend;
