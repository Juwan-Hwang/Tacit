//! 平台 BLE 后端注册接口。
//!
//! `PresenceBackend` trait 定义了平台无关的 BLE 广播/扫描接口。
//! 实际平台实现通过 FFI 注入：
//!
//! - **Linux**: [`BluerBackend`](crate::bluer_backend::BluerBackend)（feature `linux-bluez`）
//! - **Android**: 通过 FFI 回调注入 CoreBluetooth / Android BluetoothManager 实现
//! - **Apple (iOS/macOS)**: 通过 FFI 回调注入 CoreBluetooth 实现
//! - **测试**: [`MockPresenceBackend`](crate::MockPresenceBackend)
//!
//! 平台层通过 `set_platform_backend()` 注入实现，运行时动态绑定。
//! 这样 Rust 核心不需要链接平台特定库，由宿主 App 提供原生 BLE 能力。

use std::sync::Arc;

use parking_lot::RwLock;
use tacit_core::CoreResult;

use crate::backend::PresenceBackend;

/// 全局平台后端持有器。
///
/// 平台层（Android/iOS/macOS）在初始化时调用 [`set_platform_backend`] 注入
/// 原生 BLE 实现。Rust 核心通过 [`get_platform_backend`] 获取当前后端。
///
/// 设计模式：运行时依赖注入，避免编译期链接平台特定库。
static PLATFORM_BACKEND: once_cell::sync::Lazy<RwLock<Option<Arc<dyn PresenceBackend>>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(None));

/// 注入平台 BLE 后端。
///
/// 由宿主 App（Android Activity / iOS AppDelegate）在启动时调用。
/// 注入后，`BlePresence` 和 `BleTransport` 会自动使用此后端进行广播与扫描。
///
/// # 参数
/// - `backend`: 实现 [`PresenceBackend`] trait 的平台原生对象
///
/// # 示例
/// ```ignore
/// // Android (Kotlin) 侧通过 UniFFI 注入
/// // iOS (Swift) 侧通过 UniFFI 注入
/// tacit_ble::set_platform_backend(Box::new(MyAndroidBleBackend { ... }));
/// ```
pub fn set_platform_backend(backend: Arc<dyn PresenceBackend>) {
    *PLATFORM_BACKEND.write() = Some(backend);
}

/// 获取当前已注册的平台 BLE 后端。
///
/// 返回 `None` 表示尚未注入平台后端（如纯 Rust 测试环境）。
/// 调用方应处理 `None` 情况，降级为 Mock 后端或返回错误。
pub fn get_platform_backend() -> Option<Arc<dyn PresenceBackend>> {
    PLATFORM_BACKEND.read().clone()
}

/// 检查平台后端是否已注册。
pub fn has_platform_backend() -> bool {
    PLATFORM_BACKEND.read().is_some()
}

/// 清除已注册的平台后端（用于测试清理）。
pub fn clear_platform_backend() {
    *PLATFORM_BACKEND.write() = None;
}

/// 尝试获取平台后端，若未注册则返回错误。
pub fn require_platform_backend() -> CoreResult<Arc<dyn PresenceBackend>> {
    get_platform_backend().ok_or_else(|| {
        tacit_core::CoreError::Config(
            "平台 BLE 后端未注册。请先调用 set_platform_backend() 注入原生 BLE 实现".into(),
        )
    })
}

/// 平台后端工厂：创建并注入默认平台后端。
///
/// 此 trait 供平台层实现，提供延迟初始化能力。
/// 宿主 App 可实现此 trait 并通过 FFI 调用 `create_and_inject()` 完成注册。
pub trait PlatformBackendFactory: Send + Sync {
    /// 创建并返回平台 BLE 后端实例。
    fn create(&self) -> CoreResult<Arc<dyn PresenceBackend>>;

    /// 创建并立即注入到全局注册表。
    fn create_and_inject(&self) -> CoreResult<Arc<dyn PresenceBackend>> {
        let backend = self.create()?;
        set_platform_backend(backend.clone());
        Ok(backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockPresenceBackend;

    #[test]
    fn set_and_get_platform_backend() {
        clear_platform_backend();
        assert!(!has_platform_backend());

        let backend: Arc<dyn PresenceBackend> = Arc::new(MockPresenceBackend::new());
        set_platform_backend(backend);

        assert!(has_platform_backend());
        assert!(get_platform_backend().is_some());
        assert!(require_platform_backend().is_ok());

        clear_platform_backend();
        assert!(!has_platform_backend());
        assert!(require_platform_backend().is_err());
    }
}
