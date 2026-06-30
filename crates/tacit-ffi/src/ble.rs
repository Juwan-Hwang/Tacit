//! BLE 平台注入：UniFFI 回调接口。
//!
//! 平台层（Android/iOS/macOS）实现 [`ForeignPresenceBackend`] trait，
//! 通过 [`ffi_set_ble_backend`] 注入原生 BLE 广播/扫描能力。
//!
//! 设计模式与 [`ForeignEventListener`](crate::listener::ForeignEventListener) 一致：
//! - Rust 核心定义 `PresenceBackend` trait（同步接口）。
//! - UniFFI 导出 `ForeignPresenceBackend` 回调 trait，平台层实现。
//! - `ForeignBleAdapter` 将 `ForeignPresenceBackend` 适配为 `PresenceBackend`。
//! - 平台层在 App 启动时调用 `ffi_set_ble_backend` 注入实现。
//!
//! 类型转换：
//! - `PresenceHint` / `AnchorCapabilities` / `Endpoint` 包含 newtype，
//!   无法直接作为 UniFFI Record 导出，因此定义 FFI 友好的简化类型。
//! - `DiscoveryEvent` 中的 `peer_id` 为 `PeerId`（newtype），转为 `String`。

use std::sync::Arc;

use tacit_core::{AnchorCapabilities, Endpoint, PeerId, PresenceHint};
use tacit_transport_ble::{DiscoveryEvent, PresenceBackend};

// ── FFI 友好类型 ──────────────────────────────────────────────

/// FFI 端点描述。
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiEndpoint {
    /// 主机（IP 或主机名）。
    pub host: String,
    /// 端口。
    pub port: u16,
}

/// FFI Anchor 能力位。
#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct FfiAnchorCapabilities {
    /// 是否可作为 Anchor。
    pub can_anchor: bool,
    /// 是否可作为 relay。
    pub can_relay: bool,
    /// 是否常驻（桌面设备）。
    pub persistent: bool,
}

/// FFI Presence 提示。
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPresenceHint {
    /// group_id。
    pub group_id: String,
    /// 广播设备标识。
    pub device_id: String,
    /// 设备能力位。
    pub capabilities: FfiAnchorCapabilities,
    /// 可达端点（可选）。
    pub endpoint: Option<FfiEndpoint>,
}

/// FFI 发现事件：扫描到附近 peer。
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiDiscoveryEvent {
    /// 发现的 peer id。
    pub peer_id: String,
    /// peer 携带的 presence hint。
    pub hint: FfiPresenceHint,
    /// 信号强度（RSSI，dBm）。
    pub rssi: i16,
}

// ── 类型转换 ──────────────────────────────────────────────────

impl From<&PresenceHint> for FfiPresenceHint {
    fn from(h: &PresenceHint) -> Self {
        Self {
            group_id: h.group_id.clone(),
            device_id: h.device_id.clone(),
            capabilities: FfiAnchorCapabilities {
                can_anchor: h.capabilities.can_anchor,
                can_relay: h.capabilities.can_relay,
                persistent: h.capabilities.persistent,
            },
            endpoint: h.endpoint.as_ref().map(|e| FfiEndpoint {
                host: e.host.clone(),
                port: e.port,
            }),
        }
    }
}

impl From<&DiscoveryEvent> for FfiDiscoveryEvent {
    fn from(e: &DiscoveryEvent) -> Self {
        Self {
            peer_id: e.peer_id.as_str().to_string(),
            hint: FfiPresenceHint::from(&e.hint),
            rssi: e.rssi,
        }
    }
}

// ── UniFFI 回调 trait ─────────────────────────────────────────

/// UniFFI 回调接口：平台层实现此接口提供原生 BLE 能力。
///
/// Kotlin/Swift 实现此 trait 后，通过 [`ffi_set_ble_backend`] 注入到 Rust 核心。
/// 所有方法同步调用，发现事件通过 [`ForeignPresenceBackend::drain_discoveries`] 拉取。
#[uniffi::export(with_foreign)]
pub trait ForeignPresenceBackend: Send + Sync {
    /// 开始广播 presence payload。
    ///
    /// `payload`：已编码的 BLE 广播 payload（≤31 字节）。
    /// 返回错误字符串，成功返回空字符串。
    fn start_broadcast(&self, payload: Vec<u8>) -> String;

    /// 停止广播。
    fn stop_broadcast(&self);

    /// 开始扫描。
    ///
    /// 返回错误字符串，成功返回空字符串。
    fn start_scan(&self) -> String;

    /// 停止扫描。
    fn stop_scan(&self);

    /// 拉取自上次调用以来发现的事件。
    ///
    /// 返回 FFI 友好的发现事件列表。
    fn drain_discoveries(&self) -> Vec<FfiDiscoveryEvent>;
}

// ── 适配器 ────────────────────────────────────────────────────

/// 将 `ForeignPresenceBackend` 适配为 `PresenceBackend`。
///
/// 平台层注入的 `ForeignPresenceBackend` 通过此适配器融入 Rust 核心的
/// `PresenceBackend` 体系，使 `BlePresence` / `BleTransport` 透明使用原生 BLE。
struct ForeignBleAdapter {
    inner: Arc<dyn ForeignPresenceBackend>,
}

impl ForeignBleAdapter {
    fn new(inner: Arc<dyn ForeignPresenceBackend>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

impl PresenceBackend for ForeignBleAdapter {
    fn start_broadcast(&self, payload: Vec<u8>) -> tacit_core::CoreResult<()> {
        let err = self.inner.start_broadcast(payload);
        if err.is_empty() {
            Ok(())
        } else {
            Err(tacit_core::CoreError::Transport(format!(
                "平台 BLE 广播失败: {err}"
            )))
        }
    }

    fn stop_broadcast(&self) {
        self.inner.stop_broadcast();
    }

    fn start_scan(&self) -> tacit_core::CoreResult<()> {
        let err = self.inner.start_scan();
        if err.is_empty() {
            Ok(())
        } else {
            Err(tacit_core::CoreError::Transport(format!(
                "平台 BLE 扫描失败: {err}"
            )))
        }
    }

    fn stop_scan(&self) {
        self.inner.stop_scan();
    }

    fn drain_discoveries(&self) -> Vec<DiscoveryEvent> {
        self.inner
            .drain_discoveries()
            .into_iter()
            .map(|e| DiscoveryEvent {
                peer_id: PeerId::new(&e.peer_id),
                hint: PresenceHint {
                    group_id: e.hint.group_id,
                    device_id: e.hint.device_id,
                    capabilities: AnchorCapabilities {
                        can_anchor: e.hint.capabilities.can_anchor,
                        can_relay: e.hint.capabilities.can_relay,
                        persistent: e.hint.capabilities.persistent,
                    },
                    endpoint: e.hint.endpoint.map(|ep| Endpoint::new(ep.host, ep.port)),
                },
                rssi: e.rssi,
            })
            .collect()
    }
}

// ── UniFFI 导出函数 ───────────────────────────────────────────

/// 注入平台 BLE 后端。
///
/// 由宿主 App（Android Activity / iOS AppDelegate）在启动时调用。
/// 注入后，`BlePresence` 和 `BleTransport` 会自动使用此后端进行广播与扫描。
///
/// # 参数
/// - `backend`: 实现 [`ForeignPresenceBackend`] trait 的平台原生对象
///
/// # 返回
/// 成功返回空字符串，失败返回错误信息。
#[uniffi::export]
pub fn ffi_set_ble_backend(backend: Arc<dyn ForeignPresenceBackend>) -> String {
    let adapter = ForeignBleAdapter::new(backend);
    tacit_transport_ble::set_platform_backend(adapter);
    String::new()
}

/// 检查平台 BLE 后端是否已注册。
#[uniffi::export]
pub fn ffi_has_ble_backend() -> bool {
    tacit_transport_ble::has_platform_backend()
}

/// 清除已注册的平台 BLE 后端（用于测试清理）。
#[uniffi::export]
pub fn ffi_clear_ble_backend() {
    tacit_transport_ble::clear_platform_backend();
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    /// 测试用 ForeignPresenceBackend 实现。
    struct MockForeignBle {
        broadcasting: Mutex<bool>,
        scanning: Mutex<bool>,
        payload: Mutex<Option<Vec<u8>>>,
        discoveries: Mutex<Vec<FfiDiscoveryEvent>>,
    }

    impl MockForeignBle {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                broadcasting: Mutex::new(false),
                scanning: Mutex::new(false),
                payload: Mutex::new(None),
                discoveries: Mutex::new(Vec::new()),
            })
        }
    }

    impl ForeignPresenceBackend for MockForeignBle {
        fn start_broadcast(&self, payload: Vec<u8>) -> String {
            *self.broadcasting.lock() = true;
            *self.payload.lock() = Some(payload);
            String::new()
        }

        fn stop_broadcast(&self) {
            *self.broadcasting.lock() = false;
            self.payload.lock().take();
        }

        fn start_scan(&self) -> String {
            *self.scanning.lock() = true;
            String::new()
        }

        fn stop_scan(&self) {
            *self.scanning.lock() = false;
        }

        fn drain_discoveries(&self) -> Vec<FfiDiscoveryEvent> {
            self.discoveries.lock().drain(..).collect()
        }
    }

    #[test]
    fn foreign_backend_adapts_to_presence_backend() {
        let foreign = MockForeignBle::new();
        let adapter = ForeignBleAdapter::new(foreign.clone());

        // 测试广播
        adapter.start_broadcast(vec![1, 2, 3]).unwrap();
        assert!(*foreign.broadcasting.lock());
        assert_eq!(foreign.payload.lock().clone(), Some(vec![1, 2, 3]));

        // 测试停止广播
        adapter.stop_broadcast();
        assert!(!*foreign.broadcasting.lock());

        // 测试扫描
        adapter.start_scan().unwrap();
        assert!(*foreign.scanning.lock());
        adapter.stop_scan();
        assert!(!*foreign.scanning.lock());
    }

    #[test]
    fn foreign_backend_drain_discoveries_converts_types() {
        let foreign = MockForeignBle::new();
        let adapter = ForeignBleAdapter::new(foreign.clone());

        // 注入一个 FFI 发现事件
        foreign.discoveries.lock().push(FfiDiscoveryEvent {
            peer_id: "peer-001".into(),
            hint: FfiPresenceHint {
                group_id: "group-1".into(),
                device_id: "device-1".into(),
                capabilities: FfiAnchorCapabilities {
                    can_anchor: true,
                    can_relay: false,
                    persistent: false,
                },
                endpoint: Some(FfiEndpoint {
                    host: "192.168.1.1".into(),
                    port: 8080,
                }),
            },
            rssi: -55,
        });

        let events = adapter.drain_discoveries();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].peer_id, PeerId::new("peer-001"));
        assert_eq!(events[0].hint.group_id, "group-1");
        assert_eq!(events[0].hint.device_id, "device-1");
        assert!(events[0].hint.capabilities.can_anchor);
        assert_eq!(events[0].rssi, -55);
        assert_eq!(
            events[0].hint.endpoint,
            Some(Endpoint::new("192.168.1.1", 8080))
        );

        // 再次拉取应为空
        assert!(adapter.drain_discoveries().is_empty());
    }

    #[test]
    fn ffi_set_and_clear_ble_backend() {
        ffi_clear_ble_backend();
        assert!(!ffi_has_ble_backend());

        let foreign = MockForeignBle::new();
        let err = ffi_set_ble_backend(foreign);
        assert!(err.is_empty());
        assert!(ffi_has_ble_backend());

        ffi_clear_ble_backend();
        assert!(!ffi_has_ble_backend());
    }

    #[test]
    fn ffi_presence_hint_conversion_roundtrip() {
        let original = PresenceHint {
            group_id: "g1".into(),
            device_id: "dev1".into(),
            capabilities: AnchorCapabilities {
                can_anchor: true,
                can_relay: true,
                persistent: false,
            },
            endpoint: Some(Endpoint::new("10.0.0.1", 9999)),
        };

        let ffi_hint = FfiPresenceHint::from(&original);
        assert_eq!(ffi_hint.group_id, "g1");
        assert_eq!(ffi_hint.device_id, "dev1");
        assert!(ffi_hint.capabilities.can_anchor);
        assert!(ffi_hint.capabilities.can_relay);
        assert!(!ffi_hint.capabilities.persistent);
        assert_eq!(ffi_hint.endpoint.as_ref().unwrap().host, "10.0.0.1");
        assert_eq!(ffi_hint.endpoint.as_ref().unwrap().port, 9999);
    }

    #[test]
    fn error_propagation_from_foreign_backend() {
        struct ErrorBackend;
        impl ForeignPresenceBackend for ErrorBackend {
            fn start_broadcast(&self, _payload: Vec<u8>) -> String {
                "BLE not available".into()
            }
            fn stop_broadcast(&self) {}
            fn start_scan(&self) -> String {
                "Scan permission denied".into()
            }
            fn stop_scan(&self) {}
            fn drain_discoveries(&self) -> Vec<FfiDiscoveryEvent> {
                Vec::new()
            }
        }

        let adapter = ForeignBleAdapter::new(Arc::new(ErrorBackend));
        let result = adapter.start_broadcast(vec![]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("BLE not available"));

        let result = adapter.start_scan();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Scan permission denied"));
    }

    /// 验证 ForeignBleAdapter 与 MockPresenceBackend 的行为一致性。
    #[test]
    fn foreign_adapter_compatible_with_ble_presence() {
        use tacit_transport_ble::BlePresence;

        let foreign = MockForeignBle::new();
        let adapter = ForeignBleAdapter::new(foreign.clone());
        let presence = BlePresence::new(adapter);

        let hint = PresenceHint {
            group_id: "g1".into(),
            device_id: "dev1".into(),
            capabilities: AnchorCapabilities {
                can_anchor: true,
                can_relay: false,
                persistent: false,
            },
            endpoint: None,
        };

        presence.broadcast(&hint).unwrap();
        assert!(*foreign.broadcasting.lock());

        presence.start_scan().unwrap();
        assert!(*foreign.scanning.lock());

        presence.stop_broadcast();
        assert!(!*foreign.broadcasting.lock());

        presence.stop_scan();
        assert!(!*foreign.scanning.lock());
    }
}
