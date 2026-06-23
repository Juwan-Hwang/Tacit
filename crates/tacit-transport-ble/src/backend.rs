//! 平台后端抽象。
//!
//! [`PresenceBackend`] 是平台无关的 BLE 广播/扫描接口。
//! 实际平台实现（bluez/CoreBluetooth/WinRT）由 ffi 层注入。
//! Phase 0/1 提供 [`MockPresenceBackend`] 用于测试。

use std::collections::VecDeque;

use parking_lot::Mutex;
use tacit_core::{PeerId, PresenceHint};

/// 发现事件：扫描到附近 peer。
#[derive(Debug, Clone)]
pub struct DiscoveryEvent {
    /// 发现的 peer id。
    pub peer_id: PeerId,
    /// peer 携带的 presence hint。
    pub hint: PresenceHint,
    /// 信号强度（RSSI，dBm）。
    pub rssi: i16,
}

/// 平台后端抽象。
///
/// 实现者负责实际的 BLE 广播与扫描。
/// 所有方法同步调用，发现事件通过 [`PresenceBackend::drain_discoveries`] 拉取。
pub trait PresenceBackend: Send + Sync {
    /// 开始广播 presence payload。
    fn start_broadcast(&self, payload: Vec<u8>) -> tacit_core::CoreResult<()>;

    /// 停止广播。
    fn stop_broadcast(&self);

    /// 开始扫描。
    fn start_scan(&self) -> tacit_core::CoreResult<()>;

    /// 停止扫描。
    fn stop_scan(&self);

    /// 拉取自上次调用以来发现的事件。
    fn drain_discoveries(&self) -> Vec<DiscoveryEvent>;
}

/// Mock 后端：用于测试与单机回放。
pub struct MockPresenceBackend {
    broadcasting: Mutex<bool>,
    scanning: Mutex<bool>,
    payload: Mutex<Option<Vec<u8>>>,
    discoveries: Mutex<VecDeque<DiscoveryEvent>>,
}

impl Default for MockPresenceBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockPresenceBackend {
    /// 创建 mock 后端。
    pub fn new() -> Self {
        Self {
            broadcasting: Mutex::new(false),
            scanning: Mutex::new(false),
            payload: Mutex::new(None),
            discoveries: Mutex::new(VecDeque::new()),
        }
    }

    /// 注入一个发现事件（测试用）。
    pub fn inject_discovery(&self, event: DiscoveryEvent) {
        self.discoveries.lock().push_back(event);
    }

    /// 当前广播 payload。
    pub fn current_payload(&self) -> Option<Vec<u8>> {
        self.payload.lock().clone()
    }

    /// 是否正在广播。
    pub fn is_broadcasting(&self) -> bool {
        *self.broadcasting.lock()
    }

    /// 是否正在扫描。
    pub fn is_scanning(&self) -> bool {
        *self.scanning.lock()
    }
}

impl PresenceBackend for MockPresenceBackend {
    fn start_broadcast(&self, payload: Vec<u8>) -> tacit_core::CoreResult<()> {
        *self.broadcasting.lock() = true;
        *self.payload.lock() = Some(payload);
        Ok(())
    }

    fn stop_broadcast(&self) {
        *self.broadcasting.lock() = false;
        self.payload.lock().take();
    }

    fn start_scan(&self) -> tacit_core::CoreResult<()> {
        *self.scanning.lock() = true;
        Ok(())
    }

    fn stop_scan(&self) {
        *self.scanning.lock() = false;
    }

    fn drain_discoveries(&self) -> Vec<DiscoveryEvent> {
        self.discoveries.lock().drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_core::{AnchorCapabilities, Endpoint};

    fn hint() -> PresenceHint {
        PresenceHint {
            group_id: "g1".into(),
            capabilities: AnchorCapabilities {
                can_anchor: true,
                can_relay: false,
                persistent: false,
            },
            endpoint: Some(Endpoint::new("127.0.0.1", 8080)),
        }
    }

    #[test]
    fn mock_broadcast_and_scan() {
        let backend = MockPresenceBackend::new();
        backend.start_broadcast(vec![1, 2, 3]).unwrap();
        assert!(backend.is_broadcasting());
        assert_eq!(backend.current_payload(), Some(vec![1, 2, 3]));

        backend.start_scan().unwrap();
        assert!(backend.is_scanning());

        backend.stop_broadcast();
        assert!(!backend.is_broadcasting());
        backend.stop_scan();
        assert!(!backend.is_scanning());
    }

    #[test]
    fn mock_drain_discoveries() {
        let backend = MockPresenceBackend::new();
        backend.inject_discovery(DiscoveryEvent {
            peer_id: PeerId::new("p1"),
            hint: hint(),
            rssi: -60,
        });
        let events = backend.drain_discoveries();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].peer_id, PeerId::new("p1"));
        assert!(backend.drain_discoveries().is_empty());
    }
}
