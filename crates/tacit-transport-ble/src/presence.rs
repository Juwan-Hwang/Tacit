//! BLE Presence 管理器。
//!
//! 包装 [`PresenceBackend`]，提供序列化的 presence 广播与发现事件拉取。
//! PresenceHint 序列化为 JSON 作为 BLE 广播 payload（Phase 0 简化）。

use std::sync::Arc;

use tacit_core::{CoreResult, PresenceHint};

use crate::backend::{DiscoveryEvent, PresenceBackend};

/// BLE Presence 管理器。
pub struct BlePresence {
    backend: Arc<dyn PresenceBackend>,
}

impl BlePresence {
    /// 创建 presence 管理器。
    pub fn new(backend: Arc<dyn PresenceBackend>) -> Self {
        Self { backend }
    }

    /// 广播 presence hint。
    ///
    /// 将 hint 序列化为 JSON 作为广播 payload。
    /// Phase 0 简化：实际 BLE 广播有 31 字节限制，生产环境需压缩编码。
    pub fn broadcast(&self, hint: &PresenceHint) -> CoreResult<()> {
        let payload = serde_json::to_vec(hint)
            .map_err(|e| tacit_core::CoreError::Serialize(e.to_string()))?;
        self.backend.start_broadcast(payload)
    }

    /// 停止广播。
    pub fn stop_broadcast(&self) {
        self.backend.stop_broadcast();
    }

    /// 开始扫描附近 peer。
    pub fn start_scan(&self) -> CoreResult<()> {
        self.backend.start_scan()
    }

    /// 停止扫描。
    pub fn stop_scan(&self) {
        self.backend.stop_scan();
    }

    /// 拉取发现的 peer 事件。
    pub fn drain_discoveries(&self) -> Vec<DiscoveryEvent> {
        self.backend.drain_discoveries()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockPresenceBackend;
    use tacit_core::{AnchorCapabilities, Endpoint, PeerId};

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
    fn broadcast_serializes_hint() {
        let backend = Arc::new(MockPresenceBackend::new());
        let presence = BlePresence::new(backend.clone());
        presence.broadcast(&hint()).unwrap();
        assert!(backend.is_broadcasting());
        let payload = backend.current_payload().unwrap();
        let parsed: PresenceHint = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed.group_id, "g1");
    }

    #[test]
    fn scan_and_drain() {
        let backend = Arc::new(MockPresenceBackend::new());
        let presence = BlePresence::new(backend.clone());
        presence.start_scan().unwrap();
        backend.inject_discovery(DiscoveryEvent {
            peer_id: PeerId::new("p1"),
            hint: hint(),
            rssi: -50,
        });
        let events = presence.drain_discoveries();
        assert_eq!(events.len(), 1);
        presence.stop_scan();
        assert!(!backend.is_scanning());
    }
}
