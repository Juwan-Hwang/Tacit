//! BleTransport：实现 TransportManager trait。
//!
//! BLE 仅负责 presence 广播与发现，不承担数据面。
//! reconnect_peer 返回 Unsupported 错误。

use async_trait::async_trait;
use std::sync::Arc;
use tacit_core::{CoreError, CoreResult, DataFrame, NetworkType, PeerId, PresenceHint, Priority};
use tacit_transport::{SyncTransport, TransportManager, PathPreference, ControlMsg};
use tracing::{debug, warn};

use crate::presence::BlePresence;

/// BLE 传输：仅 presence，不承担数据面。
pub struct BleTransport {
    presence: Arc<BlePresence>,
}

impl BleTransport {
    /// 创建 BLE 传输。
    pub fn new(presence: Arc<BlePresence>) -> Self {
        Self { presence }
    }

    /// 获取 presence 管理器引用。
    pub fn presence(&self) -> &Arc<BlePresence> {
        &self.presence
    }
}

#[async_trait]
impl SyncTransport for BleTransport {
    async fn send_data(
        &self,
        _peer_id: &PeerId,
        _frame: DataFrame,
        _priority: Priority,
        _preferred_path: PathPreference,
    ) -> CoreResult<()> {
        Err(CoreError::Transport("BLE 不承担数据面".into()))
    }

    async fn send_control(
        &self,
        _peer_id: &PeerId,
        _msg: ControlMsg,
        _priority: Priority,
    ) -> CoreResult<()> {
        Err(CoreError::Transport("BLE 不承担控制面".into()))
    }

    async fn reconnect_peer(&self, _peer_id: &PeerId) -> CoreResult<()> {
        Err(CoreError::Transport("BLE 不支持数据面重连".into()))
    }

    async fn notify_network_changed(&self, online: bool, _net_type: NetworkType) -> CoreResult<()> {
        if !online {
            warn!("BLE 网络离线，停止广播与扫描");
            self.presence.stop_broadcast();
            self.presence.stop_scan();
        }
        Ok(())
    }
}

#[async_trait]
impl TransportManager for BleTransport {
    async fn broadcast_presence(&self, hint: PresenceHint) -> CoreResult<()> {
        debug!(group_id = %hint.group_id, "广播 presence");
        self.presence.broadcast(&hint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockPresenceBackend;
    use tacit_core::{AnchorCapabilities, Endpoint};

    fn hint() -> PresenceHint {
        PresenceHint {
            group_id: "g1".into(),
            device_id: "device-transport".into(),
            capabilities: AnchorCapabilities {
                can_anchor: true,
                can_relay: false,
                persistent: false,
            },
            endpoint: Some(Endpoint::new("127.0.0.1", 8080)),
        }
    }

    #[tokio::test]
    async fn broadcast_via_transport_manager() {
        let backend = Arc::new(MockPresenceBackend::new());
        let presence = Arc::new(BlePresence::new(backend.clone()));
        let transport = BleTransport::new(presence);
        transport.broadcast_presence(hint()).await.unwrap();
        assert!(backend.is_broadcasting());
    }

    #[tokio::test]
    async fn reconnect_returns_unsupported() {
        let backend = Arc::new(MockPresenceBackend::new());
        let presence = Arc::new(BlePresence::new(backend));
        let transport = BleTransport::new(presence);
        let result = SyncTransport::reconnect_peer(&transport, &PeerId::new("p1")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn network_offline_stops_broadcast() {
        let backend = Arc::new(MockPresenceBackend::new());
        let presence = Arc::new(BlePresence::new(backend.clone()));
        let transport = BleTransport::new(presence);
        transport.broadcast_presence(hint()).await.unwrap();
        assert!(backend.is_broadcasting());
        SyncTransport::notify_network_changed(&transport, false, NetworkType::Offline)
            .await
            .unwrap();
        assert!(!backend.is_broadcasting());
    }
}
