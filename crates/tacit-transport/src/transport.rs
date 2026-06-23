//! Transport trait 定义。
//!
//! - [`SyncTransport`]：sync 层使用的发送接口，由具体传输层实现。
//! - [`TransportManager`]：高层管理接口（蓝图定义），负责连接池、presence、网络变化。

use async_trait::async_trait;
use tacit_core::{
    CoreResult, DataFrame, NetworkType, PeerId, PresenceHint, Priority,
};

use crate::ControlMsg;

/// 路径偏好提示。传输层可参考但不强制。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PathPreference {
    /// 无偏好，由传输层决策。
    #[default]
    Any,
    /// 优先 BLE。
    Ble,
    /// 优先 LAN QUIC。
    LanQuic,
    /// 优先 WAN QUIC。
    WanQuic,
    /// 优先 relay。
    Relay,
}

/// sync 层使用的发送接口。
///
/// 具体传输层（quic/ble/relay）实现此 trait，sync 层通过它发送数据/控制消息。
/// 收到对端消息时，传输层通过 [`crate::TransportEvent`] 上报。
#[async_trait]
pub trait SyncTransport: Send + Sync {
    /// 发送数据帧给指定 peer。
    async fn send_data(
        &self,
        peer_id: &PeerId,
        frame: DataFrame,
        priority: Priority,
        preferred_path: PathPreference,
    ) -> CoreResult<()>;

    /// 发送控制消息给指定 peer。
    async fn send_control(
        &self,
        peer_id: &PeerId,
        msg: ControlMsg,
        priority: Priority,
    ) -> CoreResult<()>;

    /// 请求重连 peer。
    async fn reconnect_peer(&self, peer_id: &PeerId) -> CoreResult<()>;

    /// 通知网络状态变化。
    async fn notify_network_changed(&self, online: bool, net_type: NetworkType) -> CoreResult<()>;
}

/// 高层传输管理接口（蓝图定义）。
///
/// 负责连接池、presence 广播、网络变化通知。
/// 由 tacit-ffi 或集成层持有，协调多个传输实现。
#[async_trait]
pub trait TransportManager: Send + Sync {
    /// 广播 presence。
    async fn broadcast_presence(&self, hint: PresenceHint) -> CoreResult<()>;

    /// 通知网络变化。
    async fn notify_network_changed(&self, online: bool, net_type: NetworkType) -> CoreResult<()>;

    /// 重连 peer。
    async fn reconnect_peer(&self, peer_id: &PeerId) -> CoreResult<()>;
}
