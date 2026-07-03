//! 统一传输管理器：多通道复用。
//!
//! 协调 BLE、LAN QUIC、WAN QUIC、Relay、Store-and-forward 五种传输通道，
//! 根据 `PathPreference` 选择发送路径，维护通道健康度，支持故障切换。
//!
//! 通道优先级（v1.0 规范 §11.1）：
//! 1. BLE
//! 2. LAN QUIC
//! 3. WAN QUIC
//! 4. Relay
//! 5. Store-and-forward
//!
//! 蓝图要求（蓝图 114-130 行）：
//! - 统一管理 BLE、QUIC、relay 通道
//! - 根据 preferred_path 选择发送路径
//! - 维护每条通道健康度
//! - 网络变化时通知所有通道

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use parking_lot::Mutex;
use tacit_core::{CoreResult, DataFrame, NetworkType, PeerId, PresenceHint, Priority};
use tracing::{debug, warn};

use crate::transport::{PathPreference, SyncTransport, TransportManager};
use crate::ControlMsg;

/// 通道健康状态。
#[derive(Debug, Clone)]
struct ChannelHealth {
    /// 最近成功发送时间。
    last_success: Instant,
    /// 连续失败次数。
    consecutive_failures: u32,
    /// 是否可用。
    available: bool,
}

impl ChannelHealth {
    fn new() -> Self {
        Self {
            last_success: Instant::now(),
            consecutive_failures: 0,
            available: true,
        }
    }

    fn record_success(&mut self) {
        self.last_success = Instant::now();
        self.consecutive_failures = 0;
        self.available = true;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        // 连续 3 次失败标记为不可用
        if self.consecutive_failures >= 3 {
            self.available = false;
        }
    }

    fn is_healthy(&self) -> bool {
        self.available && self.consecutive_failures < 3
    }
}

/// 通道类型标识。
///
/// 对应 v1.0 规范 §11.1 的通道优先级链：
/// BLE → LAN QUIC → WAN QUIC → Relay → Store-and-forward。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelKind {
    /// BLE 通道（优先级 1）。
    Ble,
    /// LAN QUIC 通道（优先级 2）。
    LanQuic,
    /// WAN QUIC 通道（优先级 3）。
    WanQuic,
    /// Relay 通道（优先级 4）。
    Relay,
    /// Store-and-forward 通道（优先级 5，最后兜底）。
    StoreAndForward,
}

impl ChannelKind {
    /// 返回通道优先级数字（越小越优先）。
    ///
    /// 对应 v1.0 规范 §11.1：
    /// - Ble = 1
    /// - LanQuic = 2
    /// - WanQuic = 3
    /// - Relay = 4
    /// - StoreAndForward = 5
    pub fn priority_rank(&self) -> u8 {
        match self {
            ChannelKind::Ble => 1,
            ChannelKind::LanQuic => 2,
            ChannelKind::WanQuic => 3,
            ChannelKind::Relay => 4,
            ChannelKind::StoreAndForward => 5,
        }
    }

    /// 由 `PathPreference` 推导目标通道类型。
    ///
    /// `Any` 返回 `None`，表示按默认优先级链选择。
    fn from_path(pref: PathPreference) -> Option<Self> {
        match pref {
            PathPreference::Ble => Some(ChannelKind::Ble),
            PathPreference::LanQuic => Some(ChannelKind::LanQuic),
            PathPreference::WanQuic => Some(ChannelKind::WanQuic),
            PathPreference::Relay => Some(ChannelKind::Relay),
            PathPreference::Any => None,
        }
    }
}

/// 统一传输管理器：多通道复用。
///
/// 持有多个传输实现，根据 `PathPreference` 选择发送路径，
/// 支持故障切换和通道健康度管理。
pub struct TransportMultiplexer {
    /// 各通道的传输实现。
    channels: Mutex<HashMap<ChannelKind, Arc<dyn SyncTransport>>>,
    /// 各通道健康状态。
    health: Mutex<HashMap<ChannelKind, ChannelHealth>>,
    /// BLE presence 广播器（若 BLE 通道可用）。
    ble_presence: Mutex<Option<Arc<dyn TransportManager>>>,
}

impl TransportMultiplexer {
    /// 创建空的多通道管理器。
    pub fn new() -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            health: Mutex::new(HashMap::new()),
            ble_presence: Mutex::new(None),
        }
    }

    /// 注册传输通道。
    ///
    /// 若通道实现了 `TransportManager`（如 BLE），同时注册为 presence 广播器。
    pub fn register_channel(&self, kind: ChannelKind, transport: Arc<dyn SyncTransport>) {
        self.health.lock().insert(kind, ChannelHealth::new());
        self.channels.lock().insert(kind, transport);
        debug!(channel = ?kind, "已注册传输通道");
    }

    /// 注册 BLE 通道（同时设置 presence 广播器）。
    pub fn register_ble(&self, transport: Arc<dyn TransportManager>) {
        self.health
            .lock()
            .entry(ChannelKind::Ble)
            .or_insert_with(ChannelHealth::new);
        self.channels.lock().insert(
            ChannelKind::Ble,
            transport.clone() as Arc<dyn SyncTransport>,
        );
        *self.ble_presence.lock() = Some(transport);
        debug!("已注册 BLE 通道（含 presence 广播）");
    }

    /// 注册 LAN QUIC 通道。
    pub fn register_lan_quic(&self, transport: Arc<dyn SyncTransport>) {
        self.register_channel(ChannelKind::LanQuic, transport);
    }

    /// 注册 WAN QUIC 通道。
    pub fn register_wan_quic(&self, transport: Arc<dyn SyncTransport>) {
        self.register_channel(ChannelKind::WanQuic, transport);
    }

    /// 注册 Store-and-forward 通道（故障切换链的最后兜底）。
    pub fn register_store_and_forward(&self, transport: Arc<dyn SyncTransport>) {
        self.register_channel(ChannelKind::StoreAndForward, transport);
    }

    /// 注销通道。
    pub fn unregister_channel(&self, kind: ChannelKind) {
        self.channels.lock().remove(&kind);
        self.health.lock().remove(&kind);
        if kind == ChannelKind::Ble {
            *self.ble_presence.lock() = None;
        }
        debug!(channel = ?kind, "已注销传输通道");
    }

    /// 获取可用通道列表（按优先级排序）。
    ///
    /// 排序规则（v1.0 规范 §11.1，确定性，不依赖 HashMap 迭代序）：
    /// - 当 `preferred = None` 时，按 `priority_rank` 升序排列所有可用通道。
    /// - 当 `preferred = Some(kind)` 时，该通道排第一，其余按 `priority_rank` 升序排列。
    fn available_channels(
        &self,
        preferred: Option<ChannelKind>,
    ) -> Vec<(ChannelKind, Arc<dyn SyncTransport>)> {
        let channels = self.channels.lock();
        let health = self.health.lock();

        let mut available: Vec<_> = channels
            .iter()
            .filter(|(kind, _)| health.get(kind).map(|h| h.is_healthy()).unwrap_or(false))
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        // 确定性排序：preferred 通道 rank 视为 0，其余按 priority_rank 升序。
        // 由于每个 ChannelKind 的 priority_rank 唯一，排序结果完全确定。
        available.sort_by_key(|(kind, _)| {
            if Some(*kind) == preferred {
                0
            } else {
                kind.priority_rank()
            }
        });

        available
    }

    /// 记录通道发送成功。
    fn record_success(&self, kind: ChannelKind) {
        if let Some(h) = self.health.lock().get_mut(&kind) {
            h.record_success();
        }
    }

    /// 记录通道发送失败。
    fn record_failure(&self, kind: ChannelKind) {
        if let Some(h) = self.health.lock().get_mut(&kind) {
            h.record_failure();
            if !h.is_healthy() {
                warn!(channel = ?kind, "通道健康度下降，已标记为不可用");
            }
        }
    }

    /// 获取通道健康状态摘要。
    pub fn channel_health(&self) -> Vec<(ChannelKind, bool, u32)> {
        self.health
            .lock()
            .iter()
            .map(|(k, h)| (*k, h.is_healthy(), h.consecutive_failures))
            .collect()
    }
}

impl Default for TransportMultiplexer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SyncTransport for TransportMultiplexer {
    async fn send_data(
        &self,
        peer_id: &PeerId,
        frame: DataFrame,
        priority: Priority,
        preferred_path: PathPreference,
    ) -> CoreResult<()> {
        let preferred = ChannelKind::from_path(preferred_path);
        let channels = self.available_channels(preferred);

        if channels.is_empty() {
            return Err(tacit_core::CoreError::Transport(format!(
                "无可用传输通道: peer_id={peer_id}"
            )));
        }

        let mut last_err = None;
        for (kind, transport) in &channels {
            match transport
                .send_data(peer_id, frame.clone(), priority, preferred_path)
                .await
            {
                Ok(()) => {
                    self.record_success(*kind);
                    debug!(channel = ?kind, peer_id = %peer_id, "数据发送成功");
                    return Ok(());
                }
                Err(e) => {
                    self.record_failure(*kind);
                    warn!(channel = ?kind, error = %e, "通道发送失败，尝试下一个");
                    last_err = Some(e);
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| tacit_core::CoreError::Transport("所有通道均发送失败".into())))
    }

    async fn send_control(
        &self,
        peer_id: &PeerId,
        msg: ControlMsg,
        priority: Priority,
    ) -> CoreResult<()> {
        let channels = self.available_channels(None);

        if channels.is_empty() {
            return Err(tacit_core::CoreError::Transport(format!(
                "无可用传输通道: peer_id={peer_id}"
            )));
        }

        let mut last_err = None;
        for (kind, transport) in &channels {
            match transport.send_control(peer_id, msg.clone(), priority).await {
                Ok(()) => {
                    self.record_success(*kind);
                    return Ok(());
                }
                Err(e) => {
                    self.record_failure(*kind);
                    warn!(channel = ?kind, error = %e, "控制消息发送失败，尝试下一个");
                    last_err = Some(e);
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| tacit_core::CoreError::Transport("所有通道均发送失败".into())))
    }

    async fn reconnect_peer(&self, peer_id: &PeerId) -> CoreResult<()> {
        let channels = self.available_channels(None);
        let mut last_err = None;

        for (kind, transport) in &channels {
            match transport.reconnect_peer(peer_id).await {
                Ok(()) => {
                    self.record_success(*kind);
                    debug!(channel = ?kind, peer_id = %peer_id, "重连成功");
                    return Ok(());
                }
                Err(e) => {
                    self.record_failure(*kind);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            tacit_core::CoreError::Transport(format!("所有通道重连失败: peer_id={peer_id}"))
        }))
    }

    async fn notify_network_changed(&self, online: bool, net_type: NetworkType) -> CoreResult<()> {
        let channels = self.channels.lock().clone();
        let mut errors = Vec::new();

        for (kind, transport) in &channels {
            if let Err(e) = transport.notify_network_changed(online, net_type).await {
                warn!(channel = ?kind, error = %e, "网络变化通知失败");
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.into_iter().next().unwrap())
        }
    }
}

#[async_trait]
impl TransportManager for TransportMultiplexer {
    async fn broadcast_presence(&self, hint: PresenceHint) -> CoreResult<()> {
        // BLE 是唯一支持 presence 广播的通道
        // 先 clone Arc 再 await，避免跨 await 持锁
        let ble = self.ble_presence.lock().clone();
        if let Some(ble) = ble {
            ble.broadcast_presence(hint).await
        } else {
            debug!("无 BLE 通道，跳过 presence 广播");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex as PMutex;
    use tacit_core::{DataFrame, DataFrameKind, DocId, SessionId};

    /// 模拟传输实现，记录调用并可控返回成功/失败。
    struct MockTransport {
        name: String,
        success: bool,
        calls: PMutex<Vec<String>>,
    }

    impl MockTransport {
        fn new(name: &str, success: bool) -> Arc<Self> {
            Arc::new(Self {
                name: name.into(),
                success,
                calls: PMutex::new(Vec::new()),
            })
        }

        fn call_log(&self) -> Vec<String> {
            self.calls.lock().clone()
        }
    }

    #[async_trait]
    impl SyncTransport for MockTransport {
        async fn send_data(
            &self,
            peer_id: &PeerId,
            _frame: DataFrame,
            _priority: Priority,
            _preferred_path: PathPreference,
        ) -> CoreResult<()> {
            self.calls.lock().push(format!("data:{}", peer_id));
            if self.success {
                Ok(())
            } else {
                Err(tacit_core::CoreError::Transport(format!(
                    "{} failed",
                    self.name
                )))
            }
        }

        async fn send_control(
            &self,
            peer_id: &PeerId,
            _msg: ControlMsg,
            _priority: Priority,
        ) -> CoreResult<()> {
            self.calls.lock().push(format!("ctrl:{}", peer_id));
            if self.success {
                Ok(())
            } else {
                Err(tacit_core::CoreError::Transport(format!(
                    "{} failed",
                    self.name
                )))
            }
        }

        async fn reconnect_peer(&self, peer_id: &PeerId) -> CoreResult<()> {
            self.calls.lock().push(format!("reconnect:{}", peer_id));
            Ok(())
        }

        async fn notify_network_changed(
            &self,
            _online: bool,
            _net_type: NetworkType,
        ) -> CoreResult<()> {
            Ok(())
        }
    }

    /// 构造测试用 DataFrame。
    fn make_frame() -> DataFrame {
        DataFrame {
            doc_id: DocId::new("d1"),
            actor_id: PeerId::new("p1"),
            seq: 1,
            kind: DataFrameKind::Delta,
            payload: bytes::Bytes::new(),
            session_id: SessionId::new(0),
        }
    }

    #[tokio::test]
    async fn send_data_uses_preferred_channel() {
        let mux = TransportMultiplexer::new();
        let quic = MockTransport::new("quic", true);
        let relay = MockTransport::new("relay", true);
        mux.register_channel(ChannelKind::LanQuic, quic.clone());
        mux.register_channel(ChannelKind::Relay, relay.clone());

        mux.send_data(
            &PeerId::new("p2"),
            make_frame(),
            Priority::High,
            PathPreference::Relay,
        )
        .await
        .unwrap();

        // relay 应被优先调用
        assert!(relay.call_log().iter().any(|c| c.starts_with("data:")));
    }

    #[tokio::test]
    async fn send_data_falls_back_on_failure() {
        let mux = TransportMultiplexer::new();
        let failing = MockTransport::new("quic", false);
        let working = MockTransport::new("relay", true);
        mux.register_channel(ChannelKind::LanQuic, failing.clone());
        mux.register_channel(ChannelKind::Relay, working.clone());

        mux.send_data(
            &PeerId::new("p2"),
            make_frame(),
            Priority::High,
            PathPreference::LanQuic,
        )
        .await
        .unwrap();

        // quic 失败后应 fallback 到 relay
        assert!(working.call_log().iter().any(|c| c.starts_with("data:")));
    }

    #[tokio::test]
    async fn no_channels_returns_error() {
        let mux = TransportMultiplexer::new();

        let result = mux
            .send_data(
                &PeerId::new("p2"),
                make_frame(),
                Priority::High,
                PathPreference::Any,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn notify_all_channels() {
        let mux = TransportMultiplexer::new();
        let quic = MockTransport::new("quic", true);
        let relay = MockTransport::new("relay", true);
        mux.register_channel(ChannelKind::LanQuic, quic.clone());
        mux.register_channel(ChannelKind::Relay, relay.clone());

        mux.notify_network_changed(true, NetworkType::Lan)
            .await
            .unwrap();

        assert!(quic.call_log().is_empty()); // notify 不记录到 calls
        assert!(relay.call_log().is_empty());
    }

    #[test]
    fn channel_health_tracking() {
        let mux = TransportMultiplexer::new();
        mux.register_channel(ChannelKind::LanQuic, MockTransport::new("quic", true));

        let health = mux.channel_health();
        assert_eq!(health.len(), 1);
        assert!(health[0].1); // is_healthy
    }

    #[test]
    fn priority_rank_matches_spec() {
        // v1.0 规范 §11.1：BLE(1) → LAN QUIC(2) → WAN QUIC(3) → Relay(4) → SaF(5)
        assert_eq!(ChannelKind::Ble.priority_rank(), 1);
        assert_eq!(ChannelKind::LanQuic.priority_rank(), 2);
        assert_eq!(ChannelKind::WanQuic.priority_rank(), 3);
        assert_eq!(ChannelKind::Relay.priority_rank(), 4);
        assert_eq!(ChannelKind::StoreAndForward.priority_rank(), 5);
    }

    #[test]
    fn available_channels_default_priority_order() {
        // preferred=None 时按 priority_rank 升序排列（与 HashMap 插入序无关）
        let mux = TransportMultiplexer::new();
        // 故意乱序注册，验证排序不依赖插入序
        mux.register_channel(
            ChannelKind::StoreAndForward,
            MockTransport::new("saf", true),
        );
        mux.register_channel(ChannelKind::Ble, MockTransport::new("ble", true));
        mux.register_channel(ChannelKind::WanQuic, MockTransport::new("wan", true));
        mux.register_channel(ChannelKind::Relay, MockTransport::new("relay", true));
        mux.register_channel(ChannelKind::LanQuic, MockTransport::new("lan", true));

        let order: Vec<ChannelKind> = mux
            .available_channels(None)
            .into_iter()
            .map(|(k, _)| k)
            .collect();

        assert_eq!(
            order,
            vec![
                ChannelKind::Ble,
                ChannelKind::LanQuic,
                ChannelKind::WanQuic,
                ChannelKind::Relay,
                ChannelKind::StoreAndForward,
            ]
        );
    }

    #[test]
    fn available_channels_preferred_first_then_priority() {
        // preferred=Some 时该通道排第一，其余按 priority_rank 升序
        let mux = TransportMultiplexer::new();
        mux.register_channel(
            ChannelKind::StoreAndForward,
            MockTransport::new("saf", true),
        );
        mux.register_channel(ChannelKind::Ble, MockTransport::new("ble", true));
        mux.register_channel(ChannelKind::WanQuic, MockTransport::new("wan", true));
        mux.register_channel(ChannelKind::Relay, MockTransport::new("relay", true));
        mux.register_channel(ChannelKind::LanQuic, MockTransport::new("lan", true));

        let order: Vec<ChannelKind> = mux
            .available_channels(Some(ChannelKind::Relay))
            .into_iter()
            .map(|(k, _)| k)
            .collect();

        // Relay 排第一
        assert_eq!(order[0], ChannelKind::Relay);
        // 其余按优先级升序
        assert_eq!(
            order[1..],
            vec![
                ChannelKind::Ble,
                ChannelKind::LanQuic,
                ChannelKind::WanQuic,
                ChannelKind::StoreAndForward,
            ]
        );
    }

    #[tokio::test]
    async fn store_and_forward_is_last_resort() {
        // 所有实时通道失败时，回退到 StoreAndForward（v1.0 §11.1 优先级链末端）
        let mux = TransportMultiplexer::new();
        let failing_ble = MockTransport::new("ble", false);
        let failing_lan = MockTransport::new("lan", false);
        let failing_relay = MockTransport::new("relay", false);
        let saf = MockTransport::new("saf", true);

        mux.register_channel(ChannelKind::Ble, failing_ble.clone());
        mux.register_channel(ChannelKind::LanQuic, failing_lan.clone());
        mux.register_channel(ChannelKind::Relay, failing_relay.clone());
        mux.register_channel(ChannelKind::StoreAndForward, saf.clone());

        mux.send_data(
            &PeerId::new("p2"),
            make_frame(),
            Priority::High,
            PathPreference::Any,
        )
        .await
        .unwrap();

        // StoreAndForward 应被调用（作为最后兜底）
        assert!(saf.call_log().iter().any(|c| c.starts_with("data:")));
    }

    #[tokio::test]
    async fn lan_quic_preferred_over_wan_quic() {
        // 同时注册 LanQuic 和 WanQuic，preferred=LanQuic 时应优先用 LanQuic
        let mux = TransportMultiplexer::new();
        let lan = MockTransport::new("lan", true);
        let wan = MockTransport::new("wan", true);
        mux.register_lan_quic(lan.clone());
        mux.register_wan_quic(wan.clone());

        mux.send_data(
            &PeerId::new("p2"),
            make_frame(),
            Priority::High,
            PathPreference::LanQuic,
        )
        .await
        .unwrap();

        // LanQuic 应被调用
        assert!(lan.call_log().iter().any(|c| c.starts_with("data:")));
        // WanQuic 不应被调用（LanQuic 成功后即返回）
        assert!(wan.call_log().is_empty());
    }
}
