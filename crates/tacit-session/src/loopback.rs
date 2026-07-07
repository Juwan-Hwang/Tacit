//! LoopbackTransport：内存回环传输层，用于测试和示例。
//!
//! 实现 [`SyncTransport`] trait，不接触真实网络。
//! 发送的数据帧通过 `crossbeam-channel` 传递到接收端。
//!
//! ## 使用方式
//!
//! ```ignore
//! let (transport_a, transport_b) = LoopbackTransport::pair_with_ids(pid(1), pid(2));
//! // transport_a 发送的数据会被 transport_b 收到，反之亦然
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use crossbeam_channel::{unbounded, Receiver, Sender};
use parking_lot::Mutex;
use tacit_core::{CoreResult, DataFrame, NetworkType, PeerId, Priority};
use tacit_transport::{ControlMsg, PathPreference, SyncTransport, TransportEvent};

/// 回环传输通道中传递的消息。
#[derive(Debug, Clone)]
enum LoopbackMsg {
    Data(DataFrame),
    /// 控制消息 + 发送方 peer_id（用于 `NeedRanges` 等无 peer_id 字段的消息）。
    Control(ControlMsg, PeerId),
    NetworkChanged {
        online: bool,
        #[allow(dead_code)]
        net_type: NetworkType,
    },
    Reconnect,
}

/// 内存回环传输层。
///
/// 一对 `LoopbackTransport` 互连：A 发送的消息被 B 接收，反之亦然。
/// 每个 transport 绑定一个 `local_peer_id`，用于填充控制消息中的发送方信息。
pub struct LoopbackTransport {
    tx: Sender<LoopbackMsg>,
    rx: Receiver<LoopbackMsg>,
    /// 本地 peer_id，用于控制消息路由。
    local_peer_id: PeerId,
    /// 缓冲收到的 TransportEvent，供 `drain_events()` 消费。
    events: Mutex<Vec<TransportEvent>>,
}

impl LoopbackTransport {
    /// 创建一对互连的回环传输层，绑定各自的 peer_id。
    ///
    /// `transport_a.send_data()` 的数据会被 `transport_b.drain_events()` 返回。
    /// 控制消息中的发送方 peer_id 由 `local_peer_id` 填充，
    /// 解决 `NeedRanges` 等无 peer_id 字段消息的路由问题。
    pub fn pair_with_ids(peer_a: PeerId, peer_b: PeerId) -> (Arc<Self>, Arc<Self>) {
        let (tx_a, rx_b) = unbounded();
        let (tx_b, rx_a) = unbounded();
        let a = Arc::new(Self {
            tx: tx_a,
            rx: rx_a,
            local_peer_id: peer_a,
            events: Mutex::new(Vec::new()),
        });
        let b = Arc::new(Self {
            tx: tx_b,
            rx: rx_b,
            local_peer_id: peer_b,
            events: Mutex::new(Vec::new()),
        });
        (a, b)
    }

    /// 排空并返回所有收到的传输事件。
    ///
    /// 将 channel 中待处理的消息转换为 `TransportEvent` 并返回。
    pub fn drain_events(&self) -> Vec<TransportEvent> {
        // 先从 channel 拉取新消息
        let mut events = self.events.lock();
        while let Ok(msg) = self.rx.try_recv() {
            let event = match msg {
                LoopbackMsg::Data(frame) => {
                    // actor_id 即发送方 peer_id
                    TransportEvent::Data {
                        peer_id: frame.actor_id.clone(),
                        frame,
                    }
                }
                LoopbackMsg::Control(msg, sender_peer_id) => {
                    // 控制消息：优先从消息体提取 peer_id，若无法提取则用发送方 peer_id
                    let peer_id = extract_peer_id(&msg).unwrap_or_else(|| sender_peer_id.clone());
                    TransportEvent::Control { peer_id, msg }
                }
                LoopbackMsg::NetworkChanged {
                    online,
                    net_type: _,
                } => TransportEvent::NetworkChanged { online },
                LoopbackMsg::Reconnect => {
                    // 重连事件不生成 TransportEvent
                    continue;
                }
            };
            events.push(event);
        }
        std::mem::take(&mut *events)
    }

    /// 检查是否有待处理事件。
    pub fn has_pending(&self) -> bool {
        !self.rx.is_empty() || !self.events.lock().is_empty()
    }
}

#[async_trait]
impl SyncTransport for LoopbackTransport {
    async fn send_data(
        &self,
        _peer_id: &PeerId,
        frame: DataFrame,
        _priority: Priority,
        _preferred_path: PathPreference,
    ) -> CoreResult<()> {
        self.tx
            .send(LoopbackMsg::Data(frame))
            .map_err(|_| tacit_core::CoreError::Internal("loopback channel 已关闭".into()))
    }

    async fn send_control(
        &self,
        _peer_id: &PeerId,
        msg: ControlMsg,
        _priority: Priority,
    ) -> CoreResult<()> {
        self.tx
            .send(LoopbackMsg::Control(msg, self.local_peer_id.clone()))
            .map_err(|_| tacit_core::CoreError::Internal("loopback channel 已关闭".into()))
    }

    async fn reconnect_peer(&self, _peer_id: &PeerId) -> CoreResult<()> {
        let _ = self.tx.send(LoopbackMsg::Reconnect);
        Ok(())
    }

    async fn notify_network_changed(&self, online: bool, net_type: NetworkType) -> CoreResult<()> {
        let _ = self
            .tx
            .send(LoopbackMsg::NetworkChanged { online, net_type });
        Ok(())
    }
}

/// 从控制消息中提取发送方 peer_id。
///
/// 返回 `None` 表示该消息类型没有内置 peer_id 字段（如 `NeedRanges`），
/// 调用方应使用 `LoopbackMsg::Control` 中携带的发送方 peer_id。
fn extract_peer_id(msg: &ControlMsg) -> Option<PeerId> {
    match msg {
        ControlMsg::Capabilities(ann) => Some(ann.peer_id.clone()),
        ControlMsg::KnownCheckpoint { peer_id, .. } => Some(peer_id.clone()),
        ControlMsg::AckSummary(ack) => Some(ack.peer_id.clone()),
        ControlMsg::NeedRanges(_) => None,
        ControlMsg::SyncIntent { peer_id, .. } => Some(peer_id.clone()),
        ControlMsg::TransportHints(h) => Some(h.peer_id.clone()),
        ControlMsg::RelayHints(h) => Some(h.peer_id.clone()),
        ControlMsg::Introduce(m) => Some(m.introducer.clone()),
        ControlMsg::Revoke(m) => Some(m.revoker.clone()),
        ControlMsg::KeyRotate(m) => Some(m.peer_id.clone()),
    }
}
