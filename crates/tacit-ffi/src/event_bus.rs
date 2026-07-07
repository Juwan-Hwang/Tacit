//! EventBus：事件总线，支持订阅/发布与过滤。
//!
//! v1.0 规范线程模型：
//! - CoreEvent 通过 EventBus 广播到所有订阅者。
//! - 支持按事件类型过滤（避免无关事件唤醒 UI）。
//! - 与 EventDispatcher 不同，EventBus 支持异步订阅与过滤。

use std::sync::Arc;

use crossbeam_channel::{bounded, Receiver, Sender};
use parking_lot::RwLock;
use tacit_core::CoreEvent;

/// 事件订阅 ID。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubscriptionId(u64);

/// 事件过滤器：返回 true 表示订阅者关心此事件。
pub type EventFilter = Arc<dyn Fn(&CoreEvent) -> bool + Send + Sync>;

/// 事件订阅者。
struct Subscriber {
    id: u64,
    filter: Option<EventFilter>,
    tx: Sender<CoreEvent>,
}

/// 事件总线：发布/订阅模式。
pub struct EventBus {
    subscribers: RwLock<Vec<Subscriber>>,
    next_id: parking_lot::Mutex<u64>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            subscribers: RwLock::new(Vec::new()),
            next_id: parking_lot::Mutex::new(0),
        }
    }

    /// 订阅所有事件（无过滤）。
    /// 返回 (SubscriptionId, Receiver) 用于接收事件。
    pub fn subscribe(&self) -> (SubscriptionId, Receiver<CoreEvent>) {
        self.subscribe_with_filter(None)
    }

    /// 订阅带过滤器的事件。
    pub fn subscribe_with_filter(
        &self,
        filter: Option<EventFilter>,
    ) -> (SubscriptionId, Receiver<CoreEvent>) {
        // 有界通道：防止慢订阅者导致无界内存增长（DoS/OOM）。
        // 容量 256：足以吸收突发事件，超出时丢弃并告警。
        let (tx, rx) = bounded(256);
        let id = {
            let mut next = self.next_id.lock();
            let v = *next;
            *next += 1;
            v
        };
        self.subscribers.write().push(Subscriber {
            id,
            filter,
            tx: tx.clone(),
        });
        (SubscriptionId(id), rx)
    }

    /// 取消订阅。
    pub fn unsubscribe(&self, id: &SubscriptionId) {
        self.subscribers.write().retain(|s| s.id != id.0);
    }

    /// 发布事件到所有匹配的订阅者。
    /// 返回成功送达的订阅者数量。
    ///
    /// 慢订阅者策略：`try_send` 非阻塞，队列满时丢弃事件并记录 warn 日志。
    /// 这是有意设计——慢订阅者不应阻塞发布者（通常是同步引擎主线程）。
    pub fn publish(&self, event: &CoreEvent) -> usize {
        let subscribers = self.subscribers.read();
        let mut count = 0;
        for sub in subscribers.iter() {
            // 检查过滤器
            let matches = sub.filter.as_ref().map(|f| f(event)).unwrap_or(true);
            if !matches {
                continue;
            }
            // 非阻塞发送：订阅者慢时丢弃事件（避免阻塞发布者）
            match sub.tx.try_send(event.clone()) {
                Ok(()) => count += 1,
                Err(crossbeam_channel::TrySendError::Full(_)) => {
                    tracing::warn!("EventBus 订阅者 {} 队列已满，丢弃事件", sub.id);
                }
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                    tracing::warn!("EventBus 订阅者 {} 已断开连接，丢弃事件", sub.id);
                }
            }
        }
        count
    }

    /// 当前订阅者数量。
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.read().len()
    }
}

/// 事件过滤器工厂：常见过滤规则。
pub mod filters {
    use std::sync::Arc;

    use super::EventFilter;
    use tacit_core::CoreEvent;

    /// 仅同步相关事件。
    pub fn sync_only() -> EventFilter {
        Arc::new(|e: &CoreEvent| {
            matches!(
                e,
                CoreEvent::SyncStarted { .. }
                    | CoreEvent::SyncProgress { .. }
                    | CoreEvent::SyncBlockedOnDependency { .. }
                    | CoreEvent::SyncCompleted { .. }
            )
        })
    }

    /// 仅 peer 状态变化事件。
    pub fn peer_status_only() -> EventFilter {
        Arc::new(|e: &CoreEvent| matches!(e, CoreEvent::PeerStatusChanged { .. }))
    }

    /// 仅错误事件。
    pub fn errors_only() -> EventFilter {
        Arc::new(|e: &CoreEvent| matches!(e, CoreEvent::ErrorRaised { .. }))
    }

    /// 仅指定文档的事件。
    pub fn doc_only(doc_id: tacit_core::DocId) -> EventFilter {
        Arc::new(move |e: &CoreEvent| match e {
            CoreEvent::SyncProgress { doc_id: d, .. } => d == &doc_id,
            CoreEvent::SyncBlockedOnDependency { doc_id: d, .. } => d == &doc_id,
            CoreEvent::ConflictMerged { doc_id: d, .. } => d == &doc_id,
            _ => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_core::{DocId, PeerId, SyncReason};

    fn sync_started() -> CoreEvent {
        CoreEvent::SyncStarted {
            peer_id: PeerId::new("p1"),
            reason: SyncReason::UserForeground,
        }
    }

    fn peer_online() -> CoreEvent {
        CoreEvent::PeerStatusChanged {
            peer_id: PeerId::new("p1"),
            online: true,
        }
    }

    #[test]
    fn subscribe_and_publish() {
        let bus = EventBus::new();
        let (id, rx) = bus.subscribe();
        bus.publish(&sync_started());
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, CoreEvent::SyncStarted { .. }));
        bus.unsubscribe(&id);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn filter_blocks_unwanted() {
        let bus = EventBus::new();
        let (_, rx) = bus.subscribe_with_filter(Some(filters::sync_only()));
        // 发布 peer 状态事件，应被过滤
        bus.publish(&peer_online());
        assert!(rx.try_recv().is_err());
        // 发布同步事件，应通过
        bus.publish(&sync_started());
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn multiple_subscribers() {
        let bus = EventBus::new();
        let (_, rx1) = bus.subscribe();
        let (_, rx2) = bus.subscribe();
        bus.publish(&sync_started());
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }

    #[test]
    fn doc_filter() {
        let bus = EventBus::new();
        let (_, rx) = bus.subscribe_with_filter(Some(filters::doc_only(DocId::new("d1"))));
        bus.publish(&CoreEvent::SyncProgress {
            doc_id: DocId::new("d1"),
            stage: tacit_core::SyncStage::MetaDoc,
            progress: 0.5,
        });
        assert!(rx.try_recv().is_ok());
        bus.publish(&CoreEvent::SyncProgress {
            doc_id: DocId::new("d2"),
            stage: tacit_core::SyncStage::MetaDoc,
            progress: 0.5,
        });
        assert!(rx.try_recv().is_err());
    }
}
