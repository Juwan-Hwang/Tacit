//! 事件监听器 trait。
//!
//! 平台层实现此 trait，通过 `TacitEngine::register_listener` 注册。
//! CoreEvent 通过此 trait 回传到平台层。
//!
//! UniFFI 导出：
//! - `ForeignEventListener`：UniFFI 回调接口，接收 JSON 字符串形式的事件。
//!   平台层（Kotlin/Swift）实现此接口，通过 `register_foreign_listener` 注册。
//! - `TacitEventListener`：Rust 内部 trait，接收强类型 `CoreEvent`。

use std::sync::Arc;
use tacit_core::CoreEvent;

/// Rust 内部事件监听器 trait（强类型）。
///
/// 平台层实现此 trait 接收 Rust 内部事件。
pub trait TacitEventListener: Send + Sync {
    /// 收到事件。
    fn on_event(&self, event: CoreEvent);
}

/// UniFFI 回调接口：平台层实现此接口接收事件（JSON 字符串形式）。
///
/// `CoreEvent` 包含 `PeerId`/`DocId`/`BlockId` 等 newtype，
/// 无法直接作为 UniFFI Record 导出（会污染 `tacit-core`）。
/// 因此通过 JSON 字符串传递事件，平台层自行反序列化。
#[uniffi::export(with_foreign)]
pub trait ForeignEventListener: Send + Sync {
    /// 收到事件（JSON 字符串）。
    fn on_event(&self, event_json: String);
}

/// 适配器：将 `ForeignEventListener` 适配为 `TacitEventListener`。
pub(crate) struct ForeignListenerAdapter {
    inner: Arc<dyn ForeignEventListener>,
}

impl ForeignListenerAdapter {
    pub(crate) fn new(inner: Arc<dyn ForeignEventListener>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

impl TacitEventListener for ForeignListenerAdapter {
    fn on_event(&self, event: CoreEvent) {
        match serde_json::to_string(&event) {
            Ok(json) => {
                self.inner.on_event(json);
            }
            Err(e) => {
                // 序列化失败时记录错误，发送错误事件而非空 JSON
                // 空 JSON "{}" 会导致平台层解析失败或得到无意义数据
                tracing::error!(error = %e, "CoreEvent 序列化失败");
                // 尝试发送一个最小化的错误事件
                let error_event = serde_json::json!({
                    "ErrorRaised": {
                        "scope": "Sync",
                        "message": format!("事件序列化失败: {e}")
                    }
                });
                self.inner.on_event(error_event.to_string());
            }
        }
    }
}

/// 内部事件分发器。
pub(crate) struct EventDispatcher {
    listeners: parking_lot::RwLock<Vec<Arc<dyn TacitEventListener>>>,
}

impl Default for EventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl EventDispatcher {
    pub(crate) fn new() -> Self {
        Self {
            listeners: parking_lot::RwLock::new(Vec::new()),
        }
    }

    pub(crate) fn register(&self, listener: Arc<dyn TacitEventListener>) {
        self.listeners.write().push(listener);
    }

    pub(crate) fn dispatch(&self, event: &CoreEvent) {
        let listeners = self.listeners.read();
        for listener in listeners.iter() {
            listener.on_event(event.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use tacit_core::{PeerId, SyncReason};

    struct MockListener {
        events: Mutex<Vec<CoreEvent>>,
    }

    impl MockListener {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
            })
        }

        fn events(&self) -> Vec<CoreEvent> {
            self.events.lock().clone()
        }
    }

    impl TacitEventListener for MockListener {
        fn on_event(&self, event: CoreEvent) {
            self.events.lock().push(event);
        }
    }

    #[test]
    fn dispatch_to_listeners() {
        let dispatcher = EventDispatcher::new();
        let listener = MockListener::new();
        dispatcher.register(listener.clone());

        let event = CoreEvent::SyncStarted {
            peer_id: PeerId::new("p1"),
            reason: SyncReason::UserForeground,
        };
        dispatcher.dispatch(&event);

        let events = listener.events();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn multiple_listeners() {
        let dispatcher = EventDispatcher::new();
        let l1 = MockListener::new();
        let l2 = MockListener::new();
        dispatcher.register(l1.clone());
        dispatcher.register(l2.clone());

        let event = CoreEvent::SyncCompleted {
            peer_id: PeerId::new("p2"),
        };
        dispatcher.dispatch(&event);

        assert_eq!(l1.events().len(), 1);
        assert_eq!(l2.events().len(), 1);
    }

    /// 测试 ForeignListenerAdapter 正确将 CoreEvent 序列化为 JSON。
    #[test]
    fn foreign_listener_adapter_serializes_event() {
        use parking_lot::Mutex;
        struct MockForeign {
            received: Mutex<Vec<String>>,
        }
        impl MockForeign {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    received: Mutex::new(Vec::new()),
                })
            }
        }
        impl ForeignEventListener for MockForeign {
            fn on_event(&self, event_json: String) {
                self.received.lock().push(event_json);
            }
        }

        let foreign = MockForeign::new();
        let adapter = ForeignListenerAdapter::new(foreign.clone());

        let event = CoreEvent::SyncStarted {
            peer_id: PeerId::new("p1"),
            reason: SyncReason::UserForeground,
        };
        adapter.on_event(event);

        let received = foreign.received.lock();
        assert_eq!(received.len(), 1);
        assert!(received[0].contains("SyncStarted"));
        assert!(received[0].contains("p1"));
    }
}
