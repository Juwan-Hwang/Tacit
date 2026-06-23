//! 事件监听器 trait。
//!
//! 平台层实现此 trait，通过 `TacitEngine::register_listener` 注册。
//! CoreEvent 通过此 trait 回传到平台层。

use std::sync::Arc;
use tacit_core::CoreEvent;

/// 事件监听器。
///
/// 平台层实现此 trait 接收 Rust 内部事件。
pub trait TacitEventListener: Send + Sync {
    /// 收到事件。
    fn on_event(&self, event: CoreEvent);
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
}
