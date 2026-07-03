//! SMS 平台后端抽象。
//!
//! [`SmsBackend`] 是平台无关的 Data SMS 收发接口。
//! 实际平台实现（Android SmsManager / iOS CTMessageCenter）由 FFI 层注入。
//! 本 crate 提供 [`MockSmsBackend`] 用于测试与单机回放。

use std::collections::VecDeque;

use parking_lot::Mutex;

/// 一条 Data SMS 消息（二进制 payload）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsMessage {
    /// 接收方 / 发送方电话号码（E.164 格式，如 `+8613800138000`）。
    pub phone: String,
    /// 二进制 payload（≤ [`MAX_SMS_PAYLOAD_LEN`](crate::codec::MAX_SMS_PAYLOAD_LEN)）。
    pub payload: Vec<u8>,
}

/// SMS 平台后端抽象。
///
/// 实现者负责实际的 SMS 发送与接收。
/// 所有方法同步调用，收到的消息通过 [`SmsBackend::drain_inbox`] 拉取。
pub trait SmsBackend: Send + Sync {
    /// 发送一条 Data SMS。
    fn send(&self, msg: SmsMessage) -> tacit_core::CoreResult<()>;

    /// 拉取自上次调用以来收到的 SMS。
    fn drain_inbox(&self) -> Vec<SmsMessage>;
}

/// Mock SMS 后端：用于测试与单机回放。
pub struct MockSmsBackend {
    outbox: Mutex<Vec<SmsMessage>>,
    inbox: Mutex<VecDeque<SmsMessage>>,
}

impl Default for MockSmsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSmsBackend {
    /// 创建 mock 后端。
    pub fn new() -> Self {
        Self {
            outbox: Mutex::new(Vec::new()),
            inbox: Mutex::new(VecDeque::new()),
        }
    }

    /// 注入一条收到的 SMS（测试用）。
    pub fn inject_incoming(&self, msg: SmsMessage) {
        self.inbox.lock().push_back(msg);
    }

    /// 返回已发送的消息列表（测试断言用）。
    pub fn sent_messages(&self) -> Vec<SmsMessage> {
        self.outbox.lock().clone()
    }

    /// 已发送消息数。
    pub fn sent_count(&self) -> usize {
        self.outbox.lock().len()
    }
}

impl SmsBackend for MockSmsBackend {
    fn send(&self, msg: SmsMessage) -> tacit_core::CoreResult<()> {
        tracing::debug!(phone = %msg.phone, len = msg.payload.len(), "MockSms send");
        self.outbox.lock().push(msg);
        Ok(())
    }

    fn drain_inbox(&self) -> Vec<SmsMessage> {
        self.inbox.lock().drain(..).collect()
    }
}

/// 将 PeerId 映射为电话号码的简单策略。
///
/// 在实验性适配器中，peer 的电话号码通过配对阶段的 `bootstrap_hints` 传递
/// （格式 `sms:+8613800138000`），由集成层在 `SmsTransport::register_peer` 时注入。
/// 此函数仅做格式提取，不做号码校验。
pub fn extract_phone_from_hint(hint: &str) -> Option<String> {
    hint.strip_prefix("sms:")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_send_and_drain() {
        let backend = MockSmsBackend::new();
        backend
            .send(SmsMessage {
                phone: "+8613800138000".into(),
                payload: vec![1, 2, 3],
            })
            .unwrap();
        assert_eq!(backend.sent_count(), 1);
        assert_eq!(backend.sent_messages()[0].payload, vec![1, 2, 3]);

        // inbox
        backend.inject_incoming(SmsMessage {
            phone: "+8613800138001".into(),
            payload: vec![4, 5, 6],
        });
        let msgs = backend.drain_inbox();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, vec![4, 5, 6]);
        assert!(backend.drain_inbox().is_empty());
    }

    #[test]
    fn extract_phone_from_hint_works() {
        assert_eq!(
            extract_phone_from_hint("sms:+8613800138000"),
            Some("+8613800138000".to_string())
        );
        assert_eq!(extract_phone_from_hint("relay://example.com"), None);
        assert_eq!(extract_phone_from_hint("sms:"), None);
    }
}
