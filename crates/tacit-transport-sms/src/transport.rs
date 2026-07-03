//! SmsTransport：实现 [`SyncTransport`] trait。
//!
//! Data SMS 作为极端离线场景的兜底通道，**同时承担控制面与小型数据面**：
//! - `send_control`：序列化控制消息，若超 SMS 单条上限则分片发送
//! - `send_data`：用 `frame_codec::encode_data` 编码 DataFrame 后分片发送
//!   - 超过 `MAX_SMS_DATA_PAYLOAD`（10 KB）的帧拒绝，避免 SMS 洪水
//! - `reconnect_peer`：SMS 无连接概念，返回 Ok
//! - `notify_network_changed`：SMS 独立于 IP 网络，忽略
//!
//! ## SMS 数据面可行性
//!
//! | 指标 | 数值 |
//! |------|------|
//! | 单段有效载荷 | 136 字节 |
//! | 10 KB delta 所需 SMS 条数 | ~75 条 |
//! | SMS 发送间隔（Android） | ~100ms/条 |
//! | 10 KB delta 传输时间 | ~7.5 秒 |
//! | 200 字节小 delta | 2 条 SMS，~0.2 秒 |
//!
//! 小型文本编辑（待办勾选、短文本修改）在 SMS 上是可行的。
//! 大 snapshot / 大 delta 被拒绝，等待 IP 恢复后走 QUIC。

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tacit_core::{CoreError, CoreResult, DataFrame, NetworkType, PeerId, PresenceHint, Priority};
use tacit_transport::{
    encode_data, ControlMsg, PathPreference, SyncTransport, TransportEvent, TransportManager,
};
use tracing::{debug, warn};

use crate::backend::{extract_phone_from_hint, SmsBackend, SmsMessage};
use crate::codec::{
    SmsSegmentCodec, FRAME_TYPE_CONTROL, FRAME_TYPE_DATA, MAX_SEGMENT_INDEX,
    MAX_SEGMENT_PAYLOAD_LEN,
};

/// SMS 数据帧 payload 上限（10 KB）。
///
/// 超过此大小的 DataFrame 被拒绝，避免单次同步产生数百条 SMS。
/// 10 KB 对应约 75 条 SMS，覆盖绝大多数文本 delta 和小型 snapshot 分片。
pub const MAX_SMS_DATA_PAYLOAD: usize = 10 * 1024;

/// 重组缓冲条目。
#[derive(Debug)]
struct ReassemblyEntry {
    frame_type: u8,
    /// 按 segment_index 去重存储的段。
    segments: Vec<Option<Vec<u8>>>,
    total: u8,
    /// 发送方 peer_id（重组完成后直接使用，免去再次查锁）。
    peer_id: PeerId,
    /// 已收到的段数（去重后）。
    received: usize,
    /// 最近活跃时间（用于 LRU 驱逐 + 超时 GC）。
    last_active: Instant,
}

/// 重组缓冲全局容量上限。
const REASSEMBLY_MAX_ENTRIES: usize = 64;
/// 单个 peer 的最大并发重组条目数。
const REASSEMBLY_MAX_PER_PEER: usize = 4;
/// 重组条目超时时间（60 秒未活跃则 GC）。
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);

/// SMS 传输：控制面 + 小型数据面。
pub struct SmsTransport {
    backend: Arc<dyn SmsBackend>,
    /// peer_id -> 电话号码映射。
    peer_phones: RwLock<HashMap<PeerId, String>>,
    /// 电话号码 -> peer_id 映射（接收时反查发送方）。
    phone_peers: RwLock<HashMap<String, PeerId>>,
    /// 分片重组缓冲：(phone, message_id) -> ReassemblyEntry
    reassembly: RwLock<HashMap<(String, u8), ReassemblyEntry>>,
    /// 下一个 message_id（0..=255 循环）。
    next_msg_id: parking_lot::Mutex<u8>,
}

impl SmsTransport {
    /// 创建 SMS 传输。
    pub fn new(backend: Arc<dyn SmsBackend>) -> Self {
        Self {
            backend,
            peer_phones: RwLock::new(HashMap::new()),
            phone_peers: RwLock::new(HashMap::new()),
            reassembly: RwLock::new(HashMap::new()),
            next_msg_id: parking_lot::Mutex::new(0),
        }
    }

    /// 注册 peer 的电话号码。
    ///
    /// 在配对阶段从 `bootstrap_hints` 中提取 `sms:` 前缀的号码，
    /// 或由集成层直接注入。
    pub fn register_peer(&self, peer_id: PeerId, phone: String) {
        if phone.is_empty() {
            warn!(peer = %peer_id, "尝试注册空电话号码，忽略");
            return;
        }
        // 统一锁顺序：peer_phones -> phone_peers（与 unregister_peer 一致）
        // 直接获取写锁，避免先读后写产生的 TOCTOU 竞态
        let mut peer_phones = self.peer_phones.write();
        let mut phone_peers = self.phone_peers.write();
        let old_phone = peer_phones.get(&peer_id).cloned();

        // 清理旧的反向映射：如果此 peer 之前注册过不同号码，且该号码仍映射到此 peer，则移除
        // 同时清理旧号码的残留重组缓存，防止内存泄漏或数据污染
        if let Some(ref old) = old_phone {
            if old != &phone && phone_peers.get(old) == Some(&peer_id) {
                phone_peers.remove(old);
                self.reassembly.write().retain(|(p, _), _| p != old);
            }
        }

        // 如果该号码已被其他 peer 绑定，解除旧 peer 的正向映射以保持双向一致
        // 同时清理该号码的残留重组缓存，防止旧 peer 的分片与新 peer 的数据混淆
        if let Some(existing_peer) = phone_peers.get(&phone).cloned() {
            if existing_peer != peer_id {
                // 仅当 existing_peer 的正向映射确实指向此号码时才移除，
                // 避免在状态不同步时误删 existing_peer 对其他号码的合法绑定
                if peer_phones.get(&existing_peer) == Some(&phone) {
                    peer_phones.remove(&existing_peer);
                }
                self.reassembly.write().retain(|(p, _), _| p != &phone);
                warn!(
                    %phone, old_peer = %existing_peer, new_peer = %peer_id,
                    "电话号码重分配，解除旧 peer 绑定并清理重组缓存"
                );
            }
        }

        phone_peers.insert(phone.clone(), peer_id.clone());
        peer_phones.insert(peer_id, phone);
    }

    /// 从配对 hints 注册 peer。
    pub fn register_peer_from_hints(&self, peer_id: PeerId, hints: &[String]) {
        for hint in hints {
            if let Some(phone) = extract_phone_from_hint(hint) {
                self.register_peer(peer_id, phone);
                return;
            }
        }
        warn!(peer = %peer_id, "配对 hints 中未找到 sms: 号码");
    }

    /// 注销 peer。
    pub fn unregister_peer(&self, peer_id: &PeerId) {
        // 统一锁顺序：peer_phones -> phone_peers（与 register_peer 一致）
        let mut peer_phones = self.peer_phones.write();
        if let Some(phone) = peer_phones.remove(peer_id) {
            let mut phone_peers = self.phone_peers.write();
            // 仅当反向映射仍指向此 peer 时才删除，防止误删已重分配的号码
            if phone_peers.get(&phone) == Some(peer_id) {
                phone_peers.remove(&phone);
                // 清理该号码的所有残留重组缓存，防止内存泄漏
                self.reassembly.write().retain(|(p, _), _| p != &phone);
            }
        }
    }

    /// 获取已注册 peer 数量。
    pub fn peer_count(&self) -> usize {
        self.peer_phones.read().len()
    }

    /// 分配下一个 message_id（循环 0..=255）。
    fn alloc_msg_id(&self) -> u8 {
        let mut id = self.next_msg_id.lock();
        let current = *id;
        *id = id.wrapping_add(1);
        current
    }

    /// 发送控制消息：序列化 -> 分片 -> 逐段发送。
    fn send_control_sync(&self, peer_id: &PeerId, msg: &ControlMsg) -> CoreResult<()> {
        let phone = self.lookup_phone(peer_id)?;

        let json = serde_json::to_vec(msg)
            .map_err(|e| CoreError::Transport(format!("控制消息序列化失败: {e}")))?;

        if json.len() > MAX_SEGMENT_PAYLOAD_LEN * MAX_SEGMENT_INDEX as usize {
            return Err(CoreError::Transport(format!(
                "控制消息过大: {} 字节，超过 SMS 最大承载能力",
                json.len()
            )));
        }

        let msg_id = self.alloc_msg_id();
        let segments = SmsSegmentCodec::segment(&json, msg_id, FRAME_TYPE_CONTROL)?;

        debug!(
            peer = %peer_id,
            phone = %phone,
            segments = segments.len(),
            msg_id,
            "发送 SMS 控制消息"
        );

        for seg in segments {
            self.backend.send(SmsMessage {
                phone: phone.clone(),
                payload: seg,
            })?;
        }

        Ok(())
    }

    /// 发送数据帧：编码 -> 分片 -> 逐段发送。
    fn send_data_sync(&self, peer_id: &PeerId, frame: &DataFrame) -> CoreResult<()> {
        let phone = self.lookup_phone(peer_id)?;

        // 编码为二进制帧格式
        let encoded = encode_data(
            &frame.doc_id,
            &frame.actor_id,
            frame.seq,
            frame.kind,
            &frame.payload,
            tacit_core::BatchFlag::Single,
            [0u8; 8],
        );

        if encoded.len() > MAX_SMS_DATA_PAYLOAD {
            return Err(CoreError::Transport(format!(
                "DataFrame 过大: {} 字节，超过 SMS 数据面上限 {} 字节（等待 IP 恢复后走 QUIC）",
                encoded.len(),
                MAX_SMS_DATA_PAYLOAD
            )));
        }

        let msg_id = self.alloc_msg_id();
        let segments = SmsSegmentCodec::segment(&encoded, msg_id, FRAME_TYPE_DATA)?;

        debug!(
            peer = %peer_id,
            phone = %phone,
            segments = segments.len(),
            msg_id,
            bytes = encoded.len(),
            "发送 SMS 数据帧"
        );

        for seg in segments {
            self.backend.send(SmsMessage {
                phone: phone.clone(),
                payload: seg,
            })?;
        }

        Ok(())
    }

    /// 查找 peer 的电话号码。
    fn lookup_phone(&self, peer_id: &PeerId) -> CoreResult<String> {
        self.peer_phones
            .read()
            .get(peer_id)
            .cloned()
            .ok_or_else(|| {
                CoreError::Transport(format!("peer {peer_id} 未注册电话号码，无法发送 SMS"))
            })
    }

    /// 处理收到的 SMS 段：若分片完整则重组并反序列化。
    ///
    /// 返回完整的 TransportEvent（若重组完成），或 `None`（等待更多分片）。
    fn process_incoming_segment(&self, msg: SmsMessage) -> CoreResult<Option<TransportEvent>> {
        // 立即校验发送方电话号码是否已注册，防止未注册号码填充重组缓冲导致 DoS
        // 同时提前获取 peer_id，存入 ReassemblyEntry 避免重组完成时再次查锁
        let peer_id = self
            .phone_peers
            .read()
            .get(&msg.phone)
            .cloned()
            .ok_or_else(|| {
                CoreError::Transport(format!("收到未注册电话号码 {} 的消息，拒绝处理", msg.phone))
            })?;

        let seg = &msg.payload;
        if seg.len() < 4 {
            return Err(CoreError::Transport("SMS 段过短".into()));
        }

        let header = SmsSegmentCodec::parse_header(seg)?;
        let total = header.total;
        let msg_id = header.message_id;
        let frame_type = header.frame_type;
        let index = header.index;

        // 校验头部合法性：total 必须非零，index 必须在 [0, total) 范围内
        if total == 0 {
            return Err(CoreError::Transport(format!(
                "非法分片头：total=0 (msg_id={msg_id})"
            )));
        }
        if index >= total {
            return Err(CoreError::Transport(format!(
                "非法分片头：index={index} >= total={total} (msg_id={msg_id})"
            )));
        }

        if total == 1 {
            // 单段消息，直接解析
            let payload = &seg[4..];
            return Ok(Some(self.decode_payload(payload, frame_type, peer_id)?));
        }

        let key = (msg.phone.clone(), msg_id);
        let key_remove = key.clone();
        let mut reasm = self.reassembly.write();

        // 超时 GC：驱逐超过 60 秒未活跃的条目
        let now = Instant::now();
        reasm.retain(|_, entry| {
            now.saturating_duration_since(entry.last_active) < REASSEMBLY_TIMEOUT
        });

        // 全局容量上限：按 LRU 驱逐最久未活跃的条目
        if reasm.len() >= REASSEMBLY_MAX_ENTRIES && !reasm.contains_key(&key) {
            warn!(msg_id, "重组缓冲已满，丢弃最旧条目");
            if let Some(oldest_key) = reasm
                .iter()
                .min_by_key(|(_, entry)| entry.last_active)
                .map(|(k, _)| k.clone())
            {
                reasm.remove(&oldest_key);
            }
        }

        // 每 peer 限制：同一号码最多 REASSEMBLY_MAX_PER_PEER 个并发重组条目
        if !reasm.contains_key(&key) {
            let peer_count = reasm.keys().filter(|(p, _)| p == &msg.phone).count();
            if peer_count >= REASSEMBLY_MAX_PER_PEER {
                // 驱逐该 peer 最旧的条目
                if let Some(oldest_peer_key) = reasm
                    .iter()
                    .filter(|((p, _), _)| p == &msg.phone)
                    .min_by_key(|(_, entry)| entry.last_active)
                    .map(|(k, _)| k.clone())
                {
                    warn!(
                        msg_id,
                        phone = %msg.phone,
                        "peer 重组条目已达上限({REASSEMBLY_MAX_PER_PEER})，丢弃最旧条目"
                    );
                    reasm.remove(&oldest_peer_key);
                }
            }
        }

        let entry = reasm.entry(key).or_insert_with(|| ReassemblyEntry {
            frame_type,
            segments: vec![None; total as usize],
            total,
            peer_id: peer_id.clone(),
            received: 0,
            last_active: Instant::now(),
        });
        entry.last_active = Instant::now();

        // 校验 frame_type + total 一致性
        if entry.frame_type != frame_type || entry.total != total {
            warn!(msg_id, "元数据不匹配，重置重组条目");
            entry.frame_type = frame_type;
            entry.segments = vec![None; total as usize];
            entry.total = total;
            entry.peer_id = peer_id.clone();
            entry.received = 0;
            entry.last_active = Instant::now();
        }

        // 去重：仅在对应槽位为空时填入
        if entry.segments[index as usize].is_none() {
            entry.segments[index as usize] = Some(msg.payload);
            entry.received += 1;
        } else {
            debug!(msg_id, index, "收到重复分片，忽略");
        }

        if entry.received == total as usize {
            // 收齐，重组
            let entry = reasm.remove(&key_remove).unwrap();
            drop(reasm);
            // 将 Option<Vec<u8>> 展平为 Vec<&Vec<u8>>
            let segments: Vec<Vec<u8>> = entry
                .segments
                .into_iter()
                .map(|opt| opt.expect("所有槽位应已填满"))
                .collect();
            let payload = SmsSegmentCodec::reassemble(&segments)?;
            return Ok(Some(self.decode_payload(
                &payload,
                entry.frame_type,
                entry.peer_id,
            )?));
        }

        Ok(None)
    }

    /// 根据帧类型解码 payload 为 TransportEvent。
    fn decode_payload(
        &self,
        payload: &[u8],
        frame_type: u8,
        peer_id: PeerId,
    ) -> CoreResult<TransportEvent> {
        match frame_type {
            FRAME_TYPE_CONTROL => {
                let msg: ControlMsg = serde_json::from_slice(payload)
                    .map_err(|e| CoreError::Transport(format!("SMS 控制消息反序列化失败: {e}")))?;
                Ok(TransportEvent::Control { peer_id, msg })
            }
            FRAME_TYPE_DATA => {
                use tacit_transport::decode_data;
                let wire = decode_data(payload)
                    .map_err(|e| CoreError::Transport(format!("SMS 数据帧解码失败: {e:?}")))?;
                let frame = wire.to_data_frame();
                Ok(TransportEvent::Data { peer_id, frame })
            }
            other => Err(CoreError::Transport(format!("未知 SMS 帧类型: {other}"))),
        }
    }

    /// 轮询收件箱，返回重组完成的 TransportEvent 列表。
    ///
    /// 集成层应定期调用此方法（如每秒一次），将返回的事件注入 sync 层事件流。
    pub fn poll_incoming(&self) -> CoreResult<Vec<TransportEvent>> {
        // 无论是否有新消息，都先执行一次超时 GC，防止过期分片长期滞留内存
        {
            let mut reasm = self.reassembly.write();
            let now = Instant::now();
            reasm.retain(|_, entry| {
                now.saturating_duration_since(entry.last_active) < REASSEMBLY_TIMEOUT
            });
        }

        let messages = self.backend.drain_inbox();
        let mut completed = Vec::new();
        for msg in messages {
            match self.process_incoming_segment(msg) {
                Ok(Some(event)) => completed.push(event),
                Ok(None) => {} // 等待更多分片
                Err(e) => warn!(error = %e, "SMS 段处理失败，丢弃"),
            }
        }
        Ok(completed)
    }
}

#[async_trait]
impl SyncTransport for SmsTransport {
    async fn send_data(
        &self,
        peer_id: &PeerId,
        frame: DataFrame,
        _priority: Priority,
        _preferred_path: PathPreference,
    ) -> CoreResult<()> {
        self.send_data_sync(peer_id, &frame)
    }

    async fn send_control(
        &self,
        peer_id: &PeerId,
        msg: ControlMsg,
        _priority: Priority,
    ) -> CoreResult<()> {
        self.send_control_sync(peer_id, &msg)
    }

    async fn reconnect_peer(&self, _peer_id: &PeerId) -> CoreResult<()> {
        // SMS 是无连接的，无需重连
        debug!("SMS 无连接概念，reconnect_peer 为空操作");
        Ok(())
    }

    async fn notify_network_changed(&self, online: bool, _net_type: NetworkType) -> CoreResult<()> {
        if online {
            debug!("IP 网络恢复，SMS 适配器不受影响");
        } else {
            debug!("IP 网络离线，SMS 适配器仍可工作（独立于 IP）");
        }
        Ok(())
    }
}

#[async_trait]
impl TransportManager for SmsTransport {
    async fn broadcast_presence(&self, _hint: PresenceHint) -> CoreResult<()> {
        // SMS 不支持广播，仅支持点对点
        debug!("SMS 不支持 presence 广播，忽略");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockSmsBackend;
    use crate::codec::MAX_SMS_PAYLOAD_LEN;
    use tacit_core::{
        AckSummary, DataFrameKind, DocId, Frontier, PeerId as TacitPeerId, SessionId,
    };

    fn make_transport() -> (SmsTransport, Arc<MockSmsBackend>) {
        let backend = Arc::new(MockSmsBackend::new());
        let transport = SmsTransport::new(backend.clone());
        (transport, backend)
    }

    fn make_ack() -> ControlMsg {
        ControlMsg::AckSummary(AckSummary {
            peer_id: TacitPeerId::new("p1"),
            doc_id: DocId::new("d1"),
            ack_checkpoint: None,
            ack_frontier: Frontier::new(),
            updated_at: std::time::SystemTime::now(),
            version_override: None,
        })
    }

    fn make_data_frame(payload: &[u8]) -> DataFrame {
        DataFrame {
            doc_id: DocId::new("d1"),
            actor_id: TacitPeerId::new("p1"),
            seq: 1,
            kind: DataFrameKind::Delta,
            payload: bytes::Bytes::copy_from_slice(payload),
            session_id: SessionId::new(1),
        }
    }

    #[tokio::test]
    async fn send_control_produces_valid_segments() {
        let (transport, backend) = make_transport();
        transport.register_peer(TacitPeerId::new("p1"), "+8613800138000".into());

        transport
            .send_control(&TacitPeerId::new("p1"), make_ack(), Priority::Medium)
            .await
            .unwrap();

        // AckSummary JSON 可能超过单段 136 字节，产生多个分片
        assert!(backend.sent_count() >= 1);
        for msg in backend.sent_messages() {
            assert!(msg.payload.len() <= MAX_SMS_PAYLOAD_LEN);
            assert_eq!(msg.phone, "+8613800138000");
            // 控制帧的 frame_type 应为 0x01
            assert_eq!(msg.payload[3], FRAME_TYPE_CONTROL);
        }
    }

    #[tokio::test]
    async fn send_data_small_frame_succeeds() {
        let (transport, backend) = make_transport();
        transport.register_peer(TacitPeerId::new("p1"), "+8613800138000".into());

        let frame = make_data_frame(b"hello world");
        transport
            .send_data(
                &TacitPeerId::new("p1"),
                frame,
                Priority::Low,
                PathPreference::Any,
            )
            .await
            .unwrap();

        assert!(backend.sent_count() >= 1);
        for msg in backend.sent_messages() {
            assert!(msg.payload.len() <= MAX_SMS_PAYLOAD_LEN);
            // 数据帧的 frame_type 应为 0x02
            assert_eq!(msg.payload[3], FRAME_TYPE_DATA);
        }
    }

    #[tokio::test]
    async fn send_data_oversized_rejected() {
        let (transport, _backend) = make_transport();
        transport.register_peer(TacitPeerId::new("p1"), "+8613800138000".into());

        // 11 KB payload，超过 10 KB 上限
        let frame = make_data_frame(&vec![0xAB; 11 * 1024]);
        let result = transport
            .send_data(
                &TacitPeerId::new("p1"),
                frame,
                Priority::Low,
                PathPreference::Any,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_data_unregistered_peer_fails() {
        let (transport, _backend) = make_transport();
        let frame = make_data_frame(b"hello");
        let result = transport
            .send_data(
                &TacitPeerId::new("unknown"),
                frame,
                Priority::Low,
                PathPreference::Any,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_control_unregistered_peer_fails() {
        let (transport, _backend) = make_transport();
        let result = transport
            .send_control(&TacitPeerId::new("unknown"), make_ack(), Priority::Medium)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn register_from_hints() {
        let (transport, _backend) = make_transport();
        transport.register_peer_from_hints(
            TacitPeerId::new("p1"),
            &["relay://example.com".into(), "sms:+8613800138000".into()],
        );
        assert_eq!(transport.peer_count(), 1);
    }

    #[tokio::test]
    async fn poll_incoming_control_single_segment() {
        let (transport, backend) = make_transport();
        transport.register_peer(TacitPeerId::new("p1"), "+8613800138000".into());

        // 发送控制消息
        transport
            .send_control(&TacitPeerId::new("p1"), make_ack(), Priority::Medium)
            .await
            .unwrap();

        // 取出已发送消息，注入到收件箱模拟回环
        let sent = backend.sent_messages();
        for s in sent {
            backend.inject_incoming(s);
        }

        // 轮询收件箱
        let incoming = transport.poll_incoming().unwrap();
        assert_eq!(incoming.len(), 1);
        assert!(matches!(incoming[0], TransportEvent::Control { .. }));
    }

    #[tokio::test]
    async fn poll_incoming_data_end_to_end() {
        let (transport, backend) = make_transport();
        transport.register_peer(TacitPeerId::new("p1"), "+8613800138000".into());

        // 发送数据帧
        let original_frame = make_data_frame(b"hello from SMS");
        transport
            .send_data(
                &TacitPeerId::new("p1"),
                original_frame.clone(),
                Priority::Low,
                PathPreference::Any,
            )
            .await
            .unwrap();

        // 模拟回环：将发送的消息注入收件箱
        let sent = backend.sent_messages();
        for s in sent {
            backend.inject_incoming(s);
        }

        // 轮询收件箱
        let incoming = transport.poll_incoming().unwrap();
        assert_eq!(incoming.len(), 1);

        match &incoming[0] {
            TransportEvent::Data { peer_id, frame } => {
                assert_eq!(peer_id, &TacitPeerId::new("p1"));
                assert_eq!(frame.seq, original_frame.seq);
                assert_eq!(frame.kind, original_frame.kind);
                assert_eq!(frame.payload, original_frame.payload);
            }
            other => panic!("期望 Data 事件，得到 {:?}", other),
        }
    }

    #[tokio::test]
    async fn poll_incoming_data_multi_segment() {
        let (transport, backend) = make_transport();
        transport.register_peer(TacitPeerId::new("p1"), "+8613800138000".into());

        // 发送较大的数据帧（需要多段 SMS）
        let payload = vec![0x42; 500]; // 500 字节，需要约 4 段
        let original_frame = make_data_frame(&payload);
        transport
            .send_data(
                &TacitPeerId::new("p1"),
                original_frame.clone(),
                Priority::Low,
                PathPreference::Any,
            )
            .await
            .unwrap();

        // 确认产生了多个分片
        let sent = backend.sent_messages();
        assert!(sent.len() > 1, "500 字节数据应产生多个 SMS 分片");

        // 模拟回环
        for s in &sent {
            backend.inject_incoming(s.clone());
        }

        // 轮询收件箱
        let incoming = transport.poll_incoming().unwrap();
        assert_eq!(incoming.len(), 1);

        match &incoming[0] {
            TransportEvent::Data { frame, .. } => {
                assert_eq!(frame.payload, original_frame.payload);
            }
            other => panic!("期望 Data 事件，得到 {:?}", other),
        }
    }

    #[tokio::test]
    async fn poll_incoming_control_and_data() {
        let (transport, backend) = make_transport();
        transport.register_peer(TacitPeerId::new("p1"), "+8613800138000".into());

        // 先发送控制消息
        transport
            .send_control(&TacitPeerId::new("p1"), make_ack(), Priority::Medium)
            .await
            .unwrap();

        // 再发送数据帧
        transport
            .send_data(
                &TacitPeerId::new("p1"),
                make_data_frame(b"data payload"),
                Priority::Low,
                PathPreference::Any,
            )
            .await
            .unwrap();

        // 模拟回环
        let sent = backend.sent_messages();
        for s in sent {
            backend.inject_incoming(s);
        }

        // 轮询收件箱：应收到控制事件 + 数据事件
        let incoming = transport.poll_incoming().unwrap();
        assert_eq!(incoming.len(), 2);

        let has_control = incoming
            .iter()
            .any(|e| matches!(e, TransportEvent::Control { .. }));
        let has_data = incoming
            .iter()
            .any(|e| matches!(e, TransportEvent::Data { .. }));
        assert!(has_control, "应包含控制事件");
        assert!(has_data, "应包含数据事件");
    }

    #[tokio::test]
    async fn reconnect_is_noop() {
        let (transport, _backend) = make_transport();
        let result = transport.reconnect_peer(&TacitPeerId::new("p1")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn broadcast_presence_is_noop() {
        let (transport, _backend) = make_transport();
        let hint = PresenceHint {
            group_id: "g1".into(),
            device_id: "dev1".into(),
            capabilities: Default::default(),
            endpoint: None,
        };
        let result = transport.broadcast_presence(hint).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn unregister_peer_removes_both_mappings() {
        let (transport, _backend) = make_transport();
        transport.register_peer(TacitPeerId::new("p1"), "+8613800138000".into());
        assert_eq!(transport.peer_count(), 1);
        transport.unregister_peer(&TacitPeerId::new("p1"));
        assert_eq!(transport.peer_count(), 0);
    }
}
