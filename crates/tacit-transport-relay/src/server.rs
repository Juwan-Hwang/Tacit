//! Relay 服务端：session 管理 + 转发逻辑。
//!
//! - 校验 admission proof。
//! - 映射 session_id -> peer_id。
//! - 转发数据流。
//! - Per-peer token bucket 速率限制。
//! - TTL 缓存清理。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tacit_core::{CoreError, CoreResult, PeerId};
use tracing::{debug, warn};

use crate::admission::verify_proof;
use crate::protocol::{ForwardRequest, RelayMessage};

/// session 条目。
struct SessionEntry {
    peer_id: PeerId,
    created_at: Instant,
    last_active: Instant,
}

/// Per-peer token bucket 速率限制器。
///
/// 每个 peer 拥有独立的 token bucket，按字节数计量。
/// 桶容量为 `burst_bytes`，以 `rate_bytes_per_sec` 的速率补充。
/// 转发请求消耗对应字节数的 token；token 不足时拒绝转发。
struct TokenBucket {
    /// 桶内当前 token 数（字节）。
    tokens: f64,
    /// 桶容量（最大突发字节数）。
    capacity: f64,
    /// 补充速率（字节/秒）。
    rate: f64,
    /// 上次补充时间。
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            rate,
            last_refill: Instant::now(),
        }
    }

    /// 补充 token 并尝试消费 `cost` 字节。
    ///
    /// 返回 true 表示允许通过，false 表示限流。
    fn try_consume(&mut self, cost: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Relay 服务端。
pub struct RelayServer {
    /// 共享密钥（用于验证 admission proof）。
    secret: Vec<u8>,
    /// proof 最大有效时长。
    proof_max_age: Duration,
    /// session TTL。
    session_ttl: Duration,
    /// session_id -> session 条目。
    sessions: Mutex<HashMap<String, SessionEntry>>,
    /// peer_id -> session_id（用于转发路由）。
    peer_to_session: Mutex<HashMap<PeerId, String>>,
    /// per-peer token bucket 限流器。
    rate_limiters: Mutex<HashMap<PeerId, TokenBucket>>,
    /// 限流配置：桶容量（字节，默认 10 MB 突发）。
    rate_burst_bytes: f64,
    /// 限流配置：补充速率（字节/秒，默认 1 MB/s）。
    rate_bytes_per_sec: f64,
}

impl RelayServer {
    /// 创建 relay 服务端。
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret,
            proof_max_age: Duration::from_secs(60),
            session_ttl: Duration::from_secs(300),
            sessions: Mutex::new(HashMap::new()),
            peer_to_session: Mutex::new(HashMap::new()),
            rate_limiters: Mutex::new(HashMap::new()),
            rate_burst_bytes: 10.0 * 1024.0 * 1024.0,
            rate_bytes_per_sec: 1024.0 * 1024.0,
        }
    }

    /// 自定义速率限制参数。
    ///
    /// # 参数
    /// - `burst_bytes`: 桶容量（最大突发字节数）
    /// - `rate_bytes_per_sec`: 持续补充速率（字节/秒）
    pub fn with_rate_limit(mut self, burst_bytes: f64, rate_bytes_per_sec: f64) -> Self {
        self.rate_burst_bytes = burst_bytes;
        self.rate_bytes_per_sec = rate_bytes_per_sec;
        self
    }

    /// 处理注册请求。
    ///
    /// 返回分配的 session_id。
    pub fn handle_register(&self, proof: &crate::AdmissionProof) -> CoreResult<String> {
        // 验证 proof
        verify_proof(proof, &self.secret, self.proof_max_age.as_secs())?;

        let peer_id = PeerId::new(&proof.peer_id);
        let session_id = self.generate_session_id();

        // 注册 session
        let now = Instant::now();
        {
            let mut sessions = self.sessions.lock();
            sessions.insert(
                session_id.clone(),
                SessionEntry {
                    peer_id: peer_id.clone(),
                    created_at: now,
                    last_active: now,
                },
            );
        }
        {
            let mut p2s = self.peer_to_session.lock();
            p2s.insert(peer_id.clone(), session_id.clone());
        }
        // 为新 peer 初始化 token bucket
        {
            let mut limiters = self.rate_limiters.lock();
            limiters.entry(peer_id).or_insert_with(|| {
                TokenBucket::new(self.rate_burst_bytes, self.rate_bytes_per_sec)
            });
        }

        debug!(peer_id = %proof.peer_id, session_id = %session_id, "注册成功");
        Ok(session_id)
    }

    /// 处理转发请求。
    ///
    /// 返回要推送给目标客户端的消息。
    pub fn handle_forward(&self, req: &ForwardRequest) -> CoreResult<RelayMessage> {
        // 验证 session
        let from_peer_id = {
            let sessions = self.sessions.lock();
            let entry = sessions
                .get(&req.session_id)
                .ok_or_else(|| CoreError::Transport("session 不存在".into()))?;
            entry.peer_id.clone()
        };

        // 更新活跃时间
        {
            let mut sessions = self.sessions.lock();
            if let Some(entry) = sessions.get_mut(&req.session_id) {
                entry.last_active = Instant::now();
            }
        }

        // 速率限制检查
        let cost = req.data.len() as f64;
        let allowed = {
            let mut limiters = self.rate_limiters.lock();
            let bucket = limiters.entry(from_peer_id.clone()).or_insert_with(|| {
                TokenBucket::new(self.rate_burst_bytes, self.rate_bytes_per_sec)
            });
            bucket.try_consume(cost)
        };
        if !allowed {
            warn!(peer = %from_peer_id, bytes = req.data.len(), "relay 转发被限流");
            return Ok(RelayMessage::ForwardFailed {
                reason: "rate limited".into(),
            });
        }

        // 查找目标 peer 的 session
        let target_session = {
            let p2s = self.peer_to_session.lock();
            p2s.get(&PeerId::new(&req.target_peer_id)).cloned()
        };

        match target_session {
            Some(_target_session) => {
                // 目标在线，返回 Incoming 消息（由传输层推送给目标）
                debug!(
                    from = %from_peer_id,
                    to = %req.target_peer_id,
                    bytes = req.data.len(),
                    "转发数据"
                );
                Ok(RelayMessage::Incoming {
                    from_peer_id: from_peer_id.as_str().to_string(),
                    data: req.data.clone(),
                })
            }
            None => {
                warn!(target = %req.target_peer_id, "目标 peer 不在线");
                Ok(RelayMessage::ForwardFailed {
                    reason: "目标 peer 不在线".into(),
                })
            }
        }
    }

    /// 清理过期 session。
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut sessions = self.sessions.lock();
        let mut p2s = self.peer_to_session.lock();

        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.last_active) > self.session_ttl)
            .map(|(sid, _)| sid.clone())
            .collect();

        for sid in expired {
            if let Some(entry) = sessions.remove(&sid) {
                p2s.remove(&entry.peer_id);
                debug!(session_id = %sid, "清理过期 session");
            }
        }
    }

    /// 获取在线 peer 数。
    pub fn online_count(&self) -> usize {
        self.sessions.lock().len()
    }

    /// 根据 session_id 查询对应的 peer_id。
    ///
    /// 用于网络传输层在收到 Forward 请求时验证发送方身份。
    pub fn get_session_peer(&self, session_id: &str) -> Option<PeerId> {
        self.sessions
            .lock()
            .get(session_id)
            .map(|e| e.peer_id.clone())
    }

    /// 获取 session 的存活时长（从创建到现在）。
    ///
    /// 用于监控和诊断：长时间存活的 session 可能需要关注。
    pub fn session_age(&self, session_id: &str) -> Option<Duration> {
        self.sessions
            .lock()
            .get(session_id)
            .map(|e| Instant::now().duration_since(e.created_at))
    }

    /// 生成不可预测的 session_id。
    ///
    /// 使用 UUID v4（CSPRNG 随机），防止攻击者猜测其他 session_id。
    fn generate_session_id(&self) -> String {
        format!("relay_session_{}", uuid::Uuid::new_v4())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::generate_proof;

    #[test]
    fn register_and_forward() {
        let secret = b"relay_secret".to_vec();
        let server = RelayServer::new(secret.clone());

        // 注册 peer1
        let proof1 = generate_proof(&PeerId::new("1"), &secret).unwrap();
        let session1 = server.handle_register(&proof1).unwrap();

        // 注册 peer2
        let proof2 = generate_proof(&PeerId::new("2"), &secret).unwrap();
        let session2 = server.handle_register(&proof2).unwrap();

        assert_eq!(server.online_count(), 2);

        // peer1 转发数据给 peer2
        let req = ForwardRequest {
            session_id: session1,
            target_peer_id: "2".into(),
            data: vec![1, 2, 3],
        };
        let result = server.handle_forward(&req).unwrap();
        match result {
            RelayMessage::Incoming { from_peer_id, data } => {
                assert_eq!(from_peer_id, "1");
                assert_eq!(data, vec![1, 2, 3]);
            }
            _ => panic!("期望 Incoming"),
        }

        let _ = session2;
    }

    #[test]
    fn forward_to_offline_fails() {
        let secret = b"relay_secret".to_vec();
        let server = RelayServer::new(secret.clone());

        let proof = generate_proof(&PeerId::new("1"), &secret).unwrap();
        let session = server.handle_register(&proof).unwrap();

        let req = ForwardRequest {
            session_id: session,
            target_peer_id: "999".into(), // 不在线
            data: vec![],
        };
        let result = server.handle_forward(&req).unwrap();
        match result {
            RelayMessage::ForwardFailed { .. } => {}
            _ => panic!("期望 ForwardFailed"),
        }
    }

    #[test]
    fn invalid_session_rejected() {
        let secret = b"relay_secret".to_vec();
        let server = RelayServer::new(secret);

        let req = ForwardRequest {
            session_id: "fake_session".into(),
            target_peer_id: "2".into(),
            data: vec![],
        };
        assert!(server.handle_forward(&req).is_err());
    }

    #[test]
    fn invalid_proof_rejected() {
        let secret = b"relay_secret".to_vec();
        let server = RelayServer::new(b"wrong_secret".to_vec());

        let proof = generate_proof(&PeerId::new("1"), &secret).unwrap();
        assert!(server.handle_register(&proof).is_err());
    }

    #[test]
    fn rate_limit_blocks_excessive_traffic() {
        let secret = b"relay_secret".to_vec();
        // 桶容量 100 字节，速率 10 字节/秒
        let server = RelayServer::new(secret.clone()).with_rate_limit(100.0, 10.0);

        let proof = generate_proof(&PeerId::new("1"), &secret).unwrap();
        let session1 = server.handle_register(&proof).unwrap();
        let proof2 = generate_proof(&PeerId::new("2"), &secret).unwrap();
        let session2 = server.handle_register(&proof2).unwrap();

        // 发送 50 字节：应通过（桶有 100 token）
        let req = ForwardRequest {
            session_id: session1.clone(),
            target_peer_id: "2".into(),
            data: vec![0u8; 50],
        };
        match server.handle_forward(&req).unwrap() {
            RelayMessage::Incoming { .. } => {}
            other => panic!("期望 Incoming，得到 {:?}", other),
        }

        // 再发送 60 字节：应被限流（剩余 50 token < 60）
        let req = ForwardRequest {
            session_id: session1,
            target_peer_id: "2".into(),
            data: vec![0u8; 60],
        };
        match server.handle_forward(&req).unwrap() {
            RelayMessage::ForwardFailed { reason } => {
                assert!(
                    reason.contains("rate limited"),
                    "原因应包含 rate limited: {reason}"
                );
            }
            other => panic!("期望 ForwardFailed，得到 {:?}", other),
        }

        let _ = session2;
    }
}
