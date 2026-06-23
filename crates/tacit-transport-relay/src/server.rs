//! Relay 服务端：session 管理 + 转发逻辑。
//!
//! - 校验 admission proof。
//! - 映射 session_id -> peer_id。
//! - 转发数据流。
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
    #[allow(dead_code)]
    created_at: Instant,
    last_active: Instant,
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
    /// session_id 计数器。
    counter: Mutex<u64>,
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
            counter: Mutex::new(0),
        }
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
            p2s.insert(peer_id, session_id.clone());
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

    /// 生成 session_id。
    fn generate_session_id(&self) -> String {
        let mut counter = self.counter.lock();
        *counter += 1;
        format!("relay_session_{}", *counter)
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
}
