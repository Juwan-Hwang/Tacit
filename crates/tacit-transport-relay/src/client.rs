//! Relay 客户端：连接 relay 服务端，注册，转发数据。
//!
//! Phase 0/1：实现协议逻辑，实际网络传输由集成层注入。

use parking_lot::Mutex;
use tacit_core::{CoreError, CoreResult, PeerId};
use tracing::debug;

use crate::admission::generate_proof;
use crate::protocol::{ForwardRequest, RelayMessage};

/// Relay 客户端状态。
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientState {
    /// 未连接。
    Disconnected,
    /// 已注册，持有 session_id。
    Registered { session_id: String },
}

/// Relay 客户端。
pub struct RelayClient {
    /// 本设备 peer_id。
    peer_id: PeerId,
    /// 共享密钥。
    secret: Vec<u8>,
    /// 当前状态。
    state: Mutex<ClientState>,
}

impl RelayClient {
    /// 创建客户端。
    pub fn new(peer_id: PeerId, secret: Vec<u8>) -> Self {
        Self {
            peer_id,
            secret,
            state: Mutex::new(ClientState::Disconnected),
        }
    }

    /// 生成注册请求消息。
    ///
    /// 实际网络发送由集成层处理。
    pub fn create_register_message(&self) -> CoreResult<RelayMessage> {
        let proof = generate_proof(&self.peer_id, &self.secret)?;
        Ok(RelayMessage::Register(crate::protocol::RegisterRequest {
            proof,
        }))
    }

    /// 处理注册响应。
    ///
    /// 收到服务端的 RegisterOk 后调用。
    pub fn handle_register_response(&self, msg: &RelayMessage) -> CoreResult<()> {
        match msg {
            RelayMessage::RegisterOk { session_id } => {
                debug!(session_id = %session_id, "注册成功");
                *self.state.lock() = ClientState::Registered {
                    session_id: session_id.clone(),
                };
                Ok(())
            }
            RelayMessage::RegisterDenied { reason } => {
                Err(CoreError::Transport(format!("注册被拒: {reason}")))
            }
            _ => Err(CoreError::Transport("期望注册响应".into())),
        }
    }

    /// 创建转发请求。
    ///
    /// `target_peer_id`：目标 peer。
    /// `data`：要转发的数据。
    pub fn create_forward_message(
        &self,
        target_peer_id: &PeerId,
        data: Vec<u8>,
    ) -> CoreResult<RelayMessage> {
        let state = self.state.lock();
        match &*state {
            ClientState::Disconnected => {
                Err(CoreError::Transport("未注册，无法转发".into()))
            }
            ClientState::Registered { session_id } => Ok(RelayMessage::Forward(ForwardRequest {
                session_id: session_id.clone(),
                target_peer_id: target_peer_id.as_str().to_string(),
                data,
            })),
        }
    }

    /// 处理收到的转发数据。
    ///
    /// 返回发送方 peer_id 和数据。
    pub fn handle_incoming(&self, msg: &RelayMessage) -> CoreResult<(PeerId, Vec<u8>)> {
        match msg {
            RelayMessage::Incoming { from_peer_id, data } => {
                debug!(from = %from_peer_id, "收到转发数据");
                Ok((PeerId::new(from_peer_id), data.clone()))
            }
            _ => Err(CoreError::Transport("期望 Incoming 消息".into())),
        }
    }

    /// 是否已注册。
    pub fn is_registered(&self) -> bool {
        matches!(*self.state.lock(), ClientState::Registered { .. })
    }

    /// 断开连接。
    pub fn disconnect(&self) {
        *self.state.lock() = ClientState::Disconnected;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RegisterRequest;

    #[test]
    fn register_flow() {
        let client = RelayClient::new(PeerId::new("1"), b"secret".to_vec());

        // 创建注册消息
        let msg = client.create_register_message().unwrap();
        match &msg {
            RelayMessage::Register(RegisterRequest { proof }) => {
                assert_eq!(proof.peer_id, "1");
            }
            _ => panic!("期望 Register"),
        }

        // 模拟服务端响应
        let response = RelayMessage::RegisterOk {
            session_id: "s1".into(),
        };
        client.handle_register_response(&response).unwrap();
        assert!(client.is_registered());
    }

    #[test]
    fn forward_flow() {
        let client = RelayClient::new(PeerId::new("1"), b"secret".to_vec());

        // 先注册
        let response = RelayMessage::RegisterOk {
            session_id: "s1".into(),
        };
        client.handle_register_response(&response).unwrap();

        // 创建转发消息
        let msg = client
            .create_forward_message(&PeerId::new("2"), vec![1, 2, 3])
            .unwrap();
        match &msg {
            RelayMessage::Forward(req) => {
                assert_eq!(req.session_id, "s1");
                assert_eq!(req.target_peer_id, "2");
                assert_eq!(req.data, vec![1, 2, 3]);
            }
            _ => panic!("期望 Forward"),
        }
    }

    #[test]
    fn forward_without_register_fails() {
        let client = RelayClient::new(PeerId::new("1"), b"secret".to_vec());
        assert!(client
            .create_forward_message(&PeerId::new("2"), vec![])
            .is_err());
    }

    #[test]
    fn handle_incoming_data() {
        let client = RelayClient::new(PeerId::new("1"), b"secret".to_vec());
        let msg = RelayMessage::Incoming {
            from_peer_id: "2".into(),
            data: vec![4, 5, 6],
        };
        let (from, data) = client.handle_incoming(&msg).unwrap();
        assert_eq!(from, PeerId::new("2"));
        assert_eq!(data, vec![4, 5, 6]);
    }

    #[test]
    fn register_denied() {
        let client = RelayClient::new(PeerId::new("1"), b"secret".to_vec());
        let response = RelayMessage::RegisterDenied {
            reason: "invalid proof".into(),
        };
        assert!(client.handle_register_response(&response).is_err());
        assert!(!client.is_registered());
    }
}
