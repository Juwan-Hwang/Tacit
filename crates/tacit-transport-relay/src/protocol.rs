//! Relay 协议消息定义。

use tacit_core::PeerId;

/// 注册请求：客户端向 relay 服务端注册。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegisterRequest {
    /// admission proof。
    pub proof: crate::AdmissionProof,
}

/// 转发请求：客户端请求 relay 转发数据到目标 peer。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForwardRequest {
    /// 发送方 session_id（由 relay 分配）。
    pub session_id: String,
    /// 目标 peer_id。
    pub target_peer_id: String,
    /// 数据负载。
    pub data: Vec<u8>,
}

/// Relay 协议消息。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RelayMessage {
    /// 注册请求。
    Register(RegisterRequest),
    /// 注册成功响应（包含分配的 session_id）。
    RegisterOk { session_id: String },
    /// 注册失败。
    RegisterDenied { reason: String },
    /// 转发请求。
    Forward(ForwardRequest),
    /// 转发成功。
    ForwardOk,
    /// 转发失败（目标不在线等）。
    ForwardFailed { reason: String },
    /// 收到转发的数据（由 relay 推送给目标客户端）。
    Incoming {
        from_peer_id: String,
        data: Vec<u8>,
    },
}

impl RelayMessage {
    /// 序列化为字节。
    pub fn to_bytes(&self) -> tacit_core::CoreResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| tacit_core::CoreError::Serialize(e.to_string()))
    }

    /// 从字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> tacit_core::CoreResult<Self> {
        serde_json::from_slice(bytes).map_err(|e| tacit_core::CoreError::Serialize(e.to_string()))
    }
}

/// 从 ForwardRequest 提取 PeerId。
impl ForwardRequest {
    pub fn target_peer_id(&self) -> PeerId {
        PeerId::new(&self.target_peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_roundtrip() {
        let msg = RelayMessage::Forward(ForwardRequest {
            session_id: "s1".into(),
            target_peer_id: "2".into(),
            data: vec![1, 2, 3],
        });
        let bytes = msg.to_bytes().unwrap();
        let parsed = RelayMessage::from_bytes(&bytes).unwrap();
        match parsed {
            RelayMessage::Forward(req) => {
                assert_eq!(req.session_id, "s1");
                assert_eq!(req.target_peer_id, "2");
                assert_eq!(req.data, vec![1, 2, 3]);
            }
            _ => panic!("期望 Forward"),
        }
    }

    #[test]
    fn register_message() {
        let proof = crate::AdmissionProof {
            peer_id: "1".into(),
            timestamp_ms: 1000,
            signature: "abc".into(),
        };
        let msg = RelayMessage::Register(RegisterRequest { proof });
        let bytes = msg.to_bytes().unwrap();
        let parsed = RelayMessage::from_bytes(&bytes).unwrap();
        match parsed {
            RelayMessage::Register(req) => {
                assert_eq!(req.proof.peer_id, "1");
            }
            _ => panic!("期望 Register"),
        }
    }
}
