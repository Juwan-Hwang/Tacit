//! Noise 握手（Noise_XX_25519_ChaChaPoly_BLAKE2s）。
//!
//! Noise_XX 握手流程（3 次交互）：
//! 1. initiator -> responder: e
//! 2. responder -> initiator: e, ee, s, es
//! 3. initiator -> responder: s, se
//!
//! 握手完成后双方获得对方的静态公钥，可验证身份。

use snow::HandshakeState;
use tacit_core::{CoreError, CoreResult};

use crate::session::Session;

/// Noise 角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

/// 握手结果。
pub struct HandshakeResult {
    /// 对端的静态公钥（X25519，32 字节）。
    pub remote_static_pubkey: [u8; 32],
    /// 加密会话。
    pub session: Session,
}

/// Noise 握手状态机。
pub struct NoiseHandshake {
    state: HandshakeState,
    role: NoiseRole,
    /// 已完成的步数（Noise_XX 共 3 步）。
    step: u8,
}

/// Noise_XX 参数。
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

impl NoiseHandshake {
    /// 创建 initiator。
    pub fn initiator(local_static_private: &[u8]) -> CoreResult<Self> {
        let params = NOISE_PARAMS
            .parse()
            .map_err(|e| CoreError::Crypto(format!("解析 Noise 参数失败: {e}")))?;
        let builder = snow::Builder::new(params);
        let state = builder
            .local_private_key(local_static_private)
            .map_err(|e| CoreError::Crypto(format!("设置本地私钥失败: {e}")))?
            .build_initiator()
            .map_err(|e| CoreError::Crypto(format!("构建 initiator 失败: {e}")))?;
        Ok(Self {
            state,
            role: NoiseRole::Initiator,
            step: 0,
        })
    }

    /// 创建 responder。
    pub fn responder(local_static_private: &[u8]) -> CoreResult<Self> {
        let params = NOISE_PARAMS
            .parse()
            .map_err(|e| CoreError::Crypto(format!("解析 Noise 参数失败: {e}")))?;
        let builder = snow::Builder::new(params);
        let state = builder
            .local_private_key(local_static_private)
            .map_err(|e| CoreError::Crypto(format!("设置本地私钥失败: {e}")))?
            .build_responder()
            .map_err(|e| CoreError::Crypto(format!("构建 responder 失败: {e}")))?;
        Ok(Self {
            state,
            role: NoiseRole::Responder,
            step: 0,
        })
    }

    /// 处理收到的消息，返回要发送的消息。
    ///
    /// - initiator 首次调用时 `received` 传 None。
    /// - 握手完成后返回空 Vec。
    pub fn step(&mut self, received: Option<&[u8]>) -> CoreResult<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        match self.role {
            NoiseRole::Initiator => match self.step {
                0 => {
                    // -> e
                    let len = self
                        .state
                        .write_message(&[], &mut buf)
                        .map_err(|e| CoreError::Crypto(format!("write_message 失败: {e}")))?;
                    self.step = 1;
                    Ok(buf[..len].to_vec())
                }
                1 => {
                    // <- e, ee, s, es
                    let received = received.ok_or_else(|| {
                        CoreError::Crypto("initiator step 1 需要收到消息".into())
                    })?;
                    self.state
                        .read_message(received, &mut buf)
                        .map_err(|e| CoreError::Crypto(format!("read_message 失败: {e}")))?;
                    // -> s, se
                    let len = self
                        .state
                        .write_message(&[], &mut buf)
                        .map_err(|e| CoreError::Crypto(format!("write_message 失败: {e}")))?;
                    self.step = 2;
                    Ok(buf[..len].to_vec())
                }
                _ => Ok(Vec::new()),
            },
            NoiseRole::Responder => match self.step {
                0 => {
                    // <- e
                    let received = received.ok_or_else(|| {
                        CoreError::Crypto("responder step 0 需要收到消息".into())
                    })?;
                    self.state
                        .read_message(received, &mut buf)
                        .map_err(|e| CoreError::Crypto(format!("read_message 失败: {e}")))?;
                    // -> e, ee, s, es
                    let len = self
                        .state
                        .write_message(&[], &mut buf)
                        .map_err(|e| CoreError::Crypto(format!("write_message 失败: {e}")))?;
                    self.step = 1;
                    Ok(buf[..len].to_vec())
                }
                1 => {
                    // <- s, se
                    let received = received.ok_or_else(|| {
                        CoreError::Crypto("responder step 1 需要收到消息".into())
                    })?;
                    self.state
                        .read_message(received, &mut buf)
                        .map_err(|e| CoreError::Crypto(format!("read_message 失败: {e}")))?;
                    self.step = 2;
                    Ok(Vec::new())
                }
                _ => Ok(Vec::new()),
            },
        }
    }

    /// 握手是否完成。
    pub fn is_finished(&self) -> bool {
        self.step >= 2
    }

    /// 转为传输模式，返回对端公钥和加密会话。
    pub fn into_transport(self) -> CoreResult<HandshakeResult> {
        if !self.is_finished() {
            return Err(CoreError::Crypto("握手未完成".into()));
        }
        let remote_static = self
            .state
            .get_remote_static()
            .ok_or_else(|| CoreError::Crypto("无法获取对端静态公钥".into()))?;
        let mut remote_pubkey = [0u8; 32];
        remote_pubkey.copy_from_slice(&remote_static);
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| CoreError::Crypto(format!("转为传输模式失败: {e}")))?;
        Ok(HandshakeResult {
            remote_static_pubkey: remote_pubkey,
            session: Session::new(transport),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    #[test]
    fn full_handshake() {
        let id1 = DeviceIdentity::generate();
        let id2 = DeviceIdentity::generate();

        let mut init = NoiseHandshake::initiator(id1.static_keypair().private.as_slice()).unwrap();
        let mut resp = NoiseHandshake::responder(id2.static_keypair().private.as_slice()).unwrap();

        // step 1: initiator -> e
        let msg1 = init.step(None).unwrap();
        assert!(!msg1.is_empty());

        // step 2: responder <- e, -> e, ee, s, es
        let msg2 = resp.step(Some(&msg1)).unwrap();
        assert!(!msg2.is_empty());

        // step 3: initiator <- e, ee, s, es, -> s, se
        let msg3 = init.step(Some(&msg2)).unwrap();
        assert!(!msg3.is_empty());

        // responder <- s, se
        let msg4 = resp.step(Some(&msg3)).unwrap();
        assert!(msg4.is_empty());

        assert!(init.is_finished());
        assert!(resp.is_finished());

        // 转为传输模式
        let result1 = init.into_transport().unwrap();
        let result2 = resp.into_transport().unwrap();

        // 验证对端公钥
        assert_eq!(result1.remote_static_pubkey, id2.static_keypair().public);
        assert_eq!(result2.remote_static_pubkey, id1.static_keypair().public);
    }

    #[test]
    fn encrypt_decrypt_after_handshake() {
        let id1 = DeviceIdentity::generate();
        let id2 = DeviceIdentity::generate();

        let mut init = NoiseHandshake::initiator(id1.static_keypair().private.as_slice()).unwrap();
        let mut resp = NoiseHandshake::responder(id2.static_keypair().private.as_slice()).unwrap();

        let msg1 = init.step(None).unwrap();
        let msg2 = resp.step(Some(&msg1)).unwrap();
        let msg3 = init.step(Some(&msg2)).unwrap();
        let _ = resp.step(Some(&msg3)).unwrap();

        let result1 = init.into_transport().unwrap();
        let result2 = resp.into_transport().unwrap();

        let mut session1 = result1.session;
        let mut session2 = result2.session;

        // initiator 加密，responder 解密
        let plaintext = b"hello from initiator";
        let ciphertext = session1.encrypt(plaintext).unwrap();
        let decrypted = session2.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // responder 加密，initiator 解密
        let plaintext2 = b"hello from responder";
        let ciphertext2 = session2.encrypt(plaintext2).unwrap();
        let decrypted2 = session1.decrypt(&ciphertext2).unwrap();
        assert_eq!(decrypted2, plaintext2);
    }
}
