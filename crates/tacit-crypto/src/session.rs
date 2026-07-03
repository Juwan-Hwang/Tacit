//! 加密会话：握手后的传输模式封装。

use snow::TransportState;
use tacit_core::{CoreError, CoreResult};

/// 加密会话。
///
/// 包装 snow 的 TransportState，提供加密/解密接口。
pub struct Session {
    transport: TransportState,
}

impl Session {
    /// 从 TransportState 创建。
    pub(crate) fn new(transport: TransportState) -> Self {
        Self { transport }
    }

    /// 加密明文，返回密文。
    pub fn encrypt(&mut self, plaintext: &[u8]) -> CoreResult<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // AEAD 额外 16 字节
        let len = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|e| CoreError::Crypto(format!("加密失败: {e}")))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// 解密密文，返回明文。
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> CoreResult<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(ciphertext, &mut buf)
            .map_err(|e| CoreError::Crypto(format!("解密失败: {e}")))?;
        buf.truncate(len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use crate::noise::NoiseHandshake;

    fn establish_session() -> (Session, Session) {
        let id1 = DeviceIdentity::generate().unwrap();
        let id2 = DeviceIdentity::generate().unwrap();

        let mut init = NoiseHandshake::initiator(id1.static_keypair().private.as_slice()).unwrap();
        let mut resp = NoiseHandshake::responder(id2.static_keypair().private.as_slice()).unwrap();

        let msg1 = init.step(None).unwrap();
        let msg2 = resp.step(Some(&msg1)).unwrap();
        let msg3 = init.step(Some(&msg2)).unwrap();
        let _ = resp.step(Some(&msg3)).unwrap();

        let r1 = init.into_transport().unwrap();
        let r2 = resp.into_transport().unwrap();
        (r1.session, r2.session)
    }

    #[test]
    fn round_trip() {
        let (mut s1, mut s2) = establish_session();
        let msg = b"secret message";
        let ct = s1.encrypt(msg).unwrap();
        let pt = s2.decrypt(&ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn bidirectional() {
        let (mut s1, mut s2) = establish_session();
        // s1 -> s2
        let ct1 = s1.encrypt(b"one").unwrap();
        assert_eq!(s2.decrypt(&ct1).unwrap(), b"one");
        // s2 -> s1
        let ct2 = s2.encrypt(b"two").unwrap();
        assert_eq!(s1.decrypt(&ct2).unwrap(), b"two");
    }

    #[test]
    fn decrypt_rejects_tampered() {
        let (mut s1, mut s2) = establish_session();
        let mut ct = s1.encrypt(b"original").unwrap();
        // 篡改密文
        if !ct.is_empty() {
            ct[0] ^= 0xff;
        }
        assert!(s2.decrypt(&ct).is_err());
    }
}
