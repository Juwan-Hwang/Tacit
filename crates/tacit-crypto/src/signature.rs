//! 签名与验签（Ed25519）。

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use tacit_core::{CoreError, CoreResult};

use crate::identity::DeviceIdentity;

/// 对消息签名。
pub fn sign(identity: &DeviceIdentity, message: &[u8]) -> [u8; 64] {
    let sig: Signature = identity.signing_key().sign(message);
    sig.to_bytes()
}

/// 验证签名。
///
/// `pubkey` 是 Ed25519 验证密钥（32 字节）。
pub fn verify(message: &[u8], signature: &[u8], pubkey: &[u8; 32]) -> CoreResult<()> {
    if signature.len() != 64 {
        return Err(CoreError::Crypto("签名长度必须为 64 字节".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_arr);
    let vk = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| CoreError::Crypto(format!("无效公钥: {e}")))?;
    vk.verify(message, &sig)
        .map_err(|e| CoreError::Crypto(format!("验签失败: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let id = DeviceIdentity::generate();
        let msg = b"hello tacit";
        let sig = sign(&id, msg);
        let pubkey = id.public_key();
        assert!(verify(msg, &sig, &pubkey).is_ok());
    }

    #[test]
    fn verify_rejects_tampered() {
        let id = DeviceIdentity::generate();
        let msg = b"hello tacit";
        let sig = sign(&id, msg);
        let pubkey = id.public_key();
        // 篡改消息
        assert!(verify(b"hello evil", &sig, &pubkey).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let id1 = DeviceIdentity::generate();
        let id2 = DeviceIdentity::generate();
        let msg = b"hello tacit";
        let sig = sign(&id1, msg);
        // 用错误的公钥验证
        assert!(verify(msg, &sig, &id2.public_key()).is_err());
    }
}
