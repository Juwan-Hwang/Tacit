//! 加密会话：握手后的传输模式封装。

use snow::TransportState;
use tacit_core::{CoreError, CoreResult};

/// 默认 rekey 阈值：每加密 2²⁰ (≈100 万) 条消息后自动 rekey。
const DEFAULT_REKEY_THRESHOLD: u64 = 1 << 20;

/// 加密会话。
///
/// 包装 snow 的 TransportState，提供加密/解密接口。
///
/// # 前向安全性 —— 显式 Rekey 协调
///
/// Session 跟踪 `encrypt_count` / `decrypt_count`，当计数达到 `rekey_threshold`
/// 时，[`Session::outgoing_rekey_pending`] / [`Session::incoming_rekey_pending`]
/// 返回 `true`。**调用方必须检查这些标志并显式协调 rekey**：
///
/// 1. 发送方检查 `outgoing_rekey_pending()` → 发送 rekey 通知 → 调用 `rekey_outgoing()`
/// 2. 接收方收到通知 → 调用 `rekey_incoming()`
///
/// 这种显式协调模式在**任何传输层**（可靠或不可靠）上都是安全的：
/// 即使 rekey 通知丢失，双方密钥状态也不会单方面改变，不会导致永久失步。
///
/// 隐式 auto-rekey（在 encrypt/decrypt 内部自动轮换）已在设计上被移除，
/// 因为它在不可靠传输（BLE / SMS 丢包）上会导致永久密钥失步：
/// 发送方 rekey 后第 N 条消息丢失 → 接收方 decrypt_count 永远到不了阈值 →
/// 接收方永不 rekey incoming → 后续消息全部解密失败。
///
/// 集成层也可通过 [`Session::rekey`] 手动触发双向重密钥（需双方同时调用）。
pub struct Session {
    transport: TransportState,
    /// 已加密的消息数（仅统计 write_message 调用）。
    encrypt_count: u64,
    /// 已解密的消息数（仅统计 read_message 调用）。
    decrypt_count: u64,
    /// Rekey 建议阈值：当计数达到此值时 `rekey_pending()` 返回 true。
    /// 设为 `u64::MAX` 可禁用 rekey 建议。
    rekey_threshold: u64,
}

impl Session {
    /// 从 TransportState 创建。
    pub(crate) fn new(transport: TransportState) -> Self {
        Self {
            transport,
            encrypt_count: 0,
            decrypt_count: 0,
            rekey_threshold: DEFAULT_REKEY_THRESHOLD,
        }
    }

    /// 设置 rekey 建议阈值。
    ///
    /// 当 `encrypt_count` 或 `decrypt_count` 达到此值时，
    /// `outgoing_rekey_pending()` / `incoming_rekey_pending()` 返回 `true`。
    ///
    /// **不会自动触发 rekey**——调用方必须检查标志并显式协调。
    /// 设为 `u64::MAX` 可禁用 rekey 建议。
    pub fn set_rekey_threshold(&mut self, threshold: u64) {
        self.rekey_threshold = threshold;
    }

    /// 发送方向是否需要 rekey（`encrypt_count >= threshold`）。
    ///
    /// 调用方应在每次 `encrypt()` 后检查此标志。若为 `true`，
    /// 应向对端发送 rekey 通知，然后调用 [`Session::rekey_outgoing`]。
    /// 对端收到通知后调用 [`Session::rekey_incoming`]。
    pub fn outgoing_rekey_pending(&self) -> bool {
        self.encrypt_count >= self.rekey_threshold
    }

    /// 接收方向是否需要 rekey（`decrypt_count >= threshold`）。
    ///
    /// 调用方应在每次 `decrypt()` 后检查此标志。若为 `true`，
    /// 应向对端发送 rekey 通知，然后调用 [`Session::rekey_incoming`]。
    /// 对端收到通知后调用 [`Session::rekey_outgoing`]。
    pub fn incoming_rekey_pending(&self) -> bool {
        self.decrypt_count >= self.rekey_threshold
    }

    /// 仅轮换发送方向密钥。
    ///
    /// **对端必须同时调用 `rekey_incoming()`**，否则后续消息将解密失败。
    pub fn rekey_outgoing(&mut self) {
        self.transport.rekey_outgoing();
        self.encrypt_count = 0;
        tracing::debug!("Session outgoing rekey 完成");
    }

    /// 仅轮换接收方向密钥。
    ///
    /// **对端必须同时调用 `rekey_outgoing()`**，否则后续消息将解密失败。
    pub fn rekey_incoming(&mut self) {
        self.transport.rekey_incoming();
        self.decrypt_count = 0;
        tracing::debug!("Session incoming rekey 完成");
    }

    /// 手动触发双向 rekey（密钥轮换）。
    ///
    /// 调用 snow 的 `rekey_outgoing()` + `rekey_incoming()`，轮换双向 AEAD 密钥。
    /// **双方必须同时调用**：发送方 rekey 后，接收方也必须 rekey 才能解密。
    ///
    /// 典型用法：集成层在协商后同时调用。
    pub fn rekey(&mut self) -> CoreResult<()> {
        self.transport.rekey_outgoing();
        self.transport.rekey_incoming();
        self.encrypt_count = 0;
        self.decrypt_count = 0;
        tracing::debug!("Session 双向 rekey 完成，计数器已重置");
        Ok(())
    }

    /// 加密明文，返回密文。
    ///
    /// 加密后 `encrypt_count` 递增。调用方应在加密后检查
    /// [`Session::outgoing_rekey_pending`] 并在需要时显式协调 rekey。
    pub fn encrypt(&mut self, plaintext: &[u8]) -> CoreResult<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // AEAD 额外 16 字节
        let len = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|e| CoreError::Crypto(format!("加密失败: {e}")))?;
        buf.truncate(len);
        self.encrypt_count += 1;
        Ok(buf)
    }

    /// 解密密文，返回明文。
    ///
    /// 解密后 `decrypt_count` 递增。调用方应在解密后检查
    /// [`Session::incoming_rekey_pending`] 并在需要时显式协调 rekey。
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> CoreResult<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(ciphertext, &mut buf)
            .map_err(|e| CoreError::Crypto(format!("解密失败: {e}")))?;
        buf.truncate(len);
        self.decrypt_count += 1;
        Ok(buf)
    }

    /// 获取当前加密消息计数（自上次 rekey 起）。
    pub fn encrypt_count(&self) -> u64 {
        self.encrypt_count
    }

    /// 获取当前解密消息计数（自上次 rekey 起）。
    pub fn decrypt_count(&self) -> u64 {
        self.decrypt_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use crate::noise::{NoiseHandshake, NonceCache};
    use std::sync::Arc;

    fn establish_session() -> (Session, Session) {
        let id1 = DeviceIdentity::generate().unwrap();
        let id2 = DeviceIdentity::generate().unwrap();

        let cache = Arc::new(NonceCache::new());
        let local_id1 = (id1.public_key(), *id1.binding_proof());
        let local_id2 = (id2.public_key(), *id2.binding_proof());

        let mut init = NoiseHandshake::initiator(
            id1.static_keypair().private.as_slice(),
            b"tacit-test-v1",
            cache.clone(),
            local_id1,
        )
        .unwrap();
        let mut resp = NoiseHandshake::responder(
            id2.static_keypair().private.as_slice(),
            b"tacit-test-v1",
            cache,
            local_id2,
        )
        .unwrap();

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

    #[test]
    fn manual_rekey_preserves_communication() {
        let (mut s1, mut s2) = establish_session();

        // rekey 前通信
        let ct = s1.encrypt(b"before rekey").unwrap();
        assert_eq!(s2.decrypt(&ct).unwrap(), b"before rekey");

        // 双方 rekey
        s1.rekey().unwrap();
        s2.rekey().unwrap();

        // rekey 后通信
        let ct = s1.encrypt(b"after rekey").unwrap();
        assert_eq!(s2.decrypt(&ct).unwrap(), b"after rekey");

        // 反向也正常
        let ct = s2.encrypt(b"reverse after rekey").unwrap();
        assert_eq!(s1.decrypt(&ct).unwrap(), b"reverse after rekey");

        // 计数器重置
        assert_eq!(s1.encrypt_count(), 1);
        assert_eq!(s2.decrypt_count(), 1);
    }

    #[test]
    fn explicit_rekey_coordination() {
        // 验证显式 rekey 协调流程：
        // 1. 发送方检查 outgoing_rekey_pending() → 发送通知 → rekey_outgoing()
        // 2. 接收方收到通知 → rekey_incoming()
        // 3. 后续通信正常
        let (mut s1, mut s2) = establish_session();
        s1.set_rekey_threshold(3);
        s2.set_rekey_threshold(3);

        // s1 加密 3 条，s2 逐条解密
        for i in 0..3 {
            let msg = format!("msg-{i}");
            let ct = s1.encrypt(msg.as_bytes()).unwrap();
            assert_eq!(s2.decrypt(&ct).unwrap(), msg.as_bytes());
        }

        // 双方计数器均达到阈值
        assert!(s1.outgoing_rekey_pending());
        assert!(s2.incoming_rekey_pending());

        // 显式协调 rekey：s1 rekey outgoing，s2 rekey incoming
        s1.rekey_outgoing();
        s2.rekey_incoming();

        // 计数器重置
        assert!(!s1.outgoing_rekey_pending());
        assert!(!s2.incoming_rekey_pending());

        // rekey 后通信正常
        let ct = s1.encrypt(b"post-rekey").unwrap();
        assert_eq!(s2.decrypt(&ct).unwrap(), b"post-rekey");
    }

    #[test]
    fn no_implicit_rekey_on_encrypt_or_decrypt() {
        // 验证 encrypt/decrypt 不会隐式触发 rekey——
        // 即使计数器超过阈值，密钥状态也不变，必须显式调用。
        let (mut s1, mut s2) = establish_session();
        s1.set_rekey_threshold(2);
        s2.set_rekey_threshold(2);

        // 加密解密 3 条（超过阈值 2），密钥不变
        for i in 0..3 {
            let ct = s1.encrypt(format!("msg-{i}").as_bytes()).unwrap();
            assert_eq!(s2.decrypt(&ct).unwrap(), format!("msg-{i}").as_bytes());
        }
        // 计数器超过阈值但未重置（没有隐式 rekey）
        assert!(s1.outgoing_rekey_pending());
        assert!(s2.incoming_rekey_pending());
        assert_eq!(s1.encrypt_count(), 3);
        assert_eq!(s2.decrypt_count(), 3);

        // 再加密一条，s2 仍能解密（密钥未变）
        let ct = s1.encrypt(b"msg-3").unwrap();
        assert_eq!(s2.decrypt(&ct).unwrap(), b"msg-3");
    }

    #[test]
    fn failed_decrypt_does_not_increment_count() {
        // 解密失败不递增计数器，不影响 rekey 判断。
        let (mut s1, mut s2) = establish_session();
        s2.set_rekey_threshold(2);

        let ct = s1.encrypt(b"msg-1").unwrap();
        assert_eq!(s2.decrypt(&ct).unwrap(), b"msg-1");
        assert_eq!(s2.decrypt_count(), 1);

        let mut bad_ct = s1.encrypt(b"msg-2").unwrap();
        bad_ct[0] ^= 0xff;
        assert!(s2.decrypt(&bad_ct).is_err());
        assert_eq!(s2.decrypt_count(), 1, "解密失败不递增计数器");
    }

    #[test]
    fn rekey_counter_tracks_correctly() {
        let (mut s1, s2) = establish_session();

        assert_eq!(s1.encrypt_count(), 0);
        assert_eq!(s2.decrypt_count(), 0);

        s1.encrypt(b"a").unwrap();
        s1.encrypt(b"b").unwrap();
        assert_eq!(s1.encrypt_count(), 2);

        // s2 未解密，decrypt_count 仍为 0
        assert_eq!(s2.decrypt_count(), 0);
    }
}
