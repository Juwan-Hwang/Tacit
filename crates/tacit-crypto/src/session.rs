//! 加密会话：握手后的传输模式封装。

use std::sync::atomic::{AtomicU64, Ordering};

use snow::TransportState;
use tacit_core::{CoreError, CoreResult};

/// 默认 rekey 阈值：每加密 2²⁰ (≈100 万) 条消息后自动 rekey。
const DEFAULT_REKEY_THRESHOLD: u64 = 1 << 20;

/// 加密会话。
///
/// 包装 snow 的 TransportState，提供加密/解密接口。
///
/// 内置前向安全性：当加密/解密消息数达到 `rekey_threshold` 时自动调用
/// snow 的 `rekey_outgoing()` / `rekey_incoming()`，**独立**轮换对应方向的
/// AEAD 密钥。两个方向的 rekey 阈值互相独立，避免非对称消息速率下
/// 一方 rekey 导致另一方解密失败。
///
/// 集成层也可通过 [`Session::rekey`] 手动触发双向重密钥。
pub struct Session {
    transport: TransportState,
    /// 已加密的消息数（仅统计 write_message 调用）。
    encrypt_count: AtomicU64,
    /// 已解密的消息数（仅统计 read_message 调用）。
    decrypt_count: AtomicU64,
    /// 自动 rekey 阈值：当 encrypt_count 或 decrypt_count 达到此值时触发 rekey。
    rekey_threshold: u64,
}

impl Session {
    /// 从 TransportState 创建。
    pub(crate) fn new(transport: TransportState) -> Self {
        Self {
            transport,
            encrypt_count: AtomicU64::new(0),
            decrypt_count: AtomicU64::new(0),
            rekey_threshold: DEFAULT_REKEY_THRESHOLD,
        }
    }

    /// 设置自动 rekey 阈值。
    ///
    /// 当加密或解密的消息数达到此值时，下一次操作前自动调用 `rekey()`。
    /// 设为 `u64::MAX` 可禁用自动 rekey（仅手动触发）。
    pub fn set_rekey_threshold(&mut self, threshold: u64) {
        self.rekey_threshold = threshold;
    }

    /// 手动触发 rekey（密钥轮换）。
    ///
    /// 调用 snow 的 `rekey_outgoing()` + `rekey_incoming()`，轮换双向 AEAD 密钥。
    /// **双方必须同时调用**：发送方 rekey 后，接收方也必须 rekey 才能解密。
    ///
    /// 典型用法：集成层在协商后同时调用，或在达到阈值时自动触发。
    pub fn rekey(&mut self) -> CoreResult<()> {
        // snow 0.10 将 rekey 拆分为 outgoing / incoming 两个方向。
        // 双方都调用两者，确保双向密钥同步轮换。
        self.transport.rekey_outgoing();
        self.transport.rekey_incoming();
        self.encrypt_count.store(0, Ordering::Relaxed);
        self.decrypt_count.store(0, Ordering::Relaxed);
        tracing::debug!("Session rekey 完成，计数器已重置");
        Ok(())
    }

    /// 检查是否需要自动 rekey 发送方向，若需要则执行。
    fn maybe_auto_rekey_encrypt(&mut self) -> CoreResult<()> {
        let enc = self.encrypt_count.load(Ordering::Relaxed);
        if enc >= self.rekey_threshold {
            self.transport.rekey_outgoing();
            self.encrypt_count.store(0, Ordering::Relaxed);
            tracing::debug!("Session outgoing rekey 完成，encrypt_count 已重置");
        }
        Ok(())
    }

    /// 检查是否需要自动 rekey 接收方向，若需要则执行。
    fn maybe_auto_rekey_decrypt(&mut self) -> CoreResult<()> {
        let dec = self.decrypt_count.load(Ordering::Relaxed);
        if dec >= self.rekey_threshold {
            self.transport.rekey_incoming();
            self.decrypt_count.store(0, Ordering::Relaxed);
            tracing::debug!("Session incoming rekey 完成，decrypt_count 已重置");
        }
        Ok(())
    }

    /// 加密明文，返回密文。
    ///
    /// 当累计加密消息数达到阈值时，自动触发 **outgoing** rekey 以保证前向安全性。
    ///
    /// rekey 在加密成功并递增计数器**之后**执行，确保加密失败时不会破坏密钥状态。
    pub fn encrypt(&mut self, plaintext: &[u8]) -> CoreResult<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // AEAD 额外 16 字节
        let len = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|e| CoreError::Crypto(format!("加密失败: {e}")))?;
        buf.truncate(len);
        self.encrypt_count.fetch_add(1, Ordering::Relaxed);
        self.maybe_auto_rekey_encrypt()?;
        Ok(buf)
    }

    /// 解密密文，返回明文。
    ///
    /// 当累计解密消息数达到阈值时，自动触发 **incoming** rekey 以保证前向安全性。
    ///
    /// rekey 在解密成功并递增计数器**之后**执行，确保解密失败（如篡改/损坏）
    /// 时不会破坏密钥状态，避免双方密钥永久失步。
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> CoreResult<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(ciphertext, &mut buf)
            .map_err(|e| CoreError::Crypto(format!("解密失败: {e}")))?;
        buf.truncate(len);
        self.decrypt_count.fetch_add(1, Ordering::Relaxed);
        self.maybe_auto_rekey_decrypt()?;
        Ok(buf)
    }

    /// 获取当前加密消息计数（自上次 rekey 起）。
    pub fn encrypt_count(&self) -> u64 {
        self.encrypt_count.load(Ordering::Relaxed)
    }

    /// 获取当前解密消息计数（自上次 rekey 起）。
    pub fn decrypt_count(&self) -> u64 {
        self.decrypt_count.load(Ordering::Relaxed)
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
    fn auto_rekey_triggers_at_threshold() {
        let (mut s1, mut s2) = establish_session();
        s1.set_rekey_threshold(3);
        s2.set_rekey_threshold(3);

        // s1 加密 3 条消息，s2 逐条解密
        // rekey 在操作成功后触发：第 3 条加密后 encrypt_count=3 → outgoing rekey → 重置为 0
        // 第 3 条解密后 decrypt_count=3 → incoming rekey → 重置为 0
        for i in 0..3 {
            let msg = format!("msg-{i}");
            let ct = s1.encrypt(msg.as_bytes()).unwrap();
            assert_eq!(s2.decrypt(&ct).unwrap(), msg.as_bytes());
        }
        // 第 3 条操作后双方均已 rekey，计数器重置为 0
        assert_eq!(s1.encrypt_count(), 0);
        assert_eq!(s2.decrypt_count(), 0);

        // rekey 后通信仍然正常
        let ct = s1.encrypt(b"post-auto-rekey").unwrap();
        assert_eq!(s2.decrypt(&ct).unwrap(), b"post-auto-rekey");
        assert_eq!(s1.encrypt_count(), 1);
        assert_eq!(s2.decrypt_count(), 1);
    }

    #[test]
    fn independent_directional_rekey_no_asymmetric_failure() {
        // 验证非对称消息速率下不会解密失败：
        // s1 发 3 条（第 3 条后触发 s1 outgoing rekey），s2 未解密（decrypt_count=0 不 rekey），
        // 然后 s2 发 1 条，s1 解密应成功（s1 incoming 未 rekey）。
        let (mut s1, mut s2) = establish_session();
        s1.set_rekey_threshold(3);
        s2.set_rekey_threshold(3);

        // s1 连发 3 条，s2 不解密
        // 第 3 条后 encrypt_count=3 → outgoing rekey → 重置为 0
        for i in 0..3 {
            let _ = s1.encrypt(format!("msg-{i}").as_bytes()).unwrap();
        }
        assert_eq!(s1.encrypt_count(), 0);

        // s2 发 1 条给 s1
        let ct_from_s2 = s2.encrypt(b"from s2").unwrap();
        // s1 解密：incoming 密钥从未 rekey（decrypt_count 始终为 0），
        // 所以能正确解密 s2 用原始 outgoing 密钥加密的消息
        let decrypted = s1.decrypt(&ct_from_s2).unwrap();
        assert_eq!(decrypted, b"from s2");
    }

    #[test]
    fn failed_decrypt_does_not_trigger_rekey() {
        // 验证解密失败时不会触发 rekey，避免密钥失步。
        //
        // 旧代码在 read_message 之前调用 maybe_auto_rekey_decrypt：
        //   若 decrypt_count 达到阈值 → rekey_incoming → 密钥已轮换
        //   → read_message 失败（密文损坏）→ decrypt_count 不增
        //   → 发送方重传 → 接收方用新密钥解密旧密文 → 永久失步。
        //
        // 新代码在 read_message 成功后才调用 maybe_auto_rekey_decrypt，
        // 确保失败操作不会破坏密钥状态。
        let (mut s1, mut s2) = establish_session();
        s2.set_rekey_threshold(2);

        // s1 发 1 条，s2 成功解密 → decrypt_count=1
        let ct = s1.encrypt(b"msg-1").unwrap();
        assert_eq!(s2.decrypt(&ct).unwrap(), b"msg-1");
        assert_eq!(s2.decrypt_count(), 1);

        // 篡改密文 → s2 解密失败
        // 注意：snow 在 read_message 失败时不推进 nonce，
        // 所以后续解密会因 nonce 失步而失败——这是 Noise 协议的预期行为，
        // 与 rekey 无关。我们只验证 decrypt_count 未变。
        let mut bad_ct = s1.encrypt(b"msg-2").unwrap();
        bad_ct[0] ^= 0xff;
        assert!(s2.decrypt(&bad_ct).is_err());

        // 解密失败不应触发 rekey，decrypt_count 仍为 1
        assert_eq!(s2.decrypt_count(), 1);
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
