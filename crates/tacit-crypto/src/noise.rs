//! Noise 握手（Noise_XX_25519_ChaChaPoly_BLAKE2s）。
//!
//! Noise_XX 握手流程（3 次交互）：
//! 1. initiator -> responder: e (含 replay protection payload)
//! 2. responder -> initiator: e, ee, s, es
//! 3. initiator -> responder: s, se
//!
//! 握手完成后双方获得对方的静态公钥，可验证身份。
//!
//! # 重放保护
//! initiator 在第一条握手消息中嵌入 timestamp + random nonce（24 字节）。
//! responder 验证时间戳在 ±60s 窗口内，拒绝过期或超前的握手消息。
//! 虽然 Noise_XX 的 ephemeral key 已防御了密钥重放（每次握手生成新密钥对），
//! 但这层防御可阻止攻击者重放整个握手流程来消耗 responder 资源（DoS 减缓）。
//!
//! # Prologue
//! 握手双方必须传入相同的 prologue 字节。不同 prologue 会导致握手失败，
//! 从而实现跨组/跨版本隔离。调用方应构造 `protocol_version || group_id`。
//!
//! Strict mode: empty payload is rejected, no backward-compat bypass.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rand::RngCore;
use snow::HandshakeState;
use tacit_core::{CoreError, CoreResult};

use crate::session::Session;

/// 重放保护 payload 长度：8 字节时间戳 + 16 字节随机 nonce = 24 字节。
const REPLAY_PAYLOAD_LEN: usize = 24;

/// 允许的时间窗口偏差（秒）。
const REPLAY_WINDOW_SECS: u64 = 60;

/// Nonce 缓存硬上限。超过此值时触发强制 prune；
/// prune 后仍超限则拒绝新条目（返回 false = 视为重复），防止内存耗尽 DoS。
const MAX_NONCE_CACHE_ENTRIES: usize = 100_000;

/// 时钟回拨警告阈值（秒）。新消息时间戳比已见最大值回拨超过此阈值时记录 warn。
/// 不改变拒绝/接受逻辑，仅增加可观测性。
const CLOCK_ROLLBACK_WARN_SECS: u64 = 30;

/// prune 执行间隔（秒）。在此间隔内跳过 prune，避免高并发下 CPU DoS。
const PRUNE_INTERVAL_SECS: u64 = 10;

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

// ---------------------------------------------------------------------------
// NonceCache — 实例级重放保护缓存（#10 + #15）
// ---------------------------------------------------------------------------

/// Nonce 缓存内部状态。
struct NonceCacheInner {
    set: HashSet<([u8; 8], [u8; 16])>,
    last_prune: Option<std::time::Instant>,
    /// 已见到的最大时间戳（用于 #13 时钟回拨检测）。
    max_seen_timestamp: u64,
}

/// 实例级重放保护缓存。
///
/// 替代原先的 `static SEEN_NONCES`，避免多 `SyncEngine` 实例共享状态导致误判重放。
/// 调用方应创建一个 `Arc<NonceCache>` 并在多个握手之间共享（同一实例的 peer
/// 之间需要共享 nonce 缓存才能检测跨握手重放）。
///
/// 内部使用 `parking_lot::Mutex`（无中毒，无 `.unwrap()`）。
pub struct NonceCache {
    inner: Mutex<NonceCacheInner>,
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceCache {
    /// 创建空的 nonce 缓存。
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NonceCacheInner {
                set: HashSet::new(),
                last_prune: None,
                max_seen_timestamp: 0,
            }),
        }
    }

    /// 验证重放保护 payload：检查时间戳窗口 + nonce 唯一性。
    fn verify_replay(&self, payload: &[u8]) -> CoreResult<()> {
        if payload.len() < REPLAY_PAYLOAD_LEN {
            return Err(CoreError::Crypto(format!(
                "重放保护 payload 过短：需要 {REPLAY_PAYLOAD_LEN} 字节，实际 {}",
                payload.len()
            )));
        }
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&payload[..8]);
        let timestamp = u64::from_be_bytes(ts_bytes);

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&payload[8..24]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // 时间窗口检查
        if timestamp > now {
            if timestamp - now > REPLAY_WINDOW_SECS {
                return Err(CoreError::Crypto(format!(
                    "握手时间戳超前过多 ({}s > {REPLAY_WINDOW_SECS}s)，拒绝",
                    timestamp - now
                )));
            }
        } else if now - timestamp > REPLAY_WINDOW_SECS {
            return Err(CoreError::Crypto(format!(
                "握手时间戳过期 ({}s > {REPLAY_WINDOW_SECS}s)，拒绝重放",
                now - timestamp
            )));
        }

        // #13 + #15: 时钟回拨检测、prune、nonce 唯一性检查——全部在单一锁区间内完成。
        {
            let mut guard = self.inner.lock();

            // 时钟回拨检测
            if timestamp < guard.max_seen_timestamp
                && guard.max_seen_timestamp - timestamp > CLOCK_ROLLBACK_WARN_SECS
            {
                tracing::warn!(
                    "检测到时钟回拨：新消息 ts={}，已见最大 ts={}，回拨 {}s",
                    timestamp,
                    guard.max_seen_timestamp,
                    guard.max_seen_timestamp - timestamp
                );
            } else if timestamp > guard.max_seen_timestamp {
                guard.max_seen_timestamp = timestamp;
            }

            // prune 过期条目（频率限制 + 缓存满时强制）
            let now_instant = std::time::Instant::now();
            let should_prune = match guard.last_prune {
                Some(last) => {
                    now_instant.saturating_duration_since(last)
                        >= std::time::Duration::from_secs(PRUNE_INTERVAL_SECS)
                }
                None => true,
            };
            if should_prune || guard.set.len() >= MAX_NONCE_CACHE_ENTRIES {
                guard.set.retain(|(ts_bytes, _)| {
                    let ts = u64::from_be_bytes(*ts_bytes);
                    now.saturating_sub(ts) <= REPLAY_WINDOW_SECS
                });
                guard.last_prune = Some(now_instant);
            }

            // 硬上限检查
            if guard.set.len() >= MAX_NONCE_CACHE_ENTRIES {
                tracing::warn!(
                    "nonce 缓存已达硬上限 {}，拒绝新条目（可能的 flood DoS）",
                    MAX_NONCE_CACHE_ENTRIES
                );
                return Err(CoreError::Crypto("nonce 缓存已达硬上限".into()));
            }

            // nonce 唯一性检查
            if !guard.set.insert((ts_bytes, nonce)) {
                return Err(CoreError::Crypto("握手 nonce 重复，拒绝精确重放".into()));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Replay payload 生成
// ---------------------------------------------------------------------------

/// 生成重放保护 payload：当前时间戳（8B 大端）+ 随机 nonce（16B）。
fn generate_replay_payload() -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut payload = vec![0u8; REPLAY_PAYLOAD_LEN];
    payload[..8].copy_from_slice(&now.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut payload[8..]);
    payload
}

// ---------------------------------------------------------------------------
// NoiseHandshake
// ---------------------------------------------------------------------------

/// Noise 握手状态机。
pub struct NoiseHandshake {
    state: HandshakeState,
    role: NoiseRole,
    /// 已完成的步数（Noise_XX 共 3 步）。
    step: u8,
    /// initiator 生成的重放保护 payload（step 0 时写入握手消息）。
    replay_payload: Vec<u8>,
    /// 实例级 nonce 缓存（#15: 从全局 static 改为实例级）。
    nonce_cache: Arc<NonceCache>,
}

/// Noise_XX 参数。
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

impl NoiseHandshake {
    /// 创建 initiator。
    ///
    /// # 参数
    /// - `local_static_private`: 本地 X25519 静态私钥（32 字节）
    /// - `prologue`: Noise prologue 字节，双方必须一致（#6: 跨组/跨版本隔离）
    /// - `nonce_cache`: 实例级重放保护缓存（#15: 从全局 static 改为实例级）
    pub fn initiator(
        local_static_private: &[u8],
        prologue: &[u8],
        nonce_cache: Arc<NonceCache>,
    ) -> CoreResult<Self> {
        let params = NOISE_PARAMS
            .parse()
            .map_err(|e| CoreError::Crypto(format!("解析 Noise 参数失败: {e}")))?;
        let builder = snow::Builder::new(params);
        let state = builder
            .local_private_key(local_static_private)
            .map_err(|e| CoreError::Crypto(format!("设置本地私钥失败: {e}")))?
            .prologue(prologue)
            .map_err(|e| CoreError::Crypto(format!("设置 prologue 失败: {e}")))?
            .build_initiator()
            .map_err(|e| CoreError::Crypto(format!("构建 initiator 失败: {e}")))?;
        Ok(Self {
            state,
            role: NoiseRole::Initiator,
            step: 0,
            replay_payload: generate_replay_payload(),
            nonce_cache,
        })
    }

    /// 创建 responder。
    ///
    /// # 参数
    /// - `local_static_private`: 本地 X25519 静态私钥（32 字节）
    /// - `prologue`: Noise prologue 字节，双方必须一致（#6: 跨组/跨版本隔离）
    /// - `nonce_cache`: 实例级重放保护缓存（#15: 从全局 static 改为实例级）
    pub fn responder(
        local_static_private: &[u8],
        prologue: &[u8],
        nonce_cache: Arc<NonceCache>,
    ) -> CoreResult<Self> {
        let params = NOISE_PARAMS
            .parse()
            .map_err(|e| CoreError::Crypto(format!("解析 Noise 参数失败: {e}")))?;
        let builder = snow::Builder::new(params);
        let state = builder
            .local_private_key(local_static_private)
            .map_err(|e| CoreError::Crypto(format!("设置本地私钥失败: {e}")))?
            .prologue(prologue)
            .map_err(|e| CoreError::Crypto(format!("设置 prologue 失败: {e}")))?
            .build_responder()
            .map_err(|e| CoreError::Crypto(format!("构建 responder 失败: {e}")))?;
        Ok(Self {
            state,
            role: NoiseRole::Responder,
            step: 0,
            replay_payload: Vec::new(),
            nonce_cache,
        })
    }

    /// 处理收到的消息，返回要发送的消息。
    ///
    /// - initiator 首次调用时 `received` 传 None。
    /// - 握手完成后返回空 Vec。
    ///
    /// # 重放保护
    /// initiator 在 step 0 将 timestamp + nonce 嵌入握手 payload。
    /// responder 在 step 0 提取并验证时间戳新鲜性与 nonce 唯一性，
    /// 拒绝过期/超前/重复的握手消息。
    /// 空 payload 被拒绝，不存在向后兼容绕过。
    pub fn step(&mut self, received: Option<&[u8]>) -> CoreResult<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        match self.role {
            NoiseRole::Initiator => match self.step {
                0 => {
                    // -> e (含 replay protection payload)
                    let payload = &self.replay_payload;
                    let len = self
                        .state
                        .write_message(payload, &mut buf)
                        .map_err(|e| CoreError::Crypto(format!("write_message 失败: {e}")))?;
                    self.step = 1;
                    Ok(buf[..len].to_vec())
                }
                1 => {
                    // <- e, ee, s, es
                    let received = received
                        .ok_or_else(|| CoreError::Crypto("initiator step 1 需要收到消息".into()))?;
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
                    // <- e (含 replay protection payload)
                    let received = received
                        .ok_or_else(|| CoreError::Crypto("responder step 0 需要收到消息".into()))?;
                    let payload_len = self
                        .state
                        .read_message(received, &mut buf)
                        .map_err(|e| CoreError::Crypto(format!("read_message 失败: {e}")))?;

                    // 验证重放保护 payload。
                    // 空 payload 被拒绝——不存在向后兼容绕过。
                    // 攻击者不能通过发空 payload 来绕过重放保护。
                    let payload = &buf[..payload_len];
                    if payload.is_empty() {
                        return Err(CoreError::Crypto(
                            "握手 payload 为空，拒绝无重放保护的握手".into(),
                        ));
                    }
                    self.nonce_cache.verify_replay(payload)?;
                    tracing::debug!("握手重放保护验证通过");

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
                    let received = received
                        .ok_or_else(|| CoreError::Crypto("responder step 1 需要收到消息".into()))?;
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
        remote_pubkey.copy_from_slice(remote_static);
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

    /// 测试用默认 prologue。
    const TEST_PROLOGUE: &[u8] = b"tacit-test-v1";

    fn make_nonce_cache() -> Arc<NonceCache> {
        Arc::new(NonceCache::new())
    }

    #[test]
    fn full_handshake() {
        let id1 = DeviceIdentity::generate().unwrap();
        let id2 = DeviceIdentity::generate().unwrap();

        let cache = make_nonce_cache();
        let mut init = NoiseHandshake::initiator(
            id1.static_keypair().private.as_slice(),
            TEST_PROLOGUE,
            cache.clone(),
        )
        .unwrap();
        let mut resp = NoiseHandshake::responder(
            id2.static_keypair().private.as_slice(),
            TEST_PROLOGUE,
            cache,
        )
        .unwrap();

        // step 1: initiator -> e (含 replay payload)
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
        let id1 = DeviceIdentity::generate().unwrap();
        let id2 = DeviceIdentity::generate().unwrap();

        let cache = make_nonce_cache();
        let mut init = NoiseHandshake::initiator(
            id1.static_keypair().private.as_slice(),
            TEST_PROLOGUE,
            cache.clone(),
        )
        .unwrap();
        let mut resp = NoiseHandshake::responder(
            id2.static_keypair().private.as_slice(),
            TEST_PROLOGUE,
            cache,
        )
        .unwrap();

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

    #[test]
    fn mismatched_prologue_fails_handshake() {
        let id1 = DeviceIdentity::generate().unwrap();
        let id2 = DeviceIdentity::generate().unwrap();

        let cache = make_nonce_cache();
        let mut init = NoiseHandshake::initiator(
            id1.static_keypair().private.as_slice(),
            b"group-A",
            cache.clone(),
        )
        .unwrap();
        let mut resp =
            NoiseHandshake::responder(id2.static_keypair().private.as_slice(), b"group-B", cache)
                .unwrap();

        let msg1 = init.step(None).unwrap();
        // step 2: responder 读取 e（成功），发送加密的 e,ee,s,es（用错误 prologue 派生的密钥）
        let msg2 = resp.step(Some(&msg1)).unwrap();
        // step 3: initiator 尝试解密——prologue 不匹配导致解密失败
        let result = init.step(Some(&msg2));
        assert!(result.is_err(), "不同 prologue 应导致握手在解密阶段失败");
    }

    #[test]
    fn replay_protection_rejects_expired_timestamp() {
        let cache = make_nonce_cache();
        // 构造过期的 payload（时间戳 = 现在 - 120s，超过 60s 窗口）
        let mut expired = vec![0u8; REPLAY_PAYLOAD_LEN];
        let old_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            - 120;
        expired[..8].copy_from_slice(&(old_ts).to_be_bytes());
        rand::thread_rng().fill_bytes(&mut expired[8..]);

        let result = cache.verify_replay(&expired);
        assert!(result.is_err(), "过期握手应被拒绝");
    }

    #[test]
    fn replay_protection_rejects_future_timestamp() {
        let cache = make_nonce_cache();
        // 构造超前的 payload（时间戳 = 现在 + 120s，超过 60s 窗口）
        let mut future = vec![0u8; REPLAY_PAYLOAD_LEN];
        let future_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            + 120;
        future[..8].copy_from_slice(&(future_ts).to_be_bytes());
        rand::thread_rng().fill_bytes(&mut future[8..]);

        let result = cache.verify_replay(&future);
        assert!(result.is_err(), "超前握手应被拒绝");
    }

    #[test]
    fn replay_protection_rejects_duplicate_nonce() {
        let cache = make_nonce_cache();
        // 构造合法 payload
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut payload = vec![0u8; REPLAY_PAYLOAD_LEN];
        payload[..8].copy_from_slice(&now.to_be_bytes());
        rand::thread_rng().fill_bytes(&mut payload[8..]);

        // 第一次验证应通过
        let result1 = cache.verify_replay(&payload);
        assert!(result1.is_ok(), "首次验证应通过");

        // 第二次验证（相同 nonce）应拒绝
        let result2 = cache.verify_replay(&payload);
        assert!(result2.is_err(), "重复 nonce 应被拒绝");
    }

    #[test]
    fn replay_protection_accepts_fresh_payload() {
        let cache = make_nonce_cache();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut payload = vec![0u8; REPLAY_PAYLOAD_LEN];
        payload[..8].copy_from_slice(&now.to_be_bytes());
        rand::thread_rng().fill_bytes(&mut payload[8..]);

        let result = cache.verify_replay(&payload);
        assert!(result.is_ok(), "新鲜 payload 应通过验证");
    }

    #[test]
    fn replay_protection_rejects_empty_payload() {
        let cache = make_nonce_cache();
        let result = cache.verify_replay(&[]);
        assert!(result.is_err(), "空 payload 应被拒绝");
    }

    #[test]
    fn nonce_cache_independent_across_instances() {
        // #15: 不同 NonceCache 实例应独立——同一 nonce 在不同实例中都应被接受。
        let cache1 = make_nonce_cache();
        let cache2 = make_nonce_cache();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut payload = vec![0u8; REPLAY_PAYLOAD_LEN];
        payload[..8].copy_from_slice(&now.to_be_bytes());
        rand::thread_rng().fill_bytes(&mut payload[8..]);

        // cache1 接受
        assert!(cache1.verify_replay(&payload).is_ok());
        // cache2 也应接受（独立实例，不共享状态）
        assert!(
            cache2.verify_replay(&payload).is_ok(),
            "不同 NonceCache 实例应独立"
        );
    }
}
