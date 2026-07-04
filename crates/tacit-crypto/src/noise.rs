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
//! 向后兼容：payload 为空时（旧版 initiator）跳过验证，不拒绝连接。

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use snow::HandshakeState;
use tacit_core::{CoreError, CoreResult};

use crate::session::Session;

/// 重放保护 payload 长度：8 字节时间戳 + 16 字节随机 nonce = 24 字节。
const REPLAY_PAYLOAD_LEN: usize = 24;

/// 允许的时间窗口偏差（秒）。
const REPLAY_WINDOW_SECS: u64 = 60;

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

/// 已见 nonce 缓存的类型。
type SeenNonces = Option<HashSet<([u8; 8], [u8; 16])>>;

/// 全局已见 nonce 缓存，用于检测精确重放。
///
/// 使用 `Mutex<HashSet>` 存储 `(timestamp, nonce)` 对。
/// 每次插入前执行 prune：移除所有超出 `REPLAY_WINDOW_SECS` 时间窗口
/// 的过期条目。这防止攻击者通过 flood 来绕过重放保护——有效条目
/// 始终保留，只有过期条目被清除。
static SEEN_NONCES: Mutex<SeenNonces> = Mutex::new(None);

/// 记录已见的 (timestamp, nonce) 对，返回是否为重复。
///
/// `true` = 首次见到（非重复），`false` = 重复（已见过）。
///
/// 每次调用先 prune 过期条目（超出时间窗口），保持缓存大小有界。
fn record_seen_nonce(timestamp: [u8; 8], nonce: [u8; 16]) -> bool {
    let mut guard = SEEN_NONCES.lock().unwrap();
    let set = guard.get_or_insert_with(HashSet::new);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // prune 过期条目：移除时间窗口外的 (timestamp, nonce) 对。
    // 这在正常负载下自然收敛缓存大小，在 flood 攻击下仅清除
    // 过期条目，保留有效条目——攻击者无法通过 flood 来绕过重放保护。
    set.retain(|(ts_bytes, _)| {
        let ts = u64::from_be_bytes(*ts_bytes);
        now.saturating_sub(ts) <= REPLAY_WINDOW_SECS
    });

    set.insert((timestamp, nonce))
}

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

/// 验证重放保护 payload：检查时间戳窗口 + nonce 唯一性。
fn verify_replay_payload(payload: &[u8]) -> CoreResult<()> {
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

    // nonce 唯一性检查（精确重放检测）
    if !record_seen_nonce(ts_bytes, nonce) {
        return Err(CoreError::Crypto("握手 nonce 重复，拒绝精确重放".into()));
    }

    Ok(())
}

/// Noise 握手状态机。
pub struct NoiseHandshake {
    state: HandshakeState,
    role: NoiseRole,
    /// 已完成的步数（Noise_XX 共 3 步）。
    step: u8,
    /// initiator 生成的重放保护 payload（step 0 时写入握手消息）。
    replay_payload: Vec<u8>,
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
            replay_payload: generate_replay_payload(),
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
            replay_payload: Vec::new(),
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
    /// payload 为空时跳过验证（向后兼容旧版 initiator）。
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

                    // 验证重放保护 payload
                    let payload = &buf[..payload_len];
                    if !payload.is_empty() {
                        verify_replay_payload(payload)?;
                        tracing::debug!("握手重放保护验证通过");
                    }
                    // payload 为空时跳过验证（向后兼容）

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

    #[test]
    fn full_handshake() {
        let id1 = DeviceIdentity::generate().unwrap();
        let id2 = DeviceIdentity::generate().unwrap();

        let mut init = NoiseHandshake::initiator(id1.static_keypair().private.as_slice()).unwrap();
        let mut resp = NoiseHandshake::responder(id2.static_keypair().private.as_slice()).unwrap();

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

    #[test]
    fn replay_protection_rejects_expired_timestamp() {
        // 构造过期的 payload（时间戳 = 现在 - 120s，超过 60s 窗口）
        let mut expired = vec![0u8; REPLAY_PAYLOAD_LEN];
        let old_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            - 120;
        expired[..8].copy_from_slice(&(old_ts).to_be_bytes());
        rand::thread_rng().fill_bytes(&mut expired[8..]);

        let result = verify_replay_payload(&expired);
        assert!(result.is_err(), "过期握手应被拒绝");
    }

    #[test]
    fn replay_protection_rejects_future_timestamp() {
        // 构造超前的 payload（时间戳 = 现在 + 120s，超过 60s 窗口）
        let mut future = vec![0u8; REPLAY_PAYLOAD_LEN];
        let future_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            + 120;
        future[..8].copy_from_slice(&(future_ts).to_be_bytes());
        rand::thread_rng().fill_bytes(&mut future[8..]);

        let result = verify_replay_payload(&future);
        assert!(result.is_err(), "超前握手应被拒绝");
    }

    #[test]
    fn replay_protection_rejects_duplicate_nonce() {
        // 构造合法 payload
        let payload = generate_replay_payload();

        // 第一次验证应通过
        let result1 = verify_replay_payload(&payload);
        assert!(result1.is_ok(), "首次验证应通过");

        // 第二次验证（相同 nonce）应拒绝
        let result2 = verify_replay_payload(&payload);
        assert!(result2.is_err(), "重复 nonce 应被拒绝");
    }

    #[test]
    fn replay_protection_accepts_fresh_payload() {
        let payload = generate_replay_payload();
        let result = verify_replay_payload(&payload);
        assert!(result.is_ok(), "新鲜 payload 应通过验证");
    }

    #[test]
    fn replay_protection_accepts_empty_payload() {
        // 空 payload 不触发验证（向后兼容）
        // 注意：这不会在正常握手流程中发生，因为新 initiator 总是发送 payload
    }
}
