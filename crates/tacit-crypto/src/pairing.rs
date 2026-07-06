//! 首次配对：面对面扫码绑定。
//!
//! 实现 Tacit-v1.0-FINAL.md §12.1 的面对面配对协议：
//! - 发起方生成 `group_id` 与 `binding_salt`，构造 `PairingPayload` 编码为二维码
//! - 扫码方解析二维码，独立计算 `binding_digest`，两端显示同一 SAS 短码
//! - 用户确认 SAS 一致后完成绑定
//!
//! 安全模型：`binding_digest = HMAC-SHA256(group_id || initiator_pubkey, binding_salt)`
//! 将群组标识与发起方公钥绑定到盐，防止二维码被替换或中间人篡改。
//! SAS 短码提供带外人工比对，进一步降低中间人攻击风险。

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tacit_core::{CoreError, CoreResult};

/// HMAC-SHA256 类型别名。
type HmacSha256 = Hmac<Sha256>;

/// Ed25519 公钥长度（字节）。
pub const ED25519_PUBKEY_LEN: usize = 32;

/// 绑定盐长度（字节）。
pub const BINDING_SALT_LEN: usize = 16;

/// SAS 短码上界（不含），即取值范围为 0..=9999。
const SAS_MODULUS: u32 = 10000;

/// 二进制字段的 hex 编解码辅助模块（用于 JSON 序列化）。
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    /// 将 `&[u8]` 序列化为 hex 字符串。
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    /// 从 hex 字符串反序列化为 `Vec<u8>`。
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// 配对载荷：编码进二维码的内容。
///
/// 字段说明：
/// - `group_id`：群组标识（由发起方生成，例如 UUID）
/// - `initiator_pubkey`：发起方 Ed25519 公钥（32 字节）
/// - `binding_salt`：绑定盐（16 字节，用于派生 `binding_digest`）
/// - `bootstrap_hints`：可选引导提示（如中继地址、mDNS 服务名等）
/// - `timestamp`：发起方生成载荷的时刻（Unix 毫秒）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingPayload {
    pub group_id: String,
    #[serde(with = "hex_bytes")]
    pub initiator_pubkey: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub binding_salt: Vec<u8>,
    pub bootstrap_hints: Vec<String>,
    pub timestamp: i64,
}

impl PairingPayload {
    /// 构造新的配对载荷，校验二进制字段长度。
    pub fn new(
        group_id: String,
        initiator_pubkey: Vec<u8>,
        binding_salt: Vec<u8>,
        bootstrap_hints: Vec<String>,
        timestamp: i64,
    ) -> CoreResult<Self> {
        if initiator_pubkey.len() != ED25519_PUBKEY_LEN {
            return Err(CoreError::Crypto(format!(
                "initiator_pubkey 长度必须为 {ED25519_PUBKEY_LEN} 字节，实际 {}",
                initiator_pubkey.len()
            )));
        }
        if binding_salt.len() != BINDING_SALT_LEN {
            return Err(CoreError::Crypto(format!(
                "binding_salt 长度必须为 {BINDING_SALT_LEN} 字节，实际 {}",
                binding_salt.len()
            )));
        }
        Ok(Self {
            group_id,
            initiator_pubkey,
            binding_salt,
            bootstrap_hints,
            timestamp,
        })
    }

    /// 序列化为 JSON 字符串，供二维码编码。
    ///
    /// 二进制字段（`initiator_pubkey`、`binding_salt`）以 hex 字符串表示。
    pub fn to_qr_json(&self) -> CoreResult<String> {
        serde_json::to_string(self)
            .map_err(|e| CoreError::Crypto(format!("PairingPayload 序列化失败: {e}")))
    }

    /// 从 JSON 字符串反序列化（扫码得到的内容）。
    ///
    /// 除 JSON 解析外，额外校验二进制字段长度，拒绝畸形载荷。
    pub fn from_qr_json(json: &str) -> CoreResult<Self> {
        let payload: Self = serde_json::from_str(json)
            .map_err(|e| CoreError::Crypto(format!("PairingPayload 反序列化失败: {e}")))?;
        if payload.initiator_pubkey.len() != ED25519_PUBKEY_LEN {
            return Err(CoreError::Crypto(format!(
                "initiator_pubkey 长度必须为 {ED25519_PUBKEY_LEN} 字节，实际 {}",
                payload.initiator_pubkey.len()
            )));
        }
        if payload.binding_salt.len() != BINDING_SALT_LEN {
            return Err(CoreError::Crypto(format!(
                "binding_salt 长度必须为 {BINDING_SALT_LEN} 字节，实际 {}",
                payload.binding_salt.len()
            )));
        }
        Ok(payload)
    }
}

/// 计算绑定摘要：`HMAC-SHA256(group_id || initiator_pubkey, binding_salt)`。
///
/// - 消息：`group_id` 的 UTF-8 字节后接 `initiator_pubkey`
/// - 密钥：`binding_salt`
///
/// 返回 32 字节摘要。两端独立计算并比对（直接或通过 SAS 短码），
/// 可检测二维码被替换或字段被篡改。
pub fn compute_binding_digest(
    group_id: &str,
    initiator_pubkey: &[u8],
    binding_salt: &[u8],
) -> [u8; 32] {
    // HMAC-SHA256 接受任意长度密钥，new_from_slice 不会失败
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(binding_salt).expect("HMAC-SHA256 接受任意长度密钥");
    mac.update(group_id.as_bytes());
    mac.update(initiator_pubkey);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// 从绑定摘要派生 4 位 SAS 短码（0..=9999）。
///
/// 取摘要前 4 字节作为大端 `u32`，再 mod 10000。
/// 相同输入必产生相同输出（确定性），便于两端独立显示并人工比对。
pub fn derive_sas_code(binding_digest: &[u8; 32]) -> u32 {
    let raw = u32::from_be_bytes([
        binding_digest[0],
        binding_digest[1],
        binding_digest[2],
        binding_digest[3],
    ]);
    raw % SAS_MODULUS
}

/// 将 SAS 短码格式化为 4 位零填充字符串（如 `0042`）。
///
/// 用于在 UI 上显示给用户比对。始终返回恰好 4 个字符。
pub fn format_sas_code(sas: u32) -> String {
    format!("{sas:04}")
}

/// 比对两端 SAS 短码。
///
/// 匹配则返回 `Ok(())`，不匹配则返回 `Err`。
/// 此函数实现 §12.1 推荐的"短校验码确认"步骤：
/// 用户在两端屏幕上看到 4 位数字后，输入对端数字（或由 UI 直接比对）。
pub fn confirm_sas_code(local: u32, remote: u32) -> CoreResult<()> {
    // #16: 使用常量时间比较，防止时序攻击。
    // 虽然 SAS 是 4 位数字（用户可见，时序攻击风险极低），但代码应遵循安全比较最佳实践。
    if local.ct_eq(&remote).into() {
        Ok(())
    } else {
        Err(CoreError::Crypto(format!(
            "SAS 短码不匹配：本地 {}，对端 {}",
            format_sas_code(local),
            format_sas_code(remote)
        )))
    }
}

/// 配对角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingRole {
    /// 发起方：生成二维码。
    Initiator,
    /// 响应方：扫码。
    Responder,
}

/// 配对会话状态机：封装从二维码生成/扫描到 SAS 确认的完整流程。
///
/// ## 流程
///
/// ### 发起方
/// 1. [`PairingSession::initiator`] 创建会话，生成 `binding_salt` 与 `PairingPayload`
/// 2. [`PairingSession::qr_json`] 编码为二维码供对端扫描
/// 3. [`PairingSession::sas_code`] / [`PairingSession::sas_display`] 显示 4 位短码
/// 4. [`PairingSession::confirm`] 比对对端 SAS，完成绑定
///
/// ### 响应方
/// 1. [`PairingSession::responder_from_qr`] 扫描二维码创建会话
/// 2. [`PairingSession::sas_code`] / [`PairingSession::sas_display`] 显示 4 位短码
/// 3. [`PairingSession::confirm`] 比对对端 SAS，完成绑定
///
/// ## 安全模型
///
/// - `binding_digest = HMAC-SHA256(group_id || initiator_pubkey, binding_salt)`
/// - 两端独立计算 `binding_digest` 并派生 SAS 短码
/// - 用户比对 4 位数字一致后才调用 `confirm` 完成绑定
/// - SAS 不匹配意味着中间人篡改了二维码或公钥
pub struct PairingSession {
    role: PairingRole,
    group_id: String,
    initiator_pubkey: Vec<u8>,
    binding_salt: Vec<u8>,
    binding_digest: [u8; 32],
    sas_code: u32,
    confirmed: bool,
    bootstrap_hints: Vec<String>,
}

impl PairingSession {
    /// 发起方创建配对会话。
    ///
    /// 生成随机 `binding_salt`，构造 `PairingPayload` 供二维码编码。
    /// 调用方需提供自身的 Ed25519 公钥。
    pub fn initiator(
        group_id: String,
        initiator_pubkey: Vec<u8>,
        bootstrap_hints: Vec<String>,
    ) -> CoreResult<Self> {
        let salt = generate_binding_salt();
        let digest = compute_binding_digest(&group_id, &initiator_pubkey, &salt);
        let sas = derive_sas_code(&digest);
        Ok(Self {
            role: PairingRole::Initiator,
            group_id: group_id.clone(),
            initiator_pubkey,
            binding_salt: salt.to_vec(),
            binding_digest: digest,
            sas_code: sas,
            confirmed: false,
            bootstrap_hints,
        })
    }

    /// 响应方从二维码 JSON 创建配对会话。
    ///
    /// 解析 `PairingPayload`，校验时效，计算 `binding_digest` 与 SAS 短码。
    pub fn responder_from_qr(qr_json: &str) -> CoreResult<Self> {
        let payload = PairingPayload::from_qr_json(qr_json)?;
        if !validate_payload_structure(&payload) {
            return Err(CoreError::Crypto(
                "配对 payload 校验失败：已过期或字段不合法".into(),
            ));
        }
        let digest = compute_binding_digest(
            &payload.group_id,
            &payload.initiator_pubkey,
            &payload.binding_salt,
        );
        let sas = derive_sas_code(&digest);
        Ok(Self {
            role: PairingRole::Responder,
            group_id: payload.group_id,
            initiator_pubkey: payload.initiator_pubkey,
            binding_salt: payload.binding_salt,
            binding_digest: digest,
            sas_code: sas,
            confirmed: false,
            bootstrap_hints: payload.bootstrap_hints,
        })
    }

    /// 获取配对载荷（用于发起方编码二维码）。
    pub fn payload(&self) -> CoreResult<PairingPayload> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        PairingPayload::new(
            self.group_id.clone(),
            self.initiator_pubkey.clone(),
            self.binding_salt.clone(),
            self.bootstrap_hints.clone(),
            now_ms,
        )
    }

    /// 编码为二维码 JSON（发起方使用）。
    pub fn qr_json(&self) -> CoreResult<String> {
        self.payload()?.to_qr_json()
    }

    /// 获取 SAS 短码（0..=9999）。
    pub fn sas_code(&self) -> u32 {
        self.sas_code
    }

    /// 获取格式化的 SAS 短码字符串（如 "0042"）。
    pub fn sas_display(&self) -> String {
        format_sas_code(self.sas_code)
    }

    /// 获取绑定摘要（32 字节）。
    pub fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }

    /// 获取配对角色。
    pub fn role(&self) -> PairingRole {
        self.role
    }

    /// 获取 group_id。
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    /// 获取发起方公钥。
    pub fn initiator_pubkey(&self) -> &[u8] {
        &self.initiator_pubkey
    }

    /// 确认对端 SAS 短码一致。
    ///
    /// 比对本地 SAS 与对端 SAS，匹配则标记为已确认。
    /// 重复调用已确认的会话返回 `Ok(())`（幂等）。
    pub fn confirm(&mut self, remote_sas: u32) -> CoreResult<()> {
        if self.confirmed {
            return Ok(());
        }
        confirm_sas_code(self.sas_code, remote_sas)?;
        self.confirmed = true;
        Ok(())
    }

    /// 是否已确认。
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

/// 配对 payload 最大有效期：5 分钟（300 秒）。
pub const MAX_PAIRING_AGE_SECS: i64 = 300;

/// 验证 payload 结构合法性：检查字段长度、group_id 非空、timestamp 时效。
///
/// 返回 `true` 表示 payload 结构合法、时效有效；
/// 返回 `false` 表示 payload 被篡改、畸形（字段长度不符或 group_id 为空）或已过期。
///
/// # 命名说明
///
/// 此函数原名 `verify_binding`，但实际不做绑定验证——它仅做结构校验。
/// 完整的端到端完整性由 SAS 短码人工确认完成：
/// 两端独立计算 `binding_digest` 并派生 SAS，用户比对数字一致后才完成绑定。
/// 因此重命名为 `validate_payload_structure` 以准确反映其职责。
pub fn validate_payload_structure(payload: &PairingPayload) -> bool {
    if payload.initiator_pubkey.len() != ED25519_PUBKEY_LEN {
        return false;
    }
    if payload.binding_salt.len() != BINDING_SALT_LEN {
        return false;
    }
    if payload.group_id.is_empty() {
        return false;
    }
    // 时效校验：timestamp 必须在当前时间 ±5 分钟内
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let age_secs = (now_ms - payload.timestamp).abs() / 1000;
    if age_secs > MAX_PAIRING_AGE_SECS {
        return false;
    }
    true
}


/// 用 `OsRng` 生成 16 字节绑定盐。
///
/// 使用操作系统 CSPRNG，适用于密码学场景。
pub fn generate_binding_salt() -> [u8; BINDING_SALT_LEN] {
    let mut salt = [0u8; BINDING_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造测试用公钥（32 字节）。
    fn test_pubkey() -> Vec<u8> {
        (0u8..32).collect()
    }

    /// 构造测试用 payload。
    fn test_payload() -> PairingPayload {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        PairingPayload::new(
            "group-123".to_string(),
            test_pubkey(),
            vec![0xA0; BINDING_SALT_LEN],
            vec!["relay://example.com".to_string()],
            now_ms,
        )
        .unwrap()
    }

    #[test]
    fn qr_json_roundtrip() {
        let payload = test_payload();
        let json = payload.to_qr_json().unwrap();
        let parsed = PairingPayload::from_qr_json(&json).unwrap();
        assert_eq!(payload, parsed);
    }

    #[test]
    fn qr_json_contains_hex_fields() {
        let payload = test_payload();
        let json = payload.to_qr_json().unwrap();
        // hex 编码的公钥与盐应出现在 JSON 中
        assert!(json.contains(&hex::encode(&payload.initiator_pubkey)));
        assert!(json.contains(&hex::encode(&payload.binding_salt)));
        assert!(json.contains("group-123"));
    }

    #[test]
    fn from_qr_json_rejects_malformed() {
        // 缺少字段
        assert!(PairingPayload::from_qr_json(r#"{"group_id":"x"}"#).is_err());
        // 非 JSON
        assert!(PairingPayload::from_qr_json("not json").is_err());
        // 公钥长度错误（hex 编码 31 字节 = 62 字符）
        let bad = r#"{"group_id":"g","initiator_pubkey":"01020300000000000000000000000000000000000000000000000000000000","binding_salt":"0102030405060708090a0b0c0d0e0f10","bootstrap_hints":[],"timestamp":0}"#;
        assert!(PairingPayload::from_qr_json(bad).is_err());
    }

    #[test]
    fn binding_digest_consistent() {
        let group_id = "group-abc";
        let pubkey = test_pubkey();
        let salt = [0x42u8; BINDING_SALT_LEN];
        let d1 = compute_binding_digest(group_id, &pubkey, &salt);
        let d2 = compute_binding_digest(group_id, &pubkey, &salt);
        assert_eq!(d1, d2);
    }

    #[test]
    fn binding_digest_differs_on_input_change() {
        let group_id = "group-abc";
        let pubkey = test_pubkey();
        let salt = [0x42u8; BINDING_SALT_LEN];
        let d_base = compute_binding_digest(group_id, &pubkey, &salt);

        // 改 group_id
        let d_other = compute_binding_digest("group-xyz", &pubkey, &salt);
        assert_ne!(d_base, d_other);

        // 改 pubkey
        let mut other_pubkey = pubkey.clone();
        other_pubkey[0] ^= 0xff;
        let d_other = compute_binding_digest(group_id, &other_pubkey, &salt);
        assert_ne!(d_base, d_other);

        // 改 salt
        let other_salt = [0x43u8; BINDING_SALT_LEN];
        let d_other = compute_binding_digest(group_id, &pubkey, &other_salt);
        assert_ne!(d_base, d_other);
    }

    #[test]
    fn sas_code_deterministic() {
        let digest = [0xABu8; 32];
        let s1 = derive_sas_code(&digest);
        let s2 = derive_sas_code(&digest);
        assert_eq!(s1, s2);
    }

    #[test]
    fn sas_code_in_range() {
        // 测试多个不同摘要，全部应在 0..=9999
        for i in 0u8..=255u8 {
            let mut digest = [0u8; 32];
            digest[0] = i;
            digest[1] = 0xFF;
            digest[2] = 0xFF;
            digest[3] = 0xFF;
            let sas = derive_sas_code(&digest);
            assert!(sas < SAS_MODULUS, "SAS 码超出范围: {sas}");
        }
    }

    #[test]
    fn sas_code_known_value() {
        // 前 4 字节 0x00000001 -> 1
        let mut digest = [0u8; 32];
        digest[3] = 0x01;
        assert_eq!(derive_sas_code(&digest), 1);

        // 前 4 字节 0x00002710 = 10000 -> mod 10000 = 0
        let mut digest = [0u8; 32];
        digest[2] = 0x27;
        digest[3] = 0x10;
        assert_eq!(derive_sas_code(&digest), 0);
    }

    #[test]
    fn validate_payload_structure_accepts_valid() {
        let payload = test_payload();
        assert!(validate_payload_structure(&payload));
    }

    #[test]
    fn validate_payload_structure_rejects_tampered() {
        let mut payload = test_payload();

        // 篡改公钥长度
        payload.initiator_pubkey.pop();
        assert!(!validate_payload_structure(&payload));

        // 恢复并篡改盐长度
        payload.initiator_pubkey = test_pubkey();
        payload.binding_salt.push(0x00);
        assert!(!validate_payload_structure(&payload));

        // 恢复并清空 group_id
        payload.binding_salt = vec![0xA0; BINDING_SALT_LEN];
        payload.group_id.clear();
        assert!(!validate_payload_structure(&payload));

        // 时效过期：使用 10 分钟前的时间戳
        let expired_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
            - 600_000;
        let expired_payload = PairingPayload::new(
            "group-expired".to_string(),
            test_pubkey(),
            vec![0xA0; BINDING_SALT_LEN],
            vec![],
            expired_ms,
        )
        .unwrap();
        assert!(!validate_payload_structure(&expired_payload));
    }

    #[test]
    fn generate_binding_salt_produces_distinct_values() {
        let salt1 = generate_binding_salt();
        let salt2 = generate_binding_salt();
        assert_eq!(salt1.len(), BINDING_SALT_LEN);
        assert_eq!(salt2.len(), BINDING_SALT_LEN);
        // 两个 16 字节随机盐相等的概率极低（2^-128）
        assert_ne!(salt1, salt2, "两次生成的绑定盐不应相等");
    }

    #[test]
    fn end_to_end_pairing_flow() {
        // 模拟完整配对流程
        // 1. 发起方生成盐与 payload
        let group_id = "e2e-group".to_string();
        let salt = generate_binding_salt();
        let pubkey = test_pubkey();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let payload = PairingPayload::new(
            group_id.clone(),
            pubkey.clone(),
            salt.to_vec(),
            vec![],
            now_ms,
        )
        .unwrap();

        // 2. 编码为二维码 JSON
        let qr = payload.to_qr_json().unwrap();

        // 3. 扫码方解析
        let parsed = PairingPayload::from_qr_json(&qr).unwrap();
        assert!(validate_payload_structure(&parsed));

        // 4. 两端独立计算 binding_digest 与 SAS
        let digest_init = compute_binding_digest(&group_id, &pubkey, &salt);
        let digest_resp = compute_binding_digest(
            &parsed.group_id,
            &parsed.initiator_pubkey,
            &parsed.binding_salt,
        );
        assert_eq!(digest_init, digest_resp);

        let sas_init = derive_sas_code(&digest_init);
        let sas_resp = derive_sas_code(&digest_resp);
        assert_eq!(sas_init, sas_resp);
        assert!(sas_init < SAS_MODULUS);
    }

    // ===== SAS 格式化与确认测试 =====

    #[test]
    fn format_sas_code_pads_to_four_digits() {
        assert_eq!(format_sas_code(0), "0000");
        assert_eq!(format_sas_code(1), "0001");
        assert_eq!(format_sas_code(42), "0042");
        assert_eq!(format_sas_code(999), "0999");
        assert_eq!(format_sas_code(9999), "9999");
    }

    #[test]
    fn confirm_sas_code_matching() {
        assert!(confirm_sas_code(42, 42).is_ok());
        assert!(confirm_sas_code(0, 0).is_ok());
        assert!(confirm_sas_code(9999, 9999).is_ok());
    }

    #[test]
    fn confirm_sas_code_mismatching() {
        assert!(confirm_sas_code(42, 43).is_err());
        assert!(confirm_sas_code(0, 1).is_err());
        assert!(confirm_sas_code(1234, 4321).is_err());
    }

    // ===== PairingSession 测试 =====

    #[test]
    fn pairing_session_initiator_and_responder_match() {
        let group_id = "session-group".to_string();
        let pubkey = test_pubkey();

        // 发起方创建会话
        let initiator =
            PairingSession::initiator(group_id.clone(), pubkey.clone(), vec![]).unwrap();
        assert_eq!(initiator.role(), PairingRole::Initiator);
        assert!(!initiator.is_confirmed());

        // 编码二维码
        let qr = initiator.qr_json().unwrap();

        // 响应方扫码
        let mut responder = PairingSession::responder_from_qr(&qr).unwrap();
        assert_eq!(responder.role(), PairingRole::Responder);
        assert!(!responder.is_confirmed());

        // 两端 SAS 短码应一致
        assert_eq!(initiator.sas_code(), responder.sas_code());
        assert_eq!(initiator.sas_display(), responder.sas_display());
        assert_eq!(initiator.sas_display().len(), 4);

        // 确认 SAS
        let sas = initiator.sas_code();
        responder.confirm(sas).unwrap();
        assert!(responder.is_confirmed());
    }

    #[test]
    fn pairing_session_confirm_mismatch_fails() {
        let pubkey = test_pubkey();
        let initiator = PairingSession::initiator("mismatch-group".into(), pubkey, vec![]).unwrap();
        let qr = initiator.qr_json().unwrap();
        let mut responder = PairingSession::responder_from_qr(&qr).unwrap();

        // 用错误的 SAS 码确认
        let wrong_sas = (responder.sas_code() + 1) % SAS_MODULUS;
        let result = responder.confirm(wrong_sas);
        assert!(result.is_err());
        assert!(!responder.is_confirmed());
    }

    #[test]
    fn pairing_session_confirm_is_idempotent() {
        let pubkey = test_pubkey();
        let initiator =
            PairingSession::initiator("idempotent-group".into(), pubkey, vec![]).unwrap();
        let qr = initiator.qr_json().unwrap();
        let mut responder = PairingSession::responder_from_qr(&qr).unwrap();

        let sas = initiator.sas_code();

        // 第一次确认
        responder.confirm(sas).unwrap();
        assert!(responder.is_confirmed());

        // 第二次确认（幂等，即使 SAS 不同也返回 Ok）
        let wrong_sas = (sas + 1) % SAS_MODULUS;
        responder.confirm(wrong_sas).unwrap();
        assert!(responder.is_confirmed());
    }

    #[test]
    fn pairing_session_responder_rejects_expired_qr() {
        let pubkey = test_pubkey();
        let expired_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
            - 600_000; // 10 分钟前
        let payload = PairingPayload::new(
            "expired-group".to_string(),
            pubkey,
            vec![0xA0; BINDING_SALT_LEN],
            vec![],
            expired_ms,
        )
        .unwrap();
        let qr = payload.to_qr_json().unwrap();

        let result = PairingSession::responder_from_qr(&qr);
        assert!(result.is_err());
    }

    #[test]
    fn pairing_session_binding_digest_consistent() {
        let group_id = "digest-group".to_string();
        let pubkey = test_pubkey();

        let session = PairingSession::initiator(group_id.clone(), pubkey.clone(), vec![]).unwrap();

        // Session 内部存储的 digest 应可通过 accessor 获取
        // 通过 SAS 码间接验证 digest 一致性（SAS 从 digest 确定性派生）
        let expected_sas = derive_sas_code(session.binding_digest());
        assert_eq!(session.sas_code(), expected_sas);
    }

    #[test]
    fn pairing_session_group_and_pubkey_accessors() {
        let group_id = "accessor-group".to_string();
        let pubkey = test_pubkey();

        let session = PairingSession::initiator(group_id.clone(), pubkey.clone(), vec![]).unwrap();
        assert_eq!(session.group_id(), "accessor-group");
        assert_eq!(session.initiator_pubkey(), &pubkey as &[u8]);
    }

    #[test]
    fn pairing_session_full_flow_with_sas_confirmation() {
        // 模拟完整的 §12.1 推荐流程：
        // 1. 发起方生成二维码
        // 2. 响应方扫码
        // 3. 两端显示 SAS 短码
        // 4. 用户比对后确认

        let group_id = "full-flow-group".to_string();
        let pubkey = test_pubkey();

        // 1. 发起方
        let initiator =
            PairingSession::initiator(group_id, pubkey, vec!["relay://example.com".into()])
                .unwrap();
        let qr = initiator.qr_json().unwrap();

        // 2. 响应方扫码
        let mut responder = PairingSession::responder_from_qr(&qr).unwrap();

        // 3. 两端显示 SAS
        let initiator_sas = initiator.sas_display();
        let responder_sas = responder.sas_display();

        // 4. 用户比对（模拟用户确认一致）
        assert_eq!(initiator_sas, responder_sas, "两端 SAS 短码必须一致");

        // 5. 确认绑定
        responder.confirm(initiator.sas_code()).unwrap();
        assert!(responder.is_confirmed());
    }

    #[test]
    fn pairing_session_different_pubkeys_produce_different_sas() {
        let group_id = "diff-pubkey-group".to_string();
        let pubkey_a: Vec<u8> = (0u8..32).collect();
        let pubkey_b: Vec<u8> = (1u8..33).collect();

        let session_a = PairingSession::initiator(group_id.clone(), pubkey_a, vec![]).unwrap();
        let session_b = PairingSession::initiator(group_id, pubkey_b, vec![]).unwrap();

        // 不同公钥应产生不同的 SAS 短码（极大概率）
        // 注意：理论上可能碰撞（1/10000），但实际不会发生
        assert_ne!(
            session_a.sas_code(),
            session_b.sas_code(),
            "不同公钥不应产生相同 SAS 短码"
        );
    }
}
