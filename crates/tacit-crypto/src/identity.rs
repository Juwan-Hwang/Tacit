//! 设备身份：Ed25519 签名密钥 + X25519 静态密钥（用于 Noise）。
//!
//! # 安全模型
//!
//! 每台设备拥有两对密钥：
//! - **Ed25519 签名密钥对**：设备身份的唯一标识，用于签名。
//! - **X25519 静态密钥对**：用于 Noise_XX 握手的前向保密。
//!
//! ## 绑定（#1）
//!
//! 为防止 MITM 攻击者替换 X25519 静态公钥，设备在生成身份时用
//! Ed25519 签名密钥对 X25519 公钥签名，生成 `binding_proof`。
//!
//! 握手完成后，对端用设备的 Ed25519 公钥验证 `binding_proof`，
//! 确认 Noise 通道对端的 X25519 公钥确实属于该 Ed25519 身份。
//!
//! 绑定消息格式：`b"tacit-static-binding-v1" || x25519_pubkey`

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use tacit_core::{CoreError, CoreResult, PeerId};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 绑定消息域分隔符（防止跨协议签名重用）。
const BINDING_DOMAIN: &[u8] = b"tacit-static-binding-v1";

/// peer 公钥（Ed25519 验证密钥，32 字节）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPubkey(pub [u8; 32]);

impl PeerPubkey {
    /// 从字节构造。
    pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
        if bytes.len() != 32 {
            return Err(CoreError::Crypto("公钥长度必须为 32 字节".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// 转为字节。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 转为 hex 字符串。
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// 从 hex 字符串构造。
    pub fn from_hex(s: &str) -> CoreResult<Self> {
        let bytes = hex::decode(s).map_err(|e| CoreError::Crypto(format!("hex 解码失败: {e}")))?;
        Self::from_bytes(&bytes)
    }

    /// 派生 PeerId（公钥的 hex 前 32 字符，128bit）。
    pub fn to_peer_id(&self) -> PeerId {
        PeerId::new(&self.to_hex()[..32])
    }
}

/// 持久化的 X25519 密钥对（私钥 + 公钥）。
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct StaticKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

/// 设备身份：签名密钥 + 静态密钥 + 绑定证明。
#[derive(ZeroizeOnDrop)]
pub struct DeviceIdentity {
    /// Ed25519 签名密钥。
    signing_key: SigningKey,
    /// X25519 静态密钥对（用于 Noise 握手）。
    static_kp: StaticKeypair,
    /// #1 绑定证明：Ed25519 签名 over `BINDING_DOMAIN || x25519_pubkey`。
    binding_proof: [u8; 64],
}

/// 构造绑定消息：`BINDING_DOMAIN || x25519_pubkey`。
fn binding_message(x25519_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BINDING_DOMAIN.len() + 32);
    msg.extend_from_slice(BINDING_DOMAIN);
    msg.extend_from_slice(x25519_pubkey);
    msg
}

impl DeviceIdentity {
    /// 生成新身份。
    ///
    /// 生成 Ed25519 签名密钥和 X25519 静态密钥，并用 Ed25519 签名
    /// 绑定 X25519 公钥，生成 `binding_proof`。
    ///
    /// 返回 Result 而非 panic，以便调用方在极端情况（如系统熵源不可用）下优雅降级。
    pub fn generate() -> CoreResult<Self> {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        // 用 snow 生成 X25519 密钥对
        let params = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| CoreError::Crypto(format!("解析 Noise 参数失败: {e}")))?;
        let kp = snow::Builder::new(params)
            .generate_keypair()
            .map_err(|e| CoreError::Crypto(format!("生成 X25519 密钥对失败: {e}")))?;
        let static_kp = StaticKeypair {
            private: {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&kp.private);
                arr
            },
            public: {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&kp.public);
                arr
            },
        };

        // #1: 生成绑定证明——用 Ed25519 签名 X25519 公钥
        let msg = binding_message(&static_kp.public);
        let sig: Signature = signing_key.sign(&msg);
        let binding_proof = sig.to_bytes();

        Ok(Self {
            signing_key,
            static_kp,
            binding_proof,
        })
    }

    /// 从已有密钥恢复（用于从持久化恢复）。
    ///
    /// # 参数
    /// - `signing_key_bytes`: Ed25519 签名私钥（32 字节）
    /// - `static_kp`: X25519 静态密钥对
    /// - `binding_proof`: 绑定证明（64 字节），若为空则自动重新计算
    pub fn from_keys(
        signing_key_bytes: &[u8],
        static_kp: StaticKeypair,
        binding_proof: &[u8],
    ) -> CoreResult<Self> {
        if signing_key_bytes.len() != 32 {
            return Err(CoreError::Crypto("签名密钥长度必须为 32 字节".into()));
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(signing_key_bytes);
        let signing_key = SigningKey::from_bytes(&sk);

        // 绑定证明：空→重新计算（向后兼容），64 字节→使用传入值，其他→报错
        let proof = if binding_proof.is_empty() {
            let msg = binding_message(&static_kp.public);
            let sig: Signature = signing_key.sign(&msg);
            sig.to_bytes()
        } else if binding_proof.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(binding_proof);
            arr
        } else {
            return Err(CoreError::Crypto(format!(
                "无效的绑定证明长度：期望 64 字节，实际 {} 字节",
                binding_proof.len()
            )));
        };

        Ok(Self {
            signing_key,
            static_kp,
            binding_proof: proof,
        })
    }

    /// 签名密钥的公钥（Ed25519 验证密钥）。
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// 公钥字节（Ed25519）。
    pub fn public_key(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    /// PeerId（从公钥派生）。
    pub fn peer_id(&self) -> PeerId {
        PeerPubkey(self.public_key()).to_peer_id()
    }

    /// 签名密钥引用。
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// X25519 静态密钥对。
    pub fn static_keypair(&self) -> &StaticKeypair {
        &self.static_kp
    }

    /// #1 绑定证明（64 字节 Ed25519 签名）。
    pub fn binding_proof(&self) -> &[u8; 64] {
        &self.binding_proof
    }

    /// 序列化签名密钥（用于持久化）。
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// #2 验证对端身份绑定：确认 Noise 通道对端的 X25519 公钥
/// 确实属于声称的 Ed25519 身份。
///
/// 在 Noise 握手完成后调用此函数，传入握手结果中的 `remote_static_pubkey`
/// 和对端的 Ed25519 公钥 + 绑定证明。
///
/// # 参数
/// - `ed25519_pubkey`: 对端的 Ed25519 验证公钥（32 字节）
/// - `x25519_pubkey`: 握手获得的对端 X25519 静态公钥（32 字节）
/// - `binding_proof`: 对端的绑定证明（64 字节）
///
/// # 返回
/// - `Ok(())`: 绑定验证通过，X25519 公钥确实属于该 Ed25519 身份
/// - `Err`: 绑定验证失败，可能存在 MITM 攻击
pub fn verify_static_binding(
    ed25519_pubkey: &[u8; 32],
    x25519_pubkey: &[u8; 32],
    binding_proof: &[u8],
) -> CoreResult<()> {
    if binding_proof.len() != 64 {
        return Err(CoreError::Crypto(format!(
            "绑定证明长度必须为 64 字节，实际 {}",
            binding_proof.len()
        )));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(binding_proof);
    let sig = Signature::from_bytes(&sig_arr);

    let vk = VerifyingKey::from_bytes(ed25519_pubkey)
        .map_err(|e| CoreError::Crypto(format!("无效 Ed25519 公钥: {e}")))?;

    let msg = binding_message(x25519_pubkey);

    vk.verify(&msg, &sig).map_err(|e| {
        CoreError::Crypto(format!(
            "绑定验证失败：X25519 公钥与 Ed25519 身份不匹配，可能存在 MITM: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity() {
        let id = DeviceIdentity::generate().unwrap();
        let pid = id.peer_id();
        assert!(!pid.as_str().is_empty());
        assert_eq!(id.public_key().len(), 32);
        assert_eq!(id.binding_proof().len(), 64);
    }

    #[test]
    fn peer_pubkey_roundtrip() {
        let id = DeviceIdentity::generate().unwrap();
        let pubkey = id.public_key();
        let peer_pub = PeerPubkey(pubkey);
        let hex = peer_pub.to_hex();
        let parsed = PeerPubkey::from_hex(&hex).unwrap();
        assert_eq!(peer_pub, parsed);
    }

    #[test]
    fn restore_from_keys() {
        let id = DeviceIdentity::generate().unwrap();
        let sk = id.signing_key_bytes();
        let static_kp = id.static_keypair().clone();
        let proof = id.binding_proof();
        let restored = DeviceIdentity::from_keys(&sk, static_kp, proof).unwrap();
        assert_eq!(id.public_key(), restored.public_key());
        assert_eq!(id.binding_proof(), restored.binding_proof());
    }

    #[test]
    fn restore_from_keys_recomputes_binding() {
        let id = DeviceIdentity::generate().unwrap();
        let sk = id.signing_key_bytes();
        let static_kp = id.static_keypair().clone();
        // 传入空 binding_proof，应自动重新计算
        let restored = DeviceIdentity::from_keys(&sk, static_kp, &[]).unwrap();
        assert_eq!(id.binding_proof(), restored.binding_proof());
    }

    // #1: 绑定证明验证测试

    #[test]
    fn verify_binding_accepts_valid() {
        let id = DeviceIdentity::generate().unwrap();
        let ed25519_pub = id.public_key();
        let x25519_pub = id.static_keypair().public;
        let proof = id.binding_proof();

        let result = verify_static_binding(&ed25519_pub, &x25519_pub, proof);
        assert!(result.is_ok(), "有效绑定应验证通过");
    }

    #[test]
    fn verify_binding_rejects_wrong_x25519() {
        let id = DeviceIdentity::generate().unwrap();
        let ed25519_pub = id.public_key();
        // 用不同的 X25519 公钥（属于另一个设备）
        let other = DeviceIdentity::generate().unwrap();
        let wrong_x25519 = other.static_keypair().public;
        let proof = id.binding_proof();

        let result = verify_static_binding(&ed25519_pub, &wrong_x25519, proof);
        assert!(result.is_err(), "错误的 X25519 公钥应验证失败");
    }

    #[test]
    fn verify_binding_rejects_wrong_ed25519() {
        let id = DeviceIdentity::generate().unwrap();
        // 用不同的 Ed25519 公钥（属于另一个设备）
        let other = DeviceIdentity::generate().unwrap();
        let wrong_ed25519 = other.public_key();
        let x25519_pub = id.static_keypair().public;
        let proof = id.binding_proof();

        let result = verify_static_binding(&wrong_ed25519, &x25519_pub, proof);
        assert!(result.is_err(), "错误的 Ed25519 公钥应验证失败");
    }

    #[test]
    fn verify_binding_rejects_tampered_proof() {
        let id = DeviceIdentity::generate().unwrap();
        let ed25519_pub = id.public_key();
        let x25519_pub = id.static_keypair().public;
        let mut tampered = *id.binding_proof();
        tampered[0] ^= 0xFF; // 翻转一个 bit

        let result = verify_static_binding(&ed25519_pub, &x25519_pub, &tampered);
        assert!(result.is_err(), "篡改的绑定证明应验证失败");
    }

    #[test]
    fn verify_binding_rejects_short_proof() {
        let id = DeviceIdentity::generate().unwrap();
        let ed25519_pub = id.public_key();
        let x25519_pub = id.static_keypair().public;

        let result = verify_static_binding(&ed25519_pub, &x25519_pub, &[0u8; 32]);
        assert!(result.is_err(), "过短的绑定证明应验证失败");
    }
}
