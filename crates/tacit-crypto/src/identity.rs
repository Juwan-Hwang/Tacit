//! 设备身份：Ed25519 签名密钥 + X25519 静态密钥（用于 Noise）。

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use tacit_core::{CoreError, CoreResult, PeerId};

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

    /// 派生 PeerId（公钥的 hex 前 16 字符）。
    pub fn to_peer_id(&self) -> PeerId {
        PeerId::new(&self.to_hex()[..16])
    }
}

/// 持久化的 X25519 密钥对（私钥 + 公钥）。
#[derive(Debug, Clone)]
pub struct StaticKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

/// 设备身份：签名密钥 + 静态密钥。
pub struct DeviceIdentity {
    /// Ed25519 签名密钥。
    signing_key: SigningKey,
    /// X25519 静态密钥对（用于 Noise 握手）。
    static_kp: StaticKeypair,
}

impl DeviceIdentity {
    /// 生成新身份。
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        // 用 snow 生成 X25519 密钥对
        let kp = snow::Builder::new(
            "Noise_XX_25519_ChaChaPoly_BLAKE2s"
                .parse()
                .expect("解析 Noise 参数"),
        )
        .generate_keypair()
        .expect("生成 X25519 密钥对");
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
        Self {
            signing_key,
            static_kp,
        }
    }

    /// 从已有密钥恢复（用于从持久化恢复）。
    pub fn from_keys(signing_key_bytes: &[u8], static_kp: StaticKeypair) -> CoreResult<Self> {
        if signing_key_bytes.len() != 32 {
            return Err(CoreError::Crypto("签名密钥长度必须为 32 字节".into()));
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(signing_key_bytes);
        let signing_key = SigningKey::from_bytes(&sk);
        Ok(Self {
            signing_key,
            static_kp,
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

    /// 序列化签名密钥（用于持久化）。
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity() {
        let id = DeviceIdentity::generate();
        let pid = id.peer_id();
        assert!(!pid.as_str().is_empty());
        assert_eq!(id.public_key().len(), 32);
    }

    #[test]
    fn peer_pubkey_roundtrip() {
        let id = DeviceIdentity::generate();
        let pubkey = id.public_key();
        let peer_pub = PeerPubkey(pubkey);
        let hex = peer_pub.to_hex();
        let parsed = PeerPubkey::from_hex(&hex).unwrap();
        assert_eq!(peer_pub, parsed);
    }

    #[test]
    fn restore_from_keys() {
        let id = DeviceIdentity::generate();
        let sk = id.signing_key_bytes();
        let static_kp = id.static_keypair().clone();
        let restored = DeviceIdentity::from_keys(&sk, static_kp).unwrap();
        assert_eq!(id.public_key(), restored.public_key());
    }
}
