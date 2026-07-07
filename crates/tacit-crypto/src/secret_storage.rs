//! 平台安全存储抽象。
//!
//! 定义 [`SecretStorage`] trait，用于安全地持久化设备私钥等敏感数据。
//!
//! ## 职责切分
//!
//! | 实现 | 平台 | 后端 |
//! |------|------|------|
//! | [`InMemoryStorage`] | 全平台（测试用） | 进程内存，随进程退出消失 |
//! | [`KeyringStorage`]  | 桌面（Win/Mac/Linux） | 原生钥匙串（`keyring` crate） |
//! | 宿主注入 | iOS/Android | Keychain / Keystore（宿主 App 实现） |
//!
//! ## 为什么 Rust 做 trait + 桌面默认
//!
//! 私钥明文存 SQLite 是已知安全债（AUDIT_REVIEW #63）。
//! `keyring` crate 已覆盖 Win/Mac/Linux 原生钥匙串，Rust 端只需定义 trait + 接入
//! 即可消除桌面端的这个债。只有 iOS/Android 需要宿主注入平台实现。

use parking_lot::Mutex;
use std::collections::HashMap;
use tacit_core::CoreResult;

/// 安全存储 trait：抽象平台密钥存储后端。
///
/// 实现方应保证：
/// - 数据存储在操作系统级加密存储中（非明文文件）
/// - 进程退出后数据仍然存在（持久化）
/// - 未授权进程无法读取数据（访问控制由 OS 保证）
pub trait SecretStorage: Send + Sync {
    /// 存储密钥。同名密钥会被覆盖。
    fn store_secret(&self, key: &str, value: &[u8]) -> CoreResult<()>;

    /// 读取密钥。不存在时返回 `Ok(None)`。
    fn load_secret(&self, key: &str) -> CoreResult<Option<Vec<u8>>>;

    /// 删除密钥。不存在时返回 `Ok(())`。
    fn delete_secret(&self, key: &str) -> CoreResult<()>;
}

/// 内存存储：仅供测试和开发使用。
///
/// 数据存在进程内存中，进程退出即丢失。不提供任何持久化或加密保证。
pub struct InMemoryStorage {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStorage for InMemoryStorage {
    fn store_secret(&self, key: &str, value: &[u8]) -> CoreResult<()> {
        self.data.lock().insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn load_secret(&self, key: &str) -> CoreResult<Option<Vec<u8>>> {
        Ok(self.data.lock().get(key).cloned())
    }

    fn delete_secret(&self, key: &str) -> CoreResult<()> {
        self.data.lock().remove(key);
        Ok(())
    }
}

/// 桌面平台原生钥匙串存储。
///
/// 使用 `keyring` crate 访问：
/// - **Windows**: Credential Manager
/// - **macOS**: Keychain
/// - **Linux**: Secret Service (GNOME Keyring / KWallet)
///
/// 需要 `keyring` feature flag 启用。
#[cfg(feature = "keyring")]
pub struct KeyringStorage {
    service_name: String,
}

#[cfg(feature = "keyring")]
impl KeyringStorage {
    /// 创建 KeyringStorage。
    ///
    /// `service_name` 是钥匙串条目的服务标识（如 `"tacit"`）。
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }
}

#[cfg(feature = "keyring")]
impl SecretStorage for KeyringStorage {
    fn store_secret(&self, key: &str, value: &[u8]) -> CoreResult<()> {
        let entry = keyring::Entry::new(&self.service_name, key)
            .map_err(|e| tacit_core::CoreError::Crypto(format!("keyring 创建条目失败: {e}")))?;
        // keyring crate v3 接受 bytes
        entry
            .set_secret(value)
            .map_err(|e| tacit_core::CoreError::Crypto(format!("keyring 存储失败: {e}")))?;
        Ok(())
    }

    fn load_secret(&self, key: &str) -> CoreResult<Option<Vec<u8>>> {
        let entry = keyring::Entry::new(&self.service_name, key)
            .map_err(|e| tacit_core::CoreError::Crypto(format!("keyring 创建条目失败: {e}")))?;
        match entry.get_secret() {
            Ok(data) => Ok(Some(data)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(tacit_core::CoreError::Crypto(format!(
                "keyring 读取失败: {e}"
            ))),
        }
    }

    fn delete_secret(&self, key: &str) -> CoreResult<()> {
        let entry = keyring::Entry::new(&self.service_name, key)
            .map_err(|e| tacit_core::CoreError::Crypto(format!("keyring 创建条目失败: {e}")))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(tacit_core::CoreError::Crypto(format!(
                "keyring 删除失败: {e}"
            ))),
        }
    }
}

/// 序列化 `DeviceIdentity` 为字节向量，用于安全存储。
///
/// 格式：`signing_key(32) || static_private(32) || static_public(32) || binding_proof(64)`
/// 共 160 字节。
///
/// 返回 `Zeroizing<[u8; 160]>` 确保栈内存在 drop 时被安全擦除。
/// 使用栈分配而非堆分配，避免内存分配器碎片导致敏感私钥材料在堆中残留。
pub fn serialize_identity(identity: &crate::DeviceIdentity) -> zeroize::Zeroizing<[u8; 160]> {
    // 直接初始化 Zeroizing 包装的数组，避免 [u8; 160] 的 Copy 特性
    // 导致原始数组残留在栈上未被清零。
    let mut arr = zeroize::Zeroizing::new([0u8; 160]);
    arr[0..32].copy_from_slice(&identity.signing_key_bytes());
    arr[32..64].copy_from_slice(&identity.static_keypair().private);
    arr[64..96].copy_from_slice(&identity.static_keypair().public);
    arr[96..160].copy_from_slice(identity.binding_proof());
    arr
}

/// 从字节向量反序列化 `DeviceIdentity`。
///
/// 接受 `serialize_identity` 的输出格式。
/// 接收 `Zeroizing<Vec<u8>>` 所有权，确保输入缓冲区在使用后被安全擦除。
pub fn deserialize_identity(
    bytes: zeroize::Zeroizing<Vec<u8>>,
) -> CoreResult<crate::DeviceIdentity> {
    if bytes.len() != 160 {
        return Err(tacit_core::CoreError::Crypto(format!(
            "身份数据长度不正确: 期望 160 字节, 实际 {} 字节",
            bytes.len()
        )));
    }

    // 直接初始化 Zeroizing 包装的数组，避免 [u8; 32] 的 Copy 特性
    // 导致原始数组残留在栈上未被清零。
    let mut signing_key_bytes = zeroize::Zeroizing::new([0u8; 32]);
    signing_key_bytes.copy_from_slice(&bytes[..32]);
    let mut static_private = zeroize::Zeroizing::new([0u8; 32]);
    static_private.copy_from_slice(&bytes[32..64]);
    let static_public: [u8; 32] = bytes[64..96].try_into().unwrap();
    let binding_proof: [u8; 64] = bytes[96..160].try_into().unwrap();

    let static_kp = crate::StaticKeypair {
        private: *static_private,
        public: static_public,
    };
    // static_kp 派生了 Zeroize+ZeroizeOnDrop，离开作用域时自动零化

    crate::DeviceIdentity::from_keys(&*signing_key_bytes, static_kp, &binding_proof)
    // bytes (Zeroizing<Vec<u8>>) 离开作用域，自动零化
    // signing_key_bytes (Zeroizing<Vec<u8>>) 离开作用域，自动零化
    // static_private (Zeroizing<[u8;32]>) 离开作用域，自动零化
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_store_load_delete() {
        let storage = InMemoryStorage::new();

        // 存储
        storage.store_secret("test-key", b"secret-value").unwrap();

        // 读取
        let loaded = storage.load_secret("test-key").unwrap();
        assert_eq!(loaded, Some(b"secret-value".to_vec()));

        // 不存在的 key
        let missing = storage.load_secret("nonexistent").unwrap();
        assert_eq!(missing, None);

        // 删除
        storage.delete_secret("test-key").unwrap();
        let after_delete = storage.load_secret("test-key").unwrap();
        assert_eq!(after_delete, None);

        // 删除不存在的 key 不报错
        storage.delete_secret("nonexistent").unwrap();
    }

    #[test]
    fn identity_serialize_deserialize_roundtrip() {
        let identity = crate::DeviceIdentity::generate().unwrap();
        let serialized = serialize_identity(&identity);
        assert_eq!(serialized.len(), 160);

        let deserialized =
            deserialize_identity(zeroize::Zeroizing::new(serialized.to_vec())).unwrap();

        // 验证关键字段一致
        assert_eq!(identity.public_key(), deserialized.public_key());
        assert_eq!(
            identity.static_keypair().public,
            deserialized.static_keypair().public
        );
        assert_eq!(identity.binding_proof(), deserialized.binding_proof());
    }

    #[test]
    fn identity_storage_roundtrip() {
        let storage = InMemoryStorage::new();
        let identity = crate::DeviceIdentity::generate().unwrap();
        let peer_id = identity.peer_id();

        // 存储
        let serialized = serialize_identity(&identity);
        storage
            .store_secret(&format!("identity:{peer_id}"), &*serialized)
            .unwrap();

        // 读取并反序列化
        let loaded = storage
            .load_secret(&format!("identity:{peer_id}"))
            .unwrap()
            .unwrap();
        let restored = deserialize_identity(zeroize::Zeroizing::new(loaded)).unwrap();

        // 验证
        assert_eq!(identity.public_key(), restored.public_key());
        assert_eq!(peer_id, restored.peer_id());
    }

    #[test]
    fn deserialize_wrong_length_errors() {
        let result = deserialize_identity(zeroize::Zeroizing::new(vec![0u8; 100]));
        assert!(result.is_err());
    }
}
