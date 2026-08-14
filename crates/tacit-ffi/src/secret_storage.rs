//! FFI 安全存储回调接口。
//!
//! 平台层（Kotlin/Swift）实现 [`ForeignSecretStorage`] trait，
//! 通过 `TacitEngine::ffi_set_secret_storage` 注入。
//!
//! 设计模式与 [`ForeignEventListener`](crate::listener::ForeignEventListener) 一致：
//! 通过 UniFFI foreign trait 让宿主平台提供原生安全存储实现。

use std::sync::Arc;
use tacit_core::CoreResult;
use tacit_crypto::SecretStorage;

use crate::error::TacitFfiError;

/// UniFFI 回调接口：平台层实现此接口提供安全存储。
///
/// 存储和读取字节数组形式的密钥/敏感数据。
/// 平台层应将数据存储在操作系统级加密存储中
/// （Keychain / Keystore / Credential Manager）。
#[uniffi::export(with_foreign)]
pub trait ForeignSecretStorage: Send + Sync {
    /// 存储密钥。同名密钥会被覆盖。
    fn store_secret(&self, key: String, value: Vec<u8>) -> Result<(), TacitFfiError>;

    /// 读取密钥。不存在时返回 `Ok(None)`。
    fn load_secret(&self, key: String) -> Result<Option<Vec<u8>>, TacitFfiError>;

    /// 删除密钥。不存在时返回 `Ok(())`。
    fn delete_secret(&self, key: String) -> Result<(), TacitFfiError>;
}

/// 适配器：将 `ForeignSecretStorage` 适配为 `SecretStorage`。
pub(crate) struct ForeignSecretStorageAdapter {
    inner: Arc<dyn ForeignSecretStorage>,
}

impl ForeignSecretStorageAdapter {
    pub(crate) fn new(inner: Arc<dyn ForeignSecretStorage>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

impl SecretStorage for ForeignSecretStorageAdapter {
    fn store_secret(&self, key: &str, value: &[u8]) -> CoreResult<()> {
        self.inner
            .store_secret(key.to_string(), value.to_vec())
            .map_err(|e| tacit_core::CoreError::Crypto(format!("ForeignSecretStorage: {e}")))
    }

    fn load_secret(&self, key: &str) -> CoreResult<Option<zeroize::Zeroizing<Vec<u8>>>> {
        self.inner
            .load_secret(key.to_string())
            .map(|opt| opt.map(zeroize::Zeroizing::new))
            .map_err(|e| tacit_core::CoreError::Crypto(format!("ForeignSecretStorage: {e}")))
    }

    fn delete_secret(&self, key: &str) -> CoreResult<()> {
        self.inner
            .delete_secret(key.to_string())
            .map_err(|e| tacit_core::CoreError::Crypto(format!("ForeignSecretStorage: {e}")))
    }
}
