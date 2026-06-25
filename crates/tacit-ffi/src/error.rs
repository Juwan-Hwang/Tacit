//! FFI 边界错误类型。
//!
//! `CoreError` 定义在 `tacit-core` 中，无法直接添加 UniFFI 派生（会污染核心 crate）。
//! 因此在 FFI 边界定义 `TacitFfiError`，将 `CoreError` 转换为 UniFFI 可消费的错误类型。

use thiserror::Error;

/// FFI 边界错误。
///
/// Kotlin/Swift 侧通过此类型获取错误详情。
#[derive(Debug, Error, uniffi::Error)]
pub enum TacitFfiError {
    #[error("文档不存在: {0}")]
    DocNotFound(String),

    #[error("block 不存在: doc={doc_id} block={block_id}")]
    BlockNotFound { doc_id: String, block_id: String },

    #[error("frontier 非法: {0}")]
    InvalidFrontier(String),

    #[error("存储错误: {0}")]
    Store(String),

    #[error("CRDT 错误: {0}")]
    Crdt(String),

    #[error("传输错误: {0}")]
    Transport(String),

    #[error("加密错误: {0}")]
    Crypto(String),

    #[error("同步错误: {0}")]
    Sync(String),

    #[error("配置错误: {0}")]
    Config(String),

    #[error("IO 错误: {0}")]
    Io(String),

    #[error("内部错误: {0}")]
    Internal(String),

    #[error("命令总线错误: {0}")]
    CommandBus(String),
}

impl From<tacit_core::CoreError> for TacitFfiError {
    fn from(e: tacit_core::CoreError) -> Self {
        use tacit_core::CoreError;
        match e {
            CoreError::DocNotFound(s) => Self::DocNotFound(s),
            CoreError::BlockNotFound { doc_id, block_id } => Self::BlockNotFound {
                doc_id,
                block_id,
            },
            CoreError::InvalidFrontier(s) => Self::InvalidFrontier(s),
            CoreError::PeerNotFound(s) => Self::Internal(s),
            CoreError::Serialize(s) => Self::Internal(format!("序列化失败: {s}")),
            CoreError::Deserialize(s) => Self::Internal(format!("反序列化失败: {s}")),
            CoreError::Store(s) => Self::Store(s),
            CoreError::Crdt(s) => Self::Crdt(s),
            CoreError::Transport(s) => Self::Transport(s),
            CoreError::Crypto(s) => Self::Crypto(s),
            CoreError::Sync(s) => Self::Sync(s),
            CoreError::Config(s) => Self::Config(s),
            CoreError::Io(e) => Self::Io(e.to_string()),
            CoreError::Internal(s) => Self::Internal(s),
        }
    }
}

impl From<crate::command_bus::CommandBusError> for TacitFfiError {
    fn from(e: crate::command_bus::CommandBusError) -> Self {
        Self::CommandBus(e.to_string())
    }
}
