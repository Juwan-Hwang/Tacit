//! Tacit 错误类型。
//!
//! 库内部统一使用 `thiserror` 定义精确错误；FFI 边界再统一转换为
//! 平台可消费的错误码或字符串。

use thiserror::Error;

/// Tacit 核心错误。
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("文档不存在: {0}")]
    DocNotFound(String),

    #[error("block 不存在: doc={doc_id} block={block_id}")]
    BlockNotFound { doc_id: String, block_id: String },

    #[error("frontier 非法: {0}")]
    InvalidFrontier(String),

    #[error("peer 不存在: {0}")]
    PeerNotFound(String),

    #[error("序列化失败: {0}")]
    Serialize(String),

    #[error("反序列化失败: {0}")]
    Deserialize(String),

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
    Io(#[from] std::io::Error),

    #[error("内部错误: {0}")]
    Internal(String),
}

/// 库内统一返回类型。
pub type CoreResult<T> = Result<T, CoreError>;
