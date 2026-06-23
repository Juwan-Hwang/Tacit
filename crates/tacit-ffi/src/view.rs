//! FFI 视图类型。
//!
//! 不暴露 Rust 内部类型，只传递简单类型给平台层。

/// 文档视图。
#[derive(Debug, Clone)]
pub struct DocumentView {
    /// 文档 ID。
    pub doc_id: String,
    /// 文档类型。
    pub kind: String,
    /// 所有 block ID 列表。
    pub block_ids: Vec<String>,
    /// 当前 frontier（JSON 字符串）。
    pub frontier_json: String,
}

/// 同步状态。
#[derive(Debug, Clone)]
pub struct SyncStatus {
    /// 待执行的同步动作数。
    pub pending_actions: u32,
    /// 依赖等待队列长度。
    pub pending_fetches: u32,
    /// 在线 peer 数。
    pub online_peers: u32,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            pending_actions: 0,
            pending_fetches: 0,
            online_peers: 0,
        }
    }
}
