//! Tacit-crdt：Loro 封装与文档模型。
//!
//! 职责：
//! - 封装 Loro，隔离上游 API 变化（见 [`converter`]）。
//! - 提供 Meta-Document 管理 block 列表、顺序、软删除（[`MetaDoc`]）。
//! - 每个 block 一个独立 Loro 实例（[`BlockDoc`]），惰性加载。
//! - 提供 Frontier/Diff/Snapshot 接口。
//! - 内部维护 [`BlockDocCache`]（LRU）。

pub mod block_doc;
pub mod cache;
pub mod converter;
pub mod meta_doc;

pub use block_doc::BlockDoc;
pub use cache::BlockDocCache;
pub use converter::{format_peer_id, parse_peer_id, LoroExport, LoroPeerId};
pub use meta_doc::MetaDoc;
