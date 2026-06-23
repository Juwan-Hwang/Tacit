//! Tacit-core：领域模型、错误、配置与共享类型。
//!
//! 本 crate 是整个 workspace 的单一真相层，定义所有跨 crate 共享的
//! 标识符、Frontier、领域枚举、事件与错误类型。其他 crate 依赖本 crate
//! 而不是互相直接依赖领域定义，避免循环依赖与重复定义。

pub mod config;
pub mod error;
pub mod event;
pub mod frontier;
pub mod ids;
pub mod model;

pub use config::TacitConfig;
pub use error::{CoreError, CoreResult};
pub use event::{CoreEvent, ErrorScope, SyncReason, SyncStage};
pub use frontier::{Frontier, FrontierOps};
pub use ids::{BlockId, CheckpointId, DocId, PeerId, SessionId};
pub use model::{
    AckSummary, AnchorCapabilities, ApplyResult, BlockKind, BlockRecord, ChangeEnvelope,
    DataFrame, DataFrameKind, DocumentView, Endpoint, ImportResult, NatCapability, NetworkType,
    PathHint, PeerRecord, PeerSummary, PortHint, PortRange, PresenceHint, Priority, RenderModel,
    SnapshotChunk, SnapshotKind, SnapshotMeta, TrustState, UserEdit, Viewport, Watermarks,
};
