//! Tacit-ffi：UniFFI API 与命令总线。
//!
//! 职责：
//! - 暴露同步外观、异步内核的 FFI API。
//! - 命令总线（CommandBus）：UI 线程发命令到 Rust 内部队列。
//! - 事件总线（EventBus）：CoreEvent 订阅/发布与过滤。
//! - 运行时监督器（RuntimeSupervisor）：管理后台任务生命周期。
//! - per-doc 执行器（DocExecutorRegistry）：串行处理同一文档的操作。
//! - 回调事件桥接：CoreEvent 转发到平台层监听器。
//! - 不返回 LoroDoc 指针，平台层只通过 doc_id 与 blob 交互。

pub mod ble;
pub mod command_bus;
pub mod doc_executor;
pub mod engine;
pub mod error;
pub mod event_bus;
pub mod listener;
pub mod runtime;
pub mod view;

pub use ble::{
    ffi_clear_ble_backend, ffi_has_ble_backend, ffi_set_ble_backend, FfiAnchorCapabilities,
    FfiDiscoveryEvent, FfiEndpoint, FfiPresenceHint, ForeignPresenceBackend,
};
pub use command_bus::{Command, CommandBuffer, CommandBus, CommandBusError};
pub use doc_executor::{DocActor, DocExecutorRegistry};
pub use engine::TacitEngine;
pub use error::TacitFfiError;
pub use event_bus::{EventBus, EventFilter, SubscriptionId};
pub use listener::{ForeignEventListener, TacitEventListener};
pub use runtime::{RuntimeConfig, RuntimeState, RuntimeSupervisor};
pub use view::{
    DocumentView, FfiRequestDeltaAction, FfiSendControlAction, FfiSendDataAction, FfiSyncAction,
    SyncStatus,
};

uniffi::setup_scaffolding!();
