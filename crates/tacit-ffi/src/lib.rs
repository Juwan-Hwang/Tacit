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

pub mod command_bus;
pub mod doc_executor;
pub mod engine;
pub mod event_bus;
pub mod listener;
pub mod runtime;
pub mod view;

pub use command_bus::{Command, CommandBus, CommandBusError, CommandBuffer};
pub use doc_executor::{DocActor, DocExecutorRegistry};
pub use engine::TacitEngine;
pub use event_bus::{EventBus, EventFilter, SubscriptionId};
pub use listener::TacitEventListener;
pub use runtime::{RuntimeConfig, RuntimeState, RuntimeSupervisor};
pub use view::{DocumentView, SyncStatus};

uniffi::setup_scaffolding!();
