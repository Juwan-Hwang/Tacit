//! Tacit-ffi：UniFFI API 与命令总线。
//!
//! 职责：
//! - 暴露同步外观、异步内核的 FFI API。
//! - 命令总线：UI 线程发命令到 Rust 内部队列。
//! - 回调事件桥接：CoreEvent 转发到平台层监听器。
//! - 不返回 LoroDoc 指针，平台层只通过 doc_id 与 blob 交互。

pub mod engine;
pub mod listener;
pub mod view;

pub use engine::TacitEngine;
pub use listener::TacitEventListener;
pub use view::{DocumentView, SyncStatus};

uniffi::setup_scaffolding!();
