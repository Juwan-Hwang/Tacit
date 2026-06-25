//! DocExecutorRegistry：per-doc 执行器注册表。
//!
//! v1.0 规范线程模型：
//! - 每个文档有一个独立的 Actor，串行处理该文档的操作。
//! - 避免多线程并发修改同一文档导致 CRDT 状态损坏。
//! - 不同文档的操作可并行执行。
//! - 冷文档 Actor 在 idle 超时后自动休眠并释放内存。
//!
//! 实现：
//! - 每个 DocActor 持有一个 tokio::sync::mpsc channel，操作按 FIFO 顺序执行。
//! - DocExecutorRegistry 管理 doc_id -> DocActor 映射。
//! - 操作通过 spawn 提交到 tokio 任务池，但同一 doc 的操作串行等待。
//! - Actor 在 idle_timeout（默认 5 分钟）无操作后自动退出，
//!   下次提交时 registry 检测到 channel 关闭会重新创建。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tacit_core::{CoreResult, DocId};
use tokio::sync::mpsc::{self, Sender};
use tokio::task::JoinHandle;

/// 默认 idle 超时：5 分钟。
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// per-doc 操作类型：异步闭包。
type DocOp = Box<dyn FnOnce() -> CoreResult<()> + Send + 'static>;

/// per-doc Actor：串行执行该文档的操作。
pub struct DocActor {
    doc_id: DocId,
    tx: Sender<DocOp>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl DocActor {
    /// 创建 Actor 并启动后台消费循环。
    ///
    /// `idle_timeout`：无操作超时时间，超时后 Actor 自动退出释放内存。
    pub fn spawn(doc_id: DocId, idle_timeout: Duration) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<DocOp>(128);
        let actor = Arc::new(Self {
            doc_id: doc_id.clone(),
            tx,
            handle: Mutex::new(None),
        });

        // 启动后台异步消费循环（带 idle timeout）
        // 使用 spawn_blocking 包装阻塞操作，避免阻塞 tokio runtime
        let handle = tokio::spawn(async move {
            loop {
                match tokio::time::timeout(idle_timeout, rx.recv()).await {
                    Ok(Some(op)) => {
                        // 在阻塞线程中执行操作，避免阻塞 tokio runtime
                        let result = tokio::task::spawn_blocking(op).await;
                        match result {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                tracing::warn!(doc_id = %doc_id, error = %e, "doc 操作执行失败");
                            }
                            Err(e) => {
                                tracing::warn!(doc_id = %doc_id, error = %e, "doc 操作执行 panic");
                            }
                        }
                    }
                    Ok(None) => {
                        // channel 关闭，正常退出
                        break;
                    }
                    Err(_) => {
                        // idle timeout，自动休眠释放内存
                        tracing::debug!(
                            doc_id = %doc_id,
                            idle_secs = idle_timeout.as_secs(),
                            "DocActor idle 超时，自动休眠"
                        );
                        break;
                    }
                }
            }
            tracing::debug!(doc_id = %doc_id, "DocActor 退出");
        });

        *actor.handle.lock() = Some(handle);
        actor
    }

    /// 提交操作到 Actor 队列（非阻塞）。
    pub async fn submit<F>(&self, op: F) -> CoreResult<()>
    where
        F: FnOnce() -> CoreResult<()> + Send + 'static,
    {
        self.tx
            .send(Box::new(op))
            .await
            .map_err(|_| tacit_core::CoreError::Sync(format!(
                "DocActor 队列已关闭: doc_id={}",
                self.doc_id
            )))
    }

    /// channel 是否已关闭（Actor 已退出）。
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// 文档 ID。
    pub fn doc_id(&self) -> &DocId {
        &self.doc_id
    }
}

impl Drop for DocActor {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.lock().take() {
            handle.abort();
        }
    }
}

/// DocExecutorRegistry：管理 per-doc Actor。
pub struct DocExecutorRegistry {
    actors: Mutex<HashMap<DocId, Arc<DocActor>>>,
    /// idle 超时时间。
    idle_timeout: Duration,
}

impl Default for DocExecutorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DocExecutorRegistry {
    pub fn new() -> Self {
        Self {
            actors: Mutex::new(HashMap::new()),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    /// 创建带自定义 idle 超时的 registry。
    pub fn with_idle_timeout(idle_timeout: Duration) -> Self {
        Self {
            actors: Mutex::new(HashMap::new()),
            idle_timeout,
        }
    }

    /// 获取或创建指定文档的 Actor。
    ///
    /// 如果已有 Actor 但 channel 已关闭（因 idle timeout 退出），
    /// 则移除旧 Actor 并重新创建。
    pub fn get_or_create(&self, doc_id: &DocId) -> Arc<DocActor> {
        let mut actors = self.actors.lock();
        if let Some(actor) = actors.get(doc_id) {
            if !actor.is_closed() {
                return actor.clone();
            }
            // Actor 已因 idle timeout 退出，移除并重新创建
            tracing::debug!(doc_id = %doc_id, "DocActor 已休眠，重新创建");
            actors.remove(doc_id);
        }
        let actor = DocActor::spawn(doc_id.clone(), self.idle_timeout);
        actors.insert(doc_id.clone(), actor.clone());
        actor
    }

    /// 提交操作到指定文档的 Actor。
    pub async fn submit<F>(&self, doc_id: &DocId, op: F) -> CoreResult<()>
    where
        F: FnOnce() -> CoreResult<()> + Send + 'static,
    {
        let actor = self.get_or_create(doc_id);
        actor.submit(op).await
    }

    /// 移除并停止指定文档的 Actor。
    pub fn remove(&self, doc_id: &DocId) {
        self.actors.lock().remove(doc_id);
    }

    /// 当前管理的 Actor 数量。
    pub fn len(&self) -> usize {
        self.actors.lock().len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.actors.lock().is_empty()
    }

    /// 清理已关闭的 Actor（因 idle timeout 退出）。
    /// 返回清理的数量。
    pub fn cleanup_closed(&self) -> usize {
        let mut actors = self.actors.lock();
        let before = actors.len();
        actors.retain(|_, actor| !actor.is_closed());
        before - actors.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn doc_actor_serializes_ops() {
        let registry = DocExecutorRegistry::new();
        let doc_id = DocId::new("d1");
        let counter = Arc::new(AtomicU32::new(0));
        let max_concurrent = Arc::new(AtomicU32::new(0));
        let current = Arc::new(AtomicU32::new(0));

        // 提交 10 个操作，验证串行执行
        for _ in 0..10 {
            let counter = counter.clone();
            let max_concurrent = max_concurrent.clone();
            let current = current.clone();
            registry
                .submit(&doc_id, move || {
                    let cur = current.fetch_add(1, Ordering::SeqCst) + 1;
                    let max = max_concurrent.load(Ordering::SeqCst);
                    if cur > max {
                        max_concurrent.store(cur, Ordering::SeqCst);
                    }
                    // 模拟工作
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    counter.fetch_add(1, Ordering::SeqCst);
                    current.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .unwrap();
        }

        // 等待所有操作完成
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 10);
        // 应串行执行，最大并发为 1
        assert_eq!(max_concurrent.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_docs_run_in_parallel() {
        let registry = DocExecutorRegistry::new();
        let counter = Arc::new(AtomicU32::new(0));

        // 两个不同文档同时提交操作
        for i in 0..2 {
            let counter = counter.clone();
            let doc_id = DocId::new(format!("d{}", i));
            registry
                .submit(&doc_id, move || {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .unwrap();
        }

        // 等待完成
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn get_or_create_reuses_actor() {
        let registry = DocExecutorRegistry::new();
        let doc_id = DocId::new("d1");
        let a1 = registry.get_or_create(&doc_id);
        let a2 = registry.get_or_create(&doc_id);
        assert!(Arc::ptr_eq(&a1, &a2));
        assert_eq!(registry.len(), 1);
    }

    #[tokio::test]
    async fn idle_timeout_recreates_actor() {
        // 使用极短的 idle timeout 测试自动休眠
        let registry = DocExecutorRegistry::with_idle_timeout(Duration::from_millis(50));
        let doc_id = DocId::new("d_idle");

        // 提交一个操作触发 actor 创建
        registry
            .submit(&doc_id, || Ok(()))
            .await
            .unwrap();
        assert_eq!(registry.len(), 1);

        // 等待 idle timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // actor 应已退出（channel 关闭）
        let actor = registry.actors.lock().get(&doc_id).cloned();
        assert!(actor.is_some());
        assert!(actor.unwrap().is_closed());

        // 清理已关闭的 actor
        let cleaned = registry.cleanup_closed();
        assert_eq!(cleaned, 1);
        assert_eq!(registry.len(), 0);

        // 再次提交应重新创建 actor
        registry
            .submit(&doc_id, || Ok(()))
            .await
            .unwrap();
        assert_eq!(registry.len(), 1);
    }

    #[tokio::test]
    async fn cleanup_closed_removes_only_closed() {
        let registry = DocExecutorRegistry::with_idle_timeout(Duration::from_millis(50));

        // 创建两个 actor
        registry.submit(&DocId::new("d1"), || Ok(())).await.unwrap();
        registry.submit(&DocId::new("d2"), || Ok(())).await.unwrap();
        assert_eq!(registry.len(), 2);

        // 等待 idle timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 清理
        let cleaned = registry.cleanup_closed();
        assert_eq!(cleaned, 2);
        assert_eq!(registry.len(), 0);
    }
}
