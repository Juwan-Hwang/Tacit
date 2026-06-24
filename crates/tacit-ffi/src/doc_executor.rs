//! DocExecutorRegistry：per-doc 执行器注册表。
//!
//! v1.0 规范线程模型：
//! - 每个文档有一个独立的 Actor，串行处理该文档的操作。
//! - 避免多线程并发修改同一文档导致 CRDT 状态损坏。
//! - 不同文档的操作可并行执行。
//!
//! 实现：
//! - 每个 DocActor 持有一个 tokio::sync::mpsc channel，操作按 FIFO 顺序执行。
//! - DocExecutorRegistry 管理 doc_id -> DocActor 映射。
//! - 操作通过 spawn 提交到 tokio 任务池，但同一 doc 的操作串行等待。

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tacit_core::{CoreResult, DocId};
use tokio::sync::mpsc::{self, Sender};
use tokio::task::JoinHandle;

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
    pub fn spawn(doc_id: DocId) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<DocOp>(128);
        let actor = Arc::new(Self {
            doc_id: doc_id.clone(),
            tx,
            handle: Mutex::new(None),
        });

        // 启动后台异步消费循环
        let handle = tokio::spawn(async move {
            while let Some(op) = rx.recv().await {
                if let Err(e) = op() {
                    tracing::warn!(doc_id = %doc_id, error = %e, "doc 操作执行失败");
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
        }
    }

    /// 获取或创建指定文档的 Actor。
    pub fn get_or_create(&self, doc_id: &DocId) -> Arc<DocActor> {
        let mut actors = self.actors.lock();
        if let Some(actor) = actors.get(doc_id) {
            return actor.clone();
        }
        let actor = DocActor::spawn(doc_id.clone());
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
}
