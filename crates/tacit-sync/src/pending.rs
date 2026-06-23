//! 依赖等待队列。
//!
//! 当 Meta-Document 已引用新 block，但对端 block 状态尚未可取时，
//! 进入依赖等待队列。采用短退避重试，而不是报错或无限自旋。
//!
//! 策略（蓝图 189-205 行）：
//! - 初始退避约 200ms。
//! - 指数回退到上限，例如 2s。
//! - 到达上限后不报致命错误，降级为后台静默拉取。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tacit_core::{BlockId, DocId, Frontier, PeerId};

/// 依赖等待条目。
#[derive(Debug, Clone)]
pub struct PendingBlockFetch {
    pub doc_id: DocId,
    pub block_id: BlockId,
    pub expected_frontier: Frontier,
    pub peer_id: PeerId,
    pub retry_at: Instant,
    pub retries: u32,
}

impl PendingBlockFetch {
    fn key(&self) -> PendingKey {
        PendingKey {
            doc_id: self.doc_id.clone(),
            block_id: self.block_id.clone(),
            peer_id: self.peer_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingKey {
    doc_id: DocId,
    block_id: BlockId,
    peer_id: PeerId,
}

/// 依赖等待队列。
pub struct PendingFetchQueue {
    inner: Mutex<HashMap<PendingKey, PendingBlockFetch>>,
    backoff_init: Duration,
    backoff_max: Duration,
}

impl PendingFetchQueue {
    /// 创建队列。
    pub fn new(backoff_init: Duration, backoff_max: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            backoff_init,
            backoff_max,
        }
    }

    /// 入队一个 block 拉取请求。
    pub fn enqueue(&self, fetch: PendingBlockFetch) {
        let key = fetch.key();
        self.inner.lock().insert(key, fetch);
    }

    /// 取出到期且需要重试的条目。
    pub fn drain_ready(&self, now: Instant) -> Vec<PendingBlockFetch> {
        let mut inner = self.inner.lock();
        let mut ready = Vec::new();
        let mut to_requeue = Vec::new();
        for (key, fetch) in inner.drain() {
            if fetch.retry_at <= now {
                ready.push(fetch);
            } else {
                to_requeue.push((key, fetch));
            }
        }
        // 把未到期的放回
        for (key, fetch) in to_requeue {
            inner.insert(key, fetch);
        }
        ready
    }

    /// 计算下一次退避时长。
    pub fn next_backoff(&self, retries: u32) -> Duration {
        // 指数回退：init * 2^retries，上限 max
        let multiplier = 2u32.saturating_pow(retries.min(20));
        let backoff = self.backoff_init.saturating_mul(multiplier as u32);
        if backoff > self.backoff_max {
            self.backoff_max
        } else {
            backoff
        }
    }

    /// 重新入队（重试次数 +1，更新 retry_at）。
    pub fn requeue(&self, mut fetch: PendingBlockFetch, now: Instant) {
        fetch.retries = fetch.retries.saturating_add(1);
        let backoff = self.next_backoff(fetch.retries);
        fetch.retry_at = now + backoff;
        let key = fetch.key();
        self.inner.lock().insert(key, fetch);
    }

    /// 移除条目（拉取成功或不再需要时调用）。
    pub fn remove(&self, doc_id: &DocId, block_id: &BlockId, peer_id: &PeerId) {
        let key = PendingKey {
            doc_id: doc_id.clone(),
            block_id: block_id.clone(),
            peer_id: peer_id.clone(),
        };
        self.inner.lock().remove(&key);
    }

    /// 查询某条目是否存在及其重试次数。
    pub fn get(&self, doc_id: &DocId, block_id: &BlockId, peer_id: &PeerId) -> Option<u32> {
        let key = PendingKey {
            doc_id: doc_id.clone(),
            block_id: block_id.clone(),
            peer_id: peer_id.clone(),
        };
        self.inner.lock().get(&key).map(|f| f.retries)
    }

    /// 当前队列长度。
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// 队列是否为空。
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    #[test]
    fn enqueue_and_drain_ready() {
        let q = PendingFetchQueue::new(Duration::from_millis(200), Duration::from_secs(2));
        let now = Instant::now();
        q.enqueue(PendingBlockFetch {
            doc_id: DocId::new("d1"),
            block_id: BlockId::new("b1"),
            expected_frontier: Frontier::new(),
            peer_id: pid(1),
            retry_at: now,
            retries: 0,
        });
        q.enqueue(PendingBlockFetch {
            doc_id: DocId::new("d1"),
            block_id: BlockId::new("b2"),
            expected_frontier: Frontier::new(),
            peer_id: pid(1),
            retry_at: now + Duration::from_secs(1),
            retries: 0,
        });
        // 只有 b1 到期
        let ready = q.drain_ready(now);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].block_id, BlockId::new("b1"));
        // b2 仍在队列
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn backoff_schedule() {
        let q = PendingFetchQueue::new(Duration::from_millis(200), Duration::from_secs(2));
        assert_eq!(q.next_backoff(0), Duration::from_millis(200));
        assert_eq!(q.next_backoff(1), Duration::from_millis(400));
        assert_eq!(q.next_backoff(2), Duration::from_millis(800));
        assert_eq!(q.next_backoff(3), Duration::from_millis(1600));
        // 到达上限
        assert_eq!(q.next_backoff(4), Duration::from_secs(2));
        assert_eq!(q.next_backoff(100), Duration::from_secs(2));
    }

    #[test]
    fn requeue_increments_retries() {
        let q = PendingFetchQueue::new(Duration::from_millis(200), Duration::from_secs(2));
        let now = Instant::now();
        let fetch = PendingBlockFetch {
            doc_id: DocId::new("d1"),
            block_id: BlockId::new("b1"),
            expected_frontier: Frontier::new(),
            peer_id: pid(1),
            retry_at: now,
            retries: 0,
        };
        q.enqueue(fetch);
        let ready = q.drain_ready(now);
        assert_eq!(ready.len(), 1);
        q.requeue(ready.into_iter().next().unwrap(), now);
        assert_eq!(q.get(&DocId::new("d1"), &BlockId::new("b1"), &pid(1)), Some(1));
    }

    #[test]
    fn remove_entry() {
        let q = PendingFetchQueue::new(Duration::from_millis(200), Duration::from_secs(2));
        let now = Instant::now();
        q.enqueue(PendingBlockFetch {
            doc_id: DocId::new("d1"),
            block_id: BlockId::new("b1"),
            expected_frontier: Frontier::new(),
            peer_id: pid(1),
            retry_at: now,
            retries: 0,
        });
        assert_eq!(q.len(), 1);
        q.remove(&DocId::new("d1"), &BlockId::new("b1"), &pid(1));
        assert!(q.is_empty());
    }
}
