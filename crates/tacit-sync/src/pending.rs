//! 依赖等待队列。
//!
//! 当 Meta-Document 已引用新 block，但对端 block 状态尚未可取时，
//! 进入依赖等待队列。采用短退避重试，而不是报错或无限自旋。
//!
//! 策略（蓝图 189-205 行）：
//! - 初始退避约 200ms。
//! - 指数回退到上限，例如 2s。
//! - 到达上限后不报致命错误，降级为后台静默拉取。

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tacit_core::{BlockId, DocId, Frontier, PeerId};

/// 退避阶段：区分正常重试与降级后的后台静默拉取。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffPhase {
    /// 正常指数退避阶段。
    Normal,
    /// 到达退避上限后降级为后台静默拉取（更长间隔，不报错）。
    Background,
}

/// 依赖等待条目。
#[derive(Debug, Clone)]
pub struct PendingBlockFetch {
    pub doc_id: DocId,
    pub block_id: BlockId,
    pub expected_frontier: Frontier,
    /// 本地已观测到的 frontier（用于增量拉取，避免每次从头拉取）。
    pub observed_frontier: Frontier,
    pub peer_id: PeerId,
    pub retry_at: Instant,
    pub retries: u32,
    /// 当前退避阶段。
    pub phase: BackoffPhase,
}

impl Default for BackoffPhase {
    fn default() -> Self {
        BackoffPhase::Normal
    }
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
///
/// 使用双索引结构实现 O(log n) 的 drain_ready：
/// - `entries`: HashMap<PendingKey, PendingBlockFetch> 存储完整条目
/// - `time_index`: BTreeMap<Instant, Vec<PendingKey>> 按到期时间索引
///
/// drain_ready 时只需 BTreeMap::split_off 即可取出所有到期条目，无需遍历全部。
pub struct PendingFetchQueue {
    entries: Mutex<HashMap<PendingKey, PendingBlockFetch>>,
    time_index: Mutex<BTreeMap<Instant, Vec<PendingKey>>>,
    backoff_init: Duration,
    backoff_max: Duration,
    /// 降级为后台静默拉取后的重试间隔（比 backoff_max 更长，减少资源消耗）。
    background_interval: Duration,
    /// 进入 Background 阶段前的最大正常重试次数。
    /// 达到此次数后切换到 Background 阶段。
    max_normal_retries: u32,
}

impl PendingFetchQueue {
    /// 创建队列。
    pub fn new(backoff_init: Duration, backoff_max: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            time_index: Mutex::new(BTreeMap::new()),
            backoff_init,
            backoff_max,
            // 后台静默拉取间隔：默认 30s，远大于 backoff_max，减少资源消耗
            background_interval: Duration::from_secs(30),
            // 正常阶段最大重试次数：backoff 到达 max 后再重试若干次即降级
            max_normal_retries: 5,
        }
    }

    /// 自定义后台静默拉取间隔和降级阈值。
    pub fn with_background_params(
        mut self,
        background_interval: Duration,
        max_normal_retries: u32,
    ) -> Self {
        self.background_interval = background_interval;
        self.max_normal_retries = max_normal_retries;
        self
    }

    /// 入队一个 block 拉取请求。
    pub fn enqueue(&self, fetch: PendingBlockFetch) {
        let key = fetch.key();
        let retry_at = fetch.retry_at;
        self.entries.lock().insert(key.clone(), fetch);
        self.time_index
            .lock()
            .entry(retry_at)
            .or_default()
            .push(key);
    }

    /// 取出到期且需要重试的条目。
    ///
    /// 使用 BTreeMap::range 提取所有 `retry_at <= now` 的条目，O(log n) 复杂度。
    pub fn drain_ready(&self, now: Instant) -> Vec<PendingBlockFetch> {
        let due_keys: Vec<PendingKey> = {
            let mut time_index = self.time_index.lock();
            // 收集所有 retry_at <= now 的时间点
            let due_times: Vec<Instant> = time_index
                .range(..=now)
                .map(|(&k, _)| k)
                .collect();
            // 逐个移除并收集 key
            due_times
                .into_iter()
                .flat_map(|t| time_index.remove(&t).unwrap_or_default())
                .collect()
        };
        // 从 entries 中取出对应的完整条目
        let mut entries = self.entries.lock();
        due_keys
            .into_iter()
            .filter_map(|key| entries.remove(&key))
            .collect()
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
    ///
    /// 当正常阶段重试次数达到 `max_normal_retries` 后，降级为 Background 阶段：
    /// 使用更长的重试间隔（`background_interval`），不再报错或快速重试。
    pub fn requeue(&self, mut fetch: PendingBlockFetch, now: Instant) {
        fetch.retries = fetch.retries.saturating_add(1);
        let backoff = if fetch.phase == BackoffPhase::Background {
            // 已在后台静默拉取阶段，使用固定长间隔
            self.background_interval
        } else if fetch.retries >= self.max_normal_retries {
            // 达到降级阈值，切换到 Background 阶段
            fetch.phase = BackoffPhase::Background;
            tracing::debug!(
                doc_id = %fetch.doc_id,
                block_id = %fetch.block_id,
                retries = fetch.retries,
                "依赖等待降级为后台静默拉取"
            );
            self.background_interval
        } else {
            // 正常指数退避
            self.next_backoff(fetch.retries)
        };
        fetch.retry_at = now + backoff;
        let key = fetch.key();
        let retry_at = fetch.retry_at;
        self.entries.lock().insert(key.clone(), fetch);
        self.time_index
            .lock()
            .entry(retry_at)
            .or_default()
            .push(key);
    }

    /// 移除条目（拉取成功或不再需要时调用）。
    pub fn remove(&self, doc_id: &DocId, block_id: &BlockId, peer_id: &PeerId) {
        let key = PendingKey {
            doc_id: doc_id.clone(),
            block_id: block_id.clone(),
            peer_id: peer_id.clone(),
        };
        // 先从 entries 中移除，获取 retry_at
        let retry_at = match self.entries.lock().remove(&key) {
            Some(fetch) => fetch.retry_at,
            None => return,
        };
        // 再从 time_index 中清理（避免嵌套加锁导致死锁）
        let mut time_index = self.time_index.lock();
        if let Some(vec) = time_index.get_mut(&retry_at) {
            vec.retain(|k| k != &key);
            if vec.is_empty() {
                time_index.remove(&retry_at);
            }
        }
    }

    /// 查询某条目是否存在及其重试次数。
    pub fn get(&self, doc_id: &DocId, block_id: &BlockId, peer_id: &PeerId) -> Option<u32> {
        let key = PendingKey {
            doc_id: doc_id.clone(),
            block_id: block_id.clone(),
            peer_id: peer_id.clone(),
        };
        self.entries.lock().get(&key).map(|f| f.retries)
    }

    /// 查询某条目的当前退避阶段。
    pub fn phase(&self, doc_id: &DocId, block_id: &BlockId, peer_id: &PeerId) -> BackoffPhase {
        let key = PendingKey {
            doc_id: doc_id.clone(),
            block_id: block_id.clone(),
            peer_id: peer_id.clone(),
        };
        self.entries
            .lock()
            .get(&key)
            .map(|f| f.phase)
            .unwrap_or(BackoffPhase::Normal)
    }

    /// 当前队列长度。
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// 队列是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    fn make_fetch(doc: &str, block: &str, peer: u64, retry_at: Instant) -> PendingBlockFetch {
        PendingBlockFetch {
            doc_id: DocId::new(doc),
            block_id: BlockId::new(block),
            expected_frontier: Frontier::new(),
            observed_frontier: Frontier::new(),
            peer_id: pid(peer),
            retry_at,
            retries: 0,
            phase: BackoffPhase::Normal,
        }
    }

    #[test]
    fn enqueue_and_drain_ready() {
        let q = PendingFetchQueue::new(Duration::from_millis(200), Duration::from_secs(2));
        let now = Instant::now();
        q.enqueue(make_fetch("d1", "b1", 1, now));
        q.enqueue(PendingBlockFetch {
            block_id: BlockId::new("b2"),
            retry_at: now + Duration::from_secs(1),
            ..make_fetch("d1", "b2", 1, now)
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
        q.enqueue(make_fetch("d1", "b1", 1, now));
        let ready = q.drain_ready(now);
        assert_eq!(ready.len(), 1);
        q.requeue(ready.into_iter().next().unwrap(), now);
        assert_eq!(q.get(&DocId::new("d1"), &BlockId::new("b1"), &pid(1)), Some(1));
    }

    #[test]
    fn remove_entry() {
        let q = PendingFetchQueue::new(Duration::from_millis(200), Duration::from_secs(2));
        let now = Instant::now();
        q.enqueue(make_fetch("d1", "b1", 1, now));
        assert_eq!(q.len(), 1);
        q.remove(&DocId::new("d1"), &BlockId::new("b1"), &pid(1));
        assert!(q.is_empty());
    }

    #[test]
    fn degrades_to_background_after_max_retries() {
        let q = PendingFetchQueue::new(Duration::from_millis(200), Duration::from_secs(2))
            .with_background_params(Duration::from_secs(10), 3);
        let mut now = Instant::now();
        q.enqueue(make_fetch("d1", "b1", 1, now));

        // 正常阶段重试 3 次，每次推进时间以确保 drain_ready 能取到
        for _ in 0..3 {
            let ready = q.drain_ready(now);
            q.requeue(ready.into_iter().next().unwrap(), now);
            // 推进时间超过 backoff_max，确保下一次 drain_ready 能取到
            now += Duration::from_secs(5);
        }
        // 第 3 次重试后 retries=3，达到阈值，应降级为 Background
        assert_eq!(
            q.phase(&DocId::new("d1"), &BlockId::new("b1"), &pid(1)),
            BackoffPhase::Background
        );

        // 降级后 retry_at 应使用 background_interval（10s），推进时间确保能取到
        now += Duration::from_secs(10);
        let ready = q.drain_ready(now);
        q.requeue(ready.into_iter().next().unwrap(), now);
        // 验证仍在 Background 阶段
        assert_eq!(
            q.phase(&DocId::new("d1"), &BlockId::new("b1"), &pid(1)),
            BackoffPhase::Background
        );
    }
}
