//! BlockDocCache：BlockDoc 的 LRU 缓存。
//!
//! 策略：
//! - 热 block 可通过 pin 常驻内存，不被 LRU 淘汰。
//! - 冷 block 被淘汰时保留其 snapshot 字节，供后续惰性恢复。
//! - 超出容量时回收最久未访问的非 pinned BlockDoc 实例。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tacit_core::{BlockId, CoreResult};

use crate::block_doc::BlockDoc;

struct CacheEntry {
    doc: Arc<BlockDoc>,
    last_access: Instant,
}

/// 冷 block 保留的 snapshot。
#[allow(dead_code)]
struct ColdEntry {
    snapshot: Vec<u8>,
    evicted_at: Instant,
}

/// BlockDoc 的 LRU 缓存。
pub struct BlockDocCache {
    capacity: usize,
    entries: Mutex<HashMap<BlockId, CacheEntry>>,
    /// pinned block 不会被 LRU 淘汰。
    pinned: Mutex<HashSet<BlockId>>,
    /// 冷 block 的 snapshot 保留区。
    cold: Mutex<HashMap<BlockId, ColdEntry>>,
}

impl BlockDocCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: Mutex::new(HashMap::new()),
            pinned: Mutex::new(HashSet::new()),
            cold: Mutex::new(HashMap::new()),
        }
    }

    /// 获取 block，命中时更新访问时间。
    pub fn get(&self, block_id: &BlockId) -> Option<Arc<BlockDoc>> {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get_mut(block_id) {
            entry.last_access = Instant::now();
            Some(Arc::clone(&entry.doc))
        } else {
            None
        }
    }

    /// 获取冷 block 的 snapshot（用于惰性恢复）。
    pub fn get_cold_snapshot(&self, block_id: &BlockId) -> Option<Vec<u8>> {
        self.cold.lock().get(block_id).map(|e| e.snapshot.clone())
    }

    /// 插入 block。若超出容量，返回被 evict 的 (BlockId, BlockDoc)。
    ///
    /// 调用方应将被 evict 的 BlockDoc 导出 snapshot 持久化。
    /// pinned block 不会被淘汰。
    pub fn insert(&self, block_id: BlockId, doc: Arc<BlockDoc>) -> Option<(BlockId, Arc<BlockDoc>)> {
        let mut entries = self.entries.lock();
        entries.insert(
            block_id.clone(),
            CacheEntry {
                doc,
                last_access: Instant::now(),
            },
        );
        if entries.len() > self.capacity {
            let pinned = self.pinned.lock();
            // 找到 last_access 最小且非 pinned 的条目 evict
            let evict_id = entries
                .iter()
                .filter(|(k, _)| !pinned.contains(*k))
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone());
            drop(pinned);

            if let Some(evict_id) = evict_id {
                let evicted = entries.remove(&evict_id)?;
                // 保留冷 block snapshot
                if let Ok(snap) = evicted.doc.export_snapshot() {
                    self.cold.lock().insert(
                        evict_id.clone(),
                        ColdEntry {
                            snapshot: snap,
                            evicted_at: Instant::now(),
                        },
                    );
                }
                return Some((evict_id, evicted.doc));
            }
            // 所有 block 都被 pinned，不淘汰
        }
        None
    }

    /// 主动移除一个 block（例如文档关闭）。
    pub fn remove(&self, block_id: &BlockId) -> Option<Arc<BlockDoc>> {
        let doc = self.entries.lock().remove(block_id).map(|e| e.doc);
        self.pinned.lock().remove(block_id);
        doc
    }

    /// Pin 一个 block，使其常驻内存不被 LRU 淘汰。
    pub fn pin(&self, block_id: &BlockId) {
        self.pinned.lock().insert(block_id.clone());
    }

    /// 取消 pin。
    pub fn unpin(&self, block_id: &BlockId) {
        self.pinned.lock().remove(block_id);
    }

    /// 检查 block 是否被 pinned。
    pub fn is_pinned(&self, block_id: &BlockId) -> bool {
        self.pinned.lock().contains(block_id)
    }

    /// 当前缓存条目数。
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    /// 列出所有缓存的 block_id。
    pub fn block_ids(&self) -> Vec<BlockId> {
        self.entries.lock().keys().cloned().collect()
    }

    /// 对每个缓存条目执行操作（用于 checkpoint 时遍历）。
    pub fn for_each<F>(&self, mut f: F) -> CoreResult<()>
    where
        F: FnMut(&BlockId, &BlockDoc) -> CoreResult<()>,
    {
        let entries = self.entries.lock();
        for (id, entry) in entries.iter() {
            f(id, &entry.doc)?;
        }
        Ok(())
    }

    /// 清理冷 block snapshot（例如内存压力时）。
    pub fn clear_cold(&self) {
        self.cold.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_core::{BlockKind, PeerId};

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    fn make_block(id: &str) -> Arc<BlockDoc> {
        Arc::new(BlockDoc::new(BlockId::new(id), BlockKind::Text, &pid(1)).unwrap())
    }

    #[test]
    fn lru_eviction() {
        let cache = BlockDocCache::new(2);
        cache.insert(BlockId::new("b1"), make_block("b1"));
        cache.insert(BlockId::new("b2"), make_block("b2"));
        // 访问 b1，使 b2 成为最旧
        let _ = cache.get(&BlockId::new("b1"));
        let evicted = cache.insert(BlockId::new("b3"), make_block("b3"));
        assert!(evicted.is_some());
        let (evicted_id, _) = evicted.unwrap();
        assert_eq!(evicted_id, BlockId::new("b2"));
        assert!(cache.get(&BlockId::new("b1")).is_some());
        assert!(cache.get(&BlockId::new("b2")).is_none());
        assert!(cache.get(&BlockId::new("b3")).is_some());
    }

    #[test]
    fn remove_explicit() {
        let cache = BlockDocCache::new(4);
        cache.insert(BlockId::new("b1"), make_block("b1"));
        assert_eq!(cache.len(), 1);
        cache.remove(&BlockId::new("b1"));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn pinned_block_not_evicted() {
        let cache = BlockDocCache::new(2);
        cache.insert(BlockId::new("b1"), make_block("b1"));
        cache.insert(BlockId::new("b2"), make_block("b2"));
        // pin b2
        cache.pin(&BlockId::new("b2"));
        // 插入 b3，应淘汰 b1（b2 被 pinned）
        let evicted = cache.insert(BlockId::new("b3"), make_block("b3"));
        assert!(evicted.is_some());
        let (evicted_id, _) = evicted.unwrap();
        assert_eq!(evicted_id, BlockId::new("b1"));
        assert!(cache.get(&BlockId::new("b2")).is_some());
        assert!(cache.is_pinned(&BlockId::new("b2")));
    }

    #[test]
    fn cold_snapshot_retained() {
        let cache = BlockDocCache::new(1);
        let b1 = make_block("b1");
        b1.apply_edit(b"hello").unwrap();
        cache.insert(BlockId::new("b1"), b1);
        // 插入 b2，淘汰 b1
        cache.insert(BlockId::new("b2"), make_block("b2"));
        // b1 的 snapshot 应被保留
        let snap = cache.get_cold_snapshot(&BlockId::new("b1"));
        assert!(snap.is_some());
        assert!(!snap.unwrap().is_empty());
    }
}
