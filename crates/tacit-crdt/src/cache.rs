//! BlockDocCache：BlockDoc 的 LRU 缓存。
//!
//! 策略：
//! - 热 block 常驻内存。
//! - 超出容量时回收最久未访问的 BlockDoc 实例，返回给上层
//!   以导出 snapshot 持久化（仅保留可恢复状态）。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tacit_core::{BlockId, CoreResult};

use crate::block_doc::BlockDoc;

struct CacheEntry {
    doc: Arc<BlockDoc>,
    last_access: Instant,
}

/// BlockDoc 的 LRU 缓存。
pub struct BlockDocCache {
    capacity: usize,
    entries: Mutex<HashMap<BlockId, CacheEntry>>,
}

impl BlockDocCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: Mutex::new(HashMap::new()),
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

    /// 插入 block。若超出容量，返回被 evict 的 (BlockId, BlockDoc)。
    ///
    /// 调用方应将被 evict 的 BlockDoc 导出 snapshot 持久化。
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
            // 找到 last_access 最小的条目 evict
            let evict_id = entries
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone())?;
            let evicted = entries.remove(&evict_id)?;
            // 重新获取刚插入的（避免 evict 掉刚插入的）：若 evict_id == block_id 则不 evict
            if evict_id == block_id {
                // 刚插入的就被 evict，说明容量为 0（不可能，已 max(1)），放回
                entries.insert(
                    block_id.clone(),
                    CacheEntry {
                        doc: Arc::clone(&evicted.doc),
                        last_access: Instant::now(),
                    },
                );
                return None;
            }
            return Some((evict_id, evicted.doc));
        }
        None
    }

    /// 主动移除一个 block（例如文档关闭）。
    pub fn remove(&self, block_id: &BlockId) -> Option<Arc<BlockDoc>> {
        self.entries.lock().remove(block_id).map(|e| e.doc)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_core::PeerId;

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    #[test]
    fn lru_eviction() {
        let cache = BlockDocCache::new(2);
        let b1 = Arc::new(BlockDoc::new(BlockId::new("b1"), &pid(1)).unwrap());
        let b2 = Arc::new(BlockDoc::new(BlockId::new("b2"), &pid(1)).unwrap());
        let b3 = Arc::new(BlockDoc::new(BlockId::new("b3"), &pid(1)).unwrap());

        cache.insert(BlockId::new("b1"), b1);
        cache.insert(BlockId::new("b2"), b2);
        // 访问 b1，使 b2 成为最旧
        let _ = cache.get(&BlockId::new("b1"));
        let evicted = cache.insert(BlockId::new("b3"), b3);
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
        let b = Arc::new(BlockDoc::new(BlockId::new("b1"), &pid(1)).unwrap());
        cache.insert(BlockId::new("b1"), b);
        assert_eq!(cache.len(), 1);
        cache.remove(&BlockId::new("b1"));
        assert_eq!(cache.len(), 0);
    }
}
