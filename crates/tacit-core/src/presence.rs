//! Presence 与临时状态（v1.0 规范第 16 节）。
//!
//! 在线状态、正在编辑提示、光标位置等临时信息与持久化文档历史隔离，
//! 作为 ephemeral/presence 数据通过独立通道传播，不进入 checkpoint 与 GC 水位。
//! 定义 TTL，设备离线后自然过期。

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::ids::{BlockId, DocId, PeerId};

/// 默认 TTL：60 秒后过期。
pub const DEFAULT_PRESENCE_TTL: Duration = Duration::from_secs(60);

/// presence 类型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresenceState {
    /// 设备在线。
    Online,
    /// 正在编辑指定 block。
    Editing { doc_id: DocId, block_id: BlockId },
    /// 光标位置。
    Cursor {
        doc_id: DocId,
        block_id: BlockId,
        /// block 内偏移。
        offset: usize,
    },
    /// 自定义临时状态。
    Custom(String),
}

/// 带过期时间的 presence 条目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceEntry {
    pub peer_id: PeerId,
    pub state: PresenceState,
    /// 创建时刻（用于 TTL 过期判断）。
    pub created_at: SystemTime,
    /// TTL（毫秒）。
    pub ttl_ms: u64,
}

impl PresenceEntry {
    pub fn new(peer_id: PeerId, state: PresenceState, ttl: Duration) -> Self {
        Self {
            peer_id,
            state,
            created_at: SystemTime::now(),
            ttl_ms: ttl.as_millis() as u64,
        }
    }

    /// 是否已过期。
    ///
    /// 使用传入的 `now` 而非 `SystemTime::now()`，便于测试与批量清理。
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now.duration_since(self.created_at)
            .map(|elapsed| elapsed.as_millis() > self.ttl_ms as u128)
            .unwrap_or(true)
    }

    /// 刷新 TTL（重新计时）。
    pub fn refresh(&mut self) {
        self.created_at = SystemTime::now();
    }
}

/// Presence 注册表：管理所有 peer 的临时状态。
///
/// 不持久化，不进入 checkpoint/GC 水位。
/// 设备离线后条目自然过期。
#[derive(Debug)]
pub struct PresenceRegistry {
    entries: parking_lot::RwLock<std::collections::HashMap<PeerId, PresenceEntry>>,
    default_ttl: Duration,
}

impl Default for PresenceRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_PRESENCE_TTL)
    }
}

impl PresenceRegistry {
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            entries: parking_lot::RwLock::new(std::collections::HashMap::new()),
            default_ttl,
        }
    }

    /// 更新 peer 的 presence 状态。
    pub fn update(&self, peer_id: PeerId, state: PresenceState) {
        let mut entries = self.entries.write();
        let entry = PresenceEntry::new(peer_id.clone(), state, self.default_ttl);
        entries.insert(peer_id, entry);
    }

    /// 更新 peer 的 presence 状态（自定义 TTL）。
    pub fn update_with_ttl(&self, peer_id: PeerId, state: PresenceState, ttl: Duration) {
        let mut entries = self.entries.write();
        let entry = PresenceEntry::new(peer_id.clone(), state, ttl);
        entries.insert(peer_id, entry);
    }

    /// 获取 peer 的 presence 状态。
    pub fn get(&self, peer_id: &PeerId) -> Option<PresenceState> {
        let entries = self.entries.read();
        entries.get(peer_id).map(|e| e.state.clone())
    }

    /// 移除 peer 的 presence（设备离线）。
    pub fn remove(&self, peer_id: &PeerId) {
        self.entries.write().remove(peer_id);
    }

    /// 清理过期条目。
    pub fn gc(&self) {
        let now = SystemTime::now();
        let mut entries = self.entries.write();
        let before = entries.len();
        entries.retain(|_, entry| !entry.is_expired(now));
        let count = before - entries.len();
        tracing::debug!(count, "清理过期 presence 条目");
    }

    /// 列出所有未过期的 presence。
    pub fn list_active(&self) -> Vec<(PeerId, PresenceState)> {
        let now = SystemTime::now();
        let entries = self.entries.read();
        entries
            .iter()
            .filter(|(_, e)| !e.is_expired(now))
            .map(|(k, v)| (k.clone(), v.state.clone()))
            .collect()
    }

    /// 在线 peer 数量。
    pub fn online_count(&self) -> usize {
        let now = SystemTime::now();
        let entries = self.entries.read();
        entries.values().filter(|e| !e.is_expired(now)).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_and_get() {
        let reg = PresenceRegistry::default();
        let peer = PeerId::new("1");
        reg.update(
            peer.clone(),
            PresenceState::Editing {
                doc_id: DocId::new("d1"),
                block_id: BlockId::new("b1"),
            },
        );
        let state = reg.get(&peer).unwrap();
        assert!(matches!(state, PresenceState::Editing { .. }));
    }

    #[test]
    fn remove_clears_presence() {
        let reg = PresenceRegistry::default();
        let peer = PeerId::new("1");
        reg.update(peer.clone(), PresenceState::Online);
        assert_eq!(reg.online_count(), 1);
        reg.remove(&peer);
        assert_eq!(reg.online_count(), 0);
    }

    #[test]
    fn gc_removes_expired() {
        let reg = PresenceRegistry::new(Duration::from_millis(1));
        let peer = PeerId::new("1");
        reg.update(peer.clone(), PresenceState::Online);
        // 等待过期
        std::thread::sleep(Duration::from_millis(10));
        reg.gc();
        assert_eq!(reg.online_count(), 0);
    }

    #[test]
    fn list_active_excludes_expired() {
        let reg = PresenceRegistry::new(Duration::from_millis(1));
        reg.update(PeerId::new("1"), PresenceState::Online);
        std::thread::sleep(Duration::from_millis(10));
        let active = reg.list_active();
        assert!(active.is_empty());
    }
}
