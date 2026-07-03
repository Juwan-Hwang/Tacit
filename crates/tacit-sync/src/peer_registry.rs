//! PeerRegistry：peer 管理业务语义层。
//!
//! 封装 DAO 层的 peer CRUD，提供 mark_seen / relay_candidates / revoke_peer
//! 等业务语义接口。所有操作直接走 Store 持久化，不维护内存缓存。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use parking_lot::Mutex;
use tacit_core::{Endpoint, PeerId, PeerRecord};
use tacit_store::{dao, Store};

/// peer 管理注册表。
///
/// `best_anchor()` 结果缓存在内存中，仅在 peer 状态变更时失效，
/// 避免每次调用都执行全量排序。
pub struct PeerRegistry {
    store: Store,
    /// 缓存的 anchor 选举结果。
    anchor_cache: Mutex<Option<PeerId>>,
    /// 缓存版本号：每次 upsert/mark_seen/revoke 时递增，用于检测缓存是否过期。
    cache_generation: AtomicU64,
    /// 生成 anchor_cache 时的版本号。若与 cache_generation 不一致则缓存过期。
    cached_at_generation: AtomicU64,
}

impl PeerRegistry {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            anchor_cache: Mutex::new(None),
            cache_generation: AtomicU64::new(0),
            cached_at_generation: AtomicU64::new(0),
        }
    }

    /// 使 anchor 缓存失效（在 peer 状态变更时调用）。
    fn invalidate_anchor_cache(&self) {
        self.cache_generation.fetch_add(1, Ordering::Release);
    }

    /// 新增或覆盖 peer 记录。
    pub fn upsert_peer(&self, peer: &PeerRecord) -> tacit_core::CoreResult<()> {
        let conn = self.store.conn();
        dao::upsert_peer(&conn, peer)?;
        self.invalidate_anchor_cache();
        Ok(())
    }

    /// 查询单个 peer。
    pub fn get_peer(&self, peer_id: &PeerId) -> tacit_core::CoreResult<Option<PeerRecord>> {
        let conn = self.store.conn();
        dao::get_peer(&conn, peer_id)
    }

    /// 列出全部 peer。
    pub fn list_peers(&self) -> tacit_core::CoreResult<Vec<PeerRecord>> {
        let conn = self.store.conn();
        dao::list_peers(&conn)
    }

    /// 轻量更新 peer 的 last_seen_at 和 last_endpoint。
    pub fn mark_seen(
        &self,
        peer_id: &PeerId,
        endpoint: Option<&Endpoint>,
    ) -> tacit_core::CoreResult<()> {
        let conn = self.store.conn();
        dao::mark_peer_seen(&conn, peer_id, endpoint, SystemTime::now())?;
        self.invalidate_anchor_cache();
        Ok(())
    }

    /// 更新 peer 的 success_ema（指数移动平均成功率）。
    ///
    /// `success` 为 true 表示本次同步成功，false 表示失败。
    /// EMA 平滑因子 α=0.3，公式：ema = ema * (1-α) + success * α
    pub fn update_success_ema(
        &self,
        peer_id: &PeerId,
        success: bool,
    ) -> tacit_core::CoreResult<()> {
        const ALPHA: f64 = 0.3;
        let conn = self.store.conn();
        let peer = dao::get_peer(&conn, peer_id)?;
        if let Some(mut p) = peer {
            let new_value = p.success_ema * (1.0 - ALPHA) + if success { 1.0 } else { 0.0 } * ALPHA;
            p.success_ema = new_value.clamp(0.0, 1.0);
            dao::upsert_peer(&conn, &p)?;
            self.invalidate_anchor_cache();
        }
        Ok(())
    }

    /// 选举最佳 Anchor。
    ///
    /// 结果缓存在内存中，仅在 peer 状态变更时重新计算。
    pub fn best_anchor(&self) -> tacit_core::CoreResult<Option<PeerId>> {
        // 检查缓存是否有效
        let current_gen = self.cache_generation.load(Ordering::Acquire);
        let cached_gen = self.cached_at_generation.load(Ordering::Acquire);
        if current_gen == cached_gen {
            return Ok(self.anchor_cache.lock().clone());
        }
        // 缓存过期，重新计算
        let conn = self.store.conn();
        let result = dao::best_anchor(&conn)?;
        // 更新缓存
        *self.anchor_cache.lock() = result.clone();
        self.cached_at_generation
            .store(current_gen, Ordering::Release);
        Ok(result)
    }

    /// 列出所有可作为 relay 的 trusted peer。
    pub fn relay_candidates(&self) -> tacit_core::CoreResult<Vec<PeerId>> {
        let conn = self.store.conn();
        dao::list_relay_candidates(&conn)
    }

    /// 吊销 peer，将 trust_state 降级为 Revoked。
    pub fn revoke_peer(&self, peer_id: &PeerId) -> tacit_core::CoreResult<()> {
        let conn = self.store.conn();
        dao::revoke_peer(&conn, peer_id)?;
        self.invalidate_anchor_cache();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_core::{AnchorCapabilities, NatCapability, TrustState};

    fn make_peer(id: &str, caps: AnchorCapabilities, trust: TrustState) -> PeerRecord {
        PeerRecord {
            peer_id: PeerId::new(id),
            device_pubkey: format!("pubkey_{id}"),
            capabilities: caps,
            trust_state: trust,
            anchor_priority: 0,
            last_seen_at: SystemTime::UNIX_EPOCH,
            last_endpoint: None,
            nat_capability: NatCapability::Unknown,
            relay_hint: None,
            success_ema: 1.0,
        }
    }

    #[test]
    fn upsert_and_get_peer() {
        let store = Store::open_memory().unwrap();
        let reg = PeerRegistry::new(store);

        let peer = make_peer(
            "p1",
            AnchorCapabilities {
                can_anchor: true,
                can_relay: false,
                persistent: true,
            },
            TrustState::Trusted,
        );
        reg.upsert_peer(&peer).unwrap();

        let got = reg.get_peer(&PeerId::new("p1")).unwrap().unwrap();
        assert_eq!(got.peer_id, peer.peer_id);
        assert_eq!(got.device_pubkey, "pubkey_p1");
    }

    #[test]
    fn mark_seen_updates_endpoint() {
        let store = Store::open_memory().unwrap();
        let reg = PeerRegistry::new(store);

        let peer = make_peer("p1", AnchorCapabilities::default(), TrustState::Trusted);
        reg.upsert_peer(&peer).unwrap();

        let ep = Endpoint::new("192.168.1.10", 4433);
        reg.mark_seen(&PeerId::new("p1"), Some(&ep)).unwrap();

        let got = reg.get_peer(&PeerId::new("p1")).unwrap().unwrap();
        assert_eq!(got.last_endpoint, Some(ep));
        assert!(got.last_seen_at > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn best_anchor_picks_highest_priority() {
        let store = Store::open_memory().unwrap();
        let reg = PeerRegistry::new(store);

        // p1: priority=1, can_anchor
        reg.upsert_peer(&PeerRecord {
            anchor_priority: 1,
            ..make_peer(
                "p1",
                AnchorCapabilities {
                    can_anchor: true,
                    ..Default::default()
                },
                TrustState::Trusted,
            )
        })
        .unwrap();

        // p2: priority=5, can_anchor
        reg.upsert_peer(&PeerRecord {
            anchor_priority: 5,
            ..make_peer(
                "p2",
                AnchorCapabilities {
                    can_anchor: true,
                    ..Default::default()
                },
                TrustState::Trusted,
            )
        })
        .unwrap();

        // p3: priority=10, but NOT can_anchor
        reg.upsert_peer(&PeerRecord {
            anchor_priority: 10,
            ..make_peer("p3", AnchorCapabilities::default(), TrustState::Trusted)
        })
        .unwrap();

        let anchor = reg.best_anchor().unwrap();
        assert_eq!(anchor, Some(PeerId::new("p2")));
    }

    #[test]
    fn relay_candidates_filters_by_capability() {
        let store = Store::open_memory().unwrap();
        let reg = PeerRegistry::new(store);

        reg.upsert_peer(&make_peer(
            "p1",
            AnchorCapabilities {
                can_relay: true,
                ..Default::default()
            },
            TrustState::Trusted,
        ))
        .unwrap();
        reg.upsert_peer(&make_peer(
            "p2",
            AnchorCapabilities {
                can_relay: false,
                ..Default::default()
            },
            TrustState::Trusted,
        ))
        .unwrap();
        reg.upsert_peer(&make_peer(
            "p3",
            AnchorCapabilities {
                can_relay: true,
                ..Default::default()
            },
            TrustState::Pending,
        ))
        .unwrap();

        let candidates = reg.relay_candidates().unwrap();
        assert_eq!(candidates, vec![PeerId::new("p1")]);
    }

    #[test]
    fn revoke_peer_downgrades_trust() {
        let store = Store::open_memory().unwrap();
        let reg = PeerRegistry::new(store);

        reg.upsert_peer(&make_peer(
            "p1",
            AnchorCapabilities::default(),
            TrustState::Trusted,
        ))
        .unwrap();

        reg.revoke_peer(&PeerId::new("p1")).unwrap();

        let got = reg.get_peer(&PeerId::new("p1")).unwrap().unwrap();
        assert_eq!(got.trust_state, TrustState::Revoked);

        // 吊销后不应再被选为 anchor
        assert_eq!(reg.best_anchor().unwrap(), None);
    }
}
