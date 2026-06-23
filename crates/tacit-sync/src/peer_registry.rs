//! PeerRegistry：peer 管理业务语义层。
//!
//! 封装 DAO 层的 peer CRUD，提供 mark_seen / relay_candidates / revoke_peer
//! 等业务语义接口。所有操作直接走 Store 持久化，不维护内存缓存。

use std::time::SystemTime;

use tacit_core::{Endpoint, PeerId, PeerRecord};
use tacit_store::{Store, dao};

/// peer 管理注册表。
pub struct PeerRegistry {
    store: Store,
}

impl PeerRegistry {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// 新增或覆盖 peer 记录。
    pub fn upsert_peer(&self, peer: &PeerRecord) -> tacit_core::CoreResult<()> {
        let conn = self.store.conn();
        dao::upsert_peer(&conn, peer)
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
        dao::mark_peer_seen(&conn, peer_id, endpoint, SystemTime::now())
    }

    /// 选举最佳 Anchor。
    pub fn best_anchor(&self) -> tacit_core::CoreResult<Option<PeerId>> {
        let conn = self.store.conn();
        dao::best_anchor(&conn)
    }

    /// 列出所有可作为 relay 的 trusted peer。
    pub fn relay_candidates(&self) -> tacit_core::CoreResult<Vec<PeerId>> {
        let conn = self.store.conn();
        dao::list_relay_candidates(&conn)
    }

    /// 吊销 peer，将 trust_state 降级为 Revoked。
    pub fn revoke_peer(&self, peer_id: &PeerId) -> tacit_core::CoreResult<()> {
        let conn = self.store.conn();
        dao::revoke_peer(&conn, peer_id)
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
