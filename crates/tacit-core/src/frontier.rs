//! Frontier：版本向量抽象。
//!
//! Frontier 表示文档在某时刻的版本状态，本质是 `peer_id -> seq` 的映射。
//! 所有 ack 摘要、缺口检测、checkpoint 边界、stale 判定都复用 Frontier。
//!
//! 本类型与 Loro 解耦：`tacit-crdt` 负责 Loro 原生 frontier 与本类型之间的
//! 双向转换，使 store/sync 层无需直接依赖 Loro。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ids::PeerId;

/// 版本向量。记录每个 peer 已知的最新 seq。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frontier {
    /// peer_id -> 该 peer 的最新已知 seq。
    map: HashMap<String, u64>,
}

impl Frontier {
    pub fn new() -> Self {
        Self::default()
    }

    /// 从迭代器构造。
    pub fn from_iter<I: IntoIterator<Item = (PeerId, u64)>>(iter: I) -> Self {
        let mut f = Self::new();
        for (peer, seq) in iter {
            f.set(peer, seq);
        }
        f
    }

    /// 设置某 peer 的 seq。
    pub fn set(&mut self, peer: PeerId, seq: u64) {
        let entry = self.map.entry(peer.0).or_insert(0);
        if seq > *entry {
            *entry = seq;
        }
    }

    /// 读取某 peer 的 seq。
    pub fn get(&self, peer: &PeerId) -> Option<u64> {
        self.map.get(&peer.0).copied()
    }

    /// 是否为空（初始状态）。
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 返回内部映射的只读视图。
    pub fn entries(&self) -> impl Iterator<Item = (&str, u64)> {
        self.map.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// 合并另一个 frontier，逐 peer 取较大 seq。
    pub fn merge(&mut self, other: &Frontier) {
        for (k, v) in &other.map {
            let entry = self.map.entry(k.clone()).or_insert(0);
            if *v > *entry {
                *entry = *v;
            }
        }
    }
}

/// Frontier 操作集合。
pub trait FrontierOps {
    /// 当前 frontier 是否完全覆盖 `other`，即对每个 peer 的 seq 都 >=。
    fn covers(&self, other: &Frontier) -> bool;

    /// 计算当前 frontier 相对 `other` 缺失的部分（peer, needed_seq）。
    fn missing_against(&self, other: &Frontier) -> Vec<(PeerId, u64)>;
}

impl FrontierOps for Frontier {
    fn covers(&self, other: &Frontier) -> bool {
        other.map.iter().all(|(k, v)| {
            self.map.get(k).copied().unwrap_or(0) >= *v
        })
    }

    fn missing_against(&self, other: &Frontier) -> Vec<(PeerId, u64)> {
        other
            .map
            .iter()
            .filter_map(|(k, v)| {
                let mine = self.map.get(k).copied().unwrap_or(0);
                if mine < *v {
                    Some((PeerId(k.clone()), *v))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PeerId {
        PeerId(s.into())
    }

    #[test]
    fn merge_takes_max() {
        let mut a = Frontier::from_iter([(p("a"), 3), (p("b"), 1)]);
        let b = Frontier::from_iter([(p("b"), 5), (p("c"), 2)]);
        a.merge(&b);
        assert_eq!(a.get(&p("a")), Some(3));
        assert_eq!(a.get(&p("b")), Some(5));
        assert_eq!(a.get(&p("c")), Some(2));
    }

    #[test]
    fn covers_and_missing() {
        let a = Frontier::from_iter([(p("a"), 5), (p("b"), 2)]);
        let b = Frontier::from_iter([(p("a"), 3), (p("b"), 2), (p("c"), 1)]);
        // a 不覆盖 b，因为缺 c
        assert!(!a.covers(&b));
        let missing = a.missing_against(&b);
        assert_eq!(missing, vec![(p("c"), 1)]);

        let c = Frontier::from_iter([(p("a"), 10)]);
        let d = Frontier::from_iter([(p("a"), 5)]);
        assert!(c.covers(&d));
    }
}
