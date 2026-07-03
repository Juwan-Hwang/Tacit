//! 双水位计算。
//!
//! 根据 acks 计算强安全水位与软安全水位（v1.0 规范 8.3）。
//!
//! - **强安全水位**：所有 active 设备都覆盖的 frontier。
//! - **软安全水位**：超过阈值未上线设备临时移出 active 集合后可推进的 frontier。
//!
//! 强安全水位用于无争议压缩；软安全水位用于实际可运转的常规 compaction。
//! 低频设备回归时通过 checkpoint 追赶或手术式重入兜底。

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use tacit_core::{AckSummary, DocId, Frontier, PeerId, Watermarks};

/// 双水位计算器。
pub struct WatermarkCalculator {
    soft_timeout: Duration,
}

impl WatermarkCalculator {
    /// 创建计算器。
    ///
    /// `soft_timeout`：超过该时长未上线的设备移出 active 集合。
    pub fn new(soft_timeout: Duration) -> Self {
        Self { soft_timeout }
    }

    /// 计算指定文档的双水位。
    ///
    /// `acks`：所有 peer 对该 doc 的 ack 摘要。
    /// `now`：当前时间，用于判断 active 集合。
    pub fn compute(&self, doc_id: &DocId, acks: &[AckSummary], now: SystemTime) -> Watermarks {
        // 过滤出该 doc 的 acks
        let doc_acks: Vec<&AckSummary> = acks.iter().filter(|a| &a.doc_id == doc_id).collect();
        if doc_acks.is_empty() {
            return Watermarks::default();
        }

        // active 集合：在 soft_timeout 内有 ack 的 peer
        let active_peers: HashSet<&PeerId> = doc_acks
            .iter()
            .filter(|a| {
                now.duration_since(a.updated_at)
                    .map(|d| d < self.soft_timeout)
                    .unwrap_or(false)
            })
            .map(|a| &a.peer_id)
            .collect();

        if active_peers.is_empty() {
            // 没有 active peer，软水位取所有 ack 的并集
            let soft = Self::merge_frontiers(&doc_acks);
            return Watermarks {
                hard_frontier: Frontier::new(),
                soft_frontier: soft,
            };
        }

        // 强安全水位：所有 active 设备都覆盖的 frontier
        // = active 设备中每个 peer 的最小 seq 取交集
        let active_acks: Vec<&AckSummary> = doc_acks
            .iter()
            .copied()
            .filter(|a| active_peers.contains(&a.peer_id))
            .collect();
        let hard = Self::intersection_frontier(&active_acks);

        // 软安全水位：所有 ack 的并集（含非 active）
        let soft = Self::merge_frontiers(&doc_acks);

        Watermarks {
            hard_frontier: hard,
            soft_frontier: soft,
        }
    }

    /// 合并所有 ack 的 frontier（取并集，逐 peer 取较大 seq）。
    fn merge_frontiers(acks: &[&AckSummary]) -> Frontier {
        let mut merged = Frontier::new();
        for ack in acks {
            merged.merge(&ack.ack_frontier);
        }
        merged
    }

    /// 计算所有 ack 的交集 frontier（逐 peer 取较小 seq）。
    ///
    /// 语义：只有所有 active ack 都覆盖的 peer 才会出现在结果中。
    /// 若某个 active ack 的 frontier 不包含 peer X，则 peer X 不会出现在
    /// hard frontier 中——因为该 peer 的进度尚未被所有 active 设备确认，
    /// 不能安全压缩。这确保 hard frontier 只包含"无争议压缩"的安全 seq，
    /// 低频设备回归时通过 checkpoint 追赶或手术式重入兜底。
    fn intersection_frontier(acks: &[&AckSummary]) -> Frontier {
        if acks.is_empty() {
            return Frontier::new();
        }
        // 以第一个 ack 为基准
        let first = &acks[0].ack_frontier;
        let mut result = Frontier::new();
        for (peer, _seq) in first.entries() {
            let peer_id = PeerId(peer.to_string());
            // 所有 ack 都必须覆盖该 peer，且取最小 seq
            let min_seq = acks
                .iter()
                .map(|a| a.ack_frontier.get(&peer_id).unwrap_or(0))
                .min();
            if let Some(min) = min_seq {
                if min > 0 {
                    result.set(peer_id, min);
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

fn ack(peer: PeerId, doc: &str, frontier: Frontier, updated: SystemTime) -> AckSummary {
AckSummary {
peer_id: peer,
doc_id: DocId::new(doc),
ack_checkpoint: None,
ack_frontier: frontier,
updated_at: updated,
version_override: None,
}
}

    #[test]
    fn empty_acks_returns_default() {
        let calc = WatermarkCalculator::new(Duration::from_secs(60));
        let w = calc.compute(&DocId::new("d1"), &[], SystemTime::now());
        assert!(w.hard_frontier.is_empty());
        assert!(w.soft_frontier.is_empty());
    }

    #[test]
    fn hard_watermark_is_intersection() {
        let calc = WatermarkCalculator::new(Duration::from_secs(60));
        let now = SystemTime::now();
        let acks = vec![
            ack(
                pid(1),
                "d1",
                Frontier::from_iter([(pid(1), 5), (pid(2), 3)]),
                now,
            ),
            ack(
                pid(2),
                "d1",
                Frontier::from_iter([(pid(1), 4), (pid(2), 7)]),
                now,
            ),
        ];
        let w = calc.compute(&DocId::new("d1"), &acks, now);
        // 交集：peer1 min(5,4)=4, peer2 min(3,7)=3
        assert_eq!(w.hard_frontier.get(&pid(1)), Some(4));
        assert_eq!(w.hard_frontier.get(&pid(2)), Some(3));
        // 软水位是并集
        assert_eq!(w.soft_frontier.get(&pid(1)), Some(5));
        assert_eq!(w.soft_frontier.get(&pid(2)), Some(7));
    }

    #[test]
    fn stale_peer_excluded_from_hard() {
        let calc = WatermarkCalculator::new(Duration::from_secs(60));
        let now = SystemTime::now();
        let stale = now - Duration::from_secs(120);
        let acks = vec![
            ack(pid(1), "d1", Frontier::from_iter([(pid(1), 5)]), now),
            ack(
                pid(2),
                "d1",
                Frontier::from_iter([(pid(1), 3), (pid(2), 8)]),
                stale,
            ),
        ];
        let w = calc.compute(&DocId::new("d1"), &acks, now);
        // peer2 stale，hard 只含 peer1
        assert_eq!(w.hard_frontier.get(&pid(1)), Some(5));
        assert!(w.hard_frontier.get(&pid(2)).is_none());
        // soft 含所有
        assert_eq!(w.soft_frontier.get(&pid(2)), Some(8));
    }

    #[test]
    fn no_active_uses_soft_only() {
        let calc = WatermarkCalculator::new(Duration::from_secs(60));
        let stale = SystemTime::now() - Duration::from_secs(120);
        let acks = vec![
            ack(pid(1), "d1", Frontier::from_iter([(pid(1), 5)]), stale),
            ack(pid(2), "d1", Frontier::from_iter([(pid(2), 8)]), stale),
        ];
        let w = calc.compute(&DocId::new("d1"), &acks, SystemTime::now());
        assert!(w.hard_frontier.is_empty());
        assert_eq!(w.soft_frontier.get(&pid(1)), Some(5));
        assert_eq!(w.soft_frontier.get(&pid(2)), Some(8));
    }
}
