//! Loro 与 Tacit 类型转换。
//!
//! 本模块是 Loro 上游 API 的唯一隔离层：所有对 Loro Frontiers /
//! VersionVector / ExportMode 的调用都集中在此，其他模块只依赖
//! Tacit 自身的 Frontier 与字节接口。这样上游 API 变化时只需改本文件。

use std::borrow::Cow;

use loro::{ExportMode, Frontiers, LoroDoc, VersionVector, ID};
use tacit_core::{CoreError, CoreResult, Frontier};

/// Loro PeerID 类型别名。
pub type LoroPeerId = u64;

/// 将 Tacit Frontier 转换为 Loro VersionVector。
///
/// Tacit 的 PeerId 内部存储 Loro PeerID（u64）的字符串形式，
/// 转换时按十进制解析。若 PeerId 非数字字符串则返回错误。
pub fn frontier_to_vv(frontier: &Frontier) -> CoreResult<VersionVector> {
    let mut vv = VersionVector::new();
    for (peer_str, seq) in frontier.entries() {
        let peer = parse_peer_id(peer_str)?;
        // VersionVector 是右开区间，set_last 表示该 peer 的最后一个 op 是 ID{peer, seq-1}。
        // Tacit Frontier 中 seq 表示已知的最新 op 计数（闭区间），故 last id 的 counter = seq - 1。
        let last_counter = seq
            .checked_sub(1)
            .ok_or_else(|| CoreError::InvalidFrontier(format!("seq 为 0: peer={peer_str}")))?;
        vv.set_last(ID::new(peer, last_counter as i32));
    }
    Ok(vv)
}

/// 将 Loro Frontiers 转换为 Tacit Frontier。
pub fn frontiers_to_frontier(frontiers: &Frontiers) -> CoreResult<Frontier> {
    let mut out = Frontier::new();
    for id in frontiers.iter() {
        let peer_str = format_peer_id(id.peer);
        // id.counter 是最后一个 op 的 counter（从 0 开始），seq = counter + 1。
        let seq = (id.counter as u64) + 1;
        out.set(tacit_core::PeerId::new(peer_str), seq);
    }
    Ok(out)
}

/// 将 Tacit Frontier 转换为 Loro Frontiers 列表（用于 checkout 等 API）。
pub fn frontier_to_frontiers(frontier: &Frontier) -> CoreResult<Vec<Frontiers>> {
    let vv = frontier_to_vv(frontier)?;
    Ok(vec![vv.get_frontiers()])
}

/// 将 PeerId 字符串解析为 Loro u64 PeerID。
pub fn parse_peer_id(s: &str) -> CoreResult<LoroPeerId> {
    s.parse::<u64>()
        .map_err(|_| CoreError::InvalidFrontier(format!("PeerId 非法（期望 u64 字符串）: {s}")))
}

/// 将 Loro u64 PeerID 格式化为 Tacit PeerId 字符串。
pub fn format_peer_id(peer: LoroPeerId) -> String {
    peer.to_string()
}

/// 导出模式封装，集中管理 ExportMode 构造。
pub enum LoroExport<'a> {
    /// 完整快照。
    Snapshot,
    /// 自指定 frontier 之后的增量。
    UpdatesSince(&'a Frontier),
    /// 以指定 frontier 为边界的 shallow snapshot。
    ShallowSnapshot(&'a Frontier),
}

impl LoroExport<'_> {
    /// 在给定 LoroDoc 上执行导出，返回字节。
    pub fn export(&self, doc: &LoroDoc) -> CoreResult<Vec<u8>> {
        let mode = match self {
            LoroExport::Snapshot => ExportMode::Snapshot,
            LoroExport::UpdatesSince(f) => {
                let vv = frontier_to_vv(f)?;
                ExportMode::Updates {
                    from: Cow::Owned(vv),
                }
            }
            LoroExport::ShallowSnapshot(f) => {
                let frontiers = frontier_to_frontiers(f)?;
                // ShallowSnapshot 接受单个 Frontiers（以最新状态为基准）。
                let f0 = frontiers.into_iter().next().unwrap_or(Frontiers::None);
                ExportMode::ShallowSnapshot(Cow::Owned(f0))
            }
        };
        doc.export(mode)
            .map_err(|e| CoreError::Crdt(format!("Loro 导出失败: {e}")))
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
    fn frontier_roundtrip() {
        let mut f = Frontier::new();
        f.set(pid(1), 5);
        f.set(pid(2), 3);
        let vv = frontier_to_vv(&f).unwrap();
        let frontiers = vv.get_frontiers();
        let f2 = frontiers_to_frontier(&frontiers).unwrap();
        assert_eq!(f2.get(&pid(1)), Some(5));
        assert_eq!(f2.get(&pid(2)), Some(3));
    }

    #[test]
    fn empty_frontier() {
        let f = Frontier::new();
        let vv = frontier_to_vv(&f).unwrap();
        let frontiers = vv.get_frontiers();
        let f2 = frontiers_to_frontier(&frontiers).unwrap();
        assert!(f2.is_empty());
    }

    #[test]
    fn invalid_peer_id() {
        let mut f = Frontier::new();
        f.set(PeerId::new("not-a-number"), 1);
        assert!(frontier_to_vv(&f).is_err());
    }
}
