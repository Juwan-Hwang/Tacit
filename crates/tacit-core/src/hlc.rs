//! HLC（混合逻辑时钟）。
//!
//! v1.0 规范第 9 节：HLC 仅用于 UI 近似排序、传输层缺口检测与日志观测、
//! GC 时间窗口与 stale peer 判断、soft-delete 安全线辅助；
//! HLC **不参与 Loro 的 CRDT 排序逻辑**。
//!
//! 每台设备维护本地单调递增 seq，仅用于检测控制层/传输层重复、
//! 辅助日志分析与链路诊断、ack 粒度统计。

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// HLC 时间戳。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hlc {
    /// 物理时间（毫秒，自 UNIX_EPOCH）。
    pub physical_ms: i64,
    /// 逻辑计数器。
    pub logical: u32,
}

impl Hlc {
    /// 创建零值 HLC。
    pub fn zero() -> Self {
        Self {
            physical_ms: 0,
            logical: 0,
        }
    }

    /// 从物理时间创建（logical=0）。
    pub fn from_millis(physical_ms: i64) -> Self {
        Self {
            physical_ms,
            logical: 0,
        }
    }

    /// 获取当前墙钟毫秒。
    pub(crate) fn wall_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// 本地事件：递增 HLC。
    ///
    /// 如果当前墙钟 > 上次物理时间，则用墙钟重置 logical；
    /// 否则 logical + 1。
    pub fn tick(&mut self) -> Hlc {
        let now = Self::wall_millis();
        if now > self.physical_ms {
            self.physical_ms = now;
            self.logical = 0;
        } else {
            self.logical += 1;
        }
        *self
    }

    /// 收到远端事件：合并远端 HLC。
    ///
    /// 取物理时间较大者；若相等则 logical 取较大者 + 1。
    pub fn receive(&mut self, remote: &Hlc) -> Hlc {
        tracing::trace!(
            remote_physical = remote.physical_ms,
            remote_logical = remote.logical,
            "HLC receive"
        );
        let now = Self::wall_millis();
        let new_physical = self.physical_ms.max(remote.physical_ms).max(now);
        if new_physical == self.physical_ms && new_physical == remote.physical_ms {
            self.logical = self.logical.max(remote.logical) + 1;
        } else if new_physical == self.physical_ms {
            self.logical += 1;
        } else if new_physical == remote.physical_ms {
            self.physical_ms = remote.physical_ms;
            self.logical = remote.logical + 1;
        } else {
            self.physical_ms = new_physical;
            self.logical = 0;
        }
        *self
    }

    /// 转为 u64 紧凑表示（高 44 位物理时间，低 20 位 logical）。
    ///
    /// 44 位物理时间覆盖到约 year 2525；20 位 logical 允许同一毫秒内
    /// 1,048,576 次 tick，远超实际需求，避免 logical 截断丢数据。
    pub fn to_compact(&self) -> u64 {
        // 物理时间取低 44 位（当前时间戳远小于 2^44，不会溢出）
        let physical = (self.physical_ms as u64) & 0xFFFFFFFFFFF; // 44 bits
                                                                  // logical 取低 20 位（u32 最大值远大于 2^20，需检查溢出）
        let logical = (self.logical as u64) & 0xFFFFF; // 20 bits
        (physical << 20) | logical
    }

    /// 从紧凑表示解析。
    pub fn from_compact(v: u64) -> Self {
        Self {
            physical_ms: (v >> 20) as i64,
            logical: (v & 0xFFFFF) as u32,
        }
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.physical_ms
            .cmp(&other.physical_ms)
            .then(self.logical.cmp(&other.logical))
    }
}

impl std::fmt::Display for Hlc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.physical_ms, self.logical)
    }
}

/// 本地单调递增 seq，用于检测控制层/传输层重复。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LocalSeq(pub u64);

impl LocalSeq {
    /// 创建初始 seq。
    pub fn new() -> Self {
        Self(0)
    }

    /// 递增并返回新值。
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    /// 当前值。
    pub fn current(&self) -> u64 {
        self.0
    }

    /// 检查收到的 seq 是否为重复（<= 已见最大值）。
    pub fn is_duplicate(&self, seen: u64) -> bool {
        seen <= self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_increments_logical() {
        let mut hlc = Hlc::zero();
        let t1 = hlc.tick();
        let t2 = hlc.tick();
        assert!(t2 >= t1);
        assert!(t2.logical >= t1.logical);
    }

    #[test]
    fn receive_merges_remote() {
        let mut local = Hlc::from_millis(1000);
        let remote = Hlc::from_millis(2000);
        let merged = local.receive(&remote);
        assert!(merged.physical_ms >= 2000);
    }

    #[test]
    fn receive_same_physical_increments_logical() {
        // 使用固定物理时间（远离 wall clock），避免 Windows 低时钟分辨率导致
        // wall_millis() 返回不同值使 receive 进入 else 分支。
        let fixed_ms = 1_000_000_000; // ~2001-09-09，远离当前时间
        let mut local = Hlc {
            physical_ms: fixed_ms,
            logical: 3,
        };
        let remote = Hlc {
            physical_ms: fixed_ms,
            logical: 5,
        };
        let merged = local.receive(&remote);
        // 两者物理时间相同且远离当前，logical 应递增
        assert!(merged.logical > 5);
    }

    #[test]
    fn compact_roundtrip() {
        let hlc = Hlc {
            physical_ms: 123456,
            logical: 42,
        };
        let compact = hlc.to_compact();
        let restored = Hlc::from_compact(compact);
        assert_eq!(hlc, restored);
    }

    #[test]
    fn compact_roundtrip_large_logical() {
        // 验证 logical 不再被截断为 16 位（旧 bug：65536+ 会丢失）
        let hlc = Hlc {
            physical_ms: 123456,
            logical: 100_000, // > 65535，旧实现会截断
        };
        let compact = hlc.to_compact();
        let restored = Hlc::from_compact(compact);
        assert_eq!(hlc, restored, "logical 应完整保留，不应被截断");
    }

    #[test]
    fn compact_roundtrip_max_logical() {
        // 20 位上限 = 1,048,575
        let hlc = Hlc {
            physical_ms: 1_700_000_000_000, // 接近当前时间戳
            logical: 0xFFFFF,               // 20 位最大值
        };
        let compact = hlc.to_compact();
        let restored = Hlc::from_compact(compact);
        assert_eq!(hlc, restored);
    }

    #[test]
    fn local_seq_next() {
        let mut seq = LocalSeq::new();
        assert_eq!(seq.next(), 1);
        assert_eq!(seq.next(), 2);
        assert_eq!(seq.current(), 2);
        assert!(seq.is_duplicate(1));
        assert!(!seq.is_duplicate(3));
    }

    #[test]
    fn ordering() {
        let a = Hlc {
            physical_ms: 1000,
            logical: 0,
        };
        let b = Hlc {
            physical_ms: 1000,
            logical: 1,
        };
        let c = Hlc {
            physical_ms: 2000,
            logical: 0,
        };
        assert!(a < b);
        assert!(b < c);
    }
}
