//! 协议版本与能力协商（v1.0 规范第 14 节）。
//!
//! v1.0 采用：主版本保底，能力协商优先。
//! 主版本不兼容时拒绝，次版本差异通过 capability 降级，
//! 扩展字段统一用 TLV 携带。

use serde::{Deserialize, Serialize};

use crate::model::AnchorCapabilities;

/// 当前协议主版本。
pub const MAJOR_VERSION: u8 = 1;
/// 当前协议次版本。
pub const MINOR_VERSION: u8 = 0;

/// 协议版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    pub fn current() -> Self {
        Self {
            major: MAJOR_VERSION,
            minor: MINOR_VERSION,
        }
    }

    pub fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// 主版本是否兼容。
    pub fn is_compatible(&self, other: &Self) -> bool {
        self.major == other.major
    }

    /// 是否比 other 更新（次版本更高）。
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self.major == other.major && self.minor > other.minor
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// 能力协商结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationResult {
    /// 协商成功，使用降级后的能力。
    Ok(NegotiatedCapabilities),
    /// 主版本不兼容，拒绝连接。
    VersionMismatch {
        local: ProtocolVersion,
        remote: ProtocolVersion,
    },
}

/// 协商后的能力集。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegotiatedCapabilities {
    /// 本端能力。
    pub local: AnchorCapabilities,
    /// 对端能力。
    pub remote: AnchorCapabilities,
    /// 实际可用能力（双方交集）。
    pub effective: AnchorCapabilities,
}

/// 能力协商：取双方交集。
pub fn negotiate(
    local_version: ProtocolVersion,
    remote_version: ProtocolVersion,
    local_caps: AnchorCapabilities,
    remote_caps: AnchorCapabilities,
) -> NegotiationResult {
    if !local_version.is_compatible(&remote_version) {
        return NegotiationResult::VersionMismatch {
            local: local_version,
            remote: remote_version,
        };
    }

    // 能力降级：取交集
    let effective = AnchorCapabilities {
        can_anchor: local_caps.can_anchor && remote_caps.can_anchor,
        can_relay: local_caps.can_relay && remote_caps.can_relay,
        persistent: local_caps.persistent && remote_caps.persistent,
    };

    NegotiationResult::Ok(NegotiatedCapabilities {
        local: local_caps,
        remote: remote_caps,
        effective,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatible_versions() {
        let v1 = ProtocolVersion::new(1, 0);
        let v2 = ProtocolVersion::new(1, 5);
        assert!(v1.is_compatible(&v2));
    }

    #[test]
    fn incompatible_versions() {
        let v1 = ProtocolVersion::new(1, 0);
        let v2 = ProtocolVersion::new(2, 0);
        assert!(!v1.is_compatible(&v2));
    }

    #[test]
    fn negotiate_success() {
        let local = AnchorCapabilities {
            can_anchor: true,
            can_relay: true,
            persistent: true,
        };
        let remote = AnchorCapabilities {
            can_anchor: true,
            can_relay: false,
            persistent: true,
        };
        let result = negotiate(
            ProtocolVersion::current(),
            ProtocolVersion::current(),
            local,
            remote,
        );
        match result {
            NegotiationResult::Ok(caps) => {
                assert!(caps.effective.can_anchor);
                assert!(!caps.effective.can_relay);
                assert!(caps.effective.persistent);
            }
            _ => panic!("期望协商成功"),
        }
    }

    #[test]
    fn negotiate_version_mismatch() {
        let result = negotiate(
            ProtocolVersion::new(1, 0),
            ProtocolVersion::new(2, 0),
            AnchorCapabilities::default(),
            AnchorCapabilities::default(),
        );
        assert!(matches!(result, NegotiationResult::VersionMismatch { .. }));
    }
}
