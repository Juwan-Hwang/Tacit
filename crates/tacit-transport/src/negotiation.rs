//! 能力协商逻辑（v1.0 规范第 14 节）。
//!
//! 主版本保底，能力协商优先。
//! 主版本不兼容时拒绝，次版本差异通过 capability 降级。

use parking_lot::Mutex;
use tacit_core::PeerId;
use tacit_core::{
    negotiate, AnchorCapabilities, NegotiatedCapabilities, NegotiationResult, ProtocolVersion,
    MAJOR_VERSION, MINOR_VERSION,
};

/// 能力协商器：管理每个 peer 的协商结果。
pub struct CapabilityNegotiator {
    /// 本端协议版本。
    local_version: ProtocolVersion,
    /// 本端能力。
    local_caps: AnchorCapabilities,
    /// 已协商的 peer 能力。
    negotiated: Mutex<std::collections::HashMap<PeerId, NegotiatedCapabilities>>,
}

impl CapabilityNegotiator {
    pub fn new(local_caps: AnchorCapabilities) -> Self {
        Self {
            local_version: ProtocolVersion::new(MAJOR_VERSION, MINOR_VERSION),
            local_caps,
            negotiated: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// 与远端 peer 进行能力协商。
    ///
    /// 返回协商结果。如果主版本兼容，会缓存协商后的能力。
    pub fn negotiate_with(
        &self,
        peer_id: &PeerId,
        remote_version: ProtocolVersion,
        remote_caps: AnchorCapabilities,
    ) -> NegotiationResult {
        let result = negotiate(
            self.local_version,
            remote_version,
            self.local_caps,
            remote_caps,
        );
        if let NegotiationResult::Ok(ref caps) = result {
            let mut negotiated = self.negotiated.lock();
            negotiated.insert(peer_id.clone(), caps.clone());
        }
        result
    }

    /// 获取已协商的能力。
    pub fn get_negotiated(&self, peer_id: &PeerId) -> Option<NegotiatedCapabilities> {
        let negotiated = self.negotiated.lock();
        negotiated.get(peer_id).cloned()
    }

    /// 获取生效能力（协商后的交集）。
    pub fn effective_caps(&self, peer_id: &PeerId) -> AnchorCapabilities {
        let negotiated = self.negotiated.lock();
        negotiated
            .get(peer_id)
            .map(|c| c.effective)
            .unwrap_or_default()
    }

    /// 本端版本。
    pub fn local_version(&self) -> ProtocolVersion {
        self.local_version
    }

    /// 本端能力。
    pub fn local_caps(&self) -> AnchorCapabilities {
        self.local_caps
    }

    /// 移除 peer 的协商记录。
    pub fn remove(&self, peer_id: &PeerId) {
        self.negotiated.lock().remove(peer_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_compatible() {
        let negotiator = CapabilityNegotiator::new(AnchorCapabilities {
            can_anchor: true,
            can_relay: true,
            persistent: true,
        });
        let peer = PeerId::new("1");
        let result = negotiator.negotiate_with(
            &peer,
            ProtocolVersion::current(),
            AnchorCapabilities {
                can_anchor: true,
                can_relay: false,
                persistent: true,
            },
        );
        assert!(matches!(result, NegotiationResult::Ok(_)));
        let caps = negotiator.get_negotiated(&peer).unwrap();
        assert!(caps.effective.can_anchor);
        assert!(!caps.effective.can_relay);
    }

    #[test]
    fn negotiate_incompatible() {
        let negotiator = CapabilityNegotiator::new(AnchorCapabilities::default());
        let peer = PeerId::new("1");
        let result = negotiator.negotiate_with(
            &peer,
            ProtocolVersion::new(2, 0),
            AnchorCapabilities::default(),
        );
        assert!(matches!(result, NegotiationResult::VersionMismatch { .. }));
        // 不兼容时不应缓存
        assert!(negotiator.get_negotiated(&peer).is_none());
    }

    #[test]
    fn effective_caps_default() {
        let negotiator = CapabilityNegotiator::new(AnchorCapabilities::default());
        let peer = PeerId::new("unknown");
        assert_eq!(
            negotiator.effective_caps(&peer),
            AnchorCapabilities::default()
        );
    }
}
