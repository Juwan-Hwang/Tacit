//! mDNS 发现：局域网 peer 发现服务。
//!
//! v1.0 规范第 12 节 peer 发现：
//! - LAN 环境下通过 mDNS（Bonjour/Avahi）广播 presence。
//! - 发现新 peer 后触发连接建立与能力协商。
//! - WAN 环境下通过 Anchor relay 或手动端点连接。
//!
//! 本模块定义 mDNS 发现的抽象接口与协议帧处理。
//! 具体平台绑定（macOS NSNetService / Linux Avahi / Windows Bonjour）
//! 由集成层实现，本模块仅提供协议层逻辑。
//!
//! 发现帧使用 JSON 编码（mDNS TXT 记录友好），包含完整的 peer_id 字符串。
//! 二进制 DiscoveryFrame 用于协议层握手，不用于 mDNS 广播。

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tacit_core::{AnchorCapabilities, Endpoint, PeerId};
use tracing::{debug, info, warn};

/// mDNS 服务类型。
pub const MDNS_SERVICE_TYPE: &str = "_tacit._tcp";

/// mDNS 发现帧（JSON 编码，用于 TXT 记录或广播 payload）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsDiscoveryFrame {
    pub group_id: String,
    pub peer_id: String,
    pub capabilities: AnchorCapabilities,
}

impl MdnsDiscoveryFrame {
    /// 编码为 JSON 字节。
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// 从 JSON 字节解码。
    pub fn decode(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// 发现记录：记录已发现的 peer。
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    pub group_id: String,
    pub endpoint: Endpoint,
    pub capabilities: AnchorCapabilities,
    pub discovered_at: SystemTime,
    pub last_seen: SystemTime,
}

/// mDNS 发现管理器。
///
/// 维护已发现 peer 列表，处理发现帧的编解码。
/// 平台层通过 `on_discovered` / `on_lost` 回调上报 mDNS 事件。
pub struct MdnsDiscovery {
    /// group_id 过滤：只发现同组 peer。
    group_id: String,
    /// 本设备 ID。
    device_id: PeerId,
    /// 本设备能力位。
    capabilities: AnchorCapabilities,
    /// 已发现 peer 列表。
    peers: Mutex<HashMap<PeerId, DiscoveredPeer>>,
    /// peer 过期时间：超过此时间未收到广播则认为 peer 离线。
    peer_ttl: Duration,
}

impl MdnsDiscovery {
    pub fn new(
        group_id: String,
        device_id: PeerId,
        capabilities: AnchorCapabilities,
    ) -> Self {
        Self {
            group_id,
            device_id,
            capabilities,
            peers: Mutex::new(HashMap::new()),
            peer_ttl: Duration::from_secs(60),
        }
    }

    /// 设置 peer TTL。
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.peer_ttl = ttl;
        self
    }

    /// 生成发现帧字节（供平台层广播）。
    pub fn encode_discovery_frame(&self) -> Vec<u8> {
        let frame = MdnsDiscoveryFrame {
            group_id: self.group_id.clone(),
            peer_id: self.device_id.as_str().to_string(),
            capabilities: self.capabilities,
        };
        frame.encode()
    }

    /// 处理收到的发现帧（平台层收到 mDNS 广播后调用）。
    ///
    /// 返回 Some(DiscoveredPeer) 表示新发现或更新了 peer。
    pub fn handle_discovery_frame(
        &self,
        data: &[u8],
        endpoint: Endpoint,
    ) -> Option<DiscoveredPeer> {
        let frame = MdnsDiscoveryFrame::decode(data).ok()?;
        // 过滤不同组的 peer
        if frame.group_id != self.group_id {
            debug!(
                group_id = %frame.group_id,
                "忽略不同组的发现帧"
            );
            return None;
        }
        let peer_id = PeerId::new(frame.peer_id);
        // 忽略自己的广播
        if peer_id == self.device_id {
            return None;
        }

        let now = SystemTime::now();
        let mut peers = self.peers.lock();
        let is_new = !peers.contains_key(&peer_id);
        let entry = DiscoveredPeer {
            peer_id: peer_id.clone(),
            group_id: frame.group_id.clone(),
            endpoint: endpoint.clone(),
            capabilities: frame.capabilities,
            discovered_at: peers
                .get(&peer_id)
                .map(|p| p.discovered_at)
                .unwrap_or(now),
            last_seen: now,
        };
        peers.insert(peer_id.clone(), entry.clone());

        if is_new {
            info!(
                peer_id = %peer_id,
                endpoint = %endpoint,
                "发现新 peer"
            );
        } else {
            debug!(
                peer_id = %peer_id,
                endpoint = %endpoint,
                "更新 peer 发现信息"
            );
        }

        Some(entry)
    }

    /// 标记 peer 离线（平台层收到 mDNS remove 回调时调用）。
    pub fn handle_peer_lost(&self, peer_id: &PeerId) {
        let mut peers = self.peers.lock();
        if peers.remove(peer_id).is_some() {
            info!(peer_id = %peer_id, "peer 离线");
        }
    }

    /// 清理过期的 peer（定期调用）。
    pub fn gc(&self) -> Vec<PeerId> {
        let now = SystemTime::now();
        let mut expired = Vec::new();
        let mut peers = self.peers.lock();
        peers.retain(|peer_id, peer| {
            let age = now.duration_since(peer.last_seen).unwrap_or_default();
            if age > self.peer_ttl {
                warn!(peer_id = %peer_id, "peer 发现信息过期");
                expired.push(peer_id.clone());
                false
            } else {
                true
            }
        });
        expired
    }

    /// 获取所有已发现的 peer。
    pub fn list_peers(&self) -> Vec<DiscoveredPeer> {
        self.peers.lock().values().cloned().collect()
    }

    /// 获取指定 peer。
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<DiscoveredPeer> {
        self.peers.lock().get(peer_id).cloned()
    }

    /// 已发现 peer 数量。
    pub fn peer_count(&self) -> usize {
        self.peers.lock().len()
    }

    /// group_id。
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    /// 本设备 ID。
    pub fn device_id(&self) -> &PeerId {
        &self.device_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_discovery() -> MdnsDiscovery {
        MdnsDiscovery::new(
            "group1".into(),
            PeerId::new("device1"),
            AnchorCapabilities {
                can_anchor: true,
                can_relay: false,
                persistent: false,
            },
        )
    }

    #[test]
    fn ignores_own_broadcast() {
        let discovery = make_discovery();
        let frame = discovery.encode_discovery_frame();
        let result =
            discovery.handle_discovery_frame(&frame, Endpoint::new("127.0.0.1", 8080));
        assert!(result.is_none());
    }

    #[test]
    fn handles_external_discovery_frame() {
        let discovery = make_discovery();
        let external_frame = MdnsDiscoveryFrame {
            group_id: "group1".into(),
            peer_id: "device2".into(),
            capabilities: AnchorCapabilities {
                can_anchor: false,
                can_relay: true,
                persistent: false,
            },
        };
        let data = external_frame.encode();

        let peer = discovery
            .handle_discovery_frame(&data, Endpoint::new("192.168.1.100", 8080))
            .expect("应解析成功");
        assert_eq!(peer.peer_id, PeerId::new("device2"));
        assert_eq!(peer.endpoint.host, "192.168.1.100");
        assert!(peer.capabilities.can_relay);
    }

    #[test]
    fn ignores_different_group() {
        let discovery = make_discovery();
        let external_frame = MdnsDiscoveryFrame {
            group_id: "other_group".into(),
            peer_id: "device2".into(),
            capabilities: AnchorCapabilities::default(),
        };
        let data = external_frame.encode();

        let result =
            discovery.handle_discovery_frame(&data, Endpoint::new("127.0.0.1", 8080));
        assert!(result.is_none());
    }

    #[test]
    fn gc_removes_expired_peers() {
        let discovery = MdnsDiscovery::new(
            "group1".into(),
            PeerId::new("device1"),
            AnchorCapabilities::default(),
        )
        .with_ttl(Duration::from_millis(1));

        let external_frame = MdnsDiscoveryFrame {
            group_id: "group1".into(),
            peer_id: "device2".into(),
            capabilities: AnchorCapabilities::default(),
        };
        let data = external_frame.encode();
        discovery
            .handle_discovery_frame(&data, Endpoint::new("127.0.0.1", 8080))
            .unwrap();
        assert_eq!(discovery.peer_count(), 1);

        std::thread::sleep(Duration::from_millis(10));
        let expired = discovery.gc();
        assert_eq!(expired.len(), 1);
        assert_eq!(discovery.peer_count(), 0);
    }

    #[test]
    fn handle_peer_lost_removes_entry() {
        let discovery = make_discovery();
        let external_frame = MdnsDiscoveryFrame {
            group_id: "group1".into(),
            peer_id: "device2".into(),
            capabilities: AnchorCapabilities::default(),
        };
        let data = external_frame.encode();
        discovery
            .handle_discovery_frame(&data, Endpoint::new("127.0.0.1", 8080))
            .unwrap();
        assert_eq!(discovery.peer_count(), 1);

        discovery.handle_peer_lost(&PeerId::new("device2"));
        assert_eq!(discovery.peer_count(), 0);
    }
}
