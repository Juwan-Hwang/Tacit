//! BLE Presence 管理器。
//!
//! 包装 [`PresenceBackend`]，提供序列化的 presence 广播与发现事件拉取。
//! 使用 tacit-core 的 [`DiscoveryFrame`] 作为基础格式（19 字节），
//! 并在尾部追加可选的 endpoint 扩展（最多 7 字节），总长度 ≤ 26 字节，
//! 适配 BLE 广播 payload 31 字节限制。

use std::net::Ipv4Addr;
use std::sync::Arc;

use tacit_core::frame::{DiscoveryFrame, FrameError};
use tacit_core::{CoreResult, Endpoint, PresenceHint};

use crate::backend::{DiscoveryEvent, PresenceBackend};

/// BLE Presence 管理器。
pub struct BlePresence {
    backend: Arc<dyn PresenceBackend>,
}

impl BlePresence {
    /// 创建 presence 管理器。
    pub fn new(backend: Arc<dyn PresenceBackend>) -> Self {
        Self { backend }
    }

    /// 广播 presence hint。
    ///
    /// 使用 tacit-core 的 DiscoveryFrame（19 字节）作为基础，
    /// 尾部追加可选 endpoint 扩展（1 字节 flags + 2 字节 port + 4 字节 ipv4）。
    pub fn broadcast(&self, hint: &PresenceHint) -> CoreResult<()> {
        let payload = encode_presence_payload(hint)?;
        self.backend.start_broadcast(payload)
    }

    /// 停止广播。
    pub fn stop_broadcast(&self) {
        self.backend.stop_broadcast();
    }

    /// 开始扫描附近 peer。
    pub fn start_scan(&self) -> CoreResult<()> {
        self.backend.start_scan()
    }

    /// 停止扫描。
    pub fn stop_scan(&self) {
        self.backend.stop_scan();
    }

    /// 拉取发现的 peer 事件。
    pub fn drain_discoveries(&self) -> Vec<DiscoveryEvent> {
        self.backend.drain_discoveries()
    }
}

/// Endpoint 扩展 flags 偏移（紧跟 DiscoveryFrame 19 字节之后）。
const EXT_FLAGS_OFFSET: usize = 19;
/// Endpoint 扩展：has_endpoint 位。
const EXT_FLAG_HAS_ENDPOINT: u8 = 0b0000_0001;
/// Endpoint 扩展：is_ipv4 位。
const EXT_FLAG_IS_IPV4: u8 = 0b0000_0010;

/// 将 PresenceHint 编码为 DiscoveryFrame + 可选 endpoint 扩展（≤ 26 字节）。
///
/// 格式：
/// - [0..19] DiscoveryFrame：`magic(2)|version(1)|group_id(4)|device_id(8)|capability_bits(2)|checksum(2)`
/// - [19]    ext_flags: bit0=has_endpoint, bit1=is_ipv4
/// - [20..22] port: 大端 u16（仅 has_endpoint 时）
/// - [22..26] ipv4: 4 字节（仅 has_endpoint 且 is_ipv4 时）
pub fn encode_presence_payload(hint: &PresenceHint) -> CoreResult<Vec<u8>> {
    let frame = DiscoveryFrame::from_presence(
        &hint.group_id,
        &hint.device_id,
        hint.capabilities,
    );
    let mut buf = frame.encode();

    // endpoint 扩展
    let mut ext_flags: u8 = 0;
    if hint.endpoint.is_some() {
        ext_flags |= EXT_FLAG_HAS_ENDPOINT;
    }
    let mut is_ipv4 = false;
    if let Some(ep) = &hint.endpoint {
        if ep.host.parse::<Ipv4Addr>().is_ok() {
            ext_flags |= EXT_FLAG_IS_IPV4;
            is_ipv4 = true;
        }
    }
    buf.push(ext_flags);

    if let Some(ep) = &hint.endpoint {
        buf.extend_from_slice(&ep.port.to_be_bytes());
        if is_ipv4 {
            let ipv4: Ipv4Addr = ep.host.parse().unwrap();
            buf.extend_from_slice(&ipv4.octets());
        }
    }

    debug_assert!(
        buf.len() <= 31,
        "BLE payload 超过 31 字节限制: {} bytes",
        buf.len()
    );
    Ok(buf)
}

/// 从 DiscoveryFrame + endpoint 扩展解码 PresenceHint。
///
/// `peer_id` 由 BLE 扫描结果（MAC 地址或设备名）提供，
/// 用于校验或补充 device_id（payload 中的 device_id 优先）。
pub fn decode_presence_payload(
    payload: &[u8],
    _peer_id: &tacit_core::PeerId,
) -> CoreResult<PresenceHint> {
    if payload.len() < EXT_FLAGS_OFFSET + 1 {
        return Err(tacit_core::CoreError::Deserialize(format!(
            "BLE payload 过短: {} bytes (最少 {})",
            payload.len(),
            EXT_FLAGS_OFFSET + 1
        )));
    }

    let frame = DiscoveryFrame::decode(payload).map_err(|e: FrameError| {
        taci_core_frame_error_to_core(&e)
    })?;

    // 还原 group_id / device_id（hash 的 hex，用于匹配，不可逆推原始值）
    let group_id = hex::encode(&frame.group_id);
    let device_id = hex::encode(&frame.device_id);

    // 解析 endpoint 扩展
    let ext_flags = payload[EXT_FLAGS_OFFSET];
    let has_endpoint = ext_flags & EXT_FLAG_HAS_ENDPOINT != 0;
    let is_ipv4 = ext_flags & EXT_FLAG_IS_IPV4 != 0;

    let endpoint = if has_endpoint {
        if payload.len() < EXT_FLAGS_OFFSET + 3 {
            return Err(tacit_core::CoreError::Deserialize(
                "BLE endpoint 扩展缺少 port".into(),
            ));
        }
        let port = u16::from_be_bytes([
            payload[EXT_FLAGS_OFFSET + 1],
            payload[EXT_FLAGS_OFFSET + 2],
        ]);
        if is_ipv4 {
            if payload.len() < EXT_FLAGS_OFFSET + 7 {
                return Err(tacit_core::CoreError::Deserialize(
                    "BLE endpoint 扩展缺少 ipv4".into(),
                ));
            }
            let ipv4 = Ipv4Addr::new(
                payload[EXT_FLAGS_OFFSET + 3],
                payload[EXT_FLAGS_OFFSET + 4],
                payload[EXT_FLAGS_OFFSET + 5],
                payload[EXT_FLAGS_OFFSET + 6],
            );
            Some(Endpoint::new(ipv4.to_string(), port))
        } else {
            // 非 IPv4（hostname/IPv6），endpoint 通过 mDNS 获取
            None
        }
    } else {
        None
    };

    Ok(PresenceHint {
        group_id,
        device_id,
        capabilities: frame.capabilities(),
        endpoint,
    })
}

/// 将 FrameError 转为 CoreError。
fn taci_core_frame_error_to_core(e: &FrameError) -> tacit_core::CoreError {
    use tacit_core::CoreError;
    match e {
        FrameError::TooShort => CoreError::Deserialize("DiscoveryFrame 数据过短".into()),
        FrameError::BadMagic => CoreError::Deserialize("DiscoveryFrame magic 不匹配".into()),
        FrameError::ChecksumMismatch => {
            CoreError::Deserialize("DiscoveryFrame checksum 不匹配".into())
        }
        FrameError::UnknownControlType(v) => {
            CoreError::Deserialize(format!("未知控制类型: {v}"))
        }
        FrameError::UnknownDataFrameKind(v) => {
            CoreError::Deserialize(format!("未知数据帧类型: {v}"))
        }
        FrameError::VersionMismatch(v) => {
            CoreError::Deserialize(format!("版本不兼容: {v}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockPresenceBackend;
    use tacit_core::{AnchorCapabilities, Endpoint, PeerId};

    fn hint() -> PresenceHint {
        PresenceHint {
            group_id: "g1".into(),
            device_id: "device-abc".into(),
            capabilities: AnchorCapabilities {
                can_anchor: true,
                can_relay: false,
                persistent: false,
            },
            endpoint: Some(Endpoint::new("127.0.0.1", 8080)),
        }
    }

    #[test]
    fn broadcast_encodes_discovery_frame() {
        let backend = Arc::new(MockPresenceBackend::new());
        let presence = BlePresence::new(backend.clone());
        presence.broadcast(&hint()).unwrap();
        assert!(backend.is_broadcasting());
        let payload = backend.current_payload().unwrap();
        // DiscoveryFrame(19) + ext_flags(1) + port(2) + ipv4(4) = 26 字节
        assert_eq!(payload.len(), 26);
        // 前 2 字节是 magic
        assert_eq!(&payload[0..2], &[0x54, 0x43]);
        // version
        assert_eq!(payload[2], 1);
        // ext_flags: has_endpoint | is_ipv4 = 0b11
        assert_eq!(payload[19], 0b0000_0011);
    }

    #[test]
    fn broadcast_without_endpoint() {
        let backend = Arc::new(MockPresenceBackend::new());
        let presence = BlePresence::new(backend.clone());
        let h = PresenceHint {
            group_id: "g1".into(),
            device_id: "device-xyz".into(),
            capabilities: AnchorCapabilities {
                can_anchor: true,
                can_relay: true,
                persistent: true,
            },
            endpoint: None,
        };
        presence.broadcast(&h).unwrap();
        let payload = backend.current_payload().unwrap();
        // DiscoveryFrame(19) + ext_flags(1) = 20 字节
        assert_eq!(payload.len(), 20);
        // ext_flags: 无 endpoint = 0
        assert_eq!(payload[19], 0b0000_0000);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = hint();
        let payload = encode_presence_payload(&original).unwrap();
        assert!(payload.len() <= 31);
        let decoded = decode_presence_payload(&payload, &PeerId::new("p1")).unwrap();
        // group_id/device_id 是 hash 的 hex，无法还原原始字符串，
        // 但 capabilities 和 endpoint 应能完整还原
        assert_eq!(decoded.capabilities, original.capabilities);
        assert_eq!(decoded.endpoint, original.endpoint);
    }

    #[test]
    fn encode_decode_roundtrip_no_endpoint() {
        let original = PresenceHint {
            group_id: "group-2".into(),
            device_id: "dev-2".into(),
            capabilities: AnchorCapabilities {
                can_anchor: false,
                can_relay: true,
                persistent: false,
            },
            endpoint: None,
        };
        let payload = encode_presence_payload(&original).unwrap();
        assert!(payload.len() <= 31);
        let decoded = decode_presence_payload(&payload, &PeerId::new("p2")).unwrap();
        assert_eq!(decoded.capabilities, original.capabilities);
        assert_eq!(decoded.endpoint, None);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut payload = encode_presence_payload(&hint()).unwrap();
        payload[0] = 0x00; // 破坏 magic
        let result = decode_presence_payload(&payload, &PeerId::new("p1"));
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_too_short() {
        let payload = vec![0x54, 0x43]; // 只有 magic
        let result = decode_presence_payload(&payload, &PeerId::new("p1"));
        assert!(result.is_err());
    }

    #[test]
    fn scan_and_drain() {
        let backend = Arc::new(MockPresenceBackend::new());
        let presence = BlePresence::new(backend.clone());
        presence.start_scan().unwrap();
        backend.inject_discovery(DiscoveryEvent {
            peer_id: PeerId::new("p1"),
            hint: hint(),
            rssi: -50,
        });
        let events = presence.drain_discoveries();
        assert_eq!(events.len(), 1);
        presence.stop_scan();
        assert!(!backend.is_scanning());
    }
}
