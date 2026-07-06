//! 协议帧二进制编解码。
//!
//! v1.0 规范第 13 节定义三种帧格式：
//! - Discovery Frame：发现层广播
//! - Control Frame：控制消息（TLV payload）
//! - Data Frame：数据传输（含批次签名）
//!
//! 所有帧以 magic(2) 开头，标识为 Tacit 协议帧。

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::ids::{DocId, PeerId, SessionId};
use crate::model::{AnchorCapabilities, DataFrame, DataFrameKind};

/// 协议 magic number: "TC"。
pub const MAGIC: [u8; 2] = [0x54, 0x43];

/// 当前协议主版本。
pub const PROTOCOL_VERSION: u8 = 1;

// ===== Discovery Frame =====

/// Discovery Frame（规范 13.1）。
///
/// ```text
/// magic(2) | version(1) | group_id(4) | device_id(8) | capability_bits(2) | checksum(2)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryFrame {
    pub version: u8,
    /// group_id 的 4 字节标识。
    pub group_id: [u8; 4],
    /// device_id 的 8 字节标识。
    pub device_id: [u8; 8],
    /// 能力位（can_anchor | can_relay | persistent 各 1 bit）。
    pub capability_bits: [u8; 2],
    /// 校验和（group_id + device_id + capability_bits 的 CRC16）。
    pub checksum: u16,
}

impl DiscoveryFrame {
    /// 从 PresenceHint 构造 DiscoveryFrame。
    pub fn from_presence(group_id: &str, device_id: &str, caps: AnchorCapabilities) -> Self {
        let group_bytes = group_id_to_bytes(group_id);
        let device_bytes = device_id_to_bytes(device_id);
        let cap_bits = caps_to_bits(caps);
        let checksum = crc16(&group_bytes, &device_bytes, &cap_bits);
        Self {
            version: PROTOCOL_VERSION,
            group_id: group_bytes,
            device_id: device_bytes,
            capability_bits: cap_bits,
            checksum,
        }
    }

    /// 编码为字节流。
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(19);
        buf.extend_from_slice(&MAGIC);
        buf.push(self.version);
        buf.extend_from_slice(&self.group_id);
        buf.extend_from_slice(&self.device_id);
        buf.extend_from_slice(&self.capability_bits);
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf
    }

    /// 从字节流解码。
    pub fn decode(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < 19 {
            return Err(FrameError::TooShort);
        }
        if data[0..2] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let version = data[2];
        let group_id: [u8; 4] = data[3..7].try_into().unwrap();
        let device_id: [u8; 8] = data[7..15].try_into().unwrap();
        let capability_bits: [u8; 2] = data[15..17].try_into().unwrap();
        let checksum = u16::from_be_bytes([data[17], data[18]]);

        // 校验 checksum
        let expected = crc16(&group_id, &device_id, &capability_bits);
        if expected != checksum {
            return Err(FrameError::ChecksumMismatch);
        }
        Ok(Self {
            version,
            group_id,
            device_id,
            capability_bits,
            checksum,
        })
    }

    /// 解析能力位。
    pub fn capabilities(&self) -> AnchorCapabilities {
        bits_to_caps(&self.capability_bits)
    }
}

// ===== Control Frame =====

/// Control Frame 控制类型（规范 13.2 TLV 类型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControlType {
    Capabilities = 1,
    KnownCheckpoint = 2,
    AckSummary = 3,
    NeedRanges = 4,
    TransportHints = 5,
    RelayHints = 6,
    Introduce = 7,
    Revoke = 8,
    KeyRotate = 9,
    SyncIntent = 10,
}

impl ControlType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Capabilities),
            2 => Some(Self::KnownCheckpoint),
            3 => Some(Self::AckSummary),
            4 => Some(Self::NeedRanges),
            5 => Some(Self::TransportHints),
            6 => Some(Self::RelayHints),
            7 => Some(Self::Introduce),
            8 => Some(Self::Revoke),
            9 => Some(Self::KeyRotate),
            10 => Some(Self::SyncIntent),
            _ => None,
        }
    }
}

/// Control Frame（规范 13.2）。
///
/// ```text
/// magic(2) | version(1) | ctrl_type(1) | session_id(8) | payload_len(2) | payload(n)
/// ```
///
/// #3: mac 字段已移除。传输层完整性由 QUIC TLS 1.3 保证，
/// 应用层 E2E 加密由 Noise Session AEAD 保证，per-frame mac 冗余。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    pub version: u8,
    pub ctrl_type: ControlType,
    pub session_id: u64,
    /// TLV 编码的 payload。
    pub payload: Vec<u8>,
}

impl ControlFrame {
    /// 创建 ControlFrame。
    pub fn new(ctrl_type: ControlType, session_id: u64, payload: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ctrl_type,
            session_id,
            payload,
        }
    }

    /// 编码为字节流。
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(14 + self.payload.len());
        buf.extend_from_slice(&MAGIC);
        buf.push(self.version);
        buf.push(self.ctrl_type as u8);
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// 从字节流解码。
    pub fn decode(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < 14 {
            return Err(FrameError::TooShort);
        }
        if data[0..2] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let version = data[2];
        let ctrl_type =
            ControlType::from_u8(data[3]).ok_or(FrameError::UnknownControlType(data[3]))?;
        let session_id = u64::from_be_bytes(data[4..12].try_into().unwrap());
        let payload_len = u16::from_be_bytes([data[12], data[13]]) as usize;
        if data.len() < 14 + payload_len {
            return Err(FrameError::TooShort);
        }
        let payload = data[14..14 + payload_len].to_vec();
        Ok(Self {
            version,
            ctrl_type,
            session_id,
            payload,
        })
    }
}

// ===== Data Frame =====

/// 批次标志（规范 13.4，flags 低 2 bits）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BatchFlag {
    /// 单帧（非批次）。
    Single = 0b00,
    /// 批次开始。
    BatchStart = 0b01,
    /// 批次中间。
    BatchMiddle = 0b10,
    /// 批次结束。
    BatchEnd = 0b11,
}

impl BatchFlag {
    pub fn from_flags(flags: u8) -> Self {
        match flags & 0b11 {
            0b00 => Self::Single,
            0b01 => Self::BatchStart,
            0b10 => Self::BatchMiddle,
            0b11 => Self::BatchEnd,
            _ => unreachable!(),
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Data Frame（规范 13.3）。
///
/// ```text
/// magic(2) | version(1) | flags(1) | doc_id(8) | actor_id(8) | seq(4) | kind(1)
/// | payload_len(4) | payload(n) | ref(8) | sig(batch)
/// ```
///
/// #3: mac 字段已移除。传输层完整性由 QUIC TLS 1.3 保证，
/// 应用层 E2E 加密由 Noise Session AEAD 保证，per-frame mac 冗余。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrameWire {
    pub version: u8,
    /// flags：低 2 位为 BatchFlag，高 6 位保留。
    pub flags: u8,
    /// doc_id 的 8 字节标识。
    pub doc_id: [u8; 8],
    /// actor_id（发送方 peer）的 8 字节标识。
    pub actor_id: [u8; 8],
    /// 序号。
    pub seq: u32,
    /// 帧类型。
    pub kind: DataFrameKind,
    /// 负载。
    pub payload: Bytes,
    /// 引用（如关联的 checkpoint_id 或前置帧 hash）。
    pub ref_id: [u8; 8],
    /// 批次完整性标签（可变长度，由 sig_len 字段指示）。
    pub sig: Vec<u8>,
}

impl DataFrameWire {
    /// 创建 DataFrameWire（sig 初始为空，由批次完整性标签填充）。
    pub fn new(
        doc_id: &DocId,
        actor_id: &PeerId,
        seq: u32,
        kind: DataFrameKind,
        payload: Bytes,
        batch_flag: BatchFlag,
        ref_id: [u8; 8],
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags: batch_flag.as_u8(),
            doc_id: doc_id_to_bytes(doc_id),
            actor_id: peer_id_to_bytes(actor_id),
            seq,
            kind,
            payload,
            ref_id,
            sig: Vec::new(),
        }
    }

    /// 获取批次标志。
    pub fn batch_flag(&self) -> BatchFlag {
        BatchFlag::from_flags(self.flags)
    }

    /// 转换为领域模型 DataFrame。
    ///
    /// 将二进制 doc_id/actor_id 转为 hex 字符串作为 DocId/PeerId。
    /// 注意：这是单向转换（原始 ID 经 SHA256 哈希后不可逆），
    /// sync 层需通过 hex 字符串匹配已知的 doc/peer。
    pub fn to_data_frame(&self) -> DataFrame {
        DataFrame {
            doc_id: DocId::new(hex::encode(self.doc_id)),
            actor_id: PeerId::new(hex::encode(self.actor_id)),
            seq: self.seq,
            kind: self.kind,
            payload: self.payload.clone(),
            session_id: SessionId::new(0),
        }
    }

    /// 编码为字节流。
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let sig_len = self.sig.len() as u16;
        let mut buf = Vec::with_capacity(
            2 + 1 + 1 + 8 + 8 + 4 + 1 + 4 + self.payload.len() + 8 + 2 + self.sig.len(),
        );
        buf.extend_from_slice(&MAGIC);
        buf.push(self.version);
        buf.push(self.flags);
        buf.extend_from_slice(&self.doc_id);
        buf.extend_from_slice(&self.actor_id);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.push(data_frame_kind_to_u8(self.kind));
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&self.ref_id);
        buf.extend_from_slice(&sig_len.to_be_bytes());
        buf.extend_from_slice(&self.sig);
        buf
    }

    /// 从字节流解码。
    pub fn decode(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < 29 {
            return Err(FrameError::TooShort);
        }
        if data[0..2] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let version = data[2];
        let flags = data[3];
        let doc_id: [u8; 8] = data[4..12].try_into().unwrap();
        let actor_id: [u8; 8] = data[12..20].try_into().unwrap();
        let seq = u32::from_be_bytes(data[20..24].try_into().unwrap());
        let kind = u8_to_data_frame_kind(data[24])?;
        let payload_len = u32::from_be_bytes(data[25..29].try_into().unwrap()) as usize;
        let required_len = 29usize
            .checked_add(payload_len)
            .and_then(|len| len.checked_add(8))
            .and_then(|len| len.checked_add(2));
        if required_len.is_none_or(|total| data.len() < total) {
            return Err(FrameError::TooShort);
        }
        let payload = Bytes::copy_from_slice(&data[29..29 + payload_len]);
        let ref_id: [u8; 8] = data[29 + payload_len..29 + payload_len + 8]
            .try_into()
            .unwrap();
        let sig_len =
            u16::from_be_bytes([data[29 + payload_len + 8], data[29 + payload_len + 9]]) as usize;
        let sig_start = 29 + payload_len + 10;
        if sig_start
            .checked_add(sig_len)
            .is_none_or(|total| data.len() < total)
        {
            return Err(FrameError::TooShort);
        }
        let sig = data[sig_start..sig_start + sig_len].to_vec();
        Ok(Self {
            version,
            flags,
            doc_id,
            actor_id,
            seq,
            kind,
            payload,
            ref_id,
            sig,
        })
    }
}

// ===== TLV 编解码 =====

/// TLV（Type-Length-Value）编解码。
///
/// 规范 13.2：Control Frame payload 使用 TLV。
/// 格式：Type(1) | Length(2) | Value(n)
pub struct Tlv;

impl Tlv {
    /// 编码单个 TLV。
    pub fn encode(tlv_type: u8, value: &[u8]) -> Vec<u8> {
        let len = value.len() as u16;
        let mut buf = Vec::with_capacity(3 + value.len());
        buf.push(tlv_type);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(value);
        buf
    }

    /// 解码所有 TLV 条目。
    pub fn decode_all(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, FrameError> {
        let mut result = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if pos + 3 > data.len() {
                return Err(FrameError::TooShort);
            }
            let tlv_type = data[pos];
            let len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
            pos += 3;
            if pos + len > data.len() {
                return Err(FrameError::TooShort);
            }
            let value = data[pos..pos + len].to_vec();
            result.push((tlv_type, value));
            pos += len;
        }
        Ok(result)
    }

    /// 编码多个 TLV 条目为连续字节流。
    pub fn encode_all(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (t, v) in entries {
            buf.extend_from_slice(&Self::encode(*t, v));
        }
        buf
    }
}

// ===== 帧错误 =====

/// 帧编解码错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("数据过短")]
    TooShort,
    #[error("magic 不匹配")]
    BadMagic,
    #[error("checksum 不匹配")]
    ChecksumMismatch,
    #[error("未知控制类型: {0}")]
    UnknownControlType(u8),
    #[error("未知数据帧类型: {0}")]
    UnknownDataFrameKind(u8),
    #[error("版本不兼容: {0}")]
    VersionMismatch(u8),
    #[error("帧过大: {0} 字节，超过最大限制")]
    FrameTooLarge(usize),
}

// ===== 辅助函数 =====

/// group_id 字符串转 4 字节（取前 4 字节 hash）。
fn group_id_to_bytes(group_id: &str) -> [u8; 4] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(group_id.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&result[0..4]);
    out
}

/// device_id 字符串转 8 字节。
fn device_id_to_bytes(device_id: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&result[0..8]);
    out
}

/// doc_id 转 8 字节。
fn doc_id_to_bytes(doc_id: &DocId) -> [u8; 8] {
    device_id_to_bytes(doc_id.as_str())
}

/// peer_id 转 8 字节。
fn peer_id_to_bytes(peer_id: &PeerId) -> [u8; 8] {
    device_id_to_bytes(peer_id.as_str())
}

/// 能力位转 2 字节。
fn caps_to_bits(caps: AnchorCapabilities) -> [u8; 2] {
    let mut bits: u16 = 0;
    if caps.can_anchor {
        bits |= 1 << 0;
    }
    if caps.can_relay {
        bits |= 1 << 1;
    }
    if caps.persistent {
        bits |= 1 << 2;
    }
    bits.to_be_bytes()
}

/// 2 字节解析能力位。
fn bits_to_caps(bits: &[u8; 2]) -> AnchorCapabilities {
    let val = u16::from_be_bytes(*bits);
    AnchorCapabilities {
        can_anchor: val & (1 << 0) != 0,
        can_relay: val & (1 << 1) != 0,
        persistent: val & (1 << 2) != 0,
    }
}

/// CRC16-CCITT 校验和。
fn crc16(group: &[u8; 4], device: &[u8; 8], caps: &[u8; 2]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for byte in group.iter().chain(device.iter()).chain(caps.iter()) {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// DataFrameKind 转 u8。
fn data_frame_kind_to_u8(kind: DataFrameKind) -> u8 {
    match kind {
        DataFrameKind::Delta => 0,
        DataFrameKind::SnapshotChunk => 1,
        DataFrameKind::BatchMiddle => 2,
    }
}

/// u8 转 DataFrameKind。
///
/// 未知值返回错误而非静默降级为 Delta，避免错误数据被误处理。
fn u8_to_data_frame_kind(v: u8) -> Result<DataFrameKind, FrameError> {
    match v {
        0 => Ok(DataFrameKind::Delta),
        1 => Ok(DataFrameKind::SnapshotChunk),
        2 => Ok(DataFrameKind::BatchMiddle),
        other => Err(FrameError::UnknownDataFrameKind(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_frame_roundtrip() {
        let caps = AnchorCapabilities {
            can_anchor: true,
            can_relay: false,
            persistent: true,
        };
        let frame = DiscoveryFrame::from_presence("group1", "device1", caps);
        let encoded = frame.encode();
        let decoded = DiscoveryFrame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
        assert_eq!(decoded.capabilities(), caps);
    }

    #[test]
    fn discovery_frame_bad_magic() {
        let mut data = vec![0x00, 0x00];
        data.extend_from_slice(&[0u8; 17]);
        assert_eq!(
            DiscoveryFrame::decode(&data).unwrap_err(),
            FrameError::BadMagic
        );
    }

    #[test]
    fn discovery_frame_checksum_mismatch() {
        let caps = AnchorCapabilities::default();
        let mut frame = DiscoveryFrame::from_presence("g", "d", caps);
        frame.checksum = frame.checksum.wrapping_add(1);
        let encoded = frame.encode();
        assert_eq!(
            DiscoveryFrame::decode(&encoded).unwrap_err(),
            FrameError::ChecksumMismatch
        );
    }

    #[test]
    fn control_frame_roundtrip() {
        let payload = Tlv::encode(ControlType::AckSummary as u8, b"ack_data");
        let frame = ControlFrame::new(ControlType::AckSummary, 12345, payload);
        let encoded = frame.encode();
        let decoded = ControlFrame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn data_frame_roundtrip() {
        let doc_id = DocId::new("doc1");
        let actor_id = PeerId::new("42");
        let payload = Bytes::from_static(b"hello world");
        let frame = DataFrameWire::new(
            &doc_id,
            &actor_id,
            99,
            DataFrameKind::Delta,
            payload,
            BatchFlag::BatchStart,
            [0u8; 8],
        );
        let encoded = frame.encode();
        let decoded = DataFrameWire::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
        assert_eq!(decoded.batch_flag(), BatchFlag::BatchStart);
    }

    #[test]
    fn tlv_encode_decode() {
        let entries = vec![(1u8, b"hello".to_vec()), (2u8, b"world".to_vec())];
        let encoded = Tlv::encode_all(&entries);
        let decoded = Tlv::decode_all(&encoded).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn batch_flag_from_flags() {
        assert_eq!(BatchFlag::from_flags(0b00), BatchFlag::Single);
        assert_eq!(BatchFlag::from_flags(0b01), BatchFlag::BatchStart);
        assert_eq!(BatchFlag::from_flags(0b10), BatchFlag::BatchMiddle);
        assert_eq!(BatchFlag::from_flags(0b11), BatchFlag::BatchEnd);
        // 高位不影响
        assert_eq!(BatchFlag::from_flags(0b1100), BatchFlag::Single);
    }
}
