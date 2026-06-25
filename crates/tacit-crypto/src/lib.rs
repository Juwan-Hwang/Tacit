//! Tacit-crypto：设备身份与加密。
//!
//! 职责：
//! - 设备公钥身份（Ed25519）。
//! - 签名与验签。
//! - Noise 握手（基于 snow，Noise_XX 模式）。
//! - session key 管理。
//!
//! v1.0 安全模型：设备公钥即身份，群组内预信任所有已配对设备公钥。

pub mod identity;
pub mod noise;
pub mod pairing;
pub mod session;
pub mod signature;

pub use identity::{DeviceIdentity, PeerPubkey};
pub use noise::{NoiseHandshake, NoiseRole, HandshakeResult};
pub use pairing::{
    compute_binding_digest, derive_sas_code, generate_binding_salt, verify_binding, PairingPayload,
};
pub use session::Session;
pub use signature::{sign, verify};
