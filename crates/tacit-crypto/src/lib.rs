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

pub use identity::{verify_static_binding, DeviceIdentity, PeerPubkey, StaticKeypair};
pub use noise::{HandshakeResult, NoiseHandshake, NoiseRole, NonceCache};
pub use pairing::{
    compute_binding_digest, confirm_sas_code, derive_sas_code, format_sas_code,
    generate_binding_salt, validate_payload_structure, PairingPayload, PairingRole, PairingSession,
};

pub use session::Session;
pub use signature::{sign, verify};
