//! TLS 配置：基于设备身份的证书与 rustls 配置。
//!
//! 使用 rcgen 生成证书，CN 设为设备 PeerId，实现设备身份绑定。
//! 集成层通过 `generate_cert_with_peer_id` 生成与设备身份绑定的证书。

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tacit_core::{CoreError, CoreResult, PeerId};

/// 构建 Quinn TransportConfig，应用 idle_timeout 与 keep_alive_interval。
///
/// - `idle_timeout_secs`：连接空闲超时（秒），超过此时间无活动则断开
/// - `keep_alive_interval_secs`：keep-alive 探测间隔（秒），定期发送 PING 帧保活
///
/// 返回 `Arc<TransportConfig>`，可直接传给 `ServerConfig::transport_config`
/// 或 `ClientConfig::transport_config`。
pub fn make_transport_config(
    idle_timeout_secs: u64,
    keep_alive_interval_secs: u64,
) -> CoreResult<Arc<quinn::TransportConfig>> {
    let mut transport_config = quinn::TransportConfig::default();
    // idle_timeout 以毫秒为单位，需将秒换算并防止溢出
    let idle_ms = idle_timeout_secs
        .checked_mul(1000)
        .ok_or_else(|| CoreError::Config("idle_timeout_secs 换算毫秒溢出".into()))?;
    // IdleTimeout 由 VarInt 构造，u64 需先转 VarInt
    let idle_varint = quinn::VarInt::try_from(idle_ms)
        .map_err(|e| CoreError::Config(format!("idle_timeout VarInt 转换失败: {e}")))?;
    let idle_timeout = quinn::IdleTimeout::from(idle_varint);
    transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config.keep_alive_interval(Some(Duration::from_secs(keep_alive_interval_secs)));
    Ok(Arc::new(transport_config))
}

/// 生成自签名证书（通用，CN 为 "tacit"）。
///
/// 返回 (cert_der, key_der)。
pub fn generate_self_signed_cert() -> CoreResult<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["tacit".into()])
            .map_err(|e| CoreError::Crypto(format!("生成证书失败: {e}")))?;
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| CoreError::Crypto(format!("私钥转换失败: {e}")))?;
    Ok((cert_der, key_der))
}

/// 基于设备 PeerId 生成自签名证书。
///
/// 证书 CN（SAN）设为 PeerId，使对端可通过 SNI 校验设备身份。
/// 返回 (cert_der, key_der)。
pub fn generate_cert_with_peer_id(
    peer_id: &PeerId,
) -> CoreResult<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let params = rcgen::CertificateParams::new(vec![peer_id.as_str().to_string()])
        .map_err(|e| CoreError::Crypto(format!("证书参数创建失败: {e}")))?;
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| CoreError::Crypto(format!("密钥对生成失败: {e}")))?;
    let certified = params
        .self_signed(&key_pair)
        .map_err(|e| CoreError::Crypto(format!("证书签名失败: {e}")))?;
    let cert_der = certified.der().clone();
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| CoreError::Crypto(format!("私钥转换失败: {e}")))?;
    Ok((cert_der, key_der))
}

/// 创建 server 配置。
pub fn make_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> CoreResult<quinn::ServerConfig> {
    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| CoreError::Crypto(format!("rustls server 配置失败: {e}")))?;
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|e| CoreError::Crypto(format!("quinn server 配置失败: {e}")))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_config)))
}

/// 创建 client 配置（信任给定证书）。
pub fn make_client_config(cert: CertificateDer<'static>) -> CoreResult<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert)
        .map_err(|e| CoreError::Crypto(format!("添加根证书失败: {e}")))?;
    quinn::ClientConfig::with_root_certificates(Arc::new(roots))
        .map_err(|e| CoreError::Crypto(format!("quinn client 配置失败: {e}")))
}

/// 将 PeerId 转为 ServerName（用于 QUIC 连接时 SNI 校验）。
///
/// 连接时传入此 ServerName，rustls 会校验对端证书 CN 与之匹配。
pub fn peer_id_to_server_name(peer_id: &PeerId) -> CoreResult<ServerName<'static>> {
    ServerName::try_from(peer_id.as_str().to_string())
        .map_err(|e| CoreError::Crypto(format!("ServerName 解析失败: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_self_signed_cert_works() {
        let (cert, key) = generate_self_signed_cert().unwrap();
        assert!(!cert.as_ref().is_empty());
        assert!(!key.secret_der().is_empty());
    }

    #[test]
    fn generate_cert_with_peer_id_works() {
        let peer_id = PeerId::new("abc123def456");
        let (cert, key) = generate_cert_with_peer_id(&peer_id).unwrap();
        assert!(!cert.as_ref().is_empty());
        assert!(!key.secret_der().is_empty());
    }

    #[test]
    fn peer_id_to_server_name_works() {
        let peer_id = PeerId::new("abc123def456");
        let name = peer_id_to_server_name(&peer_id).unwrap();
        // ServerName::DnsName 变体包含原始字符串
        match &name {
            rustls::pki_types::ServerName::DnsName(dns) => {
                assert_eq!(dns.as_ref(), "abc123def456");
            }
            _ => panic!("预期 DnsName 变体"),
        }
    }
}
