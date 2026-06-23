//! TLS 配置：自签名证书与 rustls 配置。
//!
//! Phase 0/1 使用自签名证书。生产环境由 tacit-crypto 提供身份与握手。

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tacit_core::{CoreError, CoreResult};

/// 生成自签名证书。
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
