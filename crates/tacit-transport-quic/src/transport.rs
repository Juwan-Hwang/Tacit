//! QuicTransport：QUIC 传输实现。
//!
//! 实现 [`tacit_transport::SyncTransport`] trait。
//! 管理 endpoint、peer 连接池、health check。
//! network path 变化时主动断开并 fast-resume。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use quinn::{Connection, Endpoint};
use tacit_core::{CoreError, CoreResult, DataFrame, NetworkType, PeerId, Priority};
use tacit_transport::{ControlMsg, PathPreference, SyncTransport};
use tracing::{debug, warn};

use crate::config::{generate_self_signed_cert, make_client_config, make_server_config};

/// QuicTransport 配置。
#[derive(Debug, Clone)]
pub struct QuicTransportConfig {
    /// 监听地址。
    pub listen_addr: SocketAddr,
    /// 是否作为 server（监听）。
    pub is_server: bool,
    /// 连接超时（秒）。
    pub connect_timeout_secs: u64,
    /// 空闲超时（秒）。
    pub idle_timeout_secs: u64,
}

impl Default for QuicTransportConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            is_server: false,
            connect_timeout_secs: 5,
            idle_timeout_secs: 30,
        }
    }
}

/// QUIC 传输实现。
pub struct QuicTransport {
    endpoint: Endpoint,
    /// peer -> 连接
    connections: Arc<Mutex<HashMap<PeerId, Connection>>>,
    /// peer -> 远端地址
    peer_addrs: Arc<Mutex<HashMap<PeerId, SocketAddr>>>,
    /// 本端证书（用于让对端信任）
    cert: rustls::pki_types::CertificateDer<'static>,
    /// 可更新的 client config（trust_cert 时更新）
    client_config: Arc<parking_lot::RwLock<quinn::ClientConfig>>,
    config: QuicTransportConfig,
}

impl QuicTransport {
    /// 创建 QuicTransport。
    ///
    /// 如果 `config.is_server`，会生成自签名证书并监听。
    /// 否则仅创建 client endpoint。
    pub async fn new(config: QuicTransportConfig) -> CoreResult<Self> {
        let (endpoint, cert, client_config) = if config.is_server {
            // server 模式：生成证书，监听
            let (cert, key) = generate_self_signed_cert()?;
            let server_config = make_server_config(cert.clone(), key)?;
            let endpoint =
                Endpoint::server(server_config, config.listen_addr)
                    .map_err(|e| CoreError::Transport(format!("创建 endpoint 失败: {e}")))?;
            // server 也能主动发起连接，用自身证书作为信任根
            let client_config = make_client_config(cert.clone())?;
            (endpoint, cert, client_config)
        } else {
            // client 模式：仅创建 endpoint
            let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
                .map_err(|e| CoreError::Transport(format!("创建 endpoint 失败: {e}")))?;
            // client 模式下用自签名证书信任自己（占位，实际由 trust_cert 设置）
            let (cert, _) = generate_self_signed_cert()?;
            let client_config = make_client_config(cert.clone())?;
            (endpoint, cert, client_config)
        };

        Ok(Self {
            endpoint,
            connections: Arc::new(Mutex::new(HashMap::new())),
            peer_addrs: Arc::new(Mutex::new(HashMap::new())),
            cert,
            client_config: Arc::new(parking_lot::RwLock::new(client_config)),
            config,
        })
    }

    /// 获取本端证书（用于让对端信任）。
    pub fn cert(&self) -> &rustls::pki_types::CertificateDer<'static> {
        &self.cert
    }

    /// 信任对端证书（更新 client config）。
    ///
    /// Phase 0/1：直接替换为单一信任证书。
    pub fn trust_cert(&self, cert: rustls::pki_types::CertificateDer<'static>) -> CoreResult<()> {
        let client_config = make_client_config(cert)?;
        *self.client_config.write() = client_config;
        Ok(())
    }

    /// 获取本地监听地址。
    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| CoreError::Transport(format!("获取本地地址失败: {e}")))
    }

    /// 注册 peer 的远端地址。
    pub fn register_peer(&self, peer_id: PeerId, addr: SocketAddr) {
        self.peer_addrs.lock().insert(peer_id, addr);
    }

    /// 连接到 peer。
    pub async fn connect(&self, peer_id: &PeerId, addr: SocketAddr) -> CoreResult<()> {
        debug!(peer_id = %peer_id, addr = %addr, "连接 peer");
        let client_config = self.client_config.read().clone();
        let connect = self
            .endpoint
            .connect_with(client_config, addr, "tacit")
            .map_err(|e| CoreError::Transport(format!("发起连接失败: {e}")))?;
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.connect_timeout_secs),
            connect,
        )
        .await
        .map_err(|_| CoreError::Transport("连接超时".into()))?
        .map_err(|e| CoreError::Transport(format!("连接失败: {e}")))?;
        self.connections.lock().insert(peer_id.clone(), conn);
        self.peer_addrs.lock().insert(peer_id.clone(), addr);
        Ok(())
    }

    /// 获取或建立到 peer 的连接。
    async fn get_or_connect(&self, peer_id: &PeerId) -> CoreResult<Connection> {
        // 先查缓存
        if let Some(conn) = self.connections.lock().get(peer_id).cloned() {
            return Ok(conn);
        }
        // 查地址并连接
        let addr = self
            .peer_addrs
            .lock()
            .get(peer_id)
            .cloned()
            .ok_or_else(|| CoreError::Transport(format!("peer 地址未知: {peer_id}")))?;
        self.connect(peer_id, addr).await?;
        self.connections
            .lock()
            .get(peer_id)
            .cloned()
            .ok_or_else(|| CoreError::Transport("连接建立后未找到".into()))
    }

    /// 关闭到 peer 的连接。
    pub fn close_peer(&self, peer_id: &PeerId) {
        if let Some(conn) = self.connections.lock().remove(peer_id) {
            conn.close(0u32.into(), b"close_peer");
            debug!(peer_id = %peer_id, "已关闭连接");
        }
    }

    /// 关闭所有连接（用于 fast-resume）。
    pub fn close_all(&self) {
        let mut conns = self.connections.lock();
        for (peer_id, conn) in conns.drain() {
            conn.close(0u32.into(), b"close_all");
            debug!(peer_id = %peer_id, "已关闭连接");
        }
    }

    /// 启动接收循环（后台 task）。
    ///
    /// 接收到的数据通过回调处理。
    /// Phase 0/1：简化为日志，实际由集成层注入回调。
    pub fn start_accept_loop(&self) {
        let endpoint = self.endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                debug!(remote = %incoming.remote_address(), "收到入站连接");
                // 每个连接独立 task，完成握手后保持存活
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(error = %e, "连接握手失败");
                            return;
                        }
                    };
                    debug!(remote = %conn.remote_address(), "握手完成");
                    // Phase 0/1：仅保持连接存活，不处理数据
                    // 实际由集成层注入回调处理 uni/bi stream
                    loop {
                        match conn.accept_uni().await {
                            Ok(mut stream) => {
                                // 读取并丢弃数据（Phase 0 简化）
                                let mut buf = vec![0u8; 4096];
                                loop {
                                    match stream.read(&mut buf).await {
                                        Ok(Some(0)) | Ok(None) => break,
                                        Ok(Some(_)) => {}
                                        Err(e) => {
                                            debug!(error = %e, "读取失败");
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, "连接关闭");
                                break;
                            }
                        }
                    }
                });
            }
        });
    }

    /// 发送原始字节到 peer。
    async fn send_bytes(&self, peer_id: &PeerId, bytes: &[u8]) -> CoreResult<()> {
        let conn = self.get_or_connect(peer_id).await?;
        let mut stream = conn
            .open_uni()
            .await
            .map_err(|e| CoreError::Transport(format!("打开 stream 失败: {e}")))?;
        stream
            .write_all(bytes)
            .await
            .map_err(|e| CoreError::Transport(format!("写入失败: {e}")))?;
        stream
            .finish()
            .map_err(|e| CoreError::Transport(format!("finish 失败: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl SyncTransport for QuicTransport {
    async fn send_data(
        &self,
        peer_id: &PeerId,
        frame: DataFrame,
        _priority: Priority,
        _preferred_path: PathPreference,
    ) -> CoreResult<()> {
        // 序列化 DataFrame 为字节
        let bytes = serde_json::to_vec(&frame)
            .map_err(|e| CoreError::Serialize(e.to_string()))?;
        self.send_bytes(peer_id, &bytes).await
    }

    async fn send_control(
        &self,
        peer_id: &PeerId,
        msg: ControlMsg,
        _priority: Priority,
    ) -> CoreResult<()> {
        let bytes = serde_json::to_vec(&msg)
            .map_err(|e| CoreError::Serialize(e.to_string()))?;
        self.send_bytes(peer_id, &bytes).await
    }

    async fn reconnect_peer(&self, peer_id: &PeerId) -> CoreResult<()> {
        // 关闭旧连接
        self.close_peer(peer_id);
        // 重新连接
        let addr = self
            .peer_addrs
            .lock()
            .get(peer_id)
            .cloned()
            .ok_or_else(|| CoreError::Transport(format!("peer 地址未知: {peer_id}")))?;
        self.connect(peer_id, addr).await?;
        Ok(())
    }

    async fn notify_network_changed(&self, online: bool, _net_type: NetworkType) -> CoreResult<()> {
        if !online {
            warn!("网络离线，关闭所有连接");
            self.close_all();
        }
        // 网络恢复时，由上层 SyncEngine 触发 fast-resume
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_transport() {
        let config = QuicTransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            is_server: true,
            ..Default::default()
        };
        let transport = QuicTransport::new(config).await.unwrap();
        let addr = transport.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn connect_and_send() {
        // 启动 server
        let server_config = QuicTransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            is_server: true,
            ..Default::default()
        };
        let server = QuicTransport::new(server_config).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_cert = server.cert().clone();
        server.start_accept_loop();

        // 启动 client
        let client_config = QuicTransportConfig {
            is_server: false,
            ..Default::default()
        };
        let client = QuicTransport::new(client_config).await.unwrap();
        // 信任 server 的证书
        client.trust_cert(server_cert).unwrap();

        // 注册并连接
        let peer_id = PeerId::new("server");
        client.register_peer(peer_id.clone(), server_addr);
        client.connect(&peer_id, server_addr).await.unwrap();

        // 发送数据
        let frame = DataFrame {
            doc_id: tacit_core::DocId::new("d1"),
            actor_id: PeerId::new("client"),
            seq: 1,
            kind: tacit_core::DataFrameKind::Delta,
            payload: bytes::Bytes::from_static(b"hello"),
            session_id: tacit_core::SessionId::new(1),
        };
        client
            .send_data(
                &peer_id,
                frame,
                Priority::High,
                PathPreference::Any,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn close_all_connections() {
        let config = QuicTransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            is_server: true,
            ..Default::default()
        };
        let transport = QuicTransport::new(config).await.unwrap();
        transport.close_all();
    }
}
