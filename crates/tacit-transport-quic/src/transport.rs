//! QuicTransport：QUIC 传输实现。
//!
//! 实现 [`tacit_transport::SyncTransport`] trait。
//! 管理 endpoint、peer 连接池、health check。
//! network path 变化时主动断开并 fast-resume。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use quinn::{Connection, Endpoint};
use tacit_core::{CoreError, CoreResult, DataFrame, NetworkType, PeerId, Priority};
use tacit_transport::{
    encode_control, encode_data, ControlMsg, PathPreference, SyncTransport, TransportEvent,
};
use tracing::{debug, warn};

use crate::config::{generate_self_signed_cert, make_client_config, make_server_config};

/// 接收数据回调类型。
type DataHandler = Arc<RwLock<Option<Box<dyn Fn(TransportEvent) + Send + Sync>>>>;

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
    /// 接收数据回调（由集成层注入）。
    data_handler: DataHandler,
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
            data_handler: Arc::new(RwLock::new(None)),
            config,
        })
    }

    /// 设置接收数据回调。
    ///
    /// 收到的 DataFrame / ControlMsg 会通过此回调上报给集成层（如 SyncEngine）。
    pub fn set_data_handler(&self, handler: impl Fn(TransportEvent) + Send + Sync + 'static) {
        *self.data_handler.write() = Some(Box::new(handler));
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
    /// 接收到的数据通过 [`set_data_handler`](Self::set_data_handler) 注入的回调处理。
    /// 若未设置回调，数据将被丢弃并记录警告。
    pub fn start_accept_loop(&self) {
        let endpoint = self.endpoint.clone();
        let data_handler = self.data_handler.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                debug!(remote = %incoming.remote_address(), "收到入站连接");
                let handler = data_handler.clone();
                // 每个连接独立 task
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(error = %e, "连接握手失败");
                            return;
                        }
                    };
                    debug!(remote = %conn.remote_address(), "握手完成");
                    let remote_peer = conn.remote_address().to_string();
                    loop {
                        match conn.accept_uni().await {
                            Ok(mut stream) => {
                                let handler = handler.clone();
                                let peer_str = remote_peer.clone();
                                tokio::spawn(async move {
                                    // 读取完整帧
                                    let mut buf = Vec::new();
                                    let mut chunk = vec![0u8; 4096];
                                    loop {
                                        match stream.read(&mut chunk).await {
                                            Ok(Some(0)) | Ok(None) => break,
                                            Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                                            Err(e) => {
                                                debug!(error = %e, "读取失败");
                                                break;
                                            }
                                        }
                                    }
                                    if buf.is_empty() {
                                        return;
                                    }
                                    // 尝试解码为 DataFrame 或 ControlMsg
                                    let event = if let Ok(wire) =
                                        tacit_transport::decode_data(&buf)
                                    {
                                        Some(TransportEvent::Data {
                                            peer_id: PeerId::new(&peer_str),
                                            frame: wire.to_data_frame(),
                                        })
                                    } else if let Ok((msg, _sid)) =
                                        tacit_transport::decode_control(&buf)
                                    {
                                        Some(TransportEvent::Control {
                                            peer_id: PeerId::new(&peer_str),
                                            msg,
                                        })
                                    } else {
                                        warn!(
                                            len = buf.len(),
                                            "无法解码收到的数据帧，丢弃"
                                        );
                                        None
                                    };
                                    // 调用回调
                                    if let Some(event) = event {
                                        let handler = handler.read();
                                        if let Some(h) = handler.as_ref() {
                                            h(event);
                                        } else {
                                            debug!("未设置 data_handler，丢弃收到的数据");
                                        }
                                    }
                                });
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

    /// 发送原始字节到 peer，并设置 stream 优先级。
    async fn send_bytes(&self, peer_id: &PeerId, bytes: &[u8], priority: Priority) -> CoreResult<()> {
        let conn = self.get_or_connect(peer_id).await?;
        let mut stream = conn
            .open_uni()
            .await
            .map_err(|e| CoreError::Transport(format!("打开 stream 失败: {e}")))?;
        // 映射 Priority 到 QUIC stream 优先级（0=最高, 255=最低）
        let quic_priority = match priority {
            Priority::High => 0,
            Priority::Medium => 128,
            Priority::Low => 255,
        };
        stream
            .set_priority(quic_priority)
            .map_err(|e| CoreError::Transport(format!("设置 stream 优先级失败: {e}")))?;
        stream
            .write_all(bytes)
            .await
            .map_err(|e| CoreError::Transport(format!("写入失败: {e}")))?;
        stream
            .finish()
            .map_err(|e| CoreError::Transport(format!("finish 失败: {e}")))?;
        Ok(())
    }

    /// 健康检查：验证所有已连接 peer 的连接存活性。
    ///
    /// 返回不可用 peer 列表（连接已关闭或不可达）。
    pub async fn health_check(&self) -> Vec<PeerId> {
        let conns = self.connections.lock().clone();
        let mut dead = Vec::new();
        for (peer_id, conn) in conns {
            // quinn Connection 提供 close_reason 判断存活性
            if conn.close_reason().is_some() {
                dead.push(peer_id);
            }
        }
        // 清理失效连接
        if !dead.is_empty() {
            let mut conns = self.connections.lock();
            for p in &dead {
                conns.remove(p);
            }
        }
        dead
    }
}

#[async_trait]
impl SyncTransport for QuicTransport {
    async fn send_data(
        &self,
        peer_id: &PeerId,
        frame: DataFrame,
        priority: Priority,
        _preferred_path: PathPreference,
    ) -> CoreResult<()> {
        // 使用 frame_codec 二进制编码（v1.0 规范第 13.3 节）
        let bytes = encode_data(
            &frame.doc_id,
            &frame.actor_id,
            frame.seq,
            frame.kind,
            &frame.payload,
            tacit_core::BatchFlag::Single,
            [0u8; 8],
        );
        self.send_bytes(peer_id, &bytes, priority).await
    }

    async fn send_control(
        &self,
        peer_id: &PeerId,
        msg: ControlMsg,
        priority: Priority,
    ) -> CoreResult<()> {
        // 使用 frame_codec 二进制编码（v1.0 规范第 13.2 节）
        let session_id: u64 = 0; // session_id 由握手层管理，此处用 0 占位
        let bytes = encode_control(&msg, session_id)
            .map_err(|e| CoreError::Serialize(format!("控制帧编码失败: {e}")))?;
        self.send_bytes(peer_id, &bytes, priority).await
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
