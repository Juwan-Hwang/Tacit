//! QuicTransport：QUIC 传输实现。
//!
//! 实现 [`tacit_transport::SyncTransport`] trait。
//! 管理 endpoint、peer 连接池、health check。
//! network path 变化时主动断开并 fast-resume。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use quinn::{Connection, Endpoint};
use sha2::{Digest, Sha256};
use tacit_core::{CoreError, CoreResult, DataFrame, NetworkType, PeerId, Priority};
use tacit_transport::{
    encode_control, encode_data, ControlMsg, PathPreference, SyncTransport, TransportEvent,
};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::config::{generate_self_signed_cert, make_client_config, make_server_config, make_transport_config};

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
    /// 空闲超时（秒），传入 Quinn TransportConfig。
    pub idle_timeout_secs: u64,
    /// keep-alive 探测间隔（秒），传入 Quinn TransportConfig。
    pub keep_alive_interval_secs: u64,
    /// 单个 stream 操作（open_uni/write_all/read_exact）超时（秒）。
    pub stream_op_timeout_secs: u64,
    /// 最大并发入站连接数。
    pub max_concurrent_inbound: u64,
}

impl Default for QuicTransportConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            is_server: false,
            connect_timeout_secs: 5,
            idle_timeout_secs: 30,
            keep_alive_interval_secs: 15,
            stream_op_timeout_secs: 30,
            max_concurrent_inbound: 64,
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
    /// 远端地址 -> peer_id（反向映射，用于入站连接识别 peer 身份）
    addr_to_peer: Arc<Mutex<HashMap<SocketAddr, PeerId>>>,
    /// peer -> Noise 会话 ID（握手完成后由集成层注入）
    sessions: Arc<Mutex<HashMap<PeerId, u64>>>,
    /// 本端证书（用于让对端信任）
    cert: rustls::pki_types::CertificateDer<'static>,
    /// 可更新的 client config（trust_cert 时更新）
    client_config: Arc<parking_lot::RwLock<quinn::ClientConfig>>,
    /// Quinn TransportConfig（idle_timeout / keep_alive），trust_cert 时需重新应用
    transport_config: Arc<quinn::TransportConfig>,
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
        // 构建 Quinn TransportConfig：应用 idle_timeout 与 keep_alive_interval
        let transport_config = make_transport_config(
            config.idle_timeout_secs,
            config.keep_alive_interval_secs,
        )?;

        let (endpoint, cert, client_config) = if config.is_server {
            // server 模式：生成证书，监听
            let (cert, key) = generate_self_signed_cert()?;
            let mut server_config = make_server_config(cert.clone(), key)?;
            // 将 TransportConfig 应用到 server（影响入站连接）
            server_config.transport_config(transport_config.clone());
            let endpoint =
                Endpoint::server(server_config, config.listen_addr)
                    .map_err(|e| CoreError::Transport(format!("创建 endpoint 失败: {e}")))?;
            // server 也能主动发起连接，用自身证书作为信任根
            let mut client_config = make_client_config(cert.clone())?;
            // 出站连接同样应用 TransportConfig
            client_config.transport_config(transport_config.clone());
            (endpoint, cert, client_config)
        } else {
            // client 模式：仅创建 endpoint
            let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
                .map_err(|e| CoreError::Transport(format!("创建 endpoint 失败: {e}")))?;
            // client 模式下生成自签名证书作为身份（实际信任由 trust_cert 设置）
            let (cert, _) = generate_self_signed_cert()?;
            let mut client_config = make_client_config(cert.clone())?;
            client_config.transport_config(transport_config.clone());
            (endpoint, cert, client_config)
        };

        Ok(Self {
            endpoint,
            connections: Arc::new(Mutex::new(HashMap::new())),
            peer_addrs: Arc::new(Mutex::new(HashMap::new())),
            addr_to_peer: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            cert,
            client_config: Arc::new(parking_lot::RwLock::new(client_config)),
            transport_config,
            data_handler: Arc::new(RwLock::new(None)),
            config,
        })
    }

    /// 设置 peer 的 Noise 会话 ID（握手完成后由集成层调用）。
    ///
    /// 控制帧编码时会使用此 session_id 标识会话。
    pub fn set_session(&self, peer_id: &PeerId, session_id: u64) {
        self.sessions.lock().insert(peer_id.clone(), session_id);
    }

    /// 获取 peer 的会话 ID，未设置则返回 0（未握手状态）。
    fn get_session(&self, peer_id: &PeerId) -> u64 {
        self.sessions.lock().get(peer_id).copied().unwrap_or(0)
    }

    /// 清除 peer 的会话 ID（断开连接时调用）。
    fn clear_session(&self, peer_id: &PeerId) {
        self.sessions.lock().remove(peer_id);
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
    /// 更新后需重新应用 TransportConfig，避免 idle_timeout/keep_alive 丢失。
    pub fn trust_cert(&self, cert: rustls::pki_types::CertificateDer<'static>) -> CoreResult<()> {
        let mut client_config = make_client_config(cert)?;
        client_config.transport_config(self.transport_config.clone());
        *self.client_config.write() = client_config;
        Ok(())
    }

    /// 获取本地监听地址。
    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| CoreError::Transport(format!("获取本地地址失败: {e}")))
    }

    /// 注册 peer 的远端地址，同时建立反向映射。
    pub fn register_peer(&self, peer_id: PeerId, addr: SocketAddr) {
        self.peer_addrs.lock().insert(peer_id.clone(), addr);
        self.addr_to_peer.lock().insert(addr, peer_id);
    }

    /// 注册入站连接的 peer 身份（握手完成后由集成层调用）。
    ///
    /// 用于将远端地址映射到真实的 peer_id（由 Noise 公钥派生），
    /// 避免用 socket 地址冒充 peer 身份。
    pub fn register_incoming_peer(&self, addr: SocketAddr, peer_id: PeerId) {
        self.addr_to_peer.lock().insert(addr, peer_id.clone());
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
        self.addr_to_peer.lock().insert(addr, peer_id.clone());
        Ok(())
    }

    /// 获取或建立到 peer 的连接。
    ///
    /// 检查缓存连接的存活性，失效则移除并重连。
    async fn get_or_connect(&self, peer_id: &PeerId) -> CoreResult<Connection> {
        // 先查缓存，同时检查连接存活性
        {
            let mut conns = self.connections.lock();
            if let Some(conn) = conns.get(peer_id).cloned() {
                if conn.close_reason().is_none() {
                    return Ok(conn);
                }
                // 连接已失效，移除
                debug!(peer_id = %peer_id, "缓存连接已失效，移除并重连");
                conns.remove(peer_id);
            }
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
            self.clear_session(peer_id);
            // 清理反向映射
            if let Some(addr) = self.peer_addrs.lock().get(peer_id).cloned() {
                self.addr_to_peer.lock().remove(&addr);
            }
            debug!(peer_id = %peer_id, "已关闭连接并清除会话");
        }
    }

    /// 关闭所有连接（用于 fast-resume）。
    pub fn close_all(&self) {
        let mut conns = self.connections.lock();
        let peer_ids: Vec<PeerId> = conns.keys().cloned().collect();
        for peer_id in &peer_ids {
            self.clear_session(peer_id);
        }
        for (peer_id, conn) in conns.drain() {
            conn.close(0u32.into(), b"close_all");
            debug!(peer_id = %peer_id, "已关闭连接");
        }
        // 清理反向映射
        self.addr_to_peer.lock().clear();
    }

    /// 启动接收循环（后台 task）。
    ///
    /// 接收到的数据通过 [`set_data_handler`](Self::set_data_handler) 注入的回调处理。
    /// 若未设置回调，数据将被丢弃并记录警告。
    ///
    /// 使用 `Semaphore` 限制最大并发入站连接数（`max_concurrent_inbound`），
    /// 超过限制时拒绝新连接并记录 warn 日志。
    pub fn start_accept_loop(&self) {
        let endpoint = self.endpoint.clone();
        let data_handler = self.data_handler.clone();
        let addr_to_peer = self.addr_to_peer.clone();
        let max_concurrent = self.config.max_concurrent_inbound as usize;
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                debug!(remote = %incoming.remote_address(), "收到入站连接");
                // 尝试获取许可：超过并发上限则拒绝新连接
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(
                            remote = %incoming.remote_address(),
                            max = max_concurrent,
                            "并发入站连接数超限，拒绝新连接"
                        );
                        // incoming drop 时 Quinn 会发送 CONNECTION_CLOSE，
                        // 对端将收到连接拒绝
                        continue;
                    }
                };
                let handler = data_handler.clone();
                let addr_map = addr_to_peer.clone();
                // 每个连接独立 task，持有 permit 直到连接结束
                tokio::spawn(async move {
                    let _permit = permit;
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(error = %e, "连接握手失败");
                            return;
                        }
                    };
                    let remote_addr = conn.remote_address();
                    debug!(remote = %remote_addr, "握手完成");
                    // 通过反向映射查找 peer_id；未注册则用地址派生的稳定 ID 兜底，
                    // 集成层握手后可调用 register_incoming_peer 覆盖为真实 peer_id
                    let remote_peer = {
                        let map = addr_map.lock();
                        map.get(&remote_addr)
                            .cloned()
                            .unwrap_or_else(|| PeerId::new(format!("peer_{}", stable_addr_hash(&remote_addr))))
                    };
                    loop {
                        match conn.accept_uni().await {
                            Ok(mut stream) => {
                                let handler = handler.clone();
                                let peer_id = remote_peer.clone();
                                tokio::spawn(async move {
                                    // 读取长度前缀 + 载荷，防止粘包/拆包
                                    let mut len_buf = [0u8; 4];
                                    if stream.read_exact(&mut len_buf).await.is_err() {
                                        return;
                                    }
                                    let frame_len = u32::from_be_bytes(len_buf) as usize;
                                    // 限制最大帧大小，防止恶意大帧耗尽内存
                                    if frame_len > 16 * 1024 * 1024 {
                                        warn!(frame_len, "帧过大，丢弃");
                                        return;
                                    }
                                    let mut buf = vec![0u8; frame_len];
                                    if stream.read_exact(&mut buf).await.is_err() {
                                        return;
                                    }
                                    // 尝试解码为 DataFrame 或 ControlMsg
                                    let event = if let Ok(wire) =
                                        tacit_transport::decode_data(&buf)
                                    {
                                        Some(TransportEvent::Data {
                                            peer_id,
                                            frame: wire.to_data_frame(),
                                        })
                                    } else if let Ok((msg, _sid)) =
                                        tacit_transport::decode_control(&buf)
                                    {
                                        Some(TransportEvent::Control {
                                            peer_id,
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
    ///
    /// 使用长度前缀（4 字节大端）+ 载荷的帧格式，防止粘包/拆包。
    /// 所有 stream 操作（open_uni / write_all / finish）均带超时，
    /// 超时返回 `CoreError::Transport("QUIC stream operation timed out")`。
    async fn send_bytes(&self, peer_id: &PeerId, bytes: &[u8], priority: Priority) -> CoreResult<()> {
        let conn = self.get_or_connect(peer_id).await?;
        let op_timeout = Duration::from_secs(self.config.stream_op_timeout_secs);
        // open_uni 带超时
        let mut stream = tokio::time::timeout(op_timeout, conn.open_uni())
            .await
            .map_err(|_| CoreError::Transport("QUIC stream operation timed out".into()))?
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
        // 写入长度前缀 + 载荷，write_all 带超时
        let len = (bytes.len() as u32).to_be_bytes();
        tokio::time::timeout(op_timeout, stream.write_all(&len))
            .await
            .map_err(|_| CoreError::Transport("QUIC stream operation timed out".into()))?
            .map_err(|e| CoreError::Transport(format!("写入长度前缀失败: {e}")))?;
        tokio::time::timeout(op_timeout, stream.write_all(bytes))
            .await
            .map_err(|_| CoreError::Transport("QUIC stream operation timed out".into()))?
            .map_err(|e| CoreError::Transport(format!("写入失败: {e}")))?;
        // finish 为同步操作，无需超时
        stream
            .finish()
            .map_err(|e| CoreError::Transport(format!("finish 失败: {e}")))?;
        Ok(())
    }

    /// 健康检查：验证所有已连接 peer 的连接存活性（被动检查）。
    ///
    /// 返回不可用 peer 列表（连接已关闭或不可达）。
    /// 除 `close_reason` 外，还会读取 `connection.stats()` 记录诊断信息，
    /// 用于发现长时间无数据传输的潜在死连接。
    pub async fn health_check(&self) -> Vec<PeerId> {
        let conns = self.connections.lock().clone();
        let mut dead = Vec::new();
        for (peer_id, conn) in &conns {
            // 被动检查：close_reason 判断存活性
            if conn.close_reason().is_some() {
                dead.push(peer_id.clone());
                continue;
            }
            // stats 检查：记录收发统计，便于诊断长时间无数据传输的连接
            let stats = conn.stats();
            debug!(
                peer_id = %peer_id,
                udp_rx = ?stats.udp_rx,
                udp_tx = ?stats.udp_tx,
                "连接统计"
            );
        }
        // 清理失效连接并清除会话
        if !dead.is_empty() {
            let mut conns = self.connections.lock();
            for p in &dead {
                if conns.remove(p).is_some() {
                    self.clear_session(p);
                }
            }
        }
        dead
    }

    /// 主动健康探测：对连接池中的每个连接发起轻量 ping，检测死连接。
    ///
    /// 通过打开一个空 uni-stream 并立即 finish 来探测连接存活性。
    /// 若 `open_uni` 失败或超时，则判定连接已死。
    /// 相比 [`health_check`](Self::health_check)（仅被动检查 close_reason），
    /// 此方法能主动发现处于半开/僵尸状态的连接。
    ///
    /// 返回探测失败的 peer 列表。
    pub async fn health_probe(&self) -> Vec<PeerId> {
        let conns = self.connections.lock().clone();
        let mut dead = Vec::new();
        let op_timeout = Duration::from_secs(self.config.stream_op_timeout_secs);
        for (peer_id, conn) in &conns {
            // 快速路径：close_reason 已判定死亡
            if conn.close_reason().is_some() {
                dead.push(peer_id.clone());
                continue;
            }
            // 主动探测：打开空 uni-stream 并 finish（轻量 ping）
            let probe = conn.open_uni();
            match tokio::time::timeout(op_timeout, probe).await {
                Ok(Ok(mut stream)) => {
                    // 立即 finish，发送空 stream 作为 ping
                    let _ = stream.finish();
                }
                Ok(Err(e)) => {
                    debug!(peer_id = %peer_id, error = %e, "健康探测失败，标记为死连接");
                    dead.push(peer_id.clone());
                }
                Err(_) => {
                    debug!(peer_id = %peer_id, "健康探测超时，标记为死连接");
                    dead.push(peer_id.clone());
                }
            }
        }
        // 清理失效连接并清除会话
        if !dead.is_empty() {
            let mut conns = self.connections.lock();
            for p in &dead {
                if conns.remove(p).is_some() {
                    self.clear_session(p);
                }
            }
        }
        dead
    }
}

/// 从 SocketAddr 派生稳定的 hash（用于未注册 peer 的兜底 ID）。
fn stable_addr_hash(addr: &SocketAddr) -> String {
    let mut hasher = Sha256::new();
    hasher.update(addr.to_string().as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
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
        // 单帧模式：使用 BatchFlag::Single 和零 ref_id。
        // 批次模式由集成层通过 start_batch/end_batch API 显式管理，
        // 此处保持单帧默认行为，确保每帧可独立解码。
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
        let session_id = self.get_session(peer_id);
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
            return Ok(());
        }
        // 网络恢复：fast-resume
        // 1. 收集所有已注册 peer 地址（close_all 不清理 peer_addrs，但提前收集更安全）
        let peers: Vec<(PeerId, SocketAddr)> = self
            .peer_addrs
            .lock()
            .iter()
            .map(|(p, a)| (p.clone(), *a))
            .collect();
        if peers.is_empty() {
            info!("网络恢复，无已注册 peer，无需 fast-resume");
            return Ok(());
        }
        // 2. 关闭所有旧连接（保留 peer_addrs 用于重连）
        self.close_all();
        info!(peer_count = peers.len(), "网络恢复，发起 fast-resume 重连");
        // 3. 对每个 peer 异步发起重连（不阻塞），失败用指数退避重试（最多 3 次：1s, 2s, 4s）
        let endpoint = self.endpoint.clone();
        let client_config = self.client_config.read().clone();
        let connections = self.connections.clone();
        let addr_to_peer = self.addr_to_peer.clone();
        let connect_timeout = self.config.connect_timeout_secs;
        for (peer_id, addr) in peers {
            let endpoint = endpoint.clone();
            let client_config = client_config.clone();
            let connections = connections.clone();
            let addr_to_peer = addr_to_peer.clone();
            tokio::spawn(async move {
                // 指数退避延迟：1s, 2s, 4s（对应 3 次重试）
                let backoffs = [
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    Duration::from_secs(4),
                ];
                // attempt 0 为立即尝试，attempt 1..=3 在退避后重试
                for attempt in 0..=backoffs.len() {
                    if attempt > 0 {
                        let delay = backoffs[attempt - 1];
                        debug!(peer_id = %peer_id, attempt, ?delay, "fast-resume 等待退避后重试");
                        tokio::time::sleep(delay).await;
                    }
                    let connect = match endpoint.connect_with(client_config.clone(), addr, "tacit") {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(peer_id = %peer_id, attempt, error = %e, "fast-resume 发起连接失败");
                            continue;
                        }
                    };
                    match tokio::time::timeout(Duration::from_secs(connect_timeout), connect).await {
                        Ok(Ok(conn)) => {
                            connections.lock().insert(peer_id.clone(), conn);
                            addr_to_peer.lock().insert(addr, peer_id.clone());
                            info!(peer_id = %peer_id, attempt, "fast-resume 重连成功");
                            return;
                        }
                        Ok(Err(e)) => {
                            warn!(peer_id = %peer_id, attempt, error = %e, "fast-resume 连接失败，将重试");
                        }
                        Err(_) => {
                            warn!(peer_id = %peer_id, attempt, "fast-resume 连接超时，将重试");
                        }
                    }
                }
                warn!(peer_id = %peer_id, "fast-resume 重连失败，已用尽 3 次重试");
            });
        }
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
