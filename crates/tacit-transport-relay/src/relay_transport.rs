//! Relay 网络传输闭环。
//!
//! 在 [`RelayClient`] / [`RelayServer`] 协议逻辑之上注入 QUIC 连接，
//! 实现端到端的注册、转发、推送。
//!
//! - [`RelayClientTransport`]：客户端侧，连接 relay 服务端，注册，转发数据，
//!   并接收 relay 推送的 Incoming 消息。
//! - [`RelayServerRunner`]：服务端侧，监听 QUIC，接受客户端连接，路由转发。
//!
//! 设计要点：
//! - 客户端使用单条 QUIC 连接 + 双向流（bi-stream）与 relay 通信。
//!   每个请求/响应在独立的 bi-stream 上完成，避免队头阻塞。
//! - relay 服务端维护 peer_id -> 推送通道 的映射，
//!   当收到 Forward 时，通过目标 peer 的推送通道发送 Incoming。
//! - 客户端启动后台 task 接收 relay 主动推送的消息（Incoming / PeerOnline / PeerOffline）。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use quinn::{Connection, Endpoint};
use tacit_core::{CoreError, CoreResult, DataFrame, NetworkType, PeerId, Priority};
use tacit_crypto::Session;
use tacit_transport::{ControlMsg, PathPreference, SyncTransport};
use tacit_transport_quic::{generate_self_signed_cert, make_client_config, make_server_config};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use crate::client::RelayClient;
use crate::protocol::{RelayMessage, RelayTier};
use crate::server::RelayServer;

/// 客户端收到的 relay 推送事件。
#[derive(Debug, Clone)]
pub enum RelayPushEvent {
    /// 收到转发的数据。
    Incoming { from_peer_id: PeerId, data: Vec<u8> },
    /// peer 上线。
    PeerOnline { peer_id: PeerId },
    /// peer 下线。
    PeerOffline { peer_id: PeerId },
}

/// 推送事件回调类型。
type PushHandler = Arc<RwLock<Option<Box<dyn Fn(RelayPushEvent) + Send + Sync>>>>;

/// Relay 客户端传输层。
///
/// 封装 [`RelayClient`] 协议逻辑 + QUIC 连接，实现端到端通信。
pub struct RelayClientTransport {
    /// 协议逻辑客户端。
    client: RelayClient,
    /// 到 relay 服务端的 QUIC 连接。
    conn: RwLock<Option<Connection>>,
    /// relay 服务端地址。
    relay_addr: SocketAddr,
    /// QUIC endpoint（用于发起连接）。
    endpoint: Endpoint,
    /// 可更新的 client config（trust_cert 时更新）。
    client_config: RwLock<quinn::ClientConfig>,
    /// 推送事件回调。
    push_handler: PushHandler,
    /// 后台接收 task 是否已启动。
    recv_started: Mutex<bool>,
    /// 心跳 task 的关闭信号（disconnect 时发送）。
    heartbeat_shutdown: Mutex<Option<oneshot::Sender<()>>>,
    /// relay 服务端层级。
    tier: RelayTier,
    /// E2E 加密会话表：peer_id -> Session。
    ///
    /// 由集成层在 Noise 握手完成后注入。注册后，所有经 relay 转发的
    /// payload（帧类型 + JSON）会被透明加密/解密，relay 服务端仅看到密文。
    /// 未注册 session 的 peer 仍以明文传输（向后兼容）。
    sessions: Arc<RwLock<HashMap<PeerId, Arc<Mutex<Session>>>>>,
}

impl RelayClientTransport {
    /// 创建客户端传输层。
    ///
    /// `peer_id`：本设备 peer_id。
    /// `secret`：relay 共享密钥。
    /// `relay_addr`：relay 服务端地址。
    pub async fn new(peer_id: PeerId, secret: Vec<u8>, relay_addr: SocketAddr) -> CoreResult<Self> {
        Self::with_tier(peer_id, secret, relay_addr, RelayTier::Public).await
    }

    /// 创建客户端传输层并指定 relay 层级。
    pub async fn with_tier(
        peer_id: PeerId,
        secret: Vec<u8>,
        relay_addr: SocketAddr,
        tier: RelayTier,
    ) -> CoreResult<Self> {
        let client = RelayClient::new(peer_id, secret);
        // 创建 client endpoint
        let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| CoreError::Transport(format!("创建 endpoint 失败: {e}")))?;
        // 生成自签名证书用于信任 relay（实际部署应由集成层注入 relay 证书）
        let (cert, _) = generate_self_signed_cert()?;
        let client_config = make_client_config(cert)?;

        Ok(Self {
            client,
            conn: RwLock::new(None),
            relay_addr,
            endpoint,
            client_config: RwLock::new(client_config),
            push_handler: Arc::new(RwLock::new(None)),
            recv_started: Mutex::new(false),
            heartbeat_shutdown: Mutex::new(None),
            tier,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// 获取 relay 层级。
    pub fn tier(&self) -> RelayTier {
        self.tier
    }

    /// 注册 E2E 加密会话。
    ///
    /// 在 Noise 握手完成后调用。注册后，所有发往该 peer 的 payload
    /// 将被 AEAD 加密，relay 服务端仅能看到密文。同时，从该 peer 收到的
    /// Incoming 数据也会被自动解密。
    pub fn register_session(&self, peer_id: PeerId, session: Session) {
        self.sessions
            .write()
            .insert(peer_id, Arc::new(Mutex::new(session)));
    }

    /// 移除 E2E 加密会话。
    ///
    /// 在 peer 断开或 session 过期时调用。
    pub fn remove_session(&self, peer_id: &PeerId) {
        self.sessions.write().remove(peer_id);
    }

    /// 加密 payload（若该 peer 已注册 session），否则返回原始 payload。
    fn encrypt_if_session(&self, peer_id: &PeerId, plaintext: Vec<u8>) -> CoreResult<Vec<u8>> {
        match self.sessions.read().get(peer_id) {
            Some(session) => {
                let mut s = session.lock();
                s.encrypt(&plaintext)
            }
            None => Ok(plaintext),
        }
    }

    /// 信任 relay 服务端证书（更新 client config）。
    ///
    /// 必须在 [`connect_and_register`](Self::connect_and_register) 之前调用。
    pub fn trust_cert(&self, cert: rustls::pki_types::CertificateDer<'static>) -> CoreResult<()> {
        let client_config = make_client_config(cert)?;
        *self.client_config.write() = client_config;
        Ok(())
    }

    /// 设置默认 client config（用于测试）。
    pub fn set_default_client_config(&self, config: quinn::ClientConfig) {
        *self.client_config.write() = config;
    }

    /// 连接到 relay 服务端并注册。
    ///
    /// 1. 建立 QUIC 连接。
    /// 2. 发送 Register 消息。
    /// 3. 等待 RegisterOk 响应。
    /// 4. 启动后台接收 task。
    pub async fn connect_and_register(&self) -> CoreResult<()> {
        // 建立 QUIC 连接
        let client_config = self.client_config.read().clone();
        let conn = self
            .endpoint
            .connect_with(client_config, self.relay_addr, "tacit")
            .map_err(|e| CoreError::Transport(format!("发起连接失败: {e}")))?
            .await
            .map_err(|e| CoreError::Transport(format!("连接 relay 失败: {e}")))?;
        debug!(addr = %self.relay_addr, "已连接 relay 服务端");

        *self.conn.write() = Some(conn.clone());

        // 发送 Register 消息
        let register_msg = self.client.create_register_message()?;
        let response = self.request_response(&register_msg).await?;

        // 处理注册响应
        self.client.handle_register_response(&response)?;

        // 启动后台接收 task
        {
            let mut started = self.recv_started.lock();
            if !*started {
                *started = true;
                self.start_recv_loop(conn.clone());
            }
        }

        // 启动心跳 task（每 30s 发送 Ping，连续 2 次超时则关闭连接触发重连）。
        // 先停止可能存在的旧心跳（重连场景）。
        if let Some(tx) = self.heartbeat_shutdown.lock().take() {
            let _ = tx.send(());
        }
        let (heartbeat_tx, heartbeat_rx) = oneshot::channel();
        *self.heartbeat_shutdown.lock() = Some(heartbeat_tx);
        self.start_heartbeat(conn, heartbeat_rx);

        Ok(())
    }

    /// 通过 bi-stream 发送请求并等待响应。
    ///
    /// 使用独立 bi-stream 避免队头阻塞。
    async fn request_response(&self, msg: &RelayMessage) -> CoreResult<RelayMessage> {
        let conn = self
            .conn
            .read()
            .clone()
            .ok_or_else(|| CoreError::Transport("未连接 relay 服务端".into()))?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| CoreError::Transport(format!("打开 bi-stream 失败: {e}")))?;
        let bytes = msg.to_bytes()?;
        send.write_all(&bytes)
            .await
            .map_err(|e| CoreError::Transport(format!("写入失败: {e}")))?;
        send.finish()
            .map_err(|e| CoreError::Transport(format!("finish 失败: {e}")))?;
        // 读取响应
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 4096];
        loop {
            match recv.read(&mut chunk).await {
                Ok(Some(0)) | Ok(None) => break,
                Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(CoreError::Transport(format!("读取响应失败: {e}"))),
            }
        }
        RelayMessage::from_bytes(&buf)
    }

    /// 启动后台接收 task，处理 relay 主动推送的消息。
    ///
    /// relay 通过 uni-stream 推送 Incoming / PeerOnline / PeerOffline。
    ///
    /// **并发读取 + 重排序串行解密**：
    /// 1. **并发读取**：每条 uni-stream 由独立 task 并发读取，避免慢流阻塞
    ///    accept 循环（Head-of-Line blocking）。
    /// 2. **重排序缓冲**：每条流在 accept 时获得一个全局递增序号 `seq`。
    ///    由于服务端串行发送（写完一条流再开下一条），同一 peer 的消息
    ///    的 `seq` 严格递增。解密消费者维护 per-peer `BTreeMap<seq, data>`
    ///    和全局 `max_contiguous` watermark，确保按 `seq` 升序解密，
    ///    从而保证 Noise 状态化 AEAD nonce 顺序正确。
    /// 3. **非加密消息**（PeerOnline / PeerOffline 等）无需排队，直接处理。
    ///
    /// **注意**：回调 `h(event)` 在解密 task 中同步调用，必须快速返回。
    /// 如需执行耗时操作，请在回调内部 `tokio::spawn`。
    fn start_recv_loop(&self, conn: Connection) {
        let push_handler = self.push_handler.clone();
        let sessions = self.sessions.clone();

        // 解密队列：(accept_seq, from_peer_id, ciphertext)
        let (decrypt_tx, mut decrypt_rx) = mpsc::channel::<(u64, String, Vec<u8>)>(256);

        // ── 串行解密消费者（含重排序缓冲） ──
        let handler_for_decrypt = push_handler.clone();
        let sessions_for_decrypt = sessions.clone();
        tokio::spawn(async move {
            // 全局连续 watermark：max_contiguous = N 表示 seq 0..=N 均已到达。
            // 用于判断 per-peer gap 是否已被其他 peer 的消息填补。
            let mut max_contiguous: Option<u64> = None;
            let mut pending_seqs: BTreeSet<u64> = BTreeSet::new();

            // Per-peer 重排序状态：(last_processed, buffered)
            type PeerReorder = (Option<u64>, BTreeMap<u64, Vec<u8>>);
            let mut peer_state: HashMap<String, PeerReorder> = HashMap::new();

            while let Some((seq, from_peer_id, data)) = decrypt_rx.recv().await {
                // ── 更新全局 watermark ──
                match max_contiguous {
                    None => {
                        if seq == 0 {
                            max_contiguous = Some(0);
                        } else {
                            pending_seqs.insert(seq);
                        }
                    }
                    Some(mc) => {
                        if seq == mc + 1 {
                            // 连续：推进 watermark 并吸收 pending
                            max_contiguous = Some(seq);
                            while pending_seqs.remove(&(max_contiguous.unwrap() + 1)) {
                                max_contiguous = Some(max_contiguous.unwrap() + 1);
                            }
                        } else if seq > mc + 1 {
                            pending_seqs.insert(seq);
                            // 防止无界增长：超过 512 条积压时跳过 gap
                            if pending_seqs.len() > 512 {
                                let new_mc = *pending_seqs.iter().next().unwrap() - 1;
                                max_contiguous = Some(new_mc);
                                pending_seqs.retain(|&s| s > new_mc);
                                warn!(
                                    max_contiguous = new_mc,
                                    "重排序 watermark 跳进（部分流可能已丢失或属于其他 peer）"
                                );
                            }
                        }
                        // seq <= mc：重复，忽略
                    }
                }

                // ── 加入 peer 的重排序缓冲 ──
                let (_, buffer) = peer_state
                    .entry(from_peer_id.clone())
                    .or_insert_with(|| (None, BTreeMap::new()));
                buffer.insert(seq, data);

                // ── 尝试处理所有 peer 的可消费消息 ──
                let mut to_process: Vec<(String, Vec<u8>)> = Vec::new();
                for (pid, (lp, buf)) in peer_state.iter_mut() {
                    while let Some(&min_seq) = buf.keys().next() {
                        let can_process = match *lp {
                            None => true, // 该 peer 的第一条消息
                            Some(last) => {
                                if min_seq <= last {
                                    buf.remove(&min_seq); // 过期/重复
                                    continue;
                                }
                                // 所有 seq < min_seq 的消息已到达（属于其他 peer
                                // 或已处理），可安全解密
                                match max_contiguous {
                                    Some(mc) => min_seq <= mc + 1,
                                    None => false,
                                }
                            }
                        };

                        if can_process {
                            let d = buf.remove(&min_seq).unwrap();
                            *lp = Some(min_seq);
                            to_process.push((pid.clone(), d));
                        } else {
                            break;
                        }
                    }
                }

                // ── 串行解密并分发 ──
                for (pid, data) in to_process {
                    let from = PeerId::new(&pid);
                    let decrypted = match sessions_for_decrypt.read().get(&from) {
                        Some(session) => {
                            let mut s = session.lock();
                            match s.decrypt(&data) {
                                Ok(pt) => pt,
                                Err(e) => {
                                    warn!(
                                        peer = %from,
                                        error = %e,
                                        "E2E 解密失败，丢弃消息",
                                    );
                                    continue;
                                }
                            }
                        }
                        None => data,
                    };
                    let msg = RelayMessage::Incoming {
                        from_peer_id: pid,
                        data: decrypted,
                    };
                    if let Some(event) = convert_push_event(&msg) {
                        let handler = handler_for_decrypt.read();
                        if let Some(h) = handler.as_ref() {
                            h(event);
                        }
                    }
                }
            }
        });

        // ── Accept 循环：并发读取 + accept 序号 ──
        let accept_seq = Arc::new(AtomicU64::new(0));
        tokio::spawn(async move {
            loop {
                match conn.accept_uni().await {
                    Ok(mut stream) => {
                        let handler = push_handler.clone();
                        let decrypt_tx = decrypt_tx.clone();
                        let seq = accept_seq.fetch_add(1, Ordering::Relaxed);
                        // 并发读取每条流，避免慢流阻塞 accept 循环
                        tokio::spawn(async move {
                            let mut buf = Vec::new();
                            let mut chunk = vec![0u8; 4096];
                            loop {
                                match stream.read(&mut chunk).await {
                                    Ok(Some(0)) | Ok(None) => break,
                                    Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                                    Err(e) => {
                                        debug!(error = %e, "读取推送流失败");
                                        break;
                                    }
                                }
                            }
                            if buf.is_empty() {
                                return;
                            }
                            match RelayMessage::from_bytes(&buf) {
                                Ok(msg) => {
                                    // Incoming 需要解密：携带 seq 交给重排序队列
                                    if let RelayMessage::Incoming { from_peer_id, data } = msg {
                                        if let Err(e) =
                                            decrypt_tx.send((seq, from_peer_id, data)).await
                                        {
                                            warn!(
                                                error = %e,
                                                "发送消息到解密队列失败，解密后台任务可能已退出"
                                            );
                                        }
                                    } else {
                                        // 非加密消息直接处理
                                        if let Some(event) = convert_push_event(&msg) {
                                            let handler = handler.read();
                                            if let Some(h) = handler.as_ref() {
                                                h(event);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "解析推送消息失败");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        debug!(error = %e, "relay 连接关闭，退出接收循环");
                        break;
                    }
                }
            }
        });
    }

    /// 启动心跳 task。
    ///
    /// 每 30 秒通过 bi-stream 发送 Ping，等待 Pong 响应（10 秒超时）。
    /// 连续 2 次超时则认为连接已断开，关闭 QUIC 连接以触发上层重连。
    /// 通过 oneshot 通道在 disconnect/shutdown 时停止。
    fn start_heartbeat(&self, conn: Connection, shutdown: oneshot::Receiver<()>) {
        tokio::spawn(async move {
            Self::run_heartbeat(conn, shutdown).await;
        });
    }

    /// 心跳 task 主体。
    async fn run_heartbeat(conn: Connection, mut shutdown: oneshot::Receiver<()>) {
        let mut consecutive_timeouts = 0u32;
        loop {
            // 等待 30 秒，或收到关闭信号时退出
            tokio::select! {
                _ = &mut shutdown => {
                    debug!("心跳 task 收到关闭信号，退出");
                    return;
                }
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
            // 发送 Ping 并等待 Pong（10 秒超时）
            match tokio::time::timeout(Duration::from_secs(10), Self::send_ping(&conn)).await {
                Ok(Ok(())) => {
                    consecutive_timeouts = 0;
                    debug!("心跳 Pong 收到");
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "心跳 Ping 发送/接收失败");
                    consecutive_timeouts += 1;
                }
                Err(_) => {
                    warn!("心跳 Ping 超时（10s 未收到 Pong）");
                    consecutive_timeouts += 1;
                }
            }
            if consecutive_timeouts >= 2 {
                warn!("连续 2 次心跳超时，关闭连接以触发重连");
                conn.close(0u32.into(), b"heartbeat timeout");
                return;
            }
        }
    }

    /// 通过 bi-stream 发送 Ping 并等待 Pong 响应。
    async fn send_ping(conn: &Connection) -> CoreResult<()> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| CoreError::Transport(format!("打开 bi-stream 失败: {e}")))?;
        let bytes = RelayMessage::Ping.to_bytes()?;
        send.write_all(&bytes)
            .await
            .map_err(|e| CoreError::Transport(format!("写入 Ping 失败: {e}")))?;
        send.finish()
            .map_err(|e| CoreError::Transport(format!("finish 失败: {e}")))?;
        // 读取 Pong 响应
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 64];
        loop {
            match recv.read(&mut chunk).await {
                Ok(Some(0)) | Ok(None) => break,
                Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(CoreError::Transport(format!("读取 Pong 失败: {e}"))),
            }
        }
        match RelayMessage::from_bytes(&buf)? {
            RelayMessage::Pong => Ok(()),
            other => Err(CoreError::Transport(format!("期望 Pong，收到 {other:?}"))),
        }
    }

    /// 设置推送事件回调。
    pub fn set_push_handler(&self, handler: impl Fn(RelayPushEvent) + Send + Sync + 'static) {
        *self.push_handler.write() = Some(Box::new(handler));
    }

    /// 通过 relay 转发数据给目标 peer。
    ///
    /// 若已注册该 peer 的 E2E session，payload 会被 AEAD 加密后再转发，
    /// relay 服务端仅看到密文。接收端在 `start_recv_loop` 中自动解密。
    pub async fn forward(&self, target: &PeerId, data: Vec<u8>) -> CoreResult<()> {
        let encrypted = self.encrypt_if_session(target, data)?;
        let forward_msg = self.client.create_forward_message(target, encrypted)?;
        let response = self.request_response(&forward_msg).await?;
        match response {
            RelayMessage::ForwardOk => Ok(()),
            RelayMessage::ForwardFailed { reason } => {
                Err(CoreError::Transport(format!("转发失败: {reason}")))
            }
            _ => Err(CoreError::Transport("期望 ForwardOk/ForwardFailed".into())),
        }
    }

    /// 是否已注册。
    pub fn is_registered(&self) -> bool {
        self.client.is_registered()
    }

    /// 断开连接。
    pub async fn disconnect(&self) {
        // 停止心跳 task
        if let Some(tx) = self.heartbeat_shutdown.lock().take() {
            let _ = tx.send(());
        }
        if let Some(conn) = self.conn.write().take() {
            conn.close(0u32.into(), b"client disconnect");
        }
        self.client.disconnect();
        // 重置接收循环标志，允许后续重连时重新启动接收 task
        *self.recv_started.lock() = false;
    }
}

/// Relay 帧类型前缀（用于区分 DataFrame 与 ControlMsg）。
const FRAME_TYPE_DATA: u8 = 0x01;
const FRAME_TYPE_CONTROL: u8 = 0x02;

/// 将帧类型前缀 + 序列化 payload 拼接为 relay 可转发的字节流。
fn encode_relay_payload<T: serde::Serialize>(frame_type: u8, msg: &T) -> CoreResult<Vec<u8>> {
    let json = serde_json::to_vec(msg).map_err(|e| CoreError::Serialize(e.to_string()))?;
    let mut buf = Vec::with_capacity(1 + json.len());
    buf.push(frame_type);
    buf.extend_from_slice(&json);
    Ok(buf)
}

#[async_trait]
impl SyncTransport for RelayClientTransport {
    async fn send_data(
        &self,
        peer_id: &PeerId,
        frame: DataFrame,
        _priority: Priority,
        _preferred_path: PathPreference,
    ) -> CoreResult<()> {
        if !self.is_registered() {
            return Err(CoreError::Transport("relay 未注册，无法发送数据".into()));
        }
        let payload = encode_relay_payload(FRAME_TYPE_DATA, &frame)?;
        self.forward(peer_id, payload).await
    }

    async fn send_control(
        &self,
        peer_id: &PeerId,
        msg: ControlMsg,
        _priority: Priority,
    ) -> CoreResult<()> {
        if !self.is_registered() {
            return Err(CoreError::Transport(
                "relay 未注册，无法发送控制消息".into(),
            ));
        }
        let payload = encode_relay_payload(FRAME_TYPE_CONTROL, &msg)?;
        self.forward(peer_id, payload).await
    }

    async fn reconnect_peer(&self, _peer_id: &PeerId) -> CoreResult<()> {
        // relay 模式下，重连意味着重新连接 relay 服务端
        if self.conn.read().is_none() {
            self.connect_and_register().await?;
        }
        Ok(())
    }

    async fn notify_network_changed(&self, online: bool, _net_type: NetworkType) -> CoreResult<()> {
        if !online {
            warn!("网络离线，断开 relay 连接");
            self.disconnect().await;
        } else {
            // 网络恢复时，若之前已注册过，尝试重新连接
            if self.conn.read().is_none() && self.client.is_registered() {
                debug!("网络恢复，尝试重新连接 relay");
                // 重置注册状态以便重新注册
                self.client.disconnect();
                if let Err(e) = self.connect_and_register().await {
                    warn!(error = %e, "网络恢复后重新连接 relay 失败");
                }
            }
        }
        Ok(())
    }
}

/// 将 relay 推送消息转为推送事件。
fn convert_push_event(msg: &RelayMessage) -> Option<RelayPushEvent> {
    match msg {
        RelayMessage::Incoming { from_peer_id, data } => Some(RelayPushEvent::Incoming {
            from_peer_id: PeerId::new(from_peer_id),
            data: data.clone(),
        }),
        RelayMessage::PeerOnline { peer_id } => Some(RelayPushEvent::PeerOnline {
            peer_id: PeerId::new(peer_id),
        }),
        RelayMessage::PeerOffline { peer_id } => Some(RelayPushEvent::PeerOffline {
            peer_id: PeerId::new(peer_id),
        }),
        _ => None,
    }
}

/// relay 服务端到客户端的推送通道（有界，容量 256，提供背压保护）。
type PushChannel = mpsc::Sender<RelayMessage>;

/// 单个 QUIC 连接的唯一标识。
///
/// 用于在 cleanup 时区分"本连接的推送通道"与"重连后新建的通道"，
/// 避免误删重连 peer 的新通道（通过 `Arc::ptr_eq` 比较身份）。
type ConnToken = Arc<()>;

/// Relay 服务端运行器。
///
/// 封装 [`RelayServer`] 协议逻辑 + QUIC endpoint，接受客户端连接并路由转发。
pub struct RelayServerRunner {
    /// 协议逻辑服务端。
    server: Arc<RelayServer>,
    /// QUIC endpoint。
    endpoint: Endpoint,
    /// peer_id -> (推送通道, 连接标识)。
    ///
    /// 推送通道用于向目标客户端推送 Incoming / PeerOnline / PeerOffline；
    /// 连接标识用于 cleanup 时避免误删重连 peer 的新通道。
    push_channels: Arc<Mutex<HashMap<PeerId, (PushChannel, ConnToken)>>>,
}

impl RelayServerRunner {
    /// 创建 relay 服务端运行器。
    ///
    /// `secret`：relay 共享密钥。
    /// `listen_addr`：监听地址。
    pub async fn new(secret: Vec<u8>, listen_addr: SocketAddr) -> CoreResult<Self> {
        let (cert, key) = generate_self_signed_cert()?;
        Self::with_cert(secret, listen_addr, cert, key).await
    }

    /// 使用指定证书创建 relay 服务端运行器。
    ///
    /// 用于测试或持久化证书场景。
    pub async fn with_cert(
        secret: Vec<u8>,
        listen_addr: SocketAddr,
        cert: rustls::pki_types::CertificateDer<'static>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> CoreResult<Self> {
        let server = Arc::new(RelayServer::new(secret));
        let server_config = make_server_config(cert, key)?;
        let endpoint = Endpoint::server(server_config, listen_addr)
            .map_err(|e| CoreError::Transport(format!("创建 endpoint 失败: {e}")))?;
        Ok(Self {
            server,
            endpoint,
            push_channels: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// 获取本地监听地址。
    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| CoreError::Transport(format!("获取本地地址失败: {e}")))
    }

    /// 获取协议逻辑服务端引用（用于测试）。
    pub fn server(&self) -> &Arc<RelayServer> {
        &self.server
    }

    /// 启动接受连接循环。
    ///
    /// 每个客户端连接独立 task 处理：
    /// - 读取 bi-stream 上的请求（Register / Forward / Ping）。
    /// - 对于 Forward，调用 handle_forward 获取 Incoming，推送到目标 peer。
    pub async fn run(self: Arc<Self>) -> CoreResult<()> {
        debug!("relay 服务端开始接受连接");
        loop {
            match self.endpoint.accept().await {
                Some(incoming) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        match incoming.await {
                            Ok(conn) => {
                                debug!(addr = %conn.remote_address(), "relay 收到客户端连接");
                                this.handle_connection(conn).await;
                            }
                            Err(e) => {
                                warn!(error = %e, "客户端连接握手失败");
                            }
                        }
                    });
                }
                None => {
                    debug!("endpoint 已关闭，退出接受循环");
                    break;
                }
            }
        }
        Ok(())
    }

    /// 处理单个客户端连接。
    ///
    /// 每个连接独立 task，循环接受 bi-stream 请求。
    /// 连接断开时清理本连接注册的所有 peer 并广播 PeerOffline。
    async fn handle_connection(&self, conn: Connection) {
        let remote_addr = conn.remote_address();
        // 本连接注册的 peer 集合（用于断开时清理 + 广播 PeerOffline）
        let conn_peers: Arc<Mutex<HashSet<PeerId>>> = Arc::new(Mutex::new(HashSet::new()));
        // 本连接的唯一标识（用于 cleanup 时区分重连后的新通道）
        let conn_token: ConnToken = Arc::new(());
        loop {
            match conn.accept_bi().await {
                Ok((send, recv)) => {
                    let server = self.server.clone();
                    let push_channels = self.push_channels.clone();
                    let conn_clone = conn.clone();
                    let conn_peers = conn_peers.clone();
                    let conn_token = conn_token.clone();
                    tokio::spawn(async move {
                        Self::handle_request(
                            server,
                            push_channels,
                            conn_clone,
                            conn_peers,
                            conn_token,
                            send,
                            recv,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    debug!(error = %e, addr = %remote_addr, "客户端连接关闭");
                    // 清理本连接的 peer 并广播 PeerOffline
                    Self::cleanup_connection(&self.push_channels, &conn_peers, &conn_token);
                    break;
                }
            }
        }
    }

    /// 处理单个 bi-stream 请求。
    async fn handle_request(
        server: Arc<RelayServer>,
        push_channels: Arc<Mutex<HashMap<PeerId, (PushChannel, ConnToken)>>>,
        conn: Connection,
        conn_peers: Arc<Mutex<HashSet<PeerId>>>,
        conn_token: ConnToken,
        send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        // 读取请求
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 4096];
        loop {
            match recv.read(&mut chunk).await {
                Ok(Some(0)) | Ok(None) => break,
                Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => {
                    debug!(error = %e, "读取请求失败");
                    return;
                }
            }
        }
        if buf.is_empty() {
            return;
        }
        let msg = match RelayMessage::from_bytes(&buf) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "解析请求失败");
                return;
            }
        };

        // 处理请求并生成响应
        let (response, maybe_peer_id) = match &msg {
            RelayMessage::Register(req) => match server.handle_register(&req.proof) {
                Ok(session_id) => {
                    let peer_id = PeerId::new(&req.proof.peer_id);
                    (RelayMessage::RegisterOk { session_id }, Some(peer_id))
                }
                Err(e) => {
                    warn!(error = %e, "注册失败");
                    (
                        RelayMessage::RegisterDenied {
                            reason: e.to_string(),
                        },
                        None,
                    )
                }
            },
            RelayMessage::Forward(req) => {
                // 验证 session 并获取 from_peer_id
                let from_peer_id = match server.get_session_peer(&req.session_id) {
                    Some(pid) => pid,
                    None => {
                        let resp = RelayMessage::ForwardFailed {
                            reason: "session 不存在".into(),
                        };
                        Self::send_response(send, &resp).await;
                        return;
                    }
                };
                // 调用 handle_forward 获取 Incoming 消息
                match server.handle_forward(req) {
                    Ok(RelayMessage::Incoming { data, .. }) => {
                        // 推送到目标 peer
                        let target = PeerId::new(&req.target_peer_id);
                        let incoming = RelayMessage::Incoming {
                            from_peer_id: from_peer_id.as_str().to_string(),
                            data,
                        };
                        let pushed = Self::push_to_peer(&push_channels, &target, incoming);
                        let resp = if pushed {
                            RelayMessage::ForwardOk
                        } else {
                            RelayMessage::ForwardFailed {
                                reason: "目标 peer 不在线".into(),
                            }
                        };
                        (resp, None)
                    }
                    Ok(other) => (other, None),
                    Err(e) => {
                        warn!(error = %e, "转发失败");
                        (
                            RelayMessage::ForwardFailed {
                                reason: e.to_string(),
                            },
                            None,
                        )
                    }
                }
            }
            RelayMessage::Ping => (RelayMessage::Pong, None),
            _ => {
                debug!("忽略不支持的请求类型");
                return;
            }
        };

        // 注册推送通道（对于 Register 成功的 peer）
        if let Some(peer_id) = maybe_peer_id {
            let (tx, rx) = mpsc::channel(256);
            let is_new = {
                let mut channels = push_channels.lock();
                let existed = channels.contains_key(&peer_id);
                channels.insert(peer_id.clone(), (tx, conn_token.clone()));
                !existed
            };
            // 记录到本连接的 peer 集合（用于断开时清理 + 广播 PeerOffline）
            conn_peers.lock().insert(peer_id.clone());
            // 启动推送发送 task
            let conn_clone = conn.clone();
            let peer_id_clone = peer_id.clone();
            tokio::spawn(async move {
                Self::run_push_sender(conn_clone, rx, peer_id_clone).await;
            });
            // 新 peer 上线：向其他已注册 peer 广播 PeerOnline
            if is_new {
                info!(peer = %peer_id, "peer 上线，通知其他已注册 peer");
                Self::broadcast_to_others(
                    &push_channels,
                    &peer_id,
                    RelayMessage::PeerOnline {
                        peer_id: peer_id.as_str().to_string(),
                    },
                );
            }
        }

        Self::send_response(send, &response).await;
    }

    /// 运行推送发送 task：从 channel 读取消息，通过 uni-stream 发送给客户端。
    async fn run_push_sender(
        conn: Connection,
        mut rx: mpsc::Receiver<RelayMessage>,
        peer_id: PeerId,
    ) {
        while let Some(msg) = rx.recv().await {
            match conn.open_uni().await {
                Ok(mut send) => {
                    let bytes = match msg.to_bytes() {
                        Ok(b) => b,
                        Err(e) => {
                            error!(error = %e, peer = %peer_id, "序列化推送消息失败");
                            continue;
                        }
                    };
                    if let Err(e) = send.write_all(&bytes).await {
                        debug!(error = %e, peer = %peer_id, "推送写入失败");
                        break;
                    }
                    if let Err(e) = send.finish() {
                        debug!(error = %e, peer = %peer_id, "推送 finish 失败");
                        break;
                    }
                }
                Err(e) => {
                    debug!(error = %e, peer = %peer_id, "打开推送 stream 失败，连接已关闭");
                    break;
                }
            }
        }
        debug!(peer = %peer_id, "推送发送 task 退出");
    }

    /// 推送消息给目标 peer。
    ///
    /// 使用 `try_send` 非阻塞写入有界通道；通道满或已关闭时记录 warn 并丢弃，
    /// 避免慢消费者阻塞服务端。返回是否成功入队。
    fn push_to_peer(
        push_channels: &Arc<Mutex<HashMap<PeerId, (PushChannel, ConnToken)>>>,
        target: &PeerId,
        msg: RelayMessage,
    ) -> bool {
        let channels = push_channels.lock();
        if let Some((tx, _)) = channels.get(target) {
            match tx.try_send(msg) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(peer = %target, "推送通道已满（256），丢弃消息");
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!(peer = %target, "推送通道已关闭，丢弃消息");
                    false
                }
            }
        } else {
            false
        }
    }

    /// 向除 `exclude` 外的所有已注册 peer 广播消息（用于 PeerOnline / PeerOffline）。
    ///
    /// 同样使用 `try_send`，通道满时记录 warn 并丢弃，不阻塞服务端。
    fn broadcast_to_others(
        push_channels: &Arc<Mutex<HashMap<PeerId, (PushChannel, ConnToken)>>>,
        exclude: &PeerId,
        msg: RelayMessage,
    ) {
        let channels = push_channels.lock();
        for (pid, (tx, _)) in channels.iter() {
            if pid == exclude {
                continue;
            }
            if let Err(e) = tx.try_send(msg.clone()) {
                warn!(peer = %pid, error = %e, "广播推送失败，丢弃消息");
            }
        }
    }

    /// 发送响应到 bi-stream。
    async fn send_response(mut send: quinn::SendStream, msg: &RelayMessage) {
        match msg.to_bytes() {
            Ok(bytes) => {
                if let Err(e) = send.write_all(&bytes).await {
                    debug!(error = %e, "发送响应失败");
                }
                if let Err(e) = send.finish() {
                    debug!(error = %e, "finish 响应失败");
                }
            }
            Err(e) => {
                error!(error = %e, "序列化响应失败");
            }
        }
    }

    /// 清理已断开连接的客户端。
    ///
    /// 移除本连接注册的所有 peer，并向剩余已注册 peer 广播 PeerOffline。
    /// 通过 `ConnToken` 身份比较，避免误删重连后新建的通道。
    fn cleanup_connection(
        push_channels: &Arc<Mutex<HashMap<PeerId, (PushChannel, ConnToken)>>>,
        conn_peers: &Arc<Mutex<HashSet<PeerId>>>,
        conn_token: &ConnToken,
    ) {
        let peers: Vec<PeerId> = conn_peers.lock().drain().collect();
        for peer_id in peers {
            let removed = {
                let mut channels = push_channels.lock();
                // 仅当通道仍属于本连接时才移除（避免误删重连后的新通道）
                let is_ours = channels
                    .get(&peer_id)
                    .map(|(_, t)| Arc::ptr_eq(t, conn_token))
                    .unwrap_or(false);
                if is_ours {
                    channels.remove(&peer_id);
                    true
                } else {
                    false
                }
            };
            if removed {
                info!(peer = %peer_id, "peer 下线，通知其他已注册 peer");
                Self::broadcast_to_others(
                    push_channels,
                    &peer_id,
                    RelayMessage::PeerOffline {
                        peer_id: peer_id.as_str().to_string(),
                    },
                );
            }
        }
    }

    /// 关闭服务端。
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"server closing");
        // 关闭所有推送通道
        let mut channels = self.push_channels.lock();
        channels.clear();
    }

    /// 获取在线 peer 数。
    pub fn online_count(&self) -> usize {
        self.push_channels.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relay_end_to_end_forward() {
        // 生成共享证书
        let (cert, key) = generate_self_signed_cert().unwrap();
        let client_config = make_client_config(cert.clone()).unwrap();

        // 启动 relay 服务端
        let secret = b"relay_e2e_secret".to_vec();
        let runner = Arc::new(
            RelayServerRunner::with_cert(secret.clone(), "127.0.0.1:0".parse().unwrap(), cert, key)
                .await
                .unwrap(),
        );
        let server_addr = runner.local_addr().unwrap();

        // 启动服务端接受循环
        let runner_clone = runner.clone();
        tokio::spawn(async move {
            runner_clone.run().await.unwrap();
        });

        // 等待服务端就绪
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 创建 client1
        let client1 = RelayClientTransport::new(PeerId::new("1"), secret.clone(), server_addr)
            .await
            .unwrap();
        client1.set_default_client_config(client_config.clone());
        client1.connect_and_register().await.unwrap();
        assert!(client1.is_registered());

        // 创建 client2，设置推送回调
        let client2 = RelayClientTransport::new(PeerId::new("2"), secret.clone(), server_addr)
            .await
            .unwrap();
        let received = Arc::new(Mutex::new(Vec::<RelayPushEvent>::new()));
        let received_clone = received.clone();
        client2.set_push_handler(move |event| {
            received_clone.lock().push(event);
        });
        client2.set_default_client_config(client_config);
        client2.connect_and_register().await.unwrap();
        assert!(client2.is_registered());

        // 等待注册完成并推送通道建立
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // client1 通过 relay 转发数据给 client2
        let data = b"hello via relay e2e".to_vec();
        client1
            .forward(&PeerId::new("2"), data.clone())
            .await
            .unwrap();

        // 等待 client2 收到推送
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let events = received.lock();
        assert_eq!(events.len(), 1, "client2 应收到 1 条推送");
        match &events[0] {
            RelayPushEvent::Incoming {
                from_peer_id,
                data: recv_data,
            } => {
                assert_eq!(*from_peer_id, PeerId::new("1"));
                assert_eq!(recv_data, &data);
            }
            _ => panic!("期望 Incoming 事件"),
        }
    }

    #[tokio::test]
    async fn relay_client_disconnect() {
        let (cert, key) = generate_self_signed_cert().unwrap();
        let client_config = make_client_config(cert.clone()).unwrap();
        let secret = b"relay_disc_secret".to_vec();
        let runner = Arc::new(
            RelayServerRunner::with_cert(secret.clone(), "127.0.0.1:0".parse().unwrap(), cert, key)
                .await
                .unwrap(),
        );
        let server_addr = runner.local_addr().unwrap();
        let runner_clone = runner.clone();
        tokio::spawn(async move {
            runner_clone.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = RelayClientTransport::new(PeerId::new("1"), secret, server_addr)
            .await
            .unwrap();
        client.set_default_client_config(client_config);
        client.connect_and_register().await.unwrap();
        assert!(client.is_registered());

        client.disconnect().await;
        assert!(!client.is_registered());
    }

    #[tokio::test]
    async fn relay_forward_to_offline_fails() {
        let (cert, key) = generate_self_signed_cert().unwrap();
        let client_config = make_client_config(cert.clone()).unwrap();
        let secret = b"relay_offline_secret".to_vec();
        let runner = Arc::new(
            RelayServerRunner::with_cert(secret.clone(), "127.0.0.1:0".parse().unwrap(), cert, key)
                .await
                .unwrap(),
        );
        let server_addr = runner.local_addr().unwrap();
        let runner_clone = runner.clone();
        tokio::spawn(async move {
            runner_clone.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = RelayClientTransport::new(PeerId::new("1"), secret, server_addr)
            .await
            .unwrap();
        client.set_default_client_config(client_config);
        client.connect_and_register().await.unwrap();

        // 转发给不在线的 peer，应失败
        let result = client.forward(&PeerId::new("999"), vec![1, 2, 3]).await;
        assert!(result.is_err(), "转发给不在线 peer 应失败");
    }

    #[test]
    fn convert_push_event_incoming() {
        let msg = RelayMessage::Incoming {
            from_peer_id: "1".into(),
            data: vec![1, 2, 3],
        };
        let event = convert_push_event(&msg).unwrap();
        match event {
            RelayPushEvent::Incoming { from_peer_id, data } => {
                assert_eq!(from_peer_id, PeerId::new("1"));
                assert_eq!(data, vec![1, 2, 3]);
            }
            _ => panic!("期望 Incoming"),
        }
    }

    #[test]
    fn convert_push_event_peer_online() {
        let msg = RelayMessage::PeerOnline {
            peer_id: "2".into(),
        };
        let event = convert_push_event(&msg).unwrap();
        match event {
            RelayPushEvent::PeerOnline { peer_id } => {
                assert_eq!(peer_id, PeerId::new("2"));
            }
            _ => panic!("期望 PeerOnline"),
        }
    }

    #[tokio::test]
    async fn relay_peer_online_offline_notification() {
        // 验证：新 peer 注册时向其他 peer 推送 PeerOnline，
        //       peer 断开时向剩余 peer 推送 PeerOffline。
        let (cert, key) = generate_self_signed_cert().unwrap();
        let client_config = make_client_config(cert.clone()).unwrap();
        let secret = b"relay_online_secret".to_vec();
        let runner = Arc::new(
            RelayServerRunner::with_cert(secret.clone(), "127.0.0.1:0".parse().unwrap(), cert, key)
                .await
                .unwrap(),
        );
        let server_addr = runner.local_addr().unwrap();
        let runner_clone = runner.clone();
        tokio::spawn(async move {
            runner_clone.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // client1 先注册，并设置推送回调（在 client2 注册之前，以便捕获 PeerOnline）
        let client1 = RelayClientTransport::new(PeerId::new("1"), secret.clone(), server_addr)
            .await
            .unwrap();
        client1.set_default_client_config(client_config.clone());
        let received = Arc::new(Mutex::new(Vec::<RelayPushEvent>::new()));
        let received_clone = received.clone();
        client1.set_push_handler(move |event| {
            received_clone.lock().push(event);
        });
        client1.connect_and_register().await.unwrap();
        assert!(client1.is_registered());

        // client2 注册 → 服务端应向 client1 推送 PeerOnline { peer_id: "2" }
        let client2 = RelayClientTransport::new(PeerId::new("2"), secret.clone(), server_addr)
            .await
            .unwrap();
        client2.set_default_client_config(client_config);
        client2.connect_and_register().await.unwrap();
        assert!(client2.is_registered());

        // 等待 PeerOnline 推送送达
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        {
            let events = received.lock();
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    RelayPushEvent::PeerOnline { peer_id } if *peer_id == PeerId::new("2")
                )),
                "client1 应收到 client2 的 PeerOnline 通知, events = {:?}",
                *events
            );
        }

        // client2 断开 → 服务端应向 client1 推送 PeerOffline { peer_id: "2" }
        client2.disconnect().await;
        // 等待服务端检测到连接关闭并广播 PeerOffline
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        {
            let events = received.lock();
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    RelayPushEvent::PeerOffline { peer_id } if *peer_id == PeerId::new("2")
                )),
                "client1 应收到 client2 的 PeerOffline 通知, events = {:?}",
                *events
            );
            // 顺序校验：PeerOnline 必须在 PeerOffline 之前
            let online_idx = events
                .iter()
                .position(|e| matches!(e, RelayPushEvent::PeerOnline { peer_id } if *peer_id == PeerId::new("2")));
            let offline_idx = events
                .iter()
                .position(|e| matches!(e, RelayPushEvent::PeerOffline { peer_id } if *peer_id == PeerId::new("2")));
            assert!(
                online_idx.is_some() && offline_idx.is_some() && online_idx < offline_idx,
                "PeerOnline 应在 PeerOffline 之前"
            );
        }

        // 清理：断开 client1，停止其心跳 task
        client1.disconnect().await;
    }

    #[tokio::test]
    async fn relay_ping_pong_roundtrip() {
        // 验证心跳路径：客户端通过 bi-stream 发送 Ping，服务端回复 Pong。
        let (cert, key) = generate_self_signed_cert().unwrap();
        let client_config = make_client_config(cert.clone()).unwrap();
        let secret = b"relay_ping_secret".to_vec();
        let runner = Arc::new(
            RelayServerRunner::with_cert(secret.clone(), "127.0.0.1:0".parse().unwrap(), cert, key)
                .await
                .unwrap(),
        );
        let server_addr = runner.local_addr().unwrap();
        let runner_clone = runner.clone();
        tokio::spawn(async move {
            runner_clone.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = RelayClientTransport::new(PeerId::new("1"), secret, server_addr)
            .await
            .unwrap();
        client.set_default_client_config(client_config);
        client.connect_and_register().await.unwrap();

        // 直接通过 bi-stream 发送 Ping，验证收到 Pong（心跳 send_ping 的核心路径）
        let resp = client.request_response(&RelayMessage::Ping).await.unwrap();
        assert!(matches!(resp, RelayMessage::Pong), "期望 Pong 响应");

        client.disconnect().await;
    }

    /// 建立 Noise 会话对（initiator → responder），用于 E2E 加密测试。
    fn establish_e2e_sessions() -> (Session, Session) {
        use tacit_crypto::{DeviceIdentity, NoiseHandshake};

        let id1 = DeviceIdentity::generate().unwrap();
        let id2 = DeviceIdentity::generate().unwrap();

        let mut init = NoiseHandshake::initiator(id1.static_keypair().private.as_slice()).unwrap();
        let mut resp = NoiseHandshake::responder(id2.static_keypair().private.as_slice()).unwrap();

        let msg1 = init.step(None).unwrap();
        let msg2 = resp.step(Some(&msg1)).unwrap();
        let msg3 = init.step(Some(&msg2)).unwrap();
        let _ = resp.step(Some(&msg3)).unwrap();

        let r1 = init.into_transport().unwrap();
        let r2 = resp.into_transport().unwrap();
        (r1.session, r2.session)
    }

    #[tokio::test]
    async fn relay_e2e_encrypted_forward() {
        // 验证：注册 Session 后，relay 转发的 payload 被 E2E 加密，
        // relay 服务端仅看到密文，接收端自动解密还原明文。
        let (cert, key) = generate_self_signed_cert().unwrap();
        let client_config = make_client_config(cert.clone()).unwrap();
        let secret = b"relay_e2e_enc_secret".to_vec();
        let runner = Arc::new(
            RelayServerRunner::with_cert(secret.clone(), "127.0.0.1:0".parse().unwrap(), cert, key)
                .await
                .unwrap(),
        );
        let server_addr = runner.local_addr().unwrap();
        let runner_clone = runner.clone();
        tokio::spawn(async move {
            runner_clone.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 建立 Noise 会话对
        let (session1, session2) = establish_e2e_sessions();

        // 创建 client1，注册到 peer2 的 session
        let client1 = RelayClientTransport::new(PeerId::new("1"), secret.clone(), server_addr)
            .await
            .unwrap();
        client1.set_default_client_config(client_config.clone());
        client1.register_session(PeerId::new("2"), session1);
        client1.connect_and_register().await.unwrap();

        // 创建 client2，注册到 peer1 的 session
        let client2 = RelayClientTransport::new(PeerId::new("2"), secret.clone(), server_addr)
            .await
            .unwrap();
        let received = Arc::new(Mutex::new(Vec::<RelayPushEvent>::new()));
        let received_clone = received.clone();
        client2.set_push_handler(move |event| {
            received_clone.lock().push(event);
        });
        client2.register_session(PeerId::new("1"), session2);
        client2.set_default_client_config(client_config);
        client2.connect_and_register().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // client1 通过 relay 转发数据给 client2（payload 被自动加密）
        let data = b"secret via e2e relay".to_vec();
        client1
            .forward(&PeerId::new("2"), data.clone())
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let events = {
            let guard = received.lock();
            guard.clone()
        };
        assert_eq!(events.len(), 1, "client2 应收到 1 条推送");
        match &events[0] {
            RelayPushEvent::Incoming {
                from_peer_id,
                data: recv_data,
            } => {
                assert_eq!(*from_peer_id, PeerId::new("1"));
                // 收到的应是解密后的原始明文
                assert_eq!(recv_data, &data, "E2E 解密后数据应匹配原始明文");
            }
            _ => panic!("期望 Incoming 事件"),
        }

        client1.disconnect().await;
        client2.disconnect().await;
    }

    #[tokio::test]
    async fn relay_e2e_unencrypted_backward_compatible() {
        // 验证：未注册 session 时，仍以明文传输（向后兼容）。
        let (cert, key) = generate_self_signed_cert().unwrap();
        let client_config = make_client_config(cert.clone()).unwrap();
        let secret = b"relay_compat_secret".to_vec();
        let runner = Arc::new(
            RelayServerRunner::with_cert(secret.clone(), "127.0.0.1:0".parse().unwrap(), cert, key)
                .await
                .unwrap(),
        );
        let server_addr = runner.local_addr().unwrap();
        let runner_clone = runner.clone();
        tokio::spawn(async move {
            runner_clone.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 不注册 session — 明文传输
        let client1 = RelayClientTransport::new(PeerId::new("1"), secret.clone(), server_addr)
            .await
            .unwrap();
        client1.set_default_client_config(client_config.clone());
        client1.connect_and_register().await.unwrap();

        let client2 = RelayClientTransport::new(PeerId::new("2"), secret.clone(), server_addr)
            .await
            .unwrap();
        let received = Arc::new(Mutex::new(Vec::<RelayPushEvent>::new()));
        let received_clone = received.clone();
        client2.set_push_handler(move |event| {
            received_clone.lock().push(event);
        });
        client2.set_default_client_config(client_config);
        client2.connect_and_register().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let data = b"plaintext via relay".to_vec();
        client1
            .forward(&PeerId::new("2"), data.clone())
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let events = {
            let guard = received.lock();
            guard.clone()
        };
        assert_eq!(events.len(), 1);
        match &events[0] {
            RelayPushEvent::Incoming {
                from_peer_id,
                data: recv_data,
            } => {
                assert_eq!(*from_peer_id, PeerId::new("1"));
                assert_eq!(recv_data, &data);
            }
            _ => panic!("期望 Incoming 事件"),
        }

        client1.disconnect().await;
        client2.disconnect().await;
    }
}
