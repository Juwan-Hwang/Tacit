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
use tokio::time::timeout;
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
    /// 心跳 task 的关闭信号（disconnect 时发送）。
    heartbeat_shutdown: Mutex<Option<oneshot::Sender<()>>>,
    /// 连接锁：串行化整个 connect_and_register 过程（含网络连接+注册），
    /// 防止并发重连创建多个 QUIC 连接和竞态条件。
    /// 使用 tokio 异步锁以跨 .await 持有。
    connect_lock: tokio::sync::Mutex<()>,
    /// relay 服务端层级。
    tier: RelayTier,
    /// E2E 加密会话表：peer_id -> Session。
    ///
    /// 由集成层在 Noise 握手完成后注入。注册后，所有经 relay 转发的
    /// payload（帧类型 + JSON）会被透明加密/解密，relay 服务端仅看到密文。
    /// 未注册 session 的 peer 通信将被拒绝（强制 E2E 加密）。
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
            heartbeat_shutdown: Mutex::new(None),
            connect_lock: tokio::sync::Mutex::new(()),
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

    /// 加密 payload。若该 peer 未注册 session，返回错误（强制 E2E 加密）。
    fn encrypt_if_session(&self, peer_id: &PeerId, plaintext: Vec<u8>) -> CoreResult<Vec<u8>> {
        match self.sessions.read().get(peer_id) {
            Some(session) => {
                let mut s = session.lock();
                s.encrypt(&plaintext)
            }
            None => Err(CoreError::Transport(format!(
                "peer {peer_id} 未注册 E2E 加密会话，拒绝明文传输"
            ))),
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
        // 异步锁：串行化整个连接+注册过程，防止并发重连创建多个 QUIC 连接。
        let _connect_guard = self.connect_lock.lock().await;

        // 建立 QUIC 连接
        let client_config = self.client_config.read().clone();
        let conn = self
            .endpoint
            .connect_with(client_config, self.relay_addr, "tacit")
            .map_err(|e| CoreError::Transport(format!("发起连接失败: {e}")))?
            .await
            .map_err(|e| CoreError::Transport(format!("连接 relay 失败: {e}")))?;
        debug!(addr = %self.relay_addr, "已连接 relay 服务端");

        // 使用局部 conn 完成注册——仅在注册完全成功后才更新 self.conn。
        // 这样若注册失败，self.conn 保持旧值（或 None），reconnect_peer 不会误判连接正常。
        // 注册失败时显式关闭 conn，防止 QUIC 连接泄漏。
        let register_msg = match self.client.create_register_message() {
            Ok(msg) => msg,
            Err(e) => {
                conn.close(0u32.into(), b"register message creation failed");
                return Err(e);
            }
        };
        let response = match self.request_response(&conn, &register_msg).await {
            Ok(resp) => resp,
            Err(e) => {
                conn.close(0u32.into(), b"registration request failed");
                return Err(e);
            }
        };
        if let Err(e) = self.client.handle_register_response(&response) {
            conn.close(0u32.into(), b"registration response rejected");
            return Err(e);
        }

        // 整个 connect_and_register 过程已由 connect_lock 串行化保护

        // 注册成功后，替换 self.conn 并关闭旧连接。
        if let Some(old) = self.conn.write().replace(conn.clone()) {
            debug!("重连：显式关闭旧 relay 连接");
            old.close(0u32.into(), b"superseded by reconnect");
        }

        // 启动后台接收 task。
        self.start_recv_loop(conn.clone());

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
    /// 接受外部传入的 `conn`，使调用方可以在更新 `self.conn` 之前完成注册。
    ///
    /// 整个流程（open_bi + write + read）受 15s 超时保护，
    /// 防止 relay 服务端无响应时无限阻塞。
    async fn request_response(
        &self,
        conn: &quinn::Connection,
        msg: &RelayMessage,
    ) -> CoreResult<RelayMessage> {
        timeout(Duration::from_secs(15), async {
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
            // 读取响应（限制 10MB 防止 OOM DoS）
            const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 4096];
            loop {
                match recv.read(&mut chunk).await {
                    Ok(Some(0)) | Ok(None) => break,
                    Ok(Some(n)) => {
                        if buf.len() + n > MAX_RESPONSE_SIZE {
                            return Err(CoreError::Transport("响应大小超过 10MB 限制".into()));
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) => return Err(CoreError::Transport(format!("读取响应失败: {e}"))),
                }
            }
            RelayMessage::from_bytes(&buf)
        })
        .await
        .map_err(|_| CoreError::Transport("请求-响应超时（15s）".into()))?
    }

    /// 启动后台接收 task，处理 relay 主动推送的消息。
    ///
    /// relay 通过 uni-stream 推送 Incoming / PeerOnline / PeerOffline。
    ///
    /// **并发读取 + per-peer 重排序 + 全局读取 watermark**：
    /// 1. **并发读取**：每条 uni-stream 由独立 task 并发读取（含 5s 超时），
    ///    避免 HoL 阻塞 accept 循环。
    /// 2. **全局读取 watermark**：`read_watermark = N` 表示 seq 0..=N 的流
    ///    均已读取完毕（含超时占位）。watermark 推进不丢弃任何消息。
    /// 3. **Per-peer 重排序**：每个 peer 独立的 `BTreeMap<seq, data>`，
    ///    仅处理 `seq <= read_watermark` 的消息，确保按序解密。
    ///    不同 peer 互不阻塞（仅在等待 watermark 推进时等待）。
    /// 4. **超时处理**：流读取超时时发送占位消息（空 peer_id）推进
    ///    watermark，不阻塞后续消息处理。丢失的加密消息会导致该 peer
    ///    的 Noise 解密失败，由解密错误处理逻辑触发会话重建。
    ///
    /// **与旧设计的关键区别**：无 512 跳进逻辑——永不丢弃消息，
    /// watermark 仅在实际读取完成（或超时占位）时推进。
    ///
    /// **注意**：回调 `h(event)` 在解密 task 中同步调用，必须快速返回。
    fn start_recv_loop(&self, conn: Connection) {
        let push_handler = self.push_handler.clone();
        let sessions = self.sessions.clone();

        // 解密/分发队列：(accept_seq, Option<RelayMessage>)
        // None = 占位（超时/空流/解析失败），仅推进 watermark
        // Some(msg) = 实际消息（Incoming 或 PeerOnline/PeerOffline）
        let (dispatch_tx, mut dispatch_rx) = mpsc::channel::<(u64, Option<RelayMessage>)>(256);

        // ── 串行解密/分发消费者（统一排序） ──
        // 所有消息（Incoming + PeerOnline/PeerOffline）按 seq 顺序处理，
        // 消除并发读取导致的 PeerOnline/PeerOffline 乱序风险。
        let handler_for_dispatch = push_handler.clone();
        let sessions_for_dispatch = sessions.clone();
        tokio::spawn(async move {
            // 全局读取 watermark：所有 seq <= watermark 的流均已读取完毕。
            let mut read_watermark: Option<u64> = None;
            let mut pending_seqs: BTreeSet<u64> = BTreeSet::new();

            // 全局消息缓冲：seq -> RelayMessage（按 seq 排序）
            let mut msg_buffer: BTreeMap<u64, RelayMessage> = BTreeMap::new();

            while let Some((seq, msg_opt)) = dispatch_rx.recv().await {
                // ── 推进全局读取 watermark ──
                match read_watermark {
                    None => {
                        if seq == 0 {
                            let mut mc = 0u64;
                            while pending_seqs.remove(&(mc + 1)) {
                                mc += 1;
                            }
                            read_watermark = Some(mc);
                        } else {
                            pending_seqs.insert(seq);
                        }
                    }
                    Some(mc) => {
                        if seq <= mc {
                            // 重复/过期，忽略
                        } else if seq == mc + 1 {
                            let mut new_mc = seq;
                            while pending_seqs.remove(&(new_mc + 1)) {
                                new_mc += 1;
                            }
                            read_watermark = Some(new_mc);
                        } else {
                            pending_seqs.insert(seq);
                        }
                    }
                }

                // 缓冲实际消息
                if let Some(msg) = msg_opt {
                    msg_buffer.insert(seq, msg);
                }

                // ── 按 seq 顺序处理所有可消费的消息 ──
                let mc = match read_watermark {
                    Some(m) => m,
                    None => continue,
                };

                let mut to_process: Vec<(u64, RelayMessage)> = Vec::new();
                while let Some((&min_seq, _)) = msg_buffer.iter().next() {
                    if min_seq <= mc {
                        let msg = msg_buffer.remove(&min_seq).unwrap();
                        to_process.push((min_seq, msg));
                    } else {
                        break;
                    }
                }

                // ── 串行处理（解密 + 分发） ──
                for (_, msg) in to_process {
                    match msg {
                        RelayMessage::Incoming { from_peer_id, data } => {
                            let from = PeerId::new(&from_peer_id);
                            let decrypted = match sessions_for_dispatch.read().get(&from) {
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
                                None => {
                                    warn!(
                                        peer = %from,
                                        "未注册 E2E 加密会话，丢弃明文消息",
                                    );
                                    continue;
                                }
                            };
                            let incoming = RelayMessage::Incoming {
                                from_peer_id,
                                data: decrypted,
                            };
                            if let Some(event) = convert_push_event(&incoming) {
                                let handler = handler_for_dispatch.read();
                                if let Some(h) = handler.as_ref() {
                                    h(event);
                                }
                            }
                        }
                        // 非加密消息（PeerOnline / PeerOffline）直接分发
                        other => {
                            if let Some(event) = convert_push_event(&other) {
                                let handler = handler_for_dispatch.read();
                                if let Some(h) = handler.as_ref() {
                                    h(event);
                                }
                            }
                        }
                    }
                }
            }
        });

        // ── Accept + 并发读取循环 ──
        // 并发读取避免 HoL 阻塞；每条流有 5s 读取超时 + 10MB 大小限制防止 DoS。
        let accept_seq = Arc::new(AtomicU64::new(0));
        tokio::spawn(async move {
            loop {
                match conn.accept_uni().await {
                    Ok(mut stream) => {
                        let dispatch_tx = dispatch_tx.clone();
                        let seq = accept_seq.fetch_add(1, Ordering::Relaxed);
                        tokio::spawn(async move {
                            // 5s 读取超时 + 10MB 大小限制：防止 DoS
                            const MAX_PUSH_STREAM_SIZE: usize = 10 * 1024 * 1024;
                            let read_result = timeout(Duration::from_secs(5), async {
                                let mut buf = Vec::new();
                                let mut chunk = vec![0u8; 4096];
                                loop {
                                    match stream.read(&mut chunk).await {
                                        Ok(Some(0)) | Ok(None) => break,
                                        Ok(Some(n)) => {
                                            if buf.len() + n > MAX_PUSH_STREAM_SIZE {
                                                warn!("推送流大小超过 10MB 限制");
                                                return Err(());
                                            }
                                            buf.extend_from_slice(&chunk[..n]);
                                        }
                                        Err(e) => {
                                            debug!(error = %e, "读取推送流失败");
                                            return Err(());
                                        }
                                    }
                                }
                                Ok(buf)
                            })
                            .await;

                            let buf = match read_result {
                                Ok(Ok(buf)) => buf,
                                Ok(Err(())) => {
                                    let _ = dispatch_tx.send((seq, None)).await;
                                    return;
                                }
                                Err(_) => {
                                    warn!("读取推送流超时（5s），发送占位推进 watermark");
                                    let _ = dispatch_tx.send((seq, None)).await;
                                    return;
                                }
                            };

                            if buf.is_empty() {
                                let _ = dispatch_tx.send((seq, None)).await;
                                return;
                            }
                            match RelayMessage::from_bytes(&buf) {
                                Ok(msg) => {
                                    // 所有消息统一通过队列按 seq 顺序处理
                                    let _ = dispatch_tx.send((seq, Some(msg))).await;
                                }
                                Err(e) => {
                                    warn!(error = %e, "解析推送消息失败");
                                    let _ = dispatch_tx.send((seq, None)).await;
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
        let conn = self
            .conn
            .read()
            .clone()
            .ok_or_else(|| CoreError::Transport("未连接 relay 服务端".into()))?;
        let response = self.request_response(&conn, &forward_msg).await?;
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

        // 建立 E2E 加密会话
        let (session1, session2) = establish_e2e_sessions();

        // 创建 client1，注册到 peer2 的 session
        let client1 = RelayClientTransport::new(PeerId::new("1"), secret.clone(), server_addr)
            .await
            .unwrap();
        client1.set_default_client_config(client_config.clone());
        client1.register_session(PeerId::new("2"), session1);
        client1.connect_and_register().await.unwrap();
        assert!(client1.is_registered());

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
        let conn = client.conn.read().clone().unwrap();
        let resp = client
            .request_response(&conn, &RelayMessage::Ping)
            .await
            .unwrap();
        assert!(matches!(resp, RelayMessage::Pong), "期望 Pong 响应");

        client.disconnect().await;
    }

    /// 建立 Noise 会话对（initiator → responder），用于 E2E 加密测试。
    fn establish_e2e_sessions() -> (Session, Session) {
        use std::sync::Arc;
        use tacit_crypto::{DeviceIdentity, NoiseHandshake, NonceCache};

        let id1 = DeviceIdentity::generate().unwrap();
        let id2 = DeviceIdentity::generate().unwrap();

        let cache = Arc::new(NonceCache::new());
        let local_id1 = Some((id1.public_key(), *id1.binding_proof()));
        let local_id2 = Some((id2.public_key(), *id2.binding_proof()));
        let mut init = NoiseHandshake::initiator(
            id1.static_keypair().private.as_slice(),
            b"tacit-test-v1",
            cache.clone(),
            local_id1,
        )
        .unwrap();
        let mut resp = NoiseHandshake::responder(
            id2.static_keypair().private.as_slice(),
            b"tacit-test-v1",
            cache,
            local_id2,
        )
        .unwrap();

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
}
