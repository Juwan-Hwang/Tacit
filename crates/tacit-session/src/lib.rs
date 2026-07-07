//! Tacit-session：引擎↔传输接线层。
//!
//! 持有 [`DefaultSyncEngine`] + [`SyncTransport`]，提供完整的同步执行闭环：
//!
//! - **出站** ([`SyncSession::drive_outbound`])：`drain_actions()` → `transport.send_data/send_control`
//! - **入站** ([`SyncSession::handle_transport_event`])：`TransportEvent` → engine handlers
//!
//! ## 为什么这是 Rust 的职责
//!
//! `SyncAction`（引擎输出）和 `SyncTransport::send_data`（传输输入）都是 Rust 契约。
//! 在 Rust 层接线意味着编译器保证二者类型一致，而非等到宿主侧运行时才发现不匹配。
//!
//! 零平台依赖——不接触 BLE/Keychain/UI，纯算法胶水。
//! 宿主 App 仍负责传输选择/配置、平台密钥存储、进程生命周期。

mod codec;
mod loopback;

pub use codec::{decode_payload, encode_payload};
pub use loopback::LoopbackTransport;

use std::sync::Arc;

use std::sync::atomic::{AtomicU32, Ordering};
use tacit_core::{CoreResult, DataFrame, DataFrameKind, PeerId, Priority, SessionId, SyncReason};
use tacit_sync::{DefaultSyncEngine, SyncAction, SyncEngine};
use tacit_transport::{ControlMsg, NeedRanges, PathPreference, SyncTransport, TransportEvent};

/// Session 层 DataFrame 的固定 session_id。
/// session 管理由传输层/宿主负责，session 层不维护会话状态。
const SESSION_ID: SessionId = SessionId(0);

/// 引擎↔传输接线器。
///
/// 持有 `Arc<DefaultSyncEngine>` 和 `Arc<dyn SyncTransport>`，提供：
///
/// - [`drive_outbound`](Self::drive_outbound)：消费引擎的 `drain_actions()` 输出，
///   将 `SendData`/`SendControl`/`RequestDelta` 路由到传输层。
/// - [`handle_transport_event`](Self::handle_transport_event)：接收传输层事件，
///   将 `Data`/`Control`/`PeerOnline` 等路由到引擎的入站 handler。
///
/// ## 线程安全
///
/// `SyncSession` 内部用 `AtomicU32` 维护帧序号，可安全跨线程共享。
/// `drive_outbound` 是 `async fn`（因 `SyncTransport::send_data` 是 async）。
/// `handle_transport_event` 是同步方法（因 engine handler 全部同步）。
pub struct SyncSession {
    engine: Arc<DefaultSyncEngine>,
    transport: Arc<dyn SyncTransport>,
    seq: AtomicU32,
}

impl SyncSession {
    /// 创建 session。
    ///
    /// `engine` 和 `transport` 均以 `Arc` 传入，session 持有共享所有权。
    pub fn new(engine: Arc<DefaultSyncEngine>, transport: Arc<dyn SyncTransport>) -> Self {
        Self {
            engine,
            transport,
            seq: AtomicU32::new(0),
        }
    }

    /// 引擎引用。
    pub fn engine(&self) -> &Arc<DefaultSyncEngine> {
        &self.engine
    }

    /// 传输层引用。
    pub fn transport(&self) -> &Arc<dyn SyncTransport> {
        &self.transport
    }

    // ─── 出站：drain_actions → transport ───────────────────────────

    /// 消费引擎的 `drain_actions()` 输出，通过传输层发送。
    ///
    /// - `SendData` → 构造 `DataFrame`（payload 含 block_id 前缀）→ `transport.send_data()`
    /// - `SendControl` → `transport.send_control()`
    /// - `RequestDelta` → 转为 `ControlMsg::NeedRanges` → `transport.send_control()`
    /// - `EmitEvent` → 跳过（引擎内部已处理事件分发）
    ///
    /// 发送失败仅记 warn 日志，不中断后续动作——单条发送失败不应阻塞整个 drain 循环。
    pub async fn drive_outbound(&self) -> CoreResult<()> {
        let actions = self.engine.drain_actions();
        let mut delivered_ids: Vec<String> = Vec::new();
        for action in actions {
            match action {
                SyncAction::SendData {
                    peer_id,
                    doc_id,
                    block_id,
                    bytes,
                    priority,
                    path,
                    entry_id,
                } => {
                    let payload = match codec::encode_payload(block_id.as_ref(), &bytes) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::error!(doc = %doc_id, block = ?block_id, error = %e, "编码 payload 失败，跳过该动作");
                            // 标记 entry_id 为已投递，防止 store-and-forward 无限重试
                            if let Some(eid) = entry_id {
                                delivered_ids.push(eid);
                            }
                            continue;
                        }
                    };
                    let frame = DataFrame {
                        doc_id: doc_id.clone(),
                        actor_id: self.engine.peer_id().clone(),
                        seq: self.next_seq(),
                        kind: DataFrameKind::Delta,
                        payload: payload.into(),
                        session_id: SESSION_ID,
                    };
                    match self
                        .transport
                        .send_data(&peer_id, frame, priority, path)
                        .await
                    {
                        Ok(()) => {
                            // 成功发送后收集 entry_id，循环结束后批量标记 delivered，
                            // 避免 N 次 SQLite fsync 开销
                            if let Some(eid) = entry_id {
                                delivered_ids.push(eid);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(peer = %peer_id, error = %e, "发送数据帧失败");
                        }
                    }
                }
                SyncAction::SendControl {
                    peer_id,
                    msg,
                    priority,
                } => {
                    if let Err(e) = self.transport.send_control(&peer_id, msg, priority).await {
                        tracing::warn!(peer = %peer_id, error = %e, "发送控制消息失败");
                    }
                }
                SyncAction::RequestDelta {
                    peer_id,
                    doc_id,
                    block_id,
                    since,
                    priority,
                } => {
                    let msg = ControlMsg::NeedRanges(NeedRanges {
                        doc_id,
                        block_id: block_id.as_ref().map(|b| b.as_str().to_string()),
                        since,
                    });
                    if let Err(e) = self.transport.send_control(&peer_id, msg, priority).await {
                        tracing::warn!(peer = %peer_id, error = %e, "发送 NeedRanges 失败");
                    }
                }
                SyncAction::EmitEvent(_) => { /* 引擎内部已处理 */ }
            }
        }
        // 批量标记 delivered：将 N 次 fsync 合并为 1 次
        if !delivered_ids.is_empty() {
            let refs: Vec<&str> = delivered_ids.iter().map(|s| s.as_str()).collect();
            if let Err(e) = self.engine.store_forward().mark_delivered_batch(&refs) {
                tracing::warn!(error = %e, "批量标记 delivered 失败");
            }
        }
        Ok(())
    }

    // ─── 入站：TransportEvent → engine ─────────────────────────────

    /// 处理传输层事件，路由到引擎入站 handler。
    ///
    /// - `PeerOnline` → `engine.request_sync()`
    /// - `PeerOffline` → 记录日志（引擎下次 `drain_actions` 自然不再发往该 peer）
    /// - `Data` → 解码 payload → `engine.apply_remote_block_delta()` / `apply_remote_meta_delta()`
    /// - `Control` → 按 `ControlMsg` 变体分发到 `handle_introduce` / `handle_key_rotate` 等
    /// - `NetworkChanged` → 触发 fast-resume
    pub fn handle_transport_event(&self, event: TransportEvent) -> CoreResult<()> {
        match event {
            TransportEvent::PeerOnline { peer_id } => {
                tracing::info!(peer = %peer_id, "peer 上线");
                self.engine.request_sync(peer_id, SyncReason::PeerOnline)?;
            }
            TransportEvent::PeerOffline { peer_id } => {
                tracing::info!(peer = %peer_id, "peer 离线");
            }
            TransportEvent::Data { peer_id, frame } => {
                self.handle_inbound_data(&peer_id, &frame)?;
            }
            TransportEvent::Control { peer_id, msg } => {
                self.handle_inbound_control(&peer_id, msg)?;
            }
            TransportEvent::NetworkChanged { online } => {
                if online {
                    self.engine.fast_resume(None)?;
                }
                tracing::info!(online, "网络状态变化");
            }
            TransportEvent::DocSynced { peer_id, doc_id } => {
                tracing::debug!(peer = %peer_id, doc = %doc_id, "文档同步完成");
            }
        }
        Ok(())
    }

    /// 处理入站数据帧。
    ///
    /// 若 block 不存在，**不盲目创建**——盲目创建为 `BlockKind::Text` 会导致 CRDT 类型
    /// 不匹配（实际可能是 Todo/Settings/Log）。正确做法是跳过此 delta，等待
    /// Meta-Document 同步完成后由 `PendingBlockFetch` 自动拉取正确类型的 block。
    ///
    /// **所有错误均被捕获并记日志**——不传播错误，防止单个畸形帧导致整个 session 断开（DoS 防护）。
    fn handle_inbound_data(&self, peer_id: &PeerId, frame: &DataFrame) -> CoreResult<()> {
        // 信任验证：仅使用内存缓存（peer_states）。
        // 所有 Trusted peer 在 engine 启动时预加载到内存，新 Trusted peer 通过
        // Capabilities → on_peer_summary 进入内存。合法的 Trusted peer 必然已在缓存中。
        // 不做 DB fallback——恶意 peer 可通过高频伪造数据帧强制 DB 查询造成 DoS。
        if !self.engine.is_peer_trusted(peer_id) {
            tracing::warn!(peer = %peer_id, "拒绝未信任 peer 的数据帧");
            return Ok(());
        }

        let (block_id, delta_bytes) = match codec::decode_payload(&frame.payload) {
            Ok(res) => res,
            Err(e) => {
                tracing::error!(peer = %peer_id, error = %e, "解码 payload 失败，丢弃该帧");
                return Ok(());
            }
        };
        match block_id {
            Some(bid) => {
                match self.engine.apply_remote_block_delta(
                    &frame.doc_id,
                    &bid,
                    delta_bytes,
                    peer_id,
                ) {
                    Ok(()) => {}
                    Err(tacit_core::CoreError::BlockNotFound { .. }) => {
                        tracing::warn!(
                            peer = %peer_id, doc = %frame.doc_id, block = %bid,
                            "block 不存在，跳过 delta（等待 Meta-Document 同步后自动拉取）"
                        );
                    }
                    Err(e) => {
                        // DB/系统级错误向上传播，使传输层能断开连接或触发重试。
                        // 仅协议级错误（验证失败、数据畸形等）才丢弃以防 DoS。
                        if matches!(
                            e,
                            tacit_core::CoreError::Store(_) | tacit_core::CoreError::Internal(_)
                        ) {
                            return Err(e);
                        }
                        tracing::error!(
                            peer = %peer_id, doc = %frame.doc_id, block = %bid, error = %e,
                            "应用远程 block delta 失败，丢弃该帧以防止 DoS"
                        );
                    }
                }
            }
            None => {
                if let Err(e) =
                    self.engine
                        .apply_remote_meta_delta(&frame.doc_id, delta_bytes, peer_id)
                {
                    // DB/系统级错误向上传播，使传输层能断开连接或触发重试。
                    if matches!(
                        e,
                        tacit_core::CoreError::Store(_) | tacit_core::CoreError::Internal(_)
                    ) {
                        return Err(e);
                    }
                    tracing::error!(
                        peer = %peer_id, doc = %frame.doc_id, error = %e,
                        "应用远程 meta delta 失败，丢弃该帧以防止 DoS"
                    );
                }
            }
        }
        Ok(())
    }

    /// 处理入站控制消息。
    ///
    /// **所有错误均被捕获并记日志**——验证/授权失败不传播，防止单个畸形消息
    /// 导致整个 transport event handler 失败或断开连接（DoS 防护）。
    fn handle_inbound_control(&self, peer_id: &PeerId, msg: ControlMsg) -> CoreResult<()> {
        // 信任验证：Introduce、KeyRotate 和 Capabilities 有自己的身份/信任验证逻辑，
        // 其余消息要求 sender 已在 peer_states 中（即已信任且已交换过 summary）
        // Capabilities 豁免信任检查——它是新 Trusted peer 首次进入 peer_states 的入口
        // （on_peer_summary 内部会查 DB 验证信任状态）。DoS 防护由 engine 层的
        // untrusted_cache 负责缓存已验证为非 Trusted 的 peer ID，避免重复 DB 查询。
        let requires_trust = !matches!(
            msg,
            ControlMsg::Introduce(_) | ControlMsg::KeyRotate(_) | ControlMsg::Capabilities(_)
        );
        if requires_trust && !self.engine.is_peer_trusted(peer_id) {
            tracing::warn!(
                peer = %peer_id,
                "拒绝来自未信任 peer 的控制消息"
            );
            return Ok(());
        }

        let res = match msg {
            ControlMsg::Introduce(m) => self.engine.handle_introduce(&m, peer_id),
            ControlMsg::KeyRotate(m) => self.engine.handle_key_rotate(&m),
            ControlMsg::Revoke(m) => {
                if m.revoker != *peer_id {
                    tracing::warn!(
                        sender = %peer_id, claimed = %m.revoker,
                        "拒绝不匹配的 Revoke 消息以防止 spoofing"
                    );
                    return Ok(());
                }
                // 权限校验：只允许 self-revocation（peer 宣布自己退出）。
                // 撤销其他 peer 应由宿主应用通过本地 API 调用 handle_revoke。
                // 没有 admin/owner 角色时，允许任何 trusted peer 撤销其他人
                // 会导致恶意节点瘫痪整个同步网络。
                if m.revoker != m.revoked_peer {
                    tracing::warn!(
                        revoker = %m.revoker, revoked = %m.revoked_peer,
                        "拒绝非 self-revocation 的撤销请求（权限不足）"
                    );
                    return Ok(());
                }
                self.engine.handle_revoke(&m.revoked_peer, &m.reason)
            }
            ControlMsg::AckSummary(m) => {
                if m.peer_id != *peer_id {
                    tracing::warn!(
                        sender = %peer_id, claimed = %m.peer_id,
                        "拒绝不匹配的 AckSummary 消息以防止 spoofing"
                    );
                    return Ok(());
                }
                self.engine.handle_ack_summary(&m)
            }
            ControlMsg::NeedRanges(m) => self.handle_need_ranges(peer_id, m),
            ControlMsg::Capabilities(ann) => {
                if ann.peer_id != *peer_id {
                    tracing::warn!(
                        sender = %peer_id, claimed = %ann.peer_id,
                        "拒绝不匹配的 Capabilities 消息以防止 spoofing"
                    );
                    return Ok(());
                }
                let summary = tacit_core::PeerSummary {
                    peer_id: peer_id.clone(),
                    online: true,
                    frontier: ann.frontier.clone(),
                    capabilities: ann.capabilities,
                };
                self.engine.on_peer_summary(peer_id.clone(), summary)
            }
            ControlMsg::SyncIntent { peer_id: pid, .. } => {
                if pid != *peer_id {
                    tracing::warn!(
                        sender = %peer_id, claimed = %pid,
                        "拒绝不匹配的 SyncIntent 消息以防止 spoofing"
                    );
                    return Ok(());
                }
                self.engine.request_sync(pid, SyncReason::PeerOnline)
            }
            _ => {
                tracing::debug!(?msg, "未处理的控制消息");
                Ok(())
            }
        };

        if let Err(e) = res {
            // DB/系统级错误向上传播，使传输层能断开连接或触发重试。
            // 仅协议级错误（验证失败、数据畸形等）才丢弃以防 DoS。
            if matches!(
                e,
                tacit_core::CoreError::Store(_) | tacit_core::CoreError::Internal(_)
            ) {
                return Err(e);
            }
            tracing::warn!(peer = %peer_id, error = %e, "处理控制消息失败，丢弃以防 DoS");
        }
        Ok(())
    }

    /// 处理 NeedRanges：导出对端请求的 delta 并推入引擎动作队列。
    ///
    /// 下次 `drive_outbound()` 时会自动将导出的 delta 发送给对端。
    ///
    /// 若对端请求了不存在的 doc/block，仅记 warn 日志并返回 `Ok(())`，
    /// 不中断整个 transport event handler——避免恶意/异常对端通过无效
    /// NeedRanges 请求触发 DoS。
    fn handle_need_ranges(&self, peer_id: &PeerId, m: NeedRanges) -> CoreResult<()> {
        let doc_id = m.doc_id.clone();
        let block_id = m
            .block_id
            .as_ref()
            .map(|s| tacit_core::BlockId::new(s.clone()));
        let since = m.since.clone();

        let ds = self.engine.doc_store();
        let bytes_res = if let Some(bid) = &block_id {
            if since.is_empty() {
                ds.export_block_snapshot(&doc_id, bid)
            } else {
                ds.export_block_delta(&doc_id, bid, &since)
                    .or_else(|_| ds.export_block_snapshot(&doc_id, bid))
            }
        } else if since.is_empty() {
            ds.export_meta_snapshot(&doc_id)
        } else {
            ds.export_meta_delta(&doc_id, &since)
                .or_else(|_| ds.export_meta_snapshot(&doc_id))
        };

        let bytes = match bytes_res {
            Ok(b) => b,
            Err(e) => {
                // DB/系统级错误向上传播，使传输层能断开连接或触发重试。
                if matches!(
                    e,
                    tacit_core::CoreError::Store(_) | tacit_core::CoreError::Internal(_)
                ) {
                    return Err(e);
                }
                tracing::warn!(
                    peer = %peer_id, doc = %doc_id, error = %e,
                    "导出 delta/snapshot 失败，忽略该 NeedRanges 请求"
                );
                return Ok(());
            }
        };

        self.engine.push_action(SyncAction::SendData {
            peer_id: peer_id.clone(),
            doc_id,
            block_id,
            bytes,
            priority: Priority::Medium,
            path: PathPreference::Any,
            entry_id: None,
        });

        Ok(())
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }
}
