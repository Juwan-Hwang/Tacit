//! RuntimeSupervisor：运行时监督器。
//!
//! v1.0 规范线程模型：
//! - 管理 CommandBus 消费循环。
//! - 驱动 SyncEngine 处理命令。
//! - 监控后台任务健康状态。
//! - 提供优雅关闭（drain 命令队列后退出）。
//! - 持有 Tokio runtime，使集成层无需自建 runtime 即可运行后台任务。
//!
//! RuntimeSupervisor 在独立 tokio 任务中运行，消费 CommandBus 的命令并
//! 调用 TacitEngine 的方法执行。它还负责定期触发 process_pending 和
//! drain_actions，确保依赖等待重试和动作分发及时执行。

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tacit_core::CoreResult;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::command_bus::{Command, CommandBus};
use crate::event_bus::EventBus;
use tacit_core::DocId;

/// RuntimeSupervisor 配置。
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// 命令消费循环的轮询间隔。
    pub poll_interval: Duration,
    /// 依赖等待重试间隔。
    pub pending_retry_interval: Duration,
    /// 动作分发间隔。
    pub drain_interval: Duration,
    /// checkpoint compaction 检查间隔。
    pub compaction_interval: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(10),
            pending_retry_interval: Duration::from_secs(1),
            drain_interval: Duration::from_millis(50),
            compaction_interval: Duration::from_secs(60),
        }
    }
}

/// RuntimeSupervisor 状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    /// 已创建未启动。
    Initialized,
    /// 运行中。
    Running,
    /// 正在关闭（drain 命令队列）。
    ShuttingDown,
    /// 已停止。
    Stopped,
}

/// RuntimeSupervisor：管理后台任务生命周期。
///
/// 持有 Tokio runtime，使集成层无需自建 runtime 即可运行后台任务。
/// 也可在已有 tokio runtime 上下文中使用（此时不持有自有 runtime）。
pub struct RuntimeSupervisor {
    command_bus: CommandBus,
    event_bus: Arc<EventBus>,
    config: RuntimeConfig,
    state: Mutex<RuntimeState>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    /// 自有的 Tokio runtime（可选）。
    /// 若由 `with_runtime` 创建则持有；若在外部 tokio 上下文中使用则为 None。
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

impl RuntimeSupervisor {
    /// 创建 RuntimeSupervisor（不持有自有 runtime，需在外部 tokio 上下文中启动）。
    pub fn new(command_bus: CommandBus, event_bus: Arc<EventBus>, config: RuntimeConfig) -> Self {
        Self {
            command_bus,
            event_bus,
            config,
            state: Mutex::new(RuntimeState::Initialized),
            handles: Mutex::new(Vec::new()),
            runtime: Mutex::new(None),
        }
    }

    /// 创建持有自有 Tokio runtime 的 RuntimeSupervisor。
    ///
    /// 集成层无需自建 tokio runtime 即可调用 `start()`。
    /// runtime 在 `stop()` 或 drop 时自动释放。
    pub fn with_runtime(
        command_bus: CommandBus,
        event_bus: Arc<EventBus>,
        config: RuntimeConfig,
    ) -> CoreResult<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                tacit_core::CoreError::Internal(format!("创建 Tokio runtime 失败: {e}"))
            })?;
        Ok(Self {
            command_bus,
            event_bus,
            config,
            state: Mutex::new(RuntimeState::Initialized),
            handles: Mutex::new(Vec::new()),
            runtime: Mutex::new(Some(runtime)),
        })
    }

    /// 获取命令总线引用（供 UI 线程发送命令）。
    pub fn command_bus(&self) -> &CommandBus {
        &self.command_bus
    }

    /// 获取事件总线引用。
    pub fn event_bus(&self) -> &Arc<EventBus> {
        &self.event_bus
    }

    /// 当前状态。
    pub fn state(&self) -> RuntimeState {
        *self.state.lock()
    }

    /// 启动后台任务循环。
    ///
    /// `engine`：TacitEngine 引用，用于执行命令。
    ///
    /// 若 RuntimeSupervisor 持有自有 runtime，则在该 runtime 上启动任务；
    /// 否则需在已有 tokio runtime 上下文中调用。
    pub fn start(self: &Arc<Self>, engine: Arc<crate::TacitEngine>) -> CoreResult<()> {
        {
            let mut state = self.state.lock();
            if *state != RuntimeState::Initialized {
                return Err(tacit_core::CoreError::Sync(format!(
                    "RuntimeSupervisor 状态不是 Initialized: {:?}",
                    *state
                )));
            }
            *state = RuntimeState::Running;
        }
        info!("RuntimeSupervisor 启动");

        // 若持有自有 runtime，在其上下文中 spawn 任务
        let runtime_guard = self.runtime.lock();
        if let Some(rt) = runtime_guard.as_ref() {
            let self_clone = self.clone();
            let engine_clone = engine.clone();
            let handle = rt.handle().spawn(async move {
                self_clone.command_loop_inner(engine_clone).await;
            });
            self.handles.lock().push(handle);

            let self_clone = self.clone();
            let engine_clone = engine.clone();
            let interval = self.config.pending_retry_interval;
            let handle = rt.handle().spawn(async move {
                self_clone
                    .periodic_task_inner(engine_clone, interval, |eng| eng.process_pending())
                    .await;
            });
            self.handles.lock().push(handle);

            let self_clone = self.clone();
            let engine_clone = engine.clone();
            let interval = self.config.drain_interval;
            let handle = rt.handle().spawn(async move {
                self_clone
                    .periodic_task_inner(engine_clone, interval, |eng| {
                        eng.drain_actions().map(|_| ())
                    })
                    .await;
            });
            self.handles.lock().push(handle);

            // checkpoint compaction 定期检查
            let self_clone = self.clone();
            let engine_clone = engine.clone();
            let interval = self.config.compaction_interval;
            let handle = rt.handle().spawn(async move {
                self_clone
                    .periodic_task_inner(engine_clone, interval, |eng| {
                        eng.maybe_compact_all().map(|_| ())
                    })
                    .await;
            });
            self.handles.lock().push(handle);
        } else {
            drop(runtime_guard);
            // 使用当前 tokio 上下文
            let cmd_bus = self.command_bus.clone();
            let event_bus = self.event_bus.clone();
            let engine_clone = engine.clone();
            let self_clone = self.clone();
            let handle = tokio::spawn(async move {
                self_clone
                    .command_loop(engine_clone, cmd_bus, event_bus)
                    .await;
            });
            self.handles.lock().push(handle);

            let engine_clone = engine.clone();
            let config = self.config.clone();
            let self_clone = self.clone();
            let handle = tokio::spawn(async move {
                self_clone
                    .periodic_task(engine_clone, config.pending_retry_interval, move |eng| {
                        eng.process_pending()
                    })
                    .await;
            });
            self.handles.lock().push(handle);

            let engine_clone = engine.clone();
            let config = self.config.clone();
            let self_clone = self.clone();
            let handle = tokio::spawn(async move {
                self_clone
                    .periodic_task(engine_clone, config.drain_interval, move |eng| {
                        eng.drain_actions().map(|_| ())
                    })
                    .await;
            });
            self.handles.lock().push(handle);

            // checkpoint compaction 定期检查
            let engine_clone = engine.clone();
            let config = self.config.clone();
            let self_clone = self.clone();
            let handle = tokio::spawn(async move {
                self_clone
                    .periodic_task(engine_clone, config.compaction_interval, move |eng| {
                        eng.maybe_compact_all().map(|_| ())
                    })
                    .await;
            });
            self.handles.lock().push(handle);
        }

        Ok(())
    }

    /// 命令消费循环（使用内部持有的 command_bus 和 event_bus）。
    async fn command_loop_inner(&self, engine: Arc<crate::TacitEngine>) {
        let cmd_bus = self.command_bus.clone();
        let event_bus = self.event_bus.clone();
        self.command_loop(engine, cmd_bus, event_bus).await;
    }

    /// 命令消费循环。
    async fn command_loop(
        &self,
        engine: Arc<crate::TacitEngine>,
        cmd_bus: CommandBus,
        event_bus: Arc<EventBus>,
    ) {
        debug!("命令消费循环启动");
        loop {
            let state = self.state();
            if state == RuntimeState::Stopped {
                break;
            }

            // 非阻塞接收命令
            match cmd_bus.try_recv() {
                Some(cmd) => {
                    if let Err(e) = self.execute_command(&engine, &cmd).await {
                        warn!(error = %e, "命令执行失败");
                        event_bus.publish(&tacit_core::CoreEvent::ErrorRaised {
                            scope: tacit_core::ErrorScope::Sync,
                            message: e.to_string(),
                        });
                    }
                }
                None => {
                    // 无命令可处理
                    if state == RuntimeState::ShuttingDown {
                        // drain 完成：队列已空，可以退出
                        debug!("命令队列已 drain 完毕，退出消费循环");
                        break;
                    }
                    // 正常运行：短暂休眠后继续轮询
                    tokio::time::sleep(self.config.poll_interval).await;
                }
            }
        }
        debug!("命令消费循环退出");
    }

    /// 定期任务循环（内部引用版本）。
    async fn periodic_task_inner<F>(
        &self,
        engine: Arc<crate::TacitEngine>,
        interval: Duration,
        task: F,
    ) where
        F: Fn(&crate::TacitEngine) -> CoreResult<()> + Send + Sync + 'static,
    {
        self.periodic_task(engine, interval, task).await;
    }

    /// 定期任务循环。
    async fn periodic_task<F>(&self, engine: Arc<crate::TacitEngine>, interval: Duration, task: F)
    where
        F: Fn(&crate::TacitEngine) -> CoreResult<()> + Send + Sync + 'static,
    {
        let task = Arc::new(task);
        loop {
            let state = self.state();
            if state == RuntimeState::Stopped || state == RuntimeState::ShuttingDown {
                break;
            }
            let task = task.clone();
            let eng = engine.clone();
            // 在阻塞线程池中执行（避免阻塞 tokio runtime）
            let _ = tokio::task::spawn_blocking(move || task(&eng)).await;
            tokio::time::sleep(interval).await;
        }
    }

    /// 执行单条命令。
    ///
    /// 对于 ApplyUserEdit 和 CreateBlock 命令，通过 DocExecutorRegistry 路由到
    /// per-doc actor 串行执行，确保同一文档的操作串行化、不同文档可并发。
    /// 其他命令直接同步执行。
    async fn execute_command(
        &self,
        engine: &Arc<crate::TacitEngine>,
        cmd: &Command,
    ) -> CoreResult<()> {
        use Command::*;

        match cmd {
            CreateDocument { doc_id, kind } => {
                engine.create_document(doc_id.as_str().to_string(), kind.clone())
            }
            CreateBlock {
                doc_id,
                block_id,
                kind,
            } => {
                // 通过 per-doc actor 串行执行，确保同一文档的操作不并发
                let engine_clone = engine.clone();
                let doc_id_owned = doc_id.as_str().to_string();
                let block_id_owned = block_id.as_str().to_string();
                let kind_owned = kind.clone();
                let doc_id_for_actor = DocId::new(&doc_id_owned);
                engine
                    .doc_executor()
                    .submit(&doc_id_for_actor, move || {
                        engine_clone.create_block(
                            doc_id_owned.clone(),
                            block_id_owned.clone(),
                            kind_owned.clone(),
                        )
                    })
                    .await
            }
            ApplyUserEdit {
                doc_id,
                block_id,
                edit_bytes,
            } => {
                // 通过 per-doc actor 串行执行，避免并发 CRDT 损坏
                // 大导入也通过 actor 异步执行，不阻塞命令循环
                let engine_clone = engine.clone();
                let doc_id_owned = doc_id.as_str().to_string();
                let block_id_owned = block_id.as_str().to_string();
                let edit_owned = edit_bytes.clone();
                let doc_id_for_actor = DocId::new(&doc_id_owned);

                // 大导入检测：超过 1MB 记录 warn 日志
                if edit_owned.len() > 1024 * 1024 {
                    warn!(
                        doc_id = %doc_id_owned,
                        block_id = %block_id_owned,
                        size = edit_owned.len(),
                        "大导入通过 per-doc actor 异步执行"
                    );
                }

                engine
                    .doc_executor()
                    .submit(&doc_id_for_actor, move || {
                        engine_clone.apply_user_edit(
                            doc_id_owned.clone(),
                            block_id_owned.clone(),
                            edit_owned,
                        )
                    })
                    .await
            }
            RequestFastResume => engine.request_fast_resume(),
            RequestSync { peer_id, reason: _ } => {
                engine.on_peer_online(peer_id.as_str().to_string())
            }
            PeerOnline { peer_id } => engine.on_peer_online(peer_id.as_str().to_string()),
            NetworkChanged { online, net_type } => {
                engine.notify_network_changed(*online, net_type.clone())
            }
            TriggerHotPath => {
                engine.trigger_hot_path();
                Ok(())
            }
            ExitHotPath => {
                engine.exit_hot_path();
                Ok(())
            }
            Shutdown => {
                self.initiate_shutdown();
                Ok(())
            }
        }
    }

    /// 发起优雅关闭：切换到 ShuttingDown 状态，drain 命令队列后停止。
    pub fn initiate_shutdown(&self) {
        let mut state = self.state.lock();
        if *state == RuntimeState::Running {
            *state = RuntimeState::ShuttingDown;
            info!("RuntimeSupervisor 发起优雅关闭");
        }
    }

    /// 强制停止：中止所有后台任务。
    pub fn stop(&self) {
        {
            let mut state = self.state.lock();
            *state = RuntimeState::Stopped;
        }
        let mut handles = self.handles.lock();
        for handle in handles.drain(..) {
            handle.abort();
        }
        // 释放 handles 后再 drop runtime，
        // 确保 runtime drop 时所有 task 已被 abort（会在下一个 .await 点退出）。
        drop(handles);
        let mut runtime = self.runtime.lock();
        if let Some(rt) = runtime.take() {
            drop(rt);
        }
        info!("RuntimeSupervisor 已停止");
    }
}

impl Drop for RuntimeSupervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_core::DocId;

    #[tokio::test]
    async fn supervisor_starts_and_stops() {
        let engine = Arc::new(crate::TacitEngine::new_memory("1").unwrap());
        let cmd_bus = CommandBus::unbounded();
        let event_bus = Arc::new(EventBus::new());
        let supervisor = Arc::new(RuntimeSupervisor::new(
            cmd_bus,
            event_bus,
            RuntimeConfig::default(),
        ));

        supervisor.start(engine.clone()).unwrap();
        assert_eq!(supervisor.state(), RuntimeState::Running);

        // 短暂运行
        tokio::time::sleep(Duration::from_millis(50)).await;

        supervisor.stop();
        assert_eq!(supervisor.state(), RuntimeState::Stopped);
    }

    #[tokio::test]
    async fn command_executed_via_bus() {
        let engine = Arc::new(crate::TacitEngine::new_memory("1").unwrap());
        let cmd_bus = CommandBus::unbounded();
        let event_bus = Arc::new(EventBus::new());
        let supervisor = Arc::new(RuntimeSupervisor::new(
            cmd_bus.clone(),
            event_bus,
            RuntimeConfig {
                poll_interval: Duration::from_millis(1),
                ..Default::default()
            },
        ));

        supervisor.start(engine.clone()).unwrap();

        // 发送创建文档命令
        cmd_bus
            .try_send(Command::CreateDocument {
                doc_id: DocId::new("d1"),
                kind: "note".into(),
            })
            .unwrap();

        // 等待命令执行
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 验证文档已创建
        let view = engine.open_document("d1".into()).unwrap();
        assert_eq!(view.doc_id, "d1");

        supervisor.stop();
    }

    #[tokio::test]
    async fn shutdown_command_triggers_shutdown() {
        let engine = Arc::new(crate::TacitEngine::new_memory("1").unwrap());
        let cmd_bus = CommandBus::unbounded();
        let event_bus = Arc::new(EventBus::new());
        let supervisor = Arc::new(RuntimeSupervisor::new(
            cmd_bus.clone(),
            event_bus,
            RuntimeConfig {
                poll_interval: Duration::from_millis(1),
                ..Default::default()
            },
        ));

        supervisor.start(engine).unwrap();
        cmd_bus.try_send(Command::Shutdown).unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(supervisor.state(), RuntimeState::ShuttingDown);
        supervisor.stop();
    }

    #[test]
    fn with_runtime_starts_without_external_tokio() {
        // 验证 with_runtime 创建的 supervisor 无需外部 tokio 上下文即可启动
        let engine = Arc::new(crate::TacitEngine::new_memory("1").unwrap());
        let cmd_bus = CommandBus::unbounded();
        let event_bus = Arc::new(EventBus::new());
        let supervisor = Arc::new(
            RuntimeSupervisor::with_runtime(
                cmd_bus.clone(),
                event_bus,
                RuntimeConfig {
                    poll_interval: Duration::from_millis(1),
                    ..Default::default()
                },
            )
            .unwrap(),
        );

        supervisor.start(engine.clone()).unwrap();
        assert_eq!(supervisor.state(), RuntimeState::Running);

        // 发送命令并等待执行
        cmd_bus
            .try_send(Command::CreateDocument {
                doc_id: DocId::new("d_rt"),
                kind: "note".into(),
            })
            .unwrap();

        // 等待命令执行（在自有 runtime 上）
        std::thread::sleep(Duration::from_millis(100));

        let view = engine.open_document("d_rt".into()).unwrap();
        assert_eq!(view.doc_id, "d_rt");

        supervisor.stop();
        assert_eq!(supervisor.state(), RuntimeState::Stopped);
    }

    #[tokio::test]
    async fn event_bus_receives_events() {
        // 验证 EventBus 与引擎事件分发桥接
        let engine = Arc::new(crate::TacitEngine::new_memory("1").unwrap());
        let (_, rx) = engine.event_bus().subscribe();

        // 触发网络变化事件
        engine
            .notify_network_changed(false, "offline".into())
            .unwrap();

        // EventBus 应收到事件
        let event = rx.try_recv().unwrap();
        assert!(matches!(
            event,
            tacit_core::CoreEvent::PeerStatusChanged { .. }
        ));
    }

    #[tokio::test]
    async fn send_command_via_engine() {
        // 验证 TacitEngine::send_command 入队命令
        let engine = crate::TacitEngine::new_memory("1").unwrap();
        engine.send_command(Command::RequestFastResume).unwrap();

        // 命令应在总线中
        let cmd = engine.command_bus().try_recv().unwrap();
        assert!(matches!(cmd, Command::RequestFastResume));
    }
}
