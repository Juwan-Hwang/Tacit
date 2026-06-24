//! RuntimeSupervisor：运行时监督器。
//!
//! v1.0 规范线程模型：
//! - 管理 CommandBus 消费循环。
//! - 驱动 SyncEngine 处理命令。
//! - 监控后台任务健康状态。
//! - 提供优雅关闭（drain 命令队列后退出）。
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

/// RuntimeSupervisor 配置。
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// 命令消费循环的轮询间隔。
    pub poll_interval: Duration,
    /// 依赖等待重试间隔。
    pub pending_retry_interval: Duration,
    /// 动作分发间隔。
    pub drain_interval: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(10),
            pending_retry_interval: Duration::from_secs(1),
            drain_interval: Duration::from_millis(50),
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
/// 需要在 tokio runtime 上下文中启动。
pub struct RuntimeSupervisor {
    command_bus: CommandBus,
    event_bus: Arc<EventBus>,
    config: RuntimeConfig,
    state: Mutex<RuntimeState>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl RuntimeSupervisor {
    pub fn new(
        command_bus: CommandBus,
        event_bus: Arc<EventBus>,
        config: RuntimeConfig,
    ) -> Self {
        Self {
            command_bus,
            event_bus,
            config,
            state: Mutex::new(RuntimeState::Initialized),
            handles: Mutex::new(Vec::new()),
        }
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

        // 命令消费循环
        let cmd_bus = self.command_bus.clone();
        let event_bus = self.event_bus.clone();
        let engine_clone = engine.clone();
        let self_clone = self.clone();
        let handle = tokio::spawn(async move {
            self_clone.command_loop(engine_clone, cmd_bus, event_bus).await;
        });
        self.handles.lock().push(handle);

        // 依赖等待重试循环
        let engine_clone = engine.clone();
        let config = self.config.clone();
        let self_clone = self.clone();
        let handle = tokio::spawn(async move {
            self_clone.periodic_task(engine_clone, config.pending_retry_interval, move |eng| {
                eng.process_pending()
            }).await;
        });
        self.handles.lock().push(handle);

        // 动作分发循环
        let engine_clone = engine.clone();
        let config = self.config.clone();
        let self_clone = self.clone();
        let handle = tokio::spawn(async move {
            self_clone.periodic_task(engine_clone, config.drain_interval, move |eng| {
                eng.drain_actions().map(|_| ())
            }).await;
        });
        self.handles.lock().push(handle);

        Ok(())
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
            // 检查状态
            let state = self.state();
            if state == RuntimeState::Stopped {
                break;
            }

            // 非阻塞接收命令
            match cmd_bus.try_recv() {
                Some(cmd) => {
                    if let Err(e) = self.execute_command(&engine, &cmd) {
                        warn!(error = %e, "命令执行失败");
                        event_bus.publish(&tacit_core::CoreEvent::ErrorRaised {
                            scope: tacit_core::ErrorScope::Sync,
                            message: e.to_string(),
                        });
                    }
                }
                None => {
                    // 无命令，短暂休眠
                    tokio::time::sleep(self.config.poll_interval).await;
                }
            }

            // Shutdown 命令后 drain 完毕则退出
            if state == RuntimeState::ShuttingDown {
                // 检查队列是否已空
                if cmd_bus.try_recv().is_none() {
                    break;
                }
            }
        }
        debug!("命令消费循环退出");
    }

    /// 定期任务循环。
    async fn periodic_task<F>(
        &self,
        engine: Arc<crate::TacitEngine>,
        interval: Duration,
        task: F,
    ) where
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
            let _ = tokio::task::spawn_blocking(move || task(&eng))
                .await;
            tokio::time::sleep(interval).await;
        }
    }

    /// 执行单条命令。
    fn execute_command(
        &self,
        engine: &crate::TacitEngine,
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
            } => engine.create_block(
                doc_id.as_str().to_string(),
                block_id.as_str().to_string(),
                kind.clone(),
            ),
            ApplyUserEdit {
                doc_id,
                block_id,
                edit_bytes,
            } => engine.apply_user_edit(
                doc_id.as_str().to_string(),
                block_id.as_str().to_string(),
                edit_bytes.clone(),
            ),
            RequestFastResume => engine.request_fast_resume(),
            RequestSync { peer_id, reason: _ } => {
                engine.on_peer_online(peer_id.as_str().to_string())
            }
            PeerOnline { peer_id } => {
                engine.on_peer_online(peer_id.as_str().to_string())
            }
            NetworkChanged { online, net_type } => engine.notify_network_changed(
                *online,
                net_type.clone(),
            ),
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
}
