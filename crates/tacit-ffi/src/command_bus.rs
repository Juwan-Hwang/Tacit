//! CommandBus：UI 线程发命令到 Rust 内部队列。
//!
//! v1.0 规范线程模型：
//! - UI 线程通过 CommandBus 发送命令（非阻塞）。
//! - RuntimeSupervisor 在后台线程消费命令并执行。
//! - 命令结果通过 EventBus 回传。
//!
//! 使用 crossbeam-channel 实现有界队列，避免 UI 线程无限堆积命令。

use std::time::Duration;

use crossbeam_channel::{bounded, unbounded, Receiver, Sender, TryRecvError};
use parking_lot::Mutex;
use tacit_core::{BlockId, DocId, PeerId, SyncReason};

/// 命令队列容量（有界）。
const DEFAULT_COMMAND_CAPACITY: usize = 256;

/// UI 线程发送给 Rust 内部的命令。
#[derive(Debug, Clone)]
pub enum Command {
    /// 创建文档。
    CreateDocument {
        doc_id: DocId,
        kind: String,
    },
    /// 创建 block。
    CreateBlock {
        doc_id: DocId,
        block_id: BlockId,
        kind: String,
    },
    /// 应用用户编辑。
    ApplyUserEdit {
        doc_id: DocId,
        block_id: BlockId,
        edit_bytes: Vec<u8>,
    },
    /// 请求 fast-resume。
    RequestFastResume,
    /// 请求同步。
    RequestSync {
        peer_id: PeerId,
        reason: SyncReason,
    },
    /// 通知 peer 上线。
    PeerOnline {
        peer_id: PeerId,
    },
    /// 通知网络状态变化。
    NetworkChanged {
        online: bool,
        net_type: String,
    },
    /// 触发 Hot-Path 模式。
    TriggerHotPath,
    /// 退出 Hot-Path 模式。
    ExitHotPath,
    /// 关闭引擎。
    Shutdown,
}

/// 命令总线：UI 线程发送命令的通道。
#[derive(Debug, Clone)]
pub struct CommandBus {
    tx: Sender<Command>,
    rx: Receiver<Command>,
}

impl CommandBus {
    /// 创建有界命令总线。
    pub fn bounded(capacity: usize) -> Self {
        let (tx, rx) = bounded(capacity);
        Self { tx, rx }
    }

    /// 创建无界命令总线（用于测试）。
    pub fn unbounded() -> Self {
        let (tx, rx) = unbounded();
        Self { tx, rx }
    }

    /// 使用默认容量创建。
    pub fn new() -> Self {
        Self::bounded(DEFAULT_COMMAND_CAPACITY)
    }

    /// 发送命令（非阻塞，队列满时返回错误）。
    pub fn try_send(&self, cmd: Command) -> Result<(), CommandBusError> {
        self.tx
            .try_send(cmd)
            .map_err(|e| match e {
                crossbeam_channel::TrySendError::Full(_) => CommandBusError::QueueFull,
                crossbeam_channel::TrySendError::Disconnected(_) => CommandBusError::Disconnected,
            })
    }

    /// 发送命令（阻塞等待，带超时）。
    pub fn send_timeout(&self, cmd: Command, timeout: Duration) -> Result<(), CommandBusError> {
        self.tx
            .send_timeout(cmd, timeout)
            .map_err(|e| match e {
                crossbeam_channel::SendTimeoutError::Timeout(_) => CommandBusError::Timeout,
                crossbeam_channel::SendTimeoutError::Disconnected(_) => CommandBusError::Disconnected,
            })
    }

    /// 接收端引用（供 RuntimeSupervisor 消费）。
    pub fn receiver(&self) -> &Receiver<Command> {
        &self.rx
    }

    /// 非阻塞尝试接收一条命令。
    pub fn try_recv(&self) -> Option<Command> {
        match self.rx.try_recv() {
            Ok(cmd) => Some(cmd),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        }
    }
}

impl Default for CommandBus {
    fn default() -> Self {
        Self::new()
    }
}

/// 命令总线错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandBusError {
    /// 队列已满。
    #[error("命令队列已满")]
    QueueFull,
    /// 队列已断开。
    #[error("命令队列已断开")]
    Disconnected,
    /// 发送超时。
    #[error("命令发送超时")]
    Timeout,
}

/// 命令缓冲区：批量收集命令（减少锁竞争）。
pub struct CommandBuffer {
    buffer: Mutex<Vec<Command>>,
    bus: CommandBus,
    flush_threshold: usize,
}

impl CommandBuffer {
    pub fn new(bus: CommandBus, flush_threshold: usize) -> Self {
        Self {
            buffer: Mutex::new(Vec::new()),
            bus,
            flush_threshold,
        }
    }

    /// 添加命令到缓冲区，达到阈值时自动 flush。
    pub fn push(&self, cmd: Command) -> Result<(), CommandBusError> {
        let should_flush = {
            let mut buf = self.buffer.lock();
            buf.push(cmd);
            buf.len() >= self.flush_threshold
        };
        if should_flush {
            self.flush()?;
        }
        Ok(())
    }

    /// 将缓冲区所有命令发送到总线。
    pub fn flush(&self) -> Result<(), CommandBusError> {
        let cmds: Vec<Command> = {
            let mut buf = self.buffer.lock();
            std::mem::take(&mut *buf)
        };
        for cmd in cmds {
            self.bus.try_send(cmd)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_and_recv() {
        let bus = CommandBus::unbounded();
        bus.try_send(Command::RequestFastResume).unwrap();
        let cmd = bus.try_recv().unwrap();
        assert!(matches!(cmd, Command::RequestFastResume));
    }

    #[test]
    fn bounded_queue_full() {
        let bus = CommandBus::bounded(1);
        bus.try_send(Command::RequestFastResume).unwrap();
        let result = bus.try_send(Command::RequestFastResume);
        assert_eq!(result, Err(CommandBusError::QueueFull));
    }

    #[test]
    fn try_recv_empty() {
        let bus = CommandBus::unbounded();
        assert!(bus.try_recv().is_none());
    }

    #[test]
    fn command_buffer_flushes_at_threshold() {
        let bus = CommandBus::unbounded();
        let buffer = CommandBuffer::new(bus.clone(), 2);
        buffer.push(Command::RequestFastResume).unwrap();
        // 未达阈值，不应 flush
        assert!(bus.try_recv().is_none());
        buffer.push(Command::RequestFastResume).unwrap();
        // 达阈值，应 flush
        assert!(bus.try_recv().is_some());
    }

    #[test]
    fn command_buffer_manual_flush() {
        let bus = CommandBus::unbounded();
        let buffer = CommandBuffer::new(bus.clone(), 100);
        buffer.push(Command::RequestFastResume).unwrap();
        assert!(bus.try_recv().is_none());
        buffer.flush().unwrap();
        assert!(bus.try_recv().is_some());
    }
}
