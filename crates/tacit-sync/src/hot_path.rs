//! Hot-Path Control：Apple 设备短暂唤醒时优先只处理控制信息。
//!
//! v1.0 规范：iOS/macOS 后台推送唤醒或短暂前台时，应优先处理：
//! - 控制帧（ack、能力协商、SyncIntent）
//! - presence 更新
//! - Meta-Document 小增量
//!
//! 避免在短暂唤醒窗口中触发大块数据传输（block delta、snapshot chunk），
//! 这些应等到设备进入稳定在线状态后再处理。
//!
//! 实现：维护一个"wake window"状态机，区分 Hot / Normal 两种模式。
//! - Hot 模式：仅处理控制类 SyncAction，数据类动作延后到 Normal 模式。
//! - Normal 模式：处理所有动作。

use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::engine::SyncAction;

/// Hot-Path 模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotPathMode {
    /// 热路径模式：仅处理控制类动作。
    Hot,
    /// 正常模式：处理所有动作。
    Normal,
}

/// 设备类型：不同平台的唤醒窗口差异较大。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceProfile {
    /// iOS：后台唤醒窗口极短（1-3 秒），系统启发式调度。
    Ios,
    /// Android：前台服务可保持较长连接，但后台仍受限。
    Android,
    /// Desktop：无需 Hot-Path 限制，可始终 Normal 模式。
    #[default]
    Desktop,
}

/// Hot-Path 控制器配置。
#[derive(Debug, Clone, Copy)]
pub struct HotPathConfig {
    /// Hot 模式持续时间窗口。超过此时间自动切换到 Normal。
    pub hot_window: Duration,
    /// 设备类型，用于确定默认 hot_window。
    pub device_profile: DeviceProfile,
}

impl HotPathConfig {
    /// 根据设备类型创建配置，自动选择合适的 hot_window。
    pub fn for_device(profile: DeviceProfile) -> Self {
        let hot_window = match profile {
            // iOS 后台唤醒窗口典型 1-3 秒，保守取 3 秒
            DeviceProfile::Ios => Duration::from_secs(3),
            // Android 后台窗口稍长，取 5 秒
            DeviceProfile::Android => Duration::from_secs(5),
            // Desktop 不需要 Hot-Path 限制，但仍提供默认值供统一接口
            DeviceProfile::Desktop => Duration::from_secs(5),
        };
        Self {
            hot_window,
            device_profile: profile,
        }
    }
}

impl Default for HotPathConfig {
    fn default() -> Self {
        Self::for_device(DeviceProfile::default())
    }
}

/// Hot-Path 控制器。
#[derive(Debug)]
pub struct HotPathController {
    mode: Mutex<HotPathMode>,
    hot_until: Mutex<Option<Instant>>,
    config: HotPathConfig,
}

impl HotPathController {
    pub fn new(config: HotPathConfig) -> Self {
        Self {
            mode: Mutex::new(HotPathMode::Normal),
            hot_until: Mutex::new(None),
            config,
        }
    }

    /// 触发 Hot 模式（例如设备被唤醒）。
    pub fn trigger_hot(&self) {
        let deadline = Instant::now() + self.config.hot_window;
        *self.mode.lock() = HotPathMode::Hot;
        *self.hot_until.lock() = Some(deadline);
    }

    /// 显式切换到 Normal 模式。
    pub fn enter_normal(&self) {
        *self.mode.lock() = HotPathMode::Normal;
        *self.hot_until.lock() = None;
    }

    /// 获取当前模式（自动检查 Hot 窗口是否过期）。
    pub fn current_mode(&self) -> HotPathMode {
        let mut mode = self.mode.lock();
        let mut deadline = self.hot_until.lock();
        if *mode == HotPathMode::Hot {
            if let Some(until) = *deadline {
                if Instant::now() >= until {
                    // Hot 窗口过期，切换到 Normal
                    *mode = HotPathMode::Normal;
                    *deadline = None;
                }
            }
        }
        *mode
    }

    /// 判断动作是否在当前模式下允许处理。
    pub fn should_process(&self, action: &SyncAction) -> bool {
        match self.current_mode() {
            HotPathMode::Normal => true,
            HotPathMode::Hot => is_control_action(action),
        }
    }

    /// 过滤动作列表：Hot 模式下仅保留控制类，其余延后。
    /// 返回 (processable, deferred)。
    pub fn partition(&self, actions: Vec<SyncAction>) -> (Vec<SyncAction>, Vec<SyncAction>) {
        let mode = self.current_mode();
        if mode == HotPathMode::Normal {
            return (actions, Vec::new());
        }
        let mut processable = Vec::new();
        let mut deferred = Vec::new();
        for a in actions {
            if is_control_action(&a) {
                processable.push(a);
            } else {
                deferred.push(a);
            }
        }
        (processable, deferred)
    }
}

impl Default for HotPathController {
    fn default() -> Self {
        Self::new(HotPathConfig::default())
    }
}

/// 判断动作是否属于"控制类"（Hot 模式下允许处理）。
///
/// 控制类包括：
/// - SendControl（控制帧）
/// - RequestDelta（请求拉取，本身只是控制信号，不传输大数据）
/// - EmitEvent（事件通知，无网络负载）
///
/// 数据类（Hot 模式下延后）：
/// - SendData（数据帧，可能包含大 delta/snapshot chunk）
fn is_control_action(action: &SyncAction) -> bool {
    matches!(
        action,
        SyncAction::SendControl { .. } | SyncAction::RequestDelta { .. } | SyncAction::EmitEvent(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_core::{DocId, Frontier, PeerId};
    use tacit_transport::ControlMsg;

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    fn data_action() -> SyncAction {
        SyncAction::SendData {
            peer_id: pid(1),
            doc_id: DocId::new("d1"),
            block_id: None,
            bytes: vec![1, 2, 3],
            priority: tacit_core::Priority::High,
            path: tacit_transport::PathPreference::Any,
            entry_id: None,
        }
    }

    fn control_action() -> SyncAction {
        SyncAction::SendControl {
            peer_id: pid(1),
            msg: ControlMsg::AckSummary(tacit_core::AckSummary {
                peer_id: pid(1),
                doc_id: DocId::new("d1"),
                ack_checkpoint: None,
                ack_frontier: Frontier::new(),
                updated_at: std::time::SystemTime::now(),
                version_override: None,
            }),
            priority: tacit_core::Priority::Medium,
        }
    }

    #[test]
    fn normal_mode_processes_all() {
        let ctrl = HotPathController::default();
        assert_eq!(ctrl.current_mode(), HotPathMode::Normal);
        assert!(ctrl.should_process(&data_action()));
        assert!(ctrl.should_process(&control_action()));
    }

    #[test]
    fn hot_mode_defers_data_actions() {
        let ctrl = HotPathController::new(HotPathConfig {
            hot_window: Duration::from_secs(10),
            device_profile: DeviceProfile::Desktop,
        });
        ctrl.trigger_hot();
        assert_eq!(ctrl.current_mode(), HotPathMode::Hot);
        // 控制类允许
        assert!(ctrl.should_process(&control_action()));
        // 数据类延后
        assert!(!ctrl.should_process(&data_action()));
    }

    #[test]
    fn hot_window_expires() {
        let ctrl = HotPathController::new(HotPathConfig {
            hot_window: Duration::from_millis(1),
            device_profile: DeviceProfile::Desktop,
        });
        ctrl.trigger_hot();
        assert_eq!(ctrl.current_mode(), HotPathMode::Hot);
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(ctrl.current_mode(), HotPathMode::Normal);
    }

    #[test]
    fn partition_separates_actions() {
        let ctrl = HotPathController::new(HotPathConfig {
            hot_window: Duration::from_secs(10),
            device_profile: DeviceProfile::Desktop,
        });
        ctrl.trigger_hot();
        let actions = vec![data_action(), control_action(), data_action()];
        let (processable, deferred) = ctrl.partition(actions);
        assert_eq!(processable.len(), 1);
        assert_eq!(deferred.len(), 2);
    }

    #[test]
    fn enter_normal_resets_mode() {
        let ctrl = HotPathController::new(HotPathConfig {
            hot_window: Duration::from_secs(10),
            device_profile: DeviceProfile::Desktop,
        });
        ctrl.trigger_hot();
        ctrl.enter_normal();
        assert_eq!(ctrl.current_mode(), HotPathMode::Normal);
    }
}
