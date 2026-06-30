//! Linux bluez BLE 后端实现。
//!
//! 使用 [`bluer`] crate（Linux bluez D-Bus）实现真实的 BLE 广播与扫描。
//!
//! 架构：
//! - [`BluerBackend`] 实现 [`PresenceBackend`] trait（同步接口）。
//! - 内部通过 tokio channel 与异步 bluez 任务通信：
//!   - `cmd_tx`：发送命令（StartBroadcast / StopBroadcast / StartScan / StopScan）。
//!   - `discoveries`：累积扫描发现的事件，由 `drain_discoveries` 拉取。
//! - bluez 异步任务在独立的 tokio task 中运行，处理 D-Bus 事件。
//!
//! 限制：
//! - 仅支持 Linux（需要 bluez daemon）。
//! - BLE 广播 payload 最大 31 字节（bluez 限制）。
//! - 扫描结果通过 bluez 设备发现事件获取。

use std::collections::VecDeque;
use std::sync::Arc;

use bluer::Session;
use parking_lot::Mutex;
use tacit_core::{CoreError, CoreResult, PeerId};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::backend::{DiscoveryEvent, PresenceBackend};
use crate::presence::decode_presence_payload;

/// Tacit BLE 服务 UUID（用于广播和扫描过滤）。
const TACIT_SERVICE_UUID: &str = "0000feaa-0000-1000-8000-00805f9b34fb";

/// 后端命令：从同步 trait 方法发送到异步 bluez 任务。
enum BackendCommand {
    /// 开始广播。
    StartBroadcast(Vec<u8>),
    /// 停止广播。
    StopBroadcast,
    /// 开始扫描。
    StartScan,
    /// 停止扫描。
    StopScan,
}

/// bluez 后端运行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendState {
    /// 空闲。
    Idle,
    /// 广播中。
    Broadcasting,
    /// 扫描中。
    Scanning,
    /// 广播 + 扫描。
    BroadcastingAndScanning,
}

impl BackendState {
    fn is_broadcasting(&self) -> bool {
        matches!(self, BackendState::Broadcasting | BackendState::BroadcastingAndScanning)
    }

    fn is_scanning(&self) -> bool {
        matches!(self, BackendState::Scanning | BackendState::BroadcastingAndScanning)
    }

    fn set_broadcasting(&mut self, on: bool) {
        *self = match (*self, on) {
            (BackendState::Idle, true) => BackendState::Broadcasting,
            (BackendState::Scanning, true) => BackendState::BroadcastingAndScanning,
            (BackendState::Broadcasting, false) => BackendState::Idle,
            (BackendState::BroadcastingAndScanning, false) => BackendState::Scanning,
            _ => *self,
        };
    }

    fn set_scanning(&mut self, on: bool) {
        *self = match (*self, on) {
            (BackendState::Idle, true) => BackendState::Scanning,
            (BackendState::Broadcasting, true) => BackendState::BroadcastingAndScanning,
            (BackendState::Scanning, false) => BackendState::Idle,
            (BackendState::BroadcastingAndScanning, false) => BackendState::Broadcasting,
            _ => *self,
        };
    }
}

/// Linux bluez BLE 后端。
///
/// 通过 D-Bus 与 bluez daemon 通信，实现真实的 BLE 广播与扫描。
/// 同步 trait 方法通过 channel 与异步 bluez task 通信。
pub struct BluerBackend {
    /// 命令发送通道。
    cmd_tx: Mutex<Option<mpsc::UnboundedSender<BackendCommand>>>,
    /// 当前广播 payload。
    payload: Mutex<Option<Vec<u8>>>,
    /// 运行状态。
    state: Mutex<BackendState>,
    /// 发现事件队列。
    discoveries: Mutex<VecDeque<DiscoveryEvent>>,
}

impl BluerBackend {
    /// 创建 bluez 后端并启动异步 task。
    ///
    /// 需要在 tokio 运行时中调用。
    pub async fn new() -> CoreResult<Arc<Self>> {
        // 连接 bluez D-Bus
        let session = Session::new()
            .await
            .map_err(|e| CoreError::Transport(format!("连接 bluez 失败: {e}")))?;

        // 获取默认适配器
        let adapter = session
            .default_adapter()
            .await
            .map_err(|e| CoreError::Transport(format!("获取 BLE 适配器失败: {e}")))?;

        debug!(adapter = %adapter.name(), "bluez 适配器就绪");

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<BackendCommand>();

        let backend = Arc::new(Self {
            cmd_tx: Mutex::new(Some(cmd_tx)),
            payload: Mutex::new(None),
            state: Mutex::new(BackendState::Idle),
            discoveries: Mutex::new(VecDeque::new()),
        });

        // 启动 bluez 异步任务
        let backend_clone = backend.clone();
        tokio::spawn(async move {
            Self::run_bluer_task(session, adapter, backend_clone, &mut cmd_rx).await;
        });

        Ok(backend)
    }

    /// 当前广播 payload。
    pub fn current_payload(&self) -> Option<Vec<u8>> {
        self.payload.lock().clone()
    }

    /// 是否正在广播。
    pub fn is_broadcasting(&self) -> bool {
        self.state.lock().is_broadcasting()
    }

    /// 是否正在扫描。
    pub fn is_scanning(&self) -> bool {
        self.state.lock().is_scanning()
    }

    /// bluez 异步任务主循环。
    ///
    /// 处理命令通道消息，管理广播和扫描生命周期。
    async fn run_bluer_task(
        session: Session,
        adapter: bluer::Adapter,
        backend: Arc<Self>,
        cmd_rx: &mut mpsc::UnboundedReceiver<BackendCommand>,
    ) {
        // 广播注册句柄
        let mut adv_handle: Option<bluer::adv::AdvertisementHandle> = None;
        // 扫描任务句柄
        let mut scan_handle: Option<tokio::task::JoinHandle<()>> = None;

        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                BackendCommand::StartBroadcast(payload) => {
                    // 停止旧广播
                    if let Some(h) = adv_handle.take() {
                        drop(h);
                        debug!("已停止旧广播");
                    }

                    // 创建新广播
                    let service_uuid: bluer::Uuid = match TACIT_SERVICE_UUID.parse() {
                        Ok(u) => u,
                        Err(e) => {
                            error!(error = %e, "TACIT_SERVICE_UUID 解析失败");
                            continue;
                        }
                    };

                    let adv = bluer::adv::Advertisement {
                        advertisement_type: bluer::adv::Type::Peripheral,
                        service_uuids: vec![service_uuid].into_iter().collect(),
                        service_data: [(service_uuid, payload.clone())].into_iter().collect(),
                        discoverable: Some(true),
                        ..Default::default()
                    };

                    match adapter.advertise(adv).await {
                        Ok(handle) => {
                            adv_handle = Some(handle);
                            *backend.payload.lock() = Some(payload);
                            backend.state.lock().set_broadcasting(true);
                            debug!("bluez 广播已启动");
                        }
                        Err(e) => {
                            error!(error = %e, "启动 bluez 广播失败");
                        }
                    }
                }
                BackendCommand::StopBroadcast => {
                    if let Some(h) = adv_handle.take() {
                        drop(h);
                    }
                    *backend.payload.lock() = None;
                    backend.state.lock().set_broadcasting(false);
                    debug!("bluez 广播已停止");
                }
                BackendCommand::StartScan => {
                    if scan_handle.is_some() {
                        debug!("扫描已在运行");
                        continue;
                    }

                    // 启动扫描
                    let adapter_clone = adapter.clone();
                    let backend_clone = backend.clone();
                    scan_handle = Some(tokio::spawn(async move {
                        Self::run_scan_loop(adapter_clone, backend_clone).await;
                    }));
                    backend.state.lock().set_scanning(true);
                    debug!("bluez 扫描已启动");
                }
                BackendCommand::StopScan => {
                    if let Some(handle) = scan_handle.take() {
                        handle.abort();
                    }
                    backend.state.lock().set_scanning(false);
                    debug!("bluez 扫描已停止");
                }
            }
        }

        // 清理
        if let Some(h) = adv_handle.take() {
            drop(h);
        }
        if let Some(handle) = scan_handle.take() {
            handle.abort();
        }
        debug!("bluez 任务退出");
        let _ = session;
    }

    /// 扫描循环：监听 bluez 设备发现事件。
    async fn run_scan_loop(adapter: bluer::Adapter, backend: Arc<Self>) {
        use futures::StreamExt;
        use tokio::pin;

        // 适配器上电
        if let Err(e) = adapter.set_powered(true).await {
            warn!(error = %e, "BLE 适配器上电失败");
        }

        debug!("bluez 发现已启动");

        // 启动发现（返回 Stream）
        let discover = match adapter.discover_devices().await {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "启动 bluez 发现失败");
                return;
            }
        };

        pin!(discover);

        // 监听设备事件
        while let Some(event) = discover.next().await {
            match event {
                bluer::AdapterEvent::DeviceAdded(addr) => {
                    Self::process_device(&adapter, &backend, &addr).await;
                }
                bluer::AdapterEvent::DeviceRemoved(addr) => {
                    debug!(peer = %addr, "设备离开");
                }
                _ => {}
            }
        }

        debug!("bluez 发现流结束");
    }

    /// 处理发现的设备：解析 presence payload。
    ///
    /// 仅处理包含 TACIT_SERVICE_UUID 的 service data，
    /// 并从 payload 中的 device_id 获取 peer_id（不使用 MAC 作为 fallback）。
    async fn process_device(
        adapter: &bluer::Adapter,
        backend: &Arc<Self>,
        addr: &bluer::Address,
    ) {
        let device = match adapter.device(*addr) {
            Ok(d) => d,
            Err(e) => {
                debug!(error = %e, "获取设备失败");
                return;
            }
        };

        // 获取 RSSI
        let rssi = device.rssi().await.ok().flatten().unwrap_or(-127);

        // 获取服务数据（presence payload）
        // service_data 返回 Vec<HashMap<Uuid, Vec<u8>>>
        let service_data_list = match device.service_data().await {
            Ok(sd) => sd,
            Err(_) => return,
        };

        // 解析 TACIT_SERVICE_UUID 用于过滤
        let tacit_uuid: bluer::Uuid = match TACIT_SERVICE_UUID.parse() {
            Ok(u) => u,
            Err(e) => {
                debug!(error = %e, "TACIT_SERVICE_UUID 解析失败");
                return;
            }
        };

        for service_data in service_data_list.iter() {
            // 只处理包含 TACIT_SERVICE_UUID 的 service data
            let payload = match service_data.get(&tacit_uuid) {
                Some(data) if !data.is_empty() => data.clone(),
                _ => continue,
            };

            // 先解码 payload（peer_id 参数未使用），从 device_id 获取 peer_id
            let temp_peer_id = PeerId::new(&addr.to_string());
            match decode_presence_payload(&payload, &temp_peer_id) {
                Ok(hint) => {
                    // 用 payload 中的 device_id 作为 peer_id，不使用 MAC 作为 fallback
                    if hint.device_id.is_empty() {
                        debug!(peer = %addr, "payload 中无 device_id，跳过该设备");
                        continue;
                    }
                    let peer_id = PeerId::new(&hint.device_id);
                    let event = DiscoveryEvent {
                        peer_id,
                        hint,
                        rssi,
                    };
                    backend.discoveries.lock().push_back(event);
                    debug!(peer = %addr, rssi, "发现 peer");
                }
                Err(e) => {
                    debug!(error = %e, "解析 presence payload 失败，跳过该设备");
                }
            }
        }
    }
}

impl PresenceBackend for BluerBackend {
    fn start_broadcast(&self, payload: Vec<u8>) -> CoreResult<()> {
        let tx = self.cmd_tx.lock().clone().ok_or_else(|| {
            CoreError::Transport("bluez 后端已关闭".into())
        })?;
        tx.send(BackendCommand::StartBroadcast(payload))
            .map_err(|_| CoreError::Transport("发送广播命令失败".into()))?;
        Ok(())
    }

    fn stop_broadcast(&self) {
        if let Some(tx) = self.cmd_tx.lock().as_ref() {
            let _ = tx.send(BackendCommand::StopBroadcast);
        }
        *self.payload.lock() = None;
        self.state.lock().set_broadcasting(false);
    }

    fn start_scan(&self) -> CoreResult<()> {
        let tx = self.cmd_tx.lock().clone().ok_or_else(|| {
            CoreError::Transport("bluez 后端已关闭".into())
        })?;
        tx.send(BackendCommand::StartScan)
            .map_err(|_| CoreError::Transport("发送扫描命令失败".into()))?;
        Ok(())
    }

    fn stop_scan(&self) {
        if let Some(tx) = self.cmd_tx.lock().as_ref() {
            let _ = tx.send(BackendCommand::StopScan);
        }
        self.state.lock().set_scanning(false);
    }

    fn drain_discoveries(&self) -> Vec<DiscoveryEvent> {
        self.discoveries.lock().drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_state_transitions() {
        let mut state = BackendState::Idle;
        assert!(!state.is_broadcasting());
        assert!(!state.is_scanning());

        state.set_broadcasting(true);
        assert!(state.is_broadcasting());
        assert!(!state.is_scanning());

        state.set_scanning(true);
        assert!(state.is_broadcasting());
        assert!(state.is_scanning());

        state.set_broadcasting(false);
        assert!(!state.is_broadcasting());
        assert!(state.is_scanning());

        state.set_scanning(false);
        assert!(!state.is_broadcasting());
        assert!(!state.is_scanning());
    }

    #[test]
    fn tacit_service_uuid_parses_correctly() {
        // TACIT_SERVICE_UUID 应能正确解析为 bluer::Uuid
        let uuid: bluer::Uuid = TACIT_SERVICE_UUID.parse().unwrap();
        // 序列化后应与原字符串一致（bluer::Uuid Display 为小写）
        assert_eq!(uuid.to_string(), TACIT_SERVICE_UUID);
    }

    #[test]
    fn service_uuid_filter_only_matches_tacit_uuid() {
        let tacit_uuid: bluer::Uuid = TACIT_SERVICE_UUID.parse().unwrap();
        let other_uuid: bluer::Uuid = "0000180f-0000-1000-8000-00805f9b34fb".parse().unwrap();

        // 构造包含 TACIT_SERVICE_UUID 的 service data
        let mut matching = std::collections::HashMap::new();
        matching.insert(tacit_uuid, vec![0x54, 0x43]);

        // 构造不含 TACIT_SERVICE_UUID 的 service data
        let mut non_matching = std::collections::HashMap::new();
        non_matching.insert(other_uuid, vec![0x01, 0x02]);

        // 匹配的应能取到 payload
        assert!(matching.get(&tacit_uuid).is_some());
        // 不匹配的取不到 TACIT payload
        assert!(non_matching.get(&tacit_uuid).is_none());
    }
}
