//! Tacit 配置。
//!
//! 集中管理可调参数。Phase 0 先提供最小配置项，后续按需扩展。

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacitConfig {
    /// 本设备 peer_id。
    pub peer_id: String,
    /// group_id。
    pub group_id: String,
    /// 数据库路径。
    pub db_path: String,
    /// BlockDocCache 热块上限。
    pub block_cache_capacity: usize,
    /// checkpoint 触发的 delta 数量阈值。
    pub checkpoint_delta_threshold: u64,
    /// 软安全水位：超过该时长未上线的设备移出 active 集合。
    pub soft_watermark_timeout: Duration,
    /// 依赖等待初始退避。
    pub dependency_backoff_init: Duration,
    /// 依赖等待退避上限。
    pub dependency_backoff_max: Duration,
    /// QUIC 监听端口。
    pub quic_listen_port: u16,
    /// BLE presence 广播间隔。
    pub ble_presence_interval: Duration,
}

impl Default for TacitConfig {
    fn default() -> Self {
        Self {
            peer_id: String::new(),
            group_id: String::new(),
            db_path: "tacit.db".to_string(),
            block_cache_capacity: 32,
            checkpoint_delta_threshold: 1024,
            soft_watermark_timeout: Duration::from_secs(60 * 60 * 24 * 3), // 3 天
            dependency_backoff_init: Duration::from_millis(200),
            dependency_backoff_max: Duration::from_secs(2),
            quic_listen_port: 0,
            ble_presence_interval: Duration::from_secs(2),
        }
    }
}
