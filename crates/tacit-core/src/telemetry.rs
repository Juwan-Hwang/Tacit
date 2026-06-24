//! 监控与可观测性 telemetry（v1.0 规范第 19 节）。
//!
//! 内置最小本地 telemetry：
//! - sync lag（同步延迟）
//! - 队列积压长度
//! - 每通道成功率（EMA）
//! - 最近连接延迟
//! - Anchor 在线状态
//!
//! `transport_stats.success_ema` 使用指数移动平均更新。

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::ids::PeerId;

/// EMA 默认平滑系数。
pub const DEFAULT_EMA_ALPHA: f64 = 0.3;

/// 单通道传输统计。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelStats {
    /// 成功率 EMA（0.0 ~ 1.0）。
    pub success_ema: f64,
    /// 平均延迟（毫秒）。
    pub avg_latency_ms: f64,
    /// 总发送次数。
    pub total_sent: u64,
    /// 成功次数。
    pub total_success: u64,
    /// 最近更新时间。
    pub updated_at: Option<SystemTime>,
}

impl ChannelStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// 用 EMA 更新成功率。
    ///
    /// `success` 为 true 时 success=1.0，false 时 success=0.0。
    pub fn record_result(&mut self, success: bool, latency: Duration, alpha: f64) {
        let value = if success { 1.0 } else { 0.0 };
        self.success_ema = alpha * value + (1.0 - alpha) * self.success_ema;
        let latency_ms = latency.as_secs_f64() * 1000.0;
        self.avg_latency_ms = alpha * latency_ms + (1.0 - alpha) * self.avg_latency_ms;
        self.total_sent += 1;
        if success {
            self.total_success += 1;
        }
        self.updated_at = Some(SystemTime::now());
    }
}

/// 同步延迟指标。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncLag {
    /// 本地最新 seq 与远端已知 seq 的差距。
    pub seq_lag: u64,
    /// 本地最后同步时间距今的秒数。
    pub time_lag_secs: u64,
}

/// 队列积压指标。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueBacklog {
    /// 待执行同步动作数。
    pub pending_actions: u32,
    /// 依赖等待队列长度。
    pub pending_fetches: u32,
}

/// 完整 telemetry 快照。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// 同步延迟。
    pub sync_lag: SyncLag,
    /// 队列积压。
    pub backlog: QueueBacklog,
    /// 每通道统计（channel name -> stats）。
    pub channels: HashMap<String, ChannelStats>,
    /// Anchor peer_id（None 表示无可用 Anchor）。
    pub anchor_peer: Option<String>,
    /// Anchor 是否在线。
    pub anchor_online: bool,
}

/// Telemetry 采集器：线程安全地收集和查询监控指标。
#[derive(Debug)]
pub struct TelemetryCollector {
    inner: Mutex<TelemetryInner>,
    ema_alpha: f64,
}

#[derive(Debug)]
struct TelemetryInner {
    sync_lag: SyncLag,
    backlog: QueueBacklog,
    channels: HashMap<String, ChannelStats>,
    anchor_peer: Option<PeerId>,
    anchor_online: bool,
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new(DEFAULT_EMA_ALPHA)
    }
}

impl TelemetryCollector {
    pub fn new(ema_alpha: f64) -> Self {
        Self {
            inner: Mutex::new(TelemetryInner {
                sync_lag: SyncLag::default(),
                backlog: QueueBacklog::default(),
                channels: HashMap::new(),
                anchor_peer: None,
                anchor_online: false,
            }),
            ema_alpha,
        }
    }

    /// 记录一次传输结果。
    pub fn record_transport(&self, channel: &str, success: bool, latency: Duration) {
        let mut inner = self.inner.lock();
        let stats = inner.channels.entry(channel.to_string()).or_default();
        stats.record_result(success, latency, self.ema_alpha);
    }

    /// 更新同步延迟指标。
    pub fn set_sync_lag(&self, seq_lag: u64, time_lag_secs: u64) {
        let mut inner = self.inner.lock();
        inner.sync_lag.seq_lag = seq_lag;
        inner.sync_lag.time_lag_secs = time_lag_secs;
    }

    /// 更新队列积压。
    pub fn set_backlog(&self, pending_actions: u32, pending_fetches: u32) {
        let mut inner = self.inner.lock();
        inner.backlog.pending_actions = pending_actions;
        inner.backlog.pending_fetches = pending_fetches;
    }

    /// 更新 Anchor 状态。
    pub fn set_anchor(&self, peer: Option<PeerId>, online: bool) {
        let mut inner = self.inner.lock();
        inner.anchor_peer = peer;
        inner.anchor_online = online;
    }

    /// 获取完整快照。
    pub fn snapshot(&self) -> TelemetrySnapshot {
        let inner = self.inner.lock();
        TelemetrySnapshot {
            sync_lag: inner.sync_lag.clone(),
            backlog: inner.backlog.clone(),
            channels: inner.channels.clone(),
            anchor_peer: inner.anchor_peer.as_ref().map(|p| p.as_str().to_string()),
            anchor_online: inner.anchor_online,
        }
    }

    /// 获取指定通道的成功率 EMA。
    pub fn channel_success_ema(&self, channel: &str) -> f64 {
        let inner = self.inner.lock();
        inner
            .channels
            .get(channel)
            .map(|s| s.success_ema)
            .unwrap_or(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ema_updates_on_success() {
        let mut stats = ChannelStats::new();
        stats.record_result(true, Duration::from_millis(10), 0.3);
        // 首次：ema = 0.3 * 1.0 = 0.3
        assert!((stats.success_ema - 0.3).abs() < 0.01);
        stats.record_result(true, Duration::from_millis(20), 0.3);
        // 第二次：ema = 0.3 * 1.0 + 0.7 * 0.3 = 0.51
        assert!((stats.success_ema - 0.51).abs() < 0.01);
    }

    #[test]
    fn ema_updates_on_failure() {
        let mut stats = ChannelStats::new();
        stats.record_result(true, Duration::from_millis(10), 0.5);
        stats.record_result(false, Duration::from_millis(10), 0.5);
        // ema = 0.5 * 0 + 0.5 * 0.5 = 0.25
        assert!((stats.success_ema - 0.25).abs() < 0.01);
    }

    #[test]
    fn collector_records_and_snapshots() {
        let collector = TelemetryCollector::default();
        collector.record_transport("quic", true, Duration::from_millis(50));
        collector.record_transport("quic", false, Duration::from_millis(100));
        collector.set_sync_lag(10, 30);
        collector.set_backlog(5, 2);
        collector.set_anchor(Some(PeerId::new("anchor1")), true);

        let snap = collector.snapshot();
        assert_eq!(snap.sync_lag.seq_lag, 10);
        assert_eq!(snap.backlog.pending_actions, 5);
        assert!(snap.anchor_online);
        assert!(snap.channels.contains_key("quic"));
        let quic = &snap.channels["quic"];
        assert_eq!(quic.total_sent, 2);
        assert_eq!(quic.total_success, 1);
    }

    #[test]
    fn latency_ema_updates() {
        let mut stats = ChannelStats::new();
        stats.record_result(true, Duration::from_millis(100), 0.5);
        // 首次：avg = 0.5 * 100 = 50
        assert!((stats.avg_latency_ms - 50.0).abs() < 0.1);
        stats.record_result(true, Duration::from_millis(200), 0.5);
        // 第二次：avg = 0.5 * 200 + 0.5 * 50 = 125
        assert!((stats.avg_latency_ms - 125.0).abs() < 0.1);
    }
}
