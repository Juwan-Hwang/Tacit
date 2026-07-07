//! Store-and-forward：离线消息存储与重发。
//!
//! v1.0 规范第 15 节 store-and-forward：
//! - peer 离线时，本地变更仍需持久化记录。
//! - peer 上线后，重发未投递的消息。
//! - 收到对端 ack 后，标记消息已确认并可清理。
//!
//! 本模块封装 sync_log DAO 的业务逻辑，提供高层 API。

use std::sync::Arc;
use std::time::SystemTime;

use tacit_core::{CoreResult, DocId, PeerId};
use tacit_store::{dao, Store};
use tracing::{debug, info};

/// Store-and-forward 管理器。
pub struct StoreAndForward {
    store: Arc<Store>,
}

impl StoreAndForward {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// 记录一条待发送的 delta（peer 离线时调用）。
    ///
    /// `delta_id`：delta 的唯一标识（例如 `{doc_id}:{block_id}:{seq}`）。
    /// `channel`：发送通道（quic/ble/relay）。
    pub fn record_pending(
        &self,
        entry_id: &str,
        doc_id: &DocId,
        delta_id: &str,
        recipient: &PeerId,
        channel: &str,
    ) -> CoreResult<()> {
        let conn = self.store.conn();
        dao::insert_sync_log(
            &conn,
            &dao::SyncLogRecord {
                entry_id: entry_id.to_string(),
                doc_id: doc_id.clone(),
                delta_id: delta_id.to_string(),
                recipient_peer_id: recipient.clone(),
                delivered_at: None,
                acknowledged_at: None,
                channel: channel.to_string(),
            },
        )?;
        debug!(
            entry_id = entry_id,
            doc_id = %doc_id,
            recipient = %recipient,
            "记录待发送 delta"
        );
        Ok(())
    }

    /// 标记消息已投递（传输层发送成功后调用）。
    pub fn mark_delivered(&self, entry_id: &str) -> CoreResult<()> {
        let conn = self.store.conn();
        dao::mark_delivered(&conn, entry_id, SystemTime::now())?;
        debug!(entry_id = entry_id, "标记已投递");
        Ok(())
    }

    /// 标记消息已确认（收到对端 ack 后调用）。
    pub fn mark_acknowledged(&self, entry_id: &str) -> CoreResult<()> {
        let conn = self.store.conn();
        dao::mark_acknowledged(&conn, entry_id, SystemTime::now())?;
        debug!(entry_id = entry_id, "标记已确认");
        Ok(())
    }

    /// 批量标记已投递+已确认（单事务，避免逐条 auto-commit 的 fsync 开销）。
    ///
    /// 适用于去重场景：已被更新版本覆盖的旧记录直接标记为已投递+已确认。
    pub fn mark_delivered_and_acknowledged_batch(&self, entry_ids: &[&str]) -> CoreResult<()> {
        let conn = self.store.conn();
        dao::mark_delivered_and_acknowledged_batch(&conn, entry_ids, SystemTime::now())?;
        if !entry_ids.is_empty() {
            debug!(count = entry_ids.len(), "批量标记已投递+已确认");
        }
        Ok(())
    }

    /// 批量标记已投递（单事务）。
    pub fn mark_delivered_batch(&self, entry_ids: &[&str]) -> CoreResult<()> {
        let conn = self.store.conn();
        dao::mark_delivered_batch(&conn, entry_ids, SystemTime::now())?;
        if !entry_ids.is_empty() {
            debug!(count = entry_ids.len(), "批量标记已投递");
        }
        Ok(())
    }

    /// 列出指定 peer 的未投递消息（peer 上线后重发）。
    pub fn list_undelivered(&self, peer_id: &PeerId) -> CoreResult<Vec<dao::SyncLogRecord>> {
        let conn = self.store.conn();
        dao::list_undelivered(&conn, peer_id)
    }

    /// 列出指定 peer 的未确认消息（用于重传超时检测）。
    pub fn list_unacknowledged(&self, peer_id: &PeerId) -> CoreResult<Vec<dao::SyncLogRecord>> {
        let conn = self.store.conn();
        dao::list_unacknowledged(&conn, peer_id)
    }

    /// 清理已确认的 sync_log 记录（定期 GC 调用）。
    ///
    /// 只删除 `retention_secs` 秒之前已确认的记录，保留近期记录供审计与故障排查。
    /// 若 `retention_secs` 为 0，则立即清理所有已确认记录。
    pub fn cleanup_acknowledged(&self, retention_secs: u64) -> CoreResult<usize> {
        let cutoff_ms = if retention_secs == 0 {
            i64::MAX
        } else {
            let now_ms = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            now_ms - (retention_secs as i64 * 1000)
        };
        let conn = self.store.conn();
        let count = conn
            .execute(
                "DELETE FROM sync_log WHERE acknowledged_at IS NOT NULL AND acknowledged_at < ?1",
                [cutoff_ms],
            )
            .map_err(|e| tacit_core::CoreError::Store(e.to_string()))?;
        if count > 0 {
            info!(
                cleaned = count,
                retention_secs, "清理已确认的 sync_log 记录"
            );
        }
        Ok(count)
    }

    /// peer 上线时重发所有未投递的消息。
    ///
    /// 返回待重发的 entry_id 列表（由调用方执行实际发送）。
    pub fn resend_undelivered(&self, peer_id: &PeerId) -> CoreResult<Vec<String>> {
        let records = self.list_undelivered(peer_id)?;
        let entry_ids: Vec<String> = records.iter().map(|r| r.entry_id.clone()).collect();
        if !entry_ids.is_empty() {
            info!(
                peer_id = %peer_id,
                count = entry_ids.len(),
                "peer 上线，重发未投递消息"
            );
        }
        Ok(entry_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_saf() -> StoreAndForward {
        let store = Store::open_memory().unwrap();
        StoreAndForward::new(Arc::new(store))
    }

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    #[test]
    fn record_and_list_undelivered() {
        let saf = make_saf();
        saf.record_pending("e1", &DocId::new("d1"), "delta1", &pid(2), "quic")
            .unwrap();
        saf.record_pending("e2", &DocId::new("d1"), "delta2", &pid(2), "quic")
            .unwrap();

        let undelivered = saf.list_undelivered(&pid(2)).unwrap();
        assert_eq!(undelivered.len(), 2);
    }

    #[test]
    fn mark_delivered_updates_record() {
        let saf = make_saf();
        saf.record_pending("e1", &DocId::new("d1"), "delta1", &pid(2), "quic")
            .unwrap();
        saf.mark_delivered("e1").unwrap();

        let undelivered = saf.list_undelivered(&pid(2)).unwrap();
        assert_eq!(undelivered.len(), 0);

        let unacked = saf.list_unacknowledged(&pid(2)).unwrap();
        assert_eq!(unacked.len(), 1);
    }

    #[test]
    fn mark_acknowledged_updates_record() {
        let saf = make_saf();
        saf.record_pending("e1", &DocId::new("d1"), "delta1", &pid(2), "quic")
            .unwrap();
        saf.mark_delivered("e1").unwrap();
        saf.mark_acknowledged("e1").unwrap();

        let unacked = saf.list_unacknowledged(&pid(2)).unwrap();
        assert_eq!(unacked.len(), 0);
    }

    #[test]
    fn cleanup_removes_acknowledged() {
        let saf = make_saf();
        saf.record_pending("e1", &DocId::new("d1"), "delta1", &pid(2), "quic")
            .unwrap();
        saf.record_pending("e2", &DocId::new("d1"), "delta2", &pid(2), "quic")
            .unwrap();
        saf.mark_delivered("e1").unwrap();
        saf.mark_acknowledged("e1").unwrap();

        let cleaned = saf.cleanup_acknowledged(0).unwrap();
        assert_eq!(cleaned, 1);

        let unacked = saf.list_unacknowledged(&pid(2)).unwrap();
        assert_eq!(unacked.len(), 1);
    }

    #[test]
    fn resend_undelivered_returns_entry_ids() {
        let saf = make_saf();
        saf.record_pending("e1", &DocId::new("d1"), "delta1", &pid(2), "quic")
            .unwrap();
        saf.record_pending("e2", &DocId::new("d1"), "delta2", &pid(2), "quic")
            .unwrap();

        let ids = saf.resend_undelivered(&pid(2)).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"e1".to_string()));
        assert!(ids.contains(&"e2".to_string()));
    }
}
