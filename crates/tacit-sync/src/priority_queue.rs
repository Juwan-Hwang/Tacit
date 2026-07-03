//! 优先级队列：按 Priority 排序的 SyncAction 队列。
//!
//! v1.0 规范要求高优先级动作（用户前台实时输入、活跃 block 小增量、Meta-Document）
//! 优先于低优先级动作（checkpoint、冷文档追赶）发送，避免冷数据阻塞热数据。
//!
//! 实现：使用 BinaryHeap（最大堆）按 (priority_rank, seq) 排序。
//! 同优先级按入队顺序（FIFO）保证公平。

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use tacit_core::Priority;

use crate::engine::SyncAction;

/// 优先级排序权重：High=2, Medium=1, Low=0。
fn priority_rank(p: Priority) -> u8 {
    match p {
        Priority::High => 2,
        Priority::Medium => 1,
        Priority::Low => 0,
    }
}

/// 队列条目：携带优先级与单调递增的序号（保证同优先级 FIFO）。
#[derive(Debug, Clone)]
struct QueueEntry {
    seq: u64,
    priority: Priority,
    action: SyncAction,
}

impl PartialEq for QueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}

impl Eq for QueueEntry {}

impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // 最大堆：优先级高者在前；同优先级 seq 小者在前（FIFO）
        let by_priority = priority_rank(self.priority).cmp(&priority_rank(other.priority));
        match by_priority {
            Ordering::Equal => other.seq.cmp(&self.seq), // 反转 seq 使小者在前
            _ => by_priority,
        }
    }
}

/// 优先级队列：线程安全的 SyncAction 队列。
#[derive(Debug)]
pub struct PriorityQueue {
    heap: parking_lot::Mutex<BinaryHeap<QueueEntry>>,
    next_seq: parking_lot::Mutex<u64>,
}

impl PriorityQueue {
    pub fn new() -> Self {
        Self {
            heap: parking_lot::Mutex::new(BinaryHeap::new()),
            next_seq: parking_lot::Mutex::new(0),
        }
    }

    /// 入队一个动作。
    pub fn push(&self, action: SyncAction) {
        let priority = action_priority(&action);
        let seq = {
            let mut s = self.next_seq.lock();
            let v = *s;
            *s += 1;
            v
        };
        self.heap.lock().push(QueueEntry {
            seq,
            priority,
            action,
        });
    }

    /// 弹出最高优先级动作。
    pub fn pop(&self) -> Option<SyncAction> {
        self.heap.lock().pop().map(|e| e.action)
    }

    /// 取出所有动作并清空队列（按优先级顺序）。
    pub fn drain(&self) -> Vec<SyncAction> {
        let mut heap = self.heap.lock();
        let mut out = Vec::with_capacity(heap.len());
        while let Some(e) = heap.pop() {
            out.push(e.action);
        }
        out
    }

    /// 当前队列长度。
    pub fn len(&self) -> usize {
        self.heap.lock().len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.heap.lock().is_empty()
    }

    /// 窥视队头动作的优先级（不弹出）。
    pub fn peek_priority(&self) -> Option<Priority> {
        self.heap.lock().peek().map(|e| e.priority)
    }
}

impl Default for PriorityQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// 从 SyncAction 推断其优先级。
///
/// `RequestDelta` 的优先级由调用方按场景指定（活跃同步 High / 冷文档追赶 Low），
/// 其余动作按类型固定：SendData/SendControl 用自身 priority，EmitEvent 固定 Medium。
fn action_priority(action: &SyncAction) -> Priority {
    match action {
        SyncAction::SendData { priority, .. } => *priority,
        SyncAction::SendControl { priority, .. } => *priority,
        SyncAction::RequestDelta { priority, .. } => *priority,
        SyncAction::EmitEvent(_) => Priority::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacit_core::{DocId, PeerId};
    use tacit_transport::ControlMsg;

    fn pid(n: u64) -> PeerId {
        PeerId(n.to_string())
    }

    /// 构造一个指定优先级的 RequestDelta 动作。
    fn delta_action(peer: u64, doc: &str, priority: Priority) -> SyncAction {
        SyncAction::RequestDelta {
            peer_id: pid(peer),
            doc_id: DocId::new(doc),
            block_id: None,
            since: tacit_core::Frontier::new(),
            priority,
        }
    }

    #[test]
    fn high_priority_pops_first() {
        let q = PriorityQueue::new();
        // 先入 Low，再入 High
        q.push(SyncAction::EmitEvent(
            tacit_core::CoreEvent::SyncCompleted { peer_id: pid(1) },
        ));
        q.push(delta_action(1, "d1", Priority::High));

        let first = q.pop().unwrap();
        assert!(matches!(first, SyncAction::RequestDelta { .. }));
    }

    #[test]
    fn same_priority_fifo() {
        let q = PriorityQueue::new();
        // 两个相同优先级（High）的 RequestDelta
        q.push(delta_action(1, "d1", Priority::High));
        q.push(delta_action(2, "d2", Priority::High));

        let first = q.pop().unwrap();
        if let SyncAction::RequestDelta { peer_id, .. } = first {
            assert_eq!(peer_id, pid(1));
        } else {
            panic!("期望 RequestDelta");
        }
    }

    #[test]
    fn drain_returns_in_priority_order() {
        let q = PriorityQueue::new();
        q.push(SyncAction::SendControl {
            peer_id: pid(1),
            msg: ControlMsg::AckSummary(tacit_core::AckSummary {
                peer_id: pid(1),
                doc_id: DocId::new("d1"),
                ack_checkpoint: None,
                ack_frontier: tacit_core::Frontier::new(),
                updated_at: std::time::SystemTime::now(),
                version_override: None,
            }),
            priority: Priority::Medium,
        });
        q.push(delta_action(1, "d1", Priority::High));

        let drained = q.drain();
        assert_eq!(drained.len(), 2);
        // High 应该在前
        assert!(matches!(drained[0], SyncAction::RequestDelta { .. }));
    }

    #[test]
    fn len_and_is_empty() {
        let q = PriorityQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);

        q.push(SyncAction::EmitEvent(
            tacit_core::CoreEvent::SyncCompleted { peer_id: pid(1) },
        ));
        assert!(!q.is_empty());
        assert_eq!(q.len(), 1);
    }

    /// 验证 Priority::Low 正确排序：Low 动作应排在 High 和 Medium 之后。
    /// 此测试确保冷文档追赶 / checkpoint 类低优动作不会阻塞热数据。
    #[test]
    fn low_priority_pops_last() {
        let q = PriorityQueue::new();
        // 按 Low → High → Medium 顺序入队，期望弹出顺序为 High, Medium, Low
        q.push(delta_action(1, "cold", Priority::Low));
        q.push(delta_action(2, "hot", Priority::High));
        q.push(SyncAction::EmitEvent(
            tacit_core::CoreEvent::SyncCompleted { peer_id: pid(3) },
        ));

        let first = q.pop().unwrap();
        assert!(
            matches!(
                first,
                SyncAction::RequestDelta {
                    priority: Priority::High,
                    ..
                }
            ),
            "High 应最先弹出"
        );

        let second = q.pop().unwrap();
        assert!(
            matches!(second, SyncAction::EmitEvent(_)),
            "Medium（EmitEvent）应第二弹出"
        );

        let third = q.pop().unwrap();
        assert!(
            matches!(
                third,
                SyncAction::RequestDelta {
                    priority: Priority::Low,
                    ..
                }
            ),
            "Low 应最后弹出"
        );

        assert!(q.pop().is_none(), "队列应为空");
    }

    /// 验证同优先级 Low 动作之间保持 FIFO 公平性。
    #[test]
    fn low_priority_fifo_order() {
        let q = PriorityQueue::new();
        q.push(delta_action(1, "cold1", Priority::Low));
        q.push(delta_action(2, "cold2", Priority::Low));

        let first = q.pop().unwrap();
        if let SyncAction::RequestDelta {
            peer_id, priority, ..
        } = first
        {
            assert_eq!(priority, Priority::Low);
            assert_eq!(peer_id, pid(1), "同优先级 Low 应 FIFO");
        } else {
            panic!("期望 RequestDelta");
        }
    }

    /// 验证 drain 对 Low/High 混合的正确排序。
    #[test]
    fn drain_low_after_high() {
        let q = PriorityQueue::new();
        q.push(delta_action(1, "cold", Priority::Low));
        q.push(delta_action(2, "hot", Priority::High));
        q.push(delta_action(3, "cold2", Priority::Low));

        let drained = q.drain();
        assert_eq!(drained.len(), 3);
        // High 在前，两个 Low 在后（FIFO）
        assert!(matches!(
            drained[0],
            SyncAction::RequestDelta {
                priority: Priority::High,
                ..
            }
        ));
        assert!(matches!(
            drained[1],
            SyncAction::RequestDelta {
                priority: Priority::Low,
                ..
            }
        ));
        assert!(matches!(
            drained[2],
            SyncAction::RequestDelta {
                priority: Priority::Low,
                ..
            }
        ));
    }
}
