//! 性能基准测试。
//!
//! 覆盖关键热路径：
//! - 优先级队列 push/pop 吞吐
//! - 依赖等待队列 drain_ready 吞吐（验证 BTreeMap 优化效果）
//! - 双水位计算性能
//! - CRDT block 编辑与导出延迟

use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tacit_core::{AckSummary, BlockId, BlockKind, DocId, Frontier, PeerId, Priority};
use tacit_store::Store;
use tacit_sync::{
    DocStore, EngineConfig, PendingFetchQueue, PriorityQueue, SyncAction, SyncEngine,
    WatermarkCalculator,
};

fn pid(n: u64) -> PeerId {
    PeerId(n.to_string())
}

fn ack(peer: PeerId, doc: &str, frontier: Frontier, seq: u64) -> AckSummary {
    let mut f = frontier;
    if seq > 0 {
        f.set(peer.clone(), seq);
    }
    AckSummary {
        peer_id: peer,
        doc_id: DocId::new(doc),
        ack_checkpoint: None,
        ack_frontier: f,
        updated_at: std::time::SystemTime::now(),
        version_override: None,
    }
}

// ===== 优先级队列基准 =====

fn bench_priority_queue_push(c: &mut Criterion) {
    c.bench_function("priority_queue/push_1000", |b| {
        b.iter(|| {
            let q = PriorityQueue::new();
            for i in 0..1000u64 {
                q.push(SyncAction::RequestDelta {
                    peer_id: pid(i % 8),
                    doc_id: DocId::new("d1"),
                    block_id: None,
                    since: Frontier::new(),
                    priority: if i % 3 == 0 {
                        Priority::High
                    } else if i % 3 == 1 {
                        Priority::Medium
                    } else {
                        Priority::Low
                    },
                });
            }
            black_box(q);
        });
    });
}

fn bench_priority_queue_drain(c: &mut Criterion) {
    c.bench_function("priority_queue/drain_1000", |b| {
        b.iter_batched(
            || {
                let q = PriorityQueue::new();
                for i in 0..1000u64 {
                    q.push(SyncAction::RequestDelta {
                        peer_id: pid(i % 8),
                        doc_id: DocId::new("d1"),
                        block_id: None,
                        since: Frontier::new(),
                        priority: Priority::High,
                    });
                }
                q
            },
            |q| {
                let drained = q.drain();
                black_box(drained);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

// ===== 依赖等待队列 drain_ready 基准 =====

fn bench_pending_queue_drain_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group("pending_queue/drain_ready");
    for size in [100, 500, 1000, 5000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_batched(
                || {
                    let q =
                        PendingFetchQueue::new(Duration::from_millis(200), Duration::from_secs(2));
                    let now = Instant::now();
                    for i in 0..size {
                        q.enqueue(tacit_sync::PendingBlockFetch {
                            doc_id: DocId::new("d1"),
                            block_id: BlockId::new(format!("b{i}")),
                            expected_frontier: Frontier::new(),
                            observed_frontier: Frontier::new(),
                            peer_id: pid(1),
                            retry_at: now,
                            retries: 0,
                            phase: tacit_sync::BackoffPhase::Normal,
                        });
                    }
                    (q, now)
                },
                |(q, now)| {
                    let ready = q.drain_ready(now);
                    black_box(ready);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

// ===== 双水位计算基准 =====

fn bench_watermark_calc(c: &mut Criterion) {
    let mut group = c.benchmark_group("watermark/compute");
    for peer_count in [2, 4, 8].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            peer_count,
            |b, &n| {
                let calc = WatermarkCalculator::new(Duration::from_secs(86400));
                let now = std::time::SystemTime::now();
                let acks: Vec<AckSummary> = (0..n)
                    .map(|i| {
                        ack(
                            pid(i as u64),
                            "d1",
                            Frontier::from_iter((0..n).map(|j| (pid(j as u64), 100))),
                            100,
                        )
                    })
                    .collect();
                b.iter(|| {
                    let w = calc.compute(&DocId::new("d1"), black_box(&acks), now);
                    black_box(w);
                });
            },
        );
    }
    group.finish();
}

// ===== CRDT block 编辑基准 =====

fn bench_block_edit_and_export(c: &mut Criterion) {
    let mut group = c.benchmark_group("crdt/block_edit");
    for edit_count in [10, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(edit_count),
            edit_count,
            |b, &n| {
                b.iter_batched(
                    || {
                        let store = Store::open_memory().unwrap();
                        let ds = DocStore::new(pid(1), store, 32);
                        ds.create_doc(DocId::new("d1"), "note").unwrap();
                        ds.create_block(&DocId::new("d1"), BlockId::new("b1"), BlockKind::Text)
                            .unwrap();
                        ds
                    },
                    |ds| {
                        for i in 0..n {
                            ds.apply_local_edit(
                                &DocId::new("d1"),
                                &BlockId::new("b1"),
                                format!("edit line {i}\n").as_bytes(),
                            )
                            .unwrap();
                        }
                        let delta = ds
                            .export_block_delta(
                                &DocId::new("d1"),
                                &BlockId::new("b1"),
                                &Frontier::new(),
                            )
                            .unwrap();
                        black_box(delta);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

// ===== SyncEngine on_peer_summary 基准 =====

fn bench_engine_peer_summary(c: &mut Criterion) {
    c.bench_function("sync_engine/on_peer_summary", |b| {
        b.iter_batched(
            || {
                let store = Store::open_memory().unwrap();
                let doc_store = std::sync::Arc::new(DocStore::new(pid(1), store, 32));
                doc_store.create_doc(DocId::new("d1"), "note").unwrap();
                tacit_sync::DefaultSyncEngine::new(
                    doc_store,
                    EngineConfig {
                        peer_id: pid(1),
                        ..Default::default()
                    },
               )
            },
            |engine| {
                engine
                    .on_peer_summary(
                        pid(2),
                        tacit_core::PeerSummary {
                            peer_id: pid(2),
                            online: true,
                            frontier: Frontier::new(),
                            capabilities: Default::default(),
                        },
                    )
                    .unwrap();
                let actions = engine.drain_actions();
                black_box(actions);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_priority_queue_push,
    bench_priority_queue_drain,
    bench_pending_queue_drain_ready,
    bench_watermark_calc,
    bench_block_edit_and_export,
    bench_engine_peer_summary,
);
criterion_main!(benches);
