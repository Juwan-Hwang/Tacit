//! 长运行内存泄漏检测测试。
//!
//! 模拟 SyncEngine 在持续运行下的内存行为：
//! - 多轮文档编辑 + delta 同步 + block 导入/导出
//! - snapshot 反复 export/import
//! - 批量导入回滚
//!
//! 断言策略：
//! - 每轮结束后数据一致性不变（无状态漂移）
//! - 渲染结果稳定（无数据丢失/污染）
//! - 排空 actions 后无残留
//!
//! 注意：此测试不依赖系统级内存统计（跨平台不可靠），
//! 而是通过验证数据一致性来间接验证无泄漏。

use std::sync::Arc;

use tacit_core::{BlockId, BlockKind, DocId, PeerId};
use tacit_store::Store;
use tacit_sync::{DocStore, EngineConfig};

fn pid(n: u64) -> PeerId {
    PeerId(n.to_string())
}

fn make_node(peer_n: u64) -> (Arc<DocStore>, tacit_sync::DefaultSyncEngine) {
    let store = Store::open_memory().unwrap();
    let doc_store = Arc::new(DocStore::new(pid(peer_n), store, 32));
    let engine = tacit_sync::DefaultSyncEngine::new(
        doc_store.clone(),
        EngineConfig {
            peer_id: pid(peer_n),
            ..Default::default()
        },
    );
    (doc_store, engine)
}

/// 模拟 50 轮编辑 + delta 自回环 + action 排空，验证无状态漂移。
#[test]
fn long_run_edit_sync_no_leak() {
    let (doc_store, engine) = make_node(1);
    let doc_id = DocId::new("leak-test-doc");
    let block_id = BlockId::new("leak-test-block");

    doc_store.create_doc(doc_id.clone(), "doc").unwrap();
    doc_store
        .create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();

    // 初始内容
    let block = doc_store.get_block(&doc_id, &block_id).unwrap();
    block.apply_edit(b"initial").unwrap();

    const ROUNDS: usize = 50;
    let mut last_render = doc_store
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();

    for round in 0..ROUNDS {
        // 1. 编辑 block
        {
            let block = doc_store.get_block(&doc_id, &block_id).unwrap();
            block.apply_edit(format!(" r{round} ").as_bytes()).unwrap();
        }

        // 2. 导出 delta（从当前 frontier）
        let block = doc_store.get_block(&doc_id, &block_id).unwrap();
        let frontier = block.frontier().unwrap();
        let delta = block.export_delta_since(&frontier).unwrap();

        // 3. 导入 delta（模拟远端数据回环，幂等）
        let block = doc_store.get_block(&doc_id, &block_id).unwrap();
        let result = block.import(&delta).unwrap();
        assert!(
            !result.changed,
            "round {round}: 自回环导入应幂等，frontier 不应变"
        );

        // 4. 排空 actions
        let actions = engine.drain_actions();
        assert!(
            actions.is_empty(),
            "round {round}: actions 队列残留 {} 条",
            actions.len()
        );

        // 5. 验证渲染正确（包含所有编辑）
        let render = doc_store
            .get_block(&doc_id, &block_id)
            .unwrap()
            .export_render_bytes()
            .unwrap();
        let text = String::from_utf8_lossy(&render);
        assert!(text.contains("initial"), "round {round}: 初始内容丢失");
        assert!(
            text.contains(&format!(" r{round} ")),
            "round {round}: 编辑内容丢失"
        );

        last_render = render;
    }

    // 最终验证：内容完整
    let final_text = String::from_utf8_lossy(&last_render);
    assert!(final_text.contains("initial"), "最终内容缺失 initial");
    assert!(final_text.contains(" r49 "), "最终内容缺失最后一轮编辑");
}

/// 验证批量导入回滚后缓存不泄漏：交替导入有效/无效数据。
#[test]
fn long_run_batch_import_rollback_no_leak() {
    let (doc_store, engine) = make_node(1);
    let doc_id = DocId::new("leak-rollback-doc");
    let block_id = BlockId::new("leak-rollback-block");

    doc_store.create_doc(doc_id.clone(), "doc").unwrap();
    doc_store
        .create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();

    // 初始编辑
    let block = doc_store.get_block(&doc_id, &block_id).unwrap();
    block.apply_edit(b"initial").unwrap();
    let snap = block.export_snapshot().unwrap();

    // 30 轮交替导入有效 snapshot / 无效字节
    for round in 0..30 {
        let data = if round % 2 == 0 {
            snap.clone()
        } else {
            vec![0xFF; 10] // 无效 CRDT 字节，触发回滚
        };

        let _ = doc_store.import_blocks_batch(&doc_id, &[(block_id.clone(), data)]);

        // 排空 actions
        let _ = engine.drain_actions();
    }

    // 回滚后初始内容应保留（回滚不应破坏数据）
    let block = doc_store.get_block(&doc_id, &block_id).unwrap();
    let render = block.export_render_bytes().unwrap();
    let text = String::from_utf8_lossy(&render);
    assert!(text.contains("initial"), "回滚后数据损坏: {text}");
}

/// 验证反复 export/import snapshot 不导致状态漂移。
#[test]
fn long_run_snapshot_sync_stable() {
    let (doc_store_a, engine_a) = make_node(1);
    let (doc_store_b, engine_b) = make_node(2);

    let doc_id = DocId::new("leak-snap-doc");
    let block_id = BlockId::new("leak-snap-block");

    // A 创建并编辑
    doc_store_a.create_doc(doc_id.clone(), "doc").unwrap();
    doc_store_a
        .create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    let block_a = doc_store_a.get_block(&doc_id, &block_id).unwrap();
    block_a.apply_edit(b"base content").unwrap();

    // B 创建空 block
    doc_store_b.create_doc(doc_id.clone(), "doc").unwrap();
    doc_store_b
        .create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();

    // 20 轮 snapshot 同步
    for round in 0..20 {
        // A 编辑
        let block_a = doc_store_a.get_block(&doc_id, &block_id).unwrap();
        block_a
            .apply_edit(format!(" r{round} ").as_bytes())
            .unwrap();

        // A export snapshot
        let block_a = doc_store_a.get_block(&doc_id, &block_id).unwrap();
        let snap = block_a.export_snapshot().unwrap();

        // B import snapshot
        let block_b = doc_store_b.get_block(&doc_id, &block_id).unwrap();
        block_b.import(&snap).unwrap();

        // 验证渲染一致
        let render_a = doc_store_a
            .get_block(&doc_id, &block_id)
            .unwrap()
            .export_render_bytes()
            .unwrap();
        let render_b = doc_store_b
            .get_block(&doc_id, &block_id)
            .unwrap()
            .export_render_bytes()
            .unwrap();
        assert_eq!(
            render_a, render_b,
            "round {round}: snapshot 同步后渲染不一致"
        );

        // 排空 actions
        let _ = engine_a.drain_actions();
        let _ = engine_b.drain_actions();
    }

    // 最终 frontier 一致
    let fa = doc_store_a
        .get_block(&doc_id, &block_id)
        .unwrap()
        .frontier()
        .unwrap();
    let fb = doc_store_b
        .get_block(&doc_id, &block_id)
        .unwrap()
        .frontier()
        .unwrap();
    assert_eq!(fa, fb, "最终 frontier 不一致 — 状态漂移");
}
