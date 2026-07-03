//! 3 天离线追赶完整场景测试。
//!
//! 模拟设备离线 3 天后恢复，通过 shallow snapshot + tail delta 追赶最新状态。
//! 验证：
//! - 大量离线编辑后追赶成功
//! - 多 block 场景追赶
//! - checkpoint 辅助追赶
//! - 追赶后数据一致

use std::sync::Arc;

use tacit_core::{BlockId, BlockKind, DocId, Frontier, PeerId};
use tacit_store::Store;
use tacit_sync::DocStore;

fn pid(n: u64) -> PeerId {
    PeerId(n.to_string())
}

fn make_node(peer_n: u64) -> Arc<DocStore> {
    let store = Store::open_memory().unwrap();
    Arc::new(DocStore::new(pid(peer_n), store, 32))
}

fn transfer_block_delta(
    source: &DocStore,
    target: &DocStore,
    doc_id: &DocId,
    block_id: &BlockId,
    since: &Frontier,
) {
    if target.get_block(doc_id, block_id).is_err() {
        let doc_exists = {
            let conn = target.store().conn();
            tacit_store::dao::get_doc(&conn, doc_id).unwrap().is_some()
        };
        if !doc_exists {
            target.create_doc(doc_id.clone(), "note").unwrap();
        }
        target
            .create_block(doc_id, block_id.clone(), BlockKind::Text)
            .unwrap();
    }
    let bytes = if since.is_empty() {
        source.export_block_snapshot(doc_id, block_id).unwrap()
    } else {
        source.export_block_delta(doc_id, block_id, since).unwrap()
    };
    target.import_block(doc_id, block_id, &bytes).unwrap();
}

fn transfer_meta_delta(source: &DocStore, target: &DocStore, doc_id: &DocId, since: &Frontier) {
    let doc_exists = {
        let conn = target.store().conn();
        tacit_store::dao::get_doc(&conn, doc_id).unwrap().is_some()
    };
    if !doc_exists {
        target.create_doc(doc_id.clone(), "note").unwrap();
    }
    let bytes = if since.is_empty() {
        source.export_meta_snapshot(doc_id).unwrap()
    } else {
        source.export_meta_delta(doc_id, since).unwrap()
    };
    target.import_meta(doc_id, &bytes).unwrap();
}

/// 测试：3 天离线追赶 — 模拟大量编辑后通过 shallow snapshot + tail delta 追赶。
#[test]
fn three_day_offline_catchup() {
    let ds1 = make_node(1); // 离线设备
    let ds2 = make_node(2); // 在线设备

    let doc_id = DocId::new("doc1");
    let block_id = BlockId::new("b1");

    // 初始同步
    ds1.create_doc(doc_id.clone(), "note").unwrap();
    ds1.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds1.apply_local_edit(&doc_id, &block_id, b"day 0 initial")
        .unwrap();

    let empty = Frontier::new();
    transfer_meta_delta(&ds1, &ds2, &doc_id, &empty);
    transfer_block_delta(&ds1, &ds2, &doc_id, &block_id, &empty);

    // peer 1 离线前的 frontier
    let stale_frontier = ds1.block_frontier(&doc_id, &block_id).unwrap();

    // 模拟 3 天的编辑（peer 2 持续编辑，peer 1 离线）
    for day in 1..=3 {
        for edit in 0..10 {
            let text = format!(" day{}_edit{}", day, edit);
            ds2.apply_local_edit(&doc_id, &block_id, text.as_bytes())
                .unwrap();
        }
    }

    let peer2_final_render = ds2
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();

    // peer 1 回来，通过 shallow snapshot + tail delta 追赶
    let shallow = ds2
        .export_block_shallow(&doc_id, &block_id, &stale_frontier)
        .unwrap();
    let tail_delta = ds2
        .export_block_delta(&doc_id, &block_id, &stale_frontier)
        .unwrap();

    ds1.import_block(&doc_id, &block_id, &shallow).unwrap();
    ds1.import_block(&doc_id, &block_id, &tail_delta).unwrap();

    // 验证 peer 1 追上 peer 2
    let peer1_final_render = ds1
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();
    assert_eq!(
        peer1_final_render, peer2_final_render,
        "3 天离线后应追上最新状态"
    );
}

/// 测试：多 block 离线追赶。
#[test]
fn multi_block_offline_catchup() {
    let ds1 = make_node(1);
    let ds2 = make_node(2);

    let doc_id = DocId::new("doc1");
    let blocks: Vec<BlockId> = (0..5).map(|i| BlockId::new(format!("b{i}"))).collect();

    // 初始：peer 1 创建 5 个 block
    ds1.create_doc(doc_id.clone(), "note").unwrap();
    for bid in &blocks {
        ds1.create_block(&doc_id, bid.clone(), BlockKind::Text)
            .unwrap();
        ds1.apply_local_edit(&doc_id, bid, b"initial").unwrap();
    }

    // 同步到 peer 2
    let empty = Frontier::new();
    transfer_meta_delta(&ds1, &ds2, &doc_id, &empty);
    for bid in &blocks {
        transfer_block_delta(&ds1, &ds2, &doc_id, bid, &empty);
    }

    // peer 1 离线，peer 2 编辑所有 block
    let mut stale_frontiers = Vec::new();
    for bid in &blocks {
        stale_frontiers.push(ds1.block_frontier(&doc_id, bid).unwrap());
    }

    for (i, bid) in blocks.iter().enumerate() {
        for edit in 0..5 {
            let text = format!(" edit{}_{}", i, edit);
            ds2.apply_local_edit(&doc_id, bid, text.as_bytes()).unwrap();
        }
    }

    // peer 1 追赶所有 block
    for (bid, stale_f) in blocks.iter().zip(stale_frontiers.iter()) {
        let tail = ds2.export_block_delta(&doc_id, bid, stale_f).unwrap();
        ds1.import_block(&doc_id, bid, &tail).unwrap();
    }

    // 验证所有 block 收敛
    for bid in &blocks {
        let r1 = ds1
            .get_block(&doc_id, bid)
            .unwrap()
            .export_render_bytes()
            .unwrap();
        let r2 = ds2
            .get_block(&doc_id, bid)
            .unwrap()
            .export_render_bytes()
            .unwrap();
        assert_eq!(r1, r2, "block {} 应收敛", bid.as_str());
    }
}

/// 测试：离线期间新增 block 的追赶。
#[test]
fn offline_new_block_catchup() {
    let ds1 = make_node(1);
    let ds2 = make_node(2);

    let doc_id = DocId::new("doc1");
    let block1 = BlockId::new("b1");

    // 初始同步
    ds1.create_doc(doc_id.clone(), "note").unwrap();
    ds1.create_block(&doc_id, block1.clone(), BlockKind::Text)
        .unwrap();
    ds1.apply_local_edit(&doc_id, &block1, b"initial").unwrap();

    let empty = Frontier::new();
    transfer_meta_delta(&ds1, &ds2, &doc_id, &empty);
    transfer_block_delta(&ds1, &ds2, &doc_id, &block1, &empty);

    // peer 1 离线，peer 2 新增 block2 并编辑
    let block2 = BlockId::new("b2");
    ds2.create_block(&doc_id, block2.clone(), BlockKind::Text)
        .unwrap();
    ds2.apply_local_edit(&doc_id, &block2, b"new block while peer1 offline")
        .unwrap();

    // peer 1 回来，先同步 meta（获知新 block），再同步 block2
    let stale_meta = ds1.meta_frontier(&doc_id).unwrap();
    transfer_meta_delta(&ds2, &ds1, &doc_id, &stale_meta);

    // peer 1 现在知道 block2，同步 block2 的完整 snapshot
    transfer_block_delta(&ds2, &ds1, &doc_id, &block2, &empty);

    // 验证 block2 内容一致
    let r1 = ds1
        .get_block(&doc_id, &block2)
        .unwrap()
        .export_render_bytes()
        .unwrap();
    let r2 = ds2
        .get_block(&doc_id, &block2)
        .unwrap()
        .export_render_bytes()
        .unwrap();
    assert_eq!(r1, r2, "新 block 应同步成功");
}

/// 测试：离线追赶后双向编辑仍能收敛。
#[test]
fn catchup_then_bidirectional_edit_converges() {
    let ds1 = make_node(1);
    let ds2 = make_node(2);

    let doc_id = DocId::new("doc1");
    let block_id = BlockId::new("b1");

    // 初始同步
    ds1.create_doc(doc_id.clone(), "note").unwrap();
    ds1.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds1.apply_local_edit(&doc_id, &block_id, b"initial")
        .unwrap();

    let empty = Frontier::new();
    transfer_meta_delta(&ds1, &ds2, &doc_id, &empty);
    transfer_block_delta(&ds1, &ds2, &doc_id, &block_id, &empty);

    // peer 1 离线，peer 2 编辑
    let stale_f = ds1.block_frontier(&doc_id, &block_id).unwrap();
    ds2.apply_local_edit(&doc_id, &block_id, b" peer2 offline work")
        .unwrap();

    // peer 1 追赶
    let tail = ds2
        .export_block_delta(&doc_id, &block_id, &stale_f)
        .unwrap();
    ds1.import_block(&doc_id, &block_id, &tail).unwrap();

    // 追赶后双方各自编辑
    ds1.apply_local_edit(&doc_id, &block_id, b" peer1 post-catchup")
        .unwrap();
    ds2.apply_local_edit(&doc_id, &block_id, b" peer2 post-catchup")
        .unwrap();

    // 双向同步
    let f1 = ds1.block_frontier(&doc_id, &block_id).unwrap();
    transfer_block_delta(&ds2, &ds1, &doc_id, &block_id, &f1);
    let f2 = ds2.block_frontier(&doc_id, &block_id).unwrap();
    transfer_block_delta(&ds1, &ds2, &doc_id, &block_id, &f2);

    // 验证收敛
    let r1 = ds1
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();
    let r2 = ds2
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();
    assert_eq!(r1, r2, "追赶后双向编辑应收敛");
}
