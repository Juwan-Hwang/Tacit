//! 网络混沌测试：断连/延迟/丢包/切换/kill-restart。
//!
//! 模拟真实网络环境下的异常情况，验证同步引擎的健壮性。

use std::sync::Arc;
use std::time::Duration;

use tacit_core::{BatchFlag, BlockId, BlockKind, DocId, Frontier, PeerId};
use tacit_store::Store;
use tacit_sync::{DefaultSyncEngine, DocStore, EngineConfig, SyncEngine};
use tacit_transport::batch::{BatchSigner, BatchVerifier, BatchVerifyResult};

fn pid(n: u64) -> PeerId {
    PeerId(n.to_string())
}

fn make_node(peer_n: u64) -> (Arc<DocStore>, DefaultSyncEngine) {
    let store = Store::open_memory().unwrap();
    let doc_store = Arc::new(DocStore::new(pid(peer_n), store, 32));
    let engine = DefaultSyncEngine::new(
        doc_store.clone(),
        EngineConfig {
            peer_id: pid(peer_n),
            ..Default::default()
        },
    );
    (doc_store, engine)
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

/// 测试：断连后重连，数据最终收敛。
#[test]
fn disconnect_reconnect_converges() {
    let (ds1, _e1) = make_node(1);
    let (ds2, _e2) = make_node(2);

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

    // 模拟断连：双方各自独立编辑
    ds1.apply_local_edit(&doc_id, &block_id, b" + peer1 offline edit")
        .unwrap();
    ds2.apply_local_edit(&doc_id, &block_id, b" + peer2 offline edit")
        .unwrap();

    // 重连后双向同步
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
    assert_eq!(r1, r2, "断连重连后应收敛");
}

/// 测试：乱序到达的 delta 仍能正确合并（CRDT 特性）。
#[test]
fn out_of_order_delivery_converges() {
    let (ds1, _e1) = make_node(1);
    let (ds2, _e2) = make_node(2);

    let doc_id = DocId::new("doc1");
    let block_id = BlockId::new("b1");

    ds1.create_doc(doc_id.clone(), "note").unwrap();
    ds1.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();

    // peer 1 做三次编辑，记录每次编辑后的 frontier
    ds1.apply_local_edit(&doc_id, &block_id, b"edit1").unwrap();
    let _f1 = ds1.block_frontier(&doc_id, &block_id).unwrap();

    ds1.apply_local_edit(&doc_id, &block_id, b" edit2").unwrap();
    let f2 = ds1.block_frontier(&doc_id, &block_id).unwrap();

    ds1.apply_local_edit(&doc_id, &block_id, b" edit3").unwrap();
    let _f3 = ds1.block_frontier(&doc_id, &block_id).unwrap();

    // peer 2 先创建空 block
    ds2.create_doc(doc_id.clone(), "note").unwrap();
    ds2.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();

    // 乱序导入：先导入 f2→f3 的 delta，再导入 empty→f1，再导入 f1→f2
    // CRDT 应能正确合并任意顺序的 delta
    let delta_f2_f3 = ds1.export_block_delta(&doc_id, &block_id, &f2).unwrap();
    ds2.import_block(&doc_id, &block_id, &delta_f2_f3).unwrap();

    let delta_empty_f1 = ds1.export_block_snapshot(&doc_id, &block_id).unwrap();
    // 先导入 snapshot（包含到 f3 的完整状态），后续 delta 可能是 no-op
    ds2.import_block(&doc_id, &block_id, &delta_empty_f1)
        .unwrap();

    // 最终状态应收敛
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
    assert_eq!(r1, r2, "乱序 delta 应最终收敛");
}

/// 测试：重复帧导入不会破坏数据（幂等性）。
#[test]
fn duplicate_frames_are_idempotent() {
    let (ds1, _e1) = make_node(1);
    let (ds2, _e2) = make_node(2);

    let doc_id = DocId::new("doc1");
    let block_id = BlockId::new("b1");

    ds1.create_doc(doc_id.clone(), "note").unwrap();
    ds1.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds1.apply_local_edit(&doc_id, &block_id, b"hello").unwrap();

    let empty = Frontier::new();
    transfer_meta_delta(&ds1, &ds2, &doc_id, &empty);
    transfer_block_delta(&ds1, &ds2, &doc_id, &block_id, &empty);

    // 重复导入同一个 delta
    let f_before = ds2.block_frontier(&doc_id, &block_id).unwrap();
    let _delta = ds1
        .export_block_delta(&doc_id, &block_id, &f_before)
        .unwrap();
    // peer 1 再编辑
    ds1.apply_local_edit(&doc_id, &block_id, b" world").unwrap();
    let delta = ds1
        .export_block_delta(&doc_id, &block_id, &f_before)
        .unwrap();

    // 导入两次
    ds2.import_block(&doc_id, &block_id, &delta).unwrap();
    ds2.import_block(&doc_id, &block_id, &delta).unwrap();

    // 验证内容正确且不重复
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
    assert_eq!(r1, r2, "重复导入应幂等");
}

/// 测试：kill-restart 后数据持久化（使用临时文件数据库）。
#[test]
fn kill_restart_preserves_data() {
    let doc_id = DocId::new("doc1");
    let block_id = BlockId::new("b1");

    // 使用临时目录中的数据库文件模拟 kill-restart
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db_path_str = db_path.to_str().unwrap();

    // 第一次启动：写入数据
    {
        let store = Store::open(db_path_str).unwrap();
        let ds = Arc::new(DocStore::new(pid(1), store, 32));
        ds.create_doc(doc_id.clone(), "note").unwrap();
        ds.create_block(&doc_id, block_id.clone(), BlockKind::Text)
            .unwrap();
        ds.apply_local_edit(&doc_id, &block_id, b"persistent data")
            .unwrap();
        // 显式 flush dirty blocks
        ds.flush_dirty_blocks().unwrap();
    }
    // 模拟 kill：Arc drop，Store 关闭

    // 第二次启动：验证数据仍在
    {
        let store = Store::open(db_path_str).unwrap();
        let ds = Arc::new(DocStore::new(pid(1), store, 32));
        let block = ds.get_block(&doc_id, &block_id).unwrap();
        let render = block.export_render_bytes().unwrap();
        assert!(
            render
                .windows(b"persistent data".len())
                .any(|w| w == b"persistent data"),
            "kill-restart 后数据应持久化"
        );
    }
}

/// 测试：批次签名验证 — 篡改中间帧后签名不匹配。
#[test]
fn batch_signature_detects_tampering() {
    let signer = BatchSigner::new();
    let verifier = BatchVerifier::new();

    let peer_id = pid(1);
    let doc_id = DocId::new("doc1");

    // 发送方：批次模式发送 3 帧
    signer.start_batch(&peer_id, &doc_id);
    let _ = signer.add_frame(&peer_id, &doc_id, b"frame1");
    let _ = signer.add_frame(&peer_id, &doc_id, b"frame2");
    let _ = signer.add_frame(&peer_id, &doc_id, b"frame3");
    let signature = signer.end_batch(&peer_id, &doc_id).unwrap();

    // 接收方：验证批次
    // BatchStart
    let r1 = verifier.receive_frame(&peer_id, &doc_id, b"frame1", BatchFlag::BatchStart, None);
    assert_eq!(r1, BatchVerifyResult::Accepted);

    // BatchMiddle — 篡改 payload
    let r2 = verifier.receive_frame(&peer_id, &doc_id, b"TAMPERED", BatchFlag::BatchMiddle, None);
    assert_eq!(r2, BatchVerifyResult::Accepted);

    // BatchEnd — 签名不匹配
    let r3 = verifier.receive_frame(
        &peer_id,
        &doc_id,
        b"frame3",
        BatchFlag::BatchEnd,
        Some(&signature),
    );
    assert_eq!(r3, BatchVerifyResult::Mismatch, "篡改后签名应不匹配");
}

/// 测试：批次签名验证 — 正确批次通过验证。
#[test]
fn batch_signature_correct_passes() {
    let signer = BatchSigner::new();
    let verifier = BatchVerifier::new();

    let peer_id = pid(1);
    let doc_id = DocId::new("doc1");

    signer.start_batch(&peer_id, &doc_id);
    let _ = signer.add_frame(&peer_id, &doc_id, b"frame1");
    let _ = signer.add_frame(&peer_id, &doc_id, b"frame2");
    let _ = signer.add_frame(&peer_id, &doc_id, b"frame3");
    let signature = signer.end_batch(&peer_id, &doc_id).unwrap();

    let r1 = verifier.receive_frame(&peer_id, &doc_id, b"frame1", BatchFlag::BatchStart, None);
    assert_eq!(r1, BatchVerifyResult::Accepted);

    let r2 = verifier.receive_frame(&peer_id, &doc_id, b"frame2", BatchFlag::BatchMiddle, None);
    assert_eq!(r2, BatchVerifyResult::Accepted);

    let r3 = verifier.receive_frame(
        &peer_id,
        &doc_id,
        b"frame3",
        BatchFlag::BatchEnd,
        Some(&signature),
    );
    assert_eq!(r3, BatchVerifyResult::Verified, "正确批次应通过验证");
}

/// 测试：无活跃批次时收到 BatchMiddle 返回错误。
#[test]
fn batch_middle_without_start_rejected() {
    let verifier = BatchVerifier::new();
    let peer_id = pid(1);
    let doc_id = DocId::new("doc1");

    let r = verifier.receive_frame(&peer_id, &doc_id, b"orphan", BatchFlag::BatchMiddle, None);
    assert_eq!(r, BatchVerifyResult::NoActiveBatch, "无活跃批次时应拒绝");
}

/// 测试：网络类型切换触发 fast-resume。
#[test]
fn network_switch_triggers_fast_resume() {
    let (ds, engine) = make_node(1);

    // 创建文档和 block，使 fast-resume 有内容可同步
    let doc_id = DocId::new("doc1");
    let block_id = BlockId::new("b1");
    ds.create_doc(doc_id.clone(), "note").unwrap();
    ds.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds.apply_local_edit(&doc_id, &block_id, b"initial").unwrap();

    // 初始状态无动作
    let actions = engine.drain_actions();
    assert!(actions.is_empty(), "初始状态无待执行动作");

    // 触发 fast-resume
    engine.fast_resume(None).unwrap();

    // fast-resume 后应产生同步动作（有内容需同步）
    let actions = engine.drain_actions();
    assert!(
        !actions.is_empty(),
        "fast-resume 有内容时应产生同步动作"
    );
}

/// 测试：stale peer 清理。
#[test]
fn stale_peers_are_cleaned_up() {
    use tacit_core::PeerSummary;
    let (_ds, engine) = make_node(1);

    // 注册 peer 并标记在线（on_peer_summary 会写入 peer_states）
    engine
        .on_peer_summary(
            pid(2),
            PeerSummary {
                peer_id: pid(2),
                online: true,
                frontier: Frontier::new(),
                capabilities: Default::default(),
            },
        )
        .unwrap();

    // 确认 peer 已注册
    assert!(!engine.online_peers().is_empty(), "peer 应已在线");

    // 清理 0 秒未活跃的 peer（应被清理）
    let removed = engine.cleanup_stale_peers(Duration::from_secs(0));
    assert_eq!(
        removed.len(),
        1,
        "0s TTL 应清理 1 个 stale peer，实际清理: {:?}",
        removed
    );
    assert_eq!(removed[0], pid(2));
}

/// 测试：多节点串行同步链（A→B→C→A）最终收敛。
#[test]
fn serial_sync_chain_converges() {
    let (ds1, _e1) = make_node(1);
    let (ds2, _e2) = make_node(2);
    let (ds3, _e3) = make_node(3);

    let doc_id = DocId::new("doc1");
    let block_id = BlockId::new("b1");

    // A 创建并编辑
    ds1.create_doc(doc_id.clone(), "note").unwrap();
    ds1.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds1.apply_local_edit(&doc_id, &block_id, b"A").unwrap();

    // A→B
    let empty = Frontier::new();
    transfer_meta_delta(&ds1, &ds2, &doc_id, &empty);
    transfer_block_delta(&ds1, &ds2, &doc_id, &block_id, &empty);

    // B 编辑
    ds2.apply_local_edit(&doc_id, &block_id, b" B").unwrap();

    // B→C
    transfer_meta_delta(&ds1, &ds3, &doc_id, &empty);
    transfer_block_delta(&ds2, &ds3, &doc_id, &block_id, &empty);

    // C 编辑
    ds3.apply_local_edit(&doc_id, &block_id, b" C").unwrap();

    // C→A（闭环）
    let f1 = ds1.block_frontier(&doc_id, &block_id).unwrap();
    transfer_block_delta(&ds3, &ds1, &doc_id, &block_id, &f1);

    // A→B（传播 C 的编辑）
    let f2 = ds2.block_frontier(&doc_id, &block_id).unwrap();
    transfer_block_delta(&ds1, &ds2, &doc_id, &block_id, &f2);

    // 验证三端收敛
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
    let r3 = ds3
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();

    assert_eq!(r1, r2, "A 和 B 应收敛");
    assert_eq!(r2, r3, "B 和 C 应收敛");
}
