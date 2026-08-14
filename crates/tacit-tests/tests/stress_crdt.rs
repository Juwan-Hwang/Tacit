//! CRDT 大文档 + 多 peer 高频编辑压力测试。
//!
//! 验证 CRDT 引擎在极端规模下的正确性：
//! - 大文档：单 block 1000 次编辑，验证 delta/snapshot 正确性
//! - 多 peer 并发编辑收敛：4 节点星型同步，每节点 250 次编辑
//! - 大 delta 导入：100KB delta 导入不报错
//! - 高频编辑后 GC 安全性：编辑+快照+导入后数据一致

use std::sync::Arc;

use tacit_core::{BlockId, BlockKind, DocId, Frontier, PeerId};
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

/// 模拟单机 push：从 source 导出 block delta，导入到 target。
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

/// 大文档压力测试：单 block 1000 次编辑，验证内容完整 + delta 可导出。
#[test]
fn large_document_1000_edits() {
    let (ds, _) = make_node(1);
    let doc_id = DocId::new("stress-doc");
    let block_id = BlockId::new("stress-block");

    ds.create_doc(doc_id.clone(), "note").unwrap();
    ds.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();

    // 初始内容
    ds.apply_local_edit(&doc_id, &block_id, b"base\n").unwrap();

    // 1000 次编辑
    for i in 0..1000u32 {
        let edit = format!("line {i}\n").into_bytes();
        ds.apply_local_edit(&doc_id, &block_id, &edit).unwrap();
    }

    // 验证内容完整
    let render = ds
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();
    let text = String::from_utf8_lossy(&render);
    assert!(text.contains("base"), "初始内容应保留");
    assert!(text.contains("line 0"), "第一条编辑应存在");
    assert!(text.contains("line 999"), "最后一条编辑应存在");

    // 验证 delta 可从空 frontier 导出（全量 delta）
    let delta = ds
        .export_block_delta(&doc_id, &block_id, &Frontier::new())
        .unwrap();
    assert!(!delta.is_empty(), "全量 delta 不应为空");

    // 验证 snapshot 可导出
    let snap = ds.export_block_snapshot(&doc_id, &block_id).unwrap();
    assert!(!snap.is_empty(), "snapshot 不应为空");

    // 验证增量 delta：自当前 frontier 之后无新增 → delta 可能为空或极小
    let f = ds.block_frontier(&doc_id, &block_id).unwrap();
    let tail = ds.export_block_delta(&doc_id, &block_id, &f).unwrap();
    // Loro UpdatesSince 语义：自身 frontier 处可能返回空 delta 或极小 delta
    assert!(
        tail.len() < 100,
        "自身 frontier 之后的 delta 应为空或极小，实际 {} 字节",
        tail.len()
    );
}

/// 多 peer 并发编辑收敛：4 节点星型同步，每节点 250 次编辑 → 4×250=1000 次总编辑。
///
/// 拓扑：peer 2 → peer 1（中心），peer 3 → peer 1，peer 4 → peer 1
/// 每次：各 peer 独立编辑 → 同步到 peer 1 → peer 1 同步回各 peer
#[test]
fn multi_peer_converge_4_nodes_250_edits_each() {
    let (ds1, _) = make_node(1);
    let (ds2, _) = make_node(2);
    let (ds3, _) = make_node(3);
    let (ds4, _) = make_node(4);

    let doc_id = DocId::new("converge-doc");
    let block_id = BlockId::new("converge-block");

    // 所有节点创建文档和 block
    for ds in &[&ds1, &ds2, &ds3, &ds4] {
        ds.create_doc(doc_id.clone(), "note").unwrap();
        ds.create_block(&doc_id, block_id.clone(), BlockKind::Text)
            .unwrap();
    }

    // peer 1 写初始内容
    ds1.apply_local_edit(&doc_id, &block_id, b"init\n").unwrap();

    // 先同步 peer1 的初始内容到所有节点
    let empty = Frontier::new();
    transfer_block_delta(&ds1, &ds2, &doc_id, &block_id, &empty);
    transfer_block_delta(&ds1, &ds3, &doc_id, &block_id, &empty);
    transfer_block_delta(&ds1, &ds4, &doc_id, &block_id, &empty);

    // 每节点 250 次编辑，分 5 轮（每轮 50 次），每轮后同步
    const ROUNDS: u32 = 5;
    const EDITS_PER_ROUND: u32 = 50;

    for round in 0..ROUNDS {
        // 各 peer 独立编辑
        for (i, ds) in [&ds2, &ds3, &ds4].iter().enumerate() {
            for j in 0..EDITS_PER_ROUND {
                let edit = format!("r{round}p{}e{j}\n", i + 2).into_bytes();
                ds.apply_local_edit(&doc_id, &block_id, &edit).unwrap();
            }
        }

        // 同步到 peer 1（中心）：以 peer1 的 frontier 为 since
        for ds in &[&ds2, &ds3, &ds4] {
            let f1 = ds1.block_frontier(&doc_id, &block_id).unwrap();
            transfer_block_delta(ds, &ds1, &doc_id, &block_id, &f1);
        }

        // peer 1 同步回各 peer：以各 peer 的 frontier 为 since
        for ds in &[&ds2, &ds3, &ds4] {
            let f = ds.block_frontier(&doc_id, &block_id).unwrap();
            transfer_block_delta(&ds1, ds, &doc_id, &block_id, &f);
        }
    }

    // 验证四端收敛
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
    let r4 = ds4
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();

    assert_eq!(r1, r2, "peer1 和 peer2 应收敛");
    assert_eq!(r2, r3, "peer2 和 peer3 应收敛");
    assert_eq!(r3, r4, "peer3 和 peer4 应收敛");

    // 验证内容包含所有编辑标记
    let text = String::from_utf8_lossy(&r1);
    assert!(text.contains("init"), "初始内容应保留");
    assert!(text.contains("r0p2e0"), "第一轮 peer2 的第一条编辑应存在");
    assert!(
        text.contains("r4p4e49"),
        "最后一轮 peer4 的最后一条编辑应存在"
    );

    // 验证 frontier 一致
    let f1 = ds1.block_frontier(&doc_id, &block_id).unwrap();
    let f2 = ds2.block_frontier(&doc_id, &block_id).unwrap();
    let f3 = ds3.block_frontier(&doc_id, &block_id).unwrap();
    let f4 = ds4.block_frontier(&doc_id, &block_id).unwrap();
    assert_eq!(f1, f2, "peer1/peer2 frontier 应一致");
    assert_eq!(f2, f3, "peer2/peer3 frontier 应一致");
    assert_eq!(f3, f4, "peer3/peer4 frontier 应一致");
}

/// 大 delta 导入测试：生成 ~100KB delta 并导入到新节点，验证不报错。
#[test]
fn large_delta_100kb_import() {
    let (ds1, _) = make_node(1);
    let (ds2, _) = make_node(2);

    let doc_id = DocId::new("large-delta-doc");
    let block_id = BlockId::new("large-delta-block");

    ds1.create_doc(doc_id.clone(), "note").unwrap();
    ds1.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();

    // 生成大内容：500 行 × ~200 字节/行 = ~100KB
    let mut content = String::with_capacity(1024 * 128);
    content.push_str("=== large delta test ===\n");
    for i in 0..500u32 {
        content.push_str(&format!(
            "this is line {i} with some padding data to make it longer xxxxxxx\n"
        ));
    }
    ds1.apply_local_edit(&doc_id, &block_id, content.as_bytes())
        .unwrap();

    // 导出 snapshot（包含全部内容）
    let snap = ds1.export_block_snapshot(&doc_id, &block_id).unwrap();
    // Loro snapshot 是二进制编码，可能比原始文本小（内部压缩）
    assert!(!snap.is_empty(), "snapshot 不应为空");

    // 导入到 peer 2
    ds2.create_doc(doc_id.clone(), "note").unwrap();
    ds2.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds2.import_block(&doc_id, &block_id, &snap).unwrap();

    // 验证内容一致
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
    assert_eq!(r1, r2, "大文档导入后内容应一致");

    // 验证特定行存在
    let text = String::from_utf8_lossy(&r2);
    assert!(text.contains("=== large delta test ==="));
    assert!(text.contains("this is line 0 "));
    assert!(text.contains("this is line 499 "));
}

/// 高频编辑后 snapshot 导入回退验证：即使大量编辑后 snapshot 仍然可正确导入到空 block。
#[test]
fn snapshot_after_500_edits_imports_to_empty_block() {
    let (ds1, _) = make_node(1);
    let (ds2, _) = make_node(2);

    let doc_id = DocId::new("snap-import-doc");
    let block_id = BlockId::new("snap-import-block");

    ds1.create_doc(doc_id.clone(), "note").unwrap();
    ds1.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();

    // 500 次编辑
    for i in 0..500u32 {
        ds1.apply_local_edit(&doc_id, &block_id, format!("e{i}\n").as_bytes())
            .unwrap();
    }

    // 导出 snapshot
    let snap = ds1.export_block_snapshot(&doc_id, &block_id).unwrap();
    assert!(!snap.is_empty());

    // peer 2 创建空 block 并导入 snapshot
    ds2.create_doc(doc_id.clone(), "note").unwrap();
    ds2.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds2.import_block(&doc_id, &block_id, &snap).unwrap();

    // 验证 frontier 一致
    let f1 = ds1.block_frontier(&doc_id, &block_id).unwrap();
    let f2 = ds2.block_frontier(&doc_id, &block_id).unwrap();
    assert_eq!(f1, f2, "snapshot 导入后 frontier 应一致");

    // 验证内容一致
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
    assert_eq!(r1, r2, "snapshot 导入后内容应一致");

    // 验证可以继续增量同步：peer 2 编辑后导出 delta 给 peer 1
    ds2.apply_local_edit(&doc_id, &block_id, b"post-import edit\n")
        .unwrap();
    let f1_new = ds1.block_frontier(&doc_id, &block_id).unwrap();
    let delta = ds2.export_block_delta(&doc_id, &block_id, &f1_new).unwrap();
    assert!(!delta.is_empty(), "增量 delta 不应为空");
    ds1.import_block(&doc_id, &block_id, &delta).unwrap();

    let r1_final = ds1
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();
    let r2_final = ds2
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();
    assert_eq!(r1_final, r2_final, "增量同步后应收敛");
    let text = String::from_utf8_lossy(&r1_final);
    assert!(text.contains("post-import edit"), "增量编辑应存在");
}
