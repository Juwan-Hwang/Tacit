//! 收敛测试：两个 engine + LoopbackTransport 端到端同步。
//!
//! 这是"引擎被真正接线后能正确收敛"的可证明性测试。
//! 之前的 429 个测试中没有一条证明 drain_actions → 真实传输 → 入站回引擎的完整闭环。
//! 本测试填补此缺口。

use std::sync::Arc;

use tacit_core::{BlockId, BlockKind, DocId, PeerId, SyncReason};
use tacit_session::{LoopbackTransport, SyncSession};
use tacit_store::Store;
use tacit_sync::{DefaultSyncEngine, DocStore, EngineConfig, SyncEngine};

fn pid(n: u64) -> PeerId {
    PeerId(n.to_string())
}

/// 构造一个内存 DocStore + DefaultSyncEngine。
fn make_engine(peer_n: u64) -> (Arc<DocStore>, Arc<DefaultSyncEngine>) {
    let store = Store::open_memory().unwrap();
    let doc_store = Arc::new(DocStore::new(pid(peer_n), store, 32));
    let engine = Arc::new(DefaultSyncEngine::new(
        doc_store.clone(),
        EngineConfig {
            peer_id: pid(peer_n),
            ..Default::default()
        },
    ));
    (doc_store, engine)
}

/// 用 tokio runtime 驱动 async drive_outbound。
fn drive(session: &SyncSession) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(session.drive_outbound())
        .unwrap();
}

/// 将 transport 上收到的事件喂给 session。
fn pump_events(session: &SyncSession, transport: &LoopbackTransport) {
    for event in transport.drain_events() {
        let _ = session.handle_transport_event(event);
    }
}

/// 双向泵送到收敛：交替 drive + pump 直到无新事件。
fn pump_until_quiet(
    a: &SyncSession,
    b: &SyncSession,
    ta: &LoopbackTransport,
    tb: &LoopbackTransport,
) {
    for _ in 0..30 {
        drive(a);
        pump_events(b, tb);
        drive(b);
        pump_events(a, ta);
        if !ta.has_pending() && !tb.has_pending() {
            break;
        }
    }
}

#[test]
fn two_engines_converge_via_loopback() {
    let (ta, tb) = LoopbackTransport::pair();
    let (ds_a, eng_a) = make_engine(1);
    let (ds_b, eng_b) = make_engine(2);
    let sa = Arc::new(SyncSession::new(eng_a.clone(), ta.clone()));
    let sb = Arc::new(SyncSession::new(eng_b.clone(), tb.clone()));

    let doc_id = DocId::new("doc1");
    let block_id = BlockId::new("b1");

    // A 创建文档和 block，编辑
    ds_a.create_doc(doc_id.clone(), "note").unwrap();
    ds_a.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds_a.apply_local_edit(&doc_id, &block_id, b"hello from peer1")
        .unwrap();

    // B 也创建空文档（这样导入 meta delta 时有 doc 记录）
    ds_b.create_doc(doc_id.clone(), "note").unwrap();

    // A 触发同步：request_sync 会为 peer 2 生成 SendData 动作
    eng_a.request_sync(pid(2), SyncReason::PeerOnline).unwrap();

    // 泵送：A 出站 → B 入站 → B 出站 → A 入站
    pump_until_quiet(&sa, &sb, &ta, &tb);

    // 验证 B 收到了 A 的 block 内容
    let block_b = ds_b.get_block(&doc_id, &block_id).unwrap();
    let render_b = block_b.export_render_bytes().unwrap();
    assert!(!render_b.is_empty(), "B 应收到 A 的 block 内容，实际为空");

    let block_a = ds_a.get_block(&doc_id, &block_id).unwrap();
    let render_a = block_a.export_render_bytes().unwrap();
    assert_eq!(render_a, render_b, "A 和 B 的 block 渲染应收敛一致");
}

#[test]
fn bidirectional_sync_converges() {
    let (ta, tb) = LoopbackTransport::pair();
    let (ds_a, eng_a) = make_engine(1);
    let (ds_b, eng_b) = make_engine(2);
    let sa = Arc::new(SyncSession::new(eng_a.clone(), ta.clone()));
    let sb = Arc::new(SyncSession::new(eng_b.clone(), tb.clone()));

    let doc_id = DocId::new("doc-bi");
    let block_id = BlockId::new("b1");

    // A 创建文档和 block
    ds_a.create_doc(doc_id.clone(), "note").unwrap();
    ds_a.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds_a.apply_local_edit(&doc_id, &block_id, b"A's edit")
        .unwrap();

    // B 创建文档
    ds_b.create_doc(doc_id.clone(), "note").unwrap();

    // A → B 同步
    eng_a.request_sync(pid(2), SyncReason::PeerOnline).unwrap();
    pump_until_quiet(&sa, &sb, &ta, &tb);

    // B 编辑
    ds_b.apply_local_edit(&doc_id, &block_id, b" + B's edit")
        .unwrap();

    // B → A 同步
    eng_b.request_sync(pid(1), SyncReason::PeerOnline).unwrap();
    pump_until_quiet(&sb, &sa, &tb, &ta);

    // 验证双向收敛
    let render_a = ds_a
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();
    let render_b = ds_b
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();

    assert_eq!(render_a, render_b, "双向同步后 A 和 B 应收敛一致");
}

#[test]
fn session_codec_roundtrip() {
    use tacit_core::BlockId;

    // meta delta
    let meta = b"meta delta payload";
    let encoded = tacit_session::encode_payload(None, meta);
    let (bid, decoded) = tacit_session::decode_payload(&encoded).unwrap();
    assert!(bid.is_none());
    assert_eq!(decoded, meta);

    // block delta
    let block_id = BlockId::new("block-42");
    let delta = b"block delta payload";
    let encoded = tacit_session::encode_payload(Some(&block_id), delta);
    let (bid, decoded) = tacit_session::decode_payload(&encoded).unwrap();
    assert_eq!(bid.as_ref().map(|b| b.as_str()), Some("block-42"));
    assert_eq!(decoded, delta);
}
