//! 集成测试：跨 crate 端到端场景。
//!
//! 覆盖蓝图"集成测试"落点：
//! - 3 节点 LAN 同步
//! - Anchor 离线切换
//! - stale device 追赶
//! - relay 兜底
//! - UI 前台 fast-resume 首屏可渲染

use std::sync::Arc;
use std::time::Instant;

use tacit_core::{BlockId, BlockKind, DocId, PeerId, SyncReason};
use tacit_store::Store;
use tacit_sync::{DefaultSyncEngine, DocStore, EngineConfig, SyncAction, SyncEngine};
use tacit_transport_relay::{generate_proof, verify_proof, RelayClient, RelayServer};

fn pid(n: u64) -> PeerId {
    PeerId(n.to_string())
}

/// 构造一个内存 DocStore + SyncEngine 组合。
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

/// 模拟单机 push：从 source 导出 block delta，导入到 target。
///
/// 若 target 无该 block，先创建空 block（模拟 MetaDoc 已知 block 但内容待同步）。
fn transfer_block_delta(
    source: &DocStore,
    target: &DocStore,
    doc_id: &DocId,
    block_id: &BlockId,
    since: &tacit_core::Frontier,
) {
    // 若 target 无该 block，先创建空 block
    if target.get_block(doc_id, block_id).is_err() {
        // 确保 doc 存在（先释放 store 锁，避免 parking_lot 不可重入死锁）
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
    // since 为空时用完整 snapshot（含容器创建 op），非空时用增量 delta
    let bytes = if since.is_empty() {
        source.export_block_snapshot(doc_id, block_id).unwrap()
    } else {
        source.export_block_delta(doc_id, block_id, since).unwrap()
    };
    target.import_block(doc_id, block_id, &bytes).unwrap();
}

/// 模拟单机 push：从 source 导出 meta delta，导入到 target。
///
/// target 需先有 doc 记录（DocStore::import_meta 依赖 open_doc）。
fn transfer_meta_delta(
    source: &DocStore,
    target: &DocStore,
    doc_id: &DocId,
    since: &tacit_core::Frontier,
) {
    // 若 target 无 doc 记录，先创建空 doc（先释放 store 锁，避免 parking_lot 不可重入死锁）
    let doc_exists = {
        let conn = target.store().conn();
        tacit_store::dao::get_doc(&conn, doc_id).unwrap().is_some()
    };
    if !doc_exists {
        target.create_doc(doc_id.clone(), "note").unwrap();
    }
    // since 为空时用完整 snapshot（含容器创建 op），非空时用增量 delta
    let bytes = if since.is_empty() {
        source.export_meta_snapshot(doc_id).unwrap()
    } else {
        source.export_meta_delta(doc_id, since).unwrap()
    };
    target.import_meta(doc_id, &bytes).unwrap();
}

// ===== 3 节点 LAN 同步 =====

#[test]
fn three_node_lan_sync_converges() {
    // 3 个节点：peer 1（源）、peer 2、peer 3
    let (ds1, _e1) = make_node(1);
    let (ds2, _e2) = make_node(2);
    let (ds3, _e3) = make_node(3);

    let doc_id = DocId::new("doc1");
    let block_id = BlockId::new("b1");

    // peer 1 创建文档和 block，编辑
    ds1.create_doc(doc_id.clone(), "note").unwrap();
    ds1.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds1.apply_local_edit(&doc_id, &block_id, b"hello from peer1")
        .unwrap();

    // 同步到 peer 2：先 meta，再 block
    let empty = tacit_core::Frontier::new();
    transfer_meta_delta(&ds1, &ds2, &doc_id, &empty);
    transfer_block_delta(&ds1, &ds2, &doc_id, &block_id, &empty);

    // peer 2 编辑
    ds2.apply_local_edit(&doc_id, &block_id, b" + peer2 edit")
        .unwrap();

    // peer 2 同步到 peer 3（peer3 无先验状态，用空 frontier 做全量同步）
    transfer_meta_delta(&ds2, &ds3, &doc_id, &empty);
    transfer_block_delta(&ds2, &ds3, &doc_id, &block_id, &empty);

    // peer 2 同步回 peer 1（双向收敛，以 peer1 的 stale frontier 为 since）
    let f1_meta = ds1.meta_frontier(&doc_id).unwrap();
    transfer_meta_delta(&ds2, &ds1, &doc_id, &f1_meta);
    let f1_block = ds1.block_frontier(&doc_id, &block_id).unwrap();
    transfer_block_delta(&ds2, &ds1, &doc_id, &block_id, &f1_block);

    // 验证三端 block 内容收敛
    let r1 = ds1.get_block(&doc_id, &block_id).unwrap();
    let r2 = ds2.get_block(&doc_id, &block_id).unwrap();
    let r3 = ds3.get_block(&doc_id, &block_id).unwrap();

    let render1 = r1.export_render_bytes().unwrap();
    let render2 = r2.export_render_bytes().unwrap();
    let render3 = r3.export_render_bytes().unwrap();

    assert_eq!(render1, render2, "peer1 和 peer2 应收敛");
    assert_eq!(render2, render3, "peer2 和 peer3 应收敛");
}

// ===== Anchor 离线切换 =====

#[test]
fn anchor_offline_switch() {
    // 3 个节点：peer 1 是 Anchor，peer 2、peer 3 是普通节点
    let (ds1, _e1) = make_node(1);
    let (ds2, _e2) = make_node(2);
    let (ds3, _e3) = make_node(3);

    let doc_id = DocId::new("doc1");
    let block_id = BlockId::new("b1");

    // 初始：peer 1（Anchor）创建文档
    ds1.create_doc(doc_id.clone(), "note").unwrap();
    ds1.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();
    ds1.apply_local_edit(&doc_id, &block_id, b"anchor initial")
        .unwrap();

    // 同步到 peer 2 和 peer 3
    let empty = tacit_core::Frontier::new();
    transfer_meta_delta(&ds1, &ds2, &doc_id, &empty);
    transfer_block_delta(&ds1, &ds2, &doc_id, &block_id, &empty);
    transfer_meta_delta(&ds1, &ds3, &doc_id, &empty);
    transfer_block_delta(&ds1, &ds3, &doc_id, &block_id, &empty);

    // Anchor（peer 1）离线，peer 2 编辑
    ds2.apply_local_edit(&doc_id, &block_id, b" + peer2 while anchor offline")
        .unwrap();

    // peer 2 直接同步给 peer 3（绕过 Anchor）
    let f2 = ds1.block_frontier(&doc_id, &block_id).unwrap();
    transfer_block_delta(&ds2, &ds3, &doc_id, &block_id, &f2);

    // 验证 peer 2 和 peer 3 收敛（Anchor 离线不影响它们同步）
    let r2 = ds2.get_block(&doc_id, &block_id).unwrap();
    let r3 = ds3.get_block(&doc_id, &block_id).unwrap();
    let render2 = r2.export_render_bytes().unwrap();
    let render3 = r3.export_render_bytes().unwrap();
    assert_eq!(render2, render3, "Anchor 离线后 peer2/peer3 仍应收敛");

    // Anchor 回来后，peer 3 同步回 Anchor（以 peer1 的 stale frontier 为 since）
    let f1 = ds1.block_frontier(&doc_id, &block_id).unwrap();
    transfer_block_delta(&ds3, &ds1, &doc_id, &block_id, &f1);
    let r1 = ds1.get_block(&doc_id, &block_id).unwrap();
    let render1 = r1.export_render_bytes().unwrap();
    assert_eq!(render1, render2, "Anchor 回归后应追上");
}

// ===== stale device 追赶 =====

#[test]
fn stale_device_catchup() {
    // peer 1 离线，peer 2 持续编辑，peer 1 回来后通过 shallow snapshot + tail delta 追赶
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

    let empty = tacit_core::Frontier::new();
    transfer_meta_delta(&ds1, &ds2, &doc_id, &empty);
    transfer_block_delta(&ds1, &ds2, &doc_id, &block_id, &empty);

    // peer 1 离线前的 frontier
    let stale_frontier = ds1.block_frontier(&doc_id, &block_id).unwrap();

    // peer 2 持续编辑（模拟 peer 1 离线期间）
    ds2.apply_local_edit(&doc_id, &block_id, b" + edit1")
        .unwrap();
    ds2.apply_local_edit(&doc_id, &block_id, b" + edit2")
        .unwrap();
    ds2.apply_local_edit(&doc_id, &block_id, b" + edit3")
        .unwrap();

    let peer2_final_render = ds2
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();

    // peer 1 回来，通过 shallow snapshot + tail delta 追赶
    // 1. 导出 peer 2 的 shallow snapshot（在 stale_frontier 处）
    let shallow = ds2
        .export_block_shallow(&doc_id, &block_id, &stale_frontier)
        .unwrap();
    // 2. 导出 peer 2 自 stale_frontier 之后的 tail delta
    let tail_delta = ds2
        .export_block_delta(&doc_id, &block_id, &stale_frontier)
        .unwrap();

    // 3. peer 1 先导入 shallow snapshot（手术式重入）
    ds1.import_block(&doc_id, &block_id, &shallow).unwrap();
    // 4. 再导入 tail delta
    ds1.import_block(&doc_id, &block_id, &tail_delta).unwrap();

    // 验证 peer 1 追上 peer 2
    let peer1_final_render = ds1
        .get_block(&doc_id, &block_id)
        .unwrap()
        .export_render_bytes()
        .unwrap();
    assert_eq!(
        peer1_final_render, peer2_final_render,
        "stale device 应追上最新状态"
    );
}

// ===== relay 兜底 =====

#[test]
fn relay_fallback_data_forwarding() {
    // 模拟：peer 1 和 peer 2 通过 relay 交换数据
    let secret = b"relay_group_secret".to_vec();
    let server = RelayServer::new(secret.clone());

    // peer 1 注册
    let proof1 = generate_proof(&pid(1), &secret).unwrap();
    let session1 = server.handle_register(&proof1).unwrap();

    // peer 2 注册
    let proof2 = generate_proof(&pid(2), &secret).unwrap();
    let session2 = server.handle_register(&proof2).unwrap();

    assert_eq!(server.online_count(), 2);

    // peer 1 通过 relay 转发数据给 peer 2
    let data = b"hello via relay".to_vec();
    let forward_req = tacit_transport_relay::ForwardRequest {
        session_id: session1,
        target_peer_id: "2".into(),
        data: data.clone(),
    };
    let incoming = server.handle_forward(&forward_req).unwrap();

    match incoming {
        tacit_transport_relay::RelayMessage::Incoming {
            from_peer_id,
            data: received,
        } => {
            assert_eq!(from_peer_id, "1");
            assert_eq!(received, data);
        }
        _ => panic!("期望 Incoming 消息"),
    }

    // 验证 peer 2 也能通过 relay 转发数据给 peer 1
    let data2 = b"reply from peer2".to_vec();
    let forward_req2 = tacit_transport_relay::ForwardRequest {
        session_id: session2,
        target_peer_id: "1".into(),
        data: data2.clone(),
    };
    let incoming2 = server.handle_forward(&forward_req2).unwrap();
    match incoming2 {
        tacit_transport_relay::RelayMessage::Incoming {
            from_peer_id,
            data: received,
        } => {
            assert_eq!(from_peer_id, "2");
            assert_eq!(received, data2);
        }
        _ => panic!("期望 Incoming 消息"),
    }
}

#[test]
fn relay_admission_rejects_unauthorized() {
    let secret = b"correct_secret".to_vec();
    let server = RelayServer::new(secret.clone());

    // 用错误密钥生成 proof
    let bad_proof = generate_proof(&pid(1), b"wrong_secret").unwrap();
    assert!(
        server.handle_register(&bad_proof).is_err(),
        "错误密钥应被拒绝"
    );

    // 用正确密钥生成 proof
    let good_proof = generate_proof(&pid(1), &secret).unwrap();
    assert!(
        server.handle_register(&good_proof).is_ok(),
        "正确密钥应通过"
    );

    // 验证 proof 完整性
    let proof = generate_proof(&pid(2), &secret).unwrap();
    assert!(verify_proof(&proof, &secret, 60).is_ok());
    assert!(verify_proof(&proof, b"wrong", 60).is_err());
}

#[test]
fn relay_client_register_forward_flow() {
    let secret = b"relay_secret".to_vec();
    let server = RelayServer::new(secret.clone());

    // 两个 client
    let client1 = RelayClient::new(pid(1), secret.clone());
    let client2 = RelayClient::new(pid(2), secret.clone());

    // client1 注册
    let register_msg = client1.create_register_message().unwrap();
    // 模拟发送到 server
    let proof = match &register_msg {
        tacit_transport_relay::RelayMessage::Register(req) => req.proof.clone(),
        _ => panic!("期望 Register"),
    };
    let session1 = server.handle_register(&proof).unwrap();
    let response = tacit_transport_relay::RelayMessage::RegisterOk {
        session_id: session1,
    };
    client1.handle_register_response(&response).unwrap();
    assert!(client1.is_registered());

    // client2 注册
    let register_msg2 = client2.create_register_message().unwrap();
    let proof2 = match &register_msg2 {
        tacit_transport_relay::RelayMessage::Register(req) => req.proof.clone(),
        _ => panic!("期望 Register"),
    };
    let session2 = server.handle_register(&proof2).unwrap();
    let response2 = tacit_transport_relay::RelayMessage::RegisterOk {
        session_id: session2,
    };
    client2.handle_register_response(&response2).unwrap();
    assert!(client2.is_registered());

    // client1 通过 relay 转发数据给 client2
    let data = vec![1, 2, 3, 4, 5];
    let forward_msg = client1
        .create_forward_message(&pid(2), data.clone())
        .unwrap();
    // 模拟 server 处理转发
    let forward_req = match &forward_msg {
        tacit_transport_relay::RelayMessage::Forward(req) => req.clone(),
        _ => panic!("期望 Forward"),
    };
    let incoming = server.handle_forward(&forward_req).unwrap();
    // 模拟 client2 接收
    let (from, received) = client2.handle_incoming(&incoming).unwrap();
    assert_eq!(from, pid(1));
    assert_eq!(received, data);
}

// ===== UI 前台 fast-resume 首屏可渲染 =====

#[test]
fn fast_resume_first_screen_renderable() {
    use tacit_ffi::TacitEngine;

    // 创建引擎，模拟用户使用
    let engine = TacitEngine::new_memory("1").unwrap();
    engine
        .create_document("doc1".into(), "note".into())
        .unwrap();
    engine
        .create_block("doc1".into(), "block1".into(), "text".into())
        .unwrap();
    engine
        .apply_user_edit("doc1".into(), "block1".into(), b"hello world".to_vec())
        .unwrap();

    // 模拟应用重启：调用 fast_resume 恢复所有文档状态
    engine.request_fast_resume().unwrap();

    // 验证首屏可渲染：打开文档，获取 block 列表
    let view = engine.open_document("doc1".into()).unwrap();
    assert_eq!(view.doc_id, "doc1");
    assert!(
        !view.block_ids.is_empty(),
        "fast-resume 后应有 block 可渲染"
    );
    assert_eq!(view.block_ids[0], "block1");
}

#[test]
fn fast_resume_after_peer_online() {
    use tacit_ffi::TacitEngine;

    let engine = TacitEngine::new_memory("1").unwrap();
    engine
        .create_document("doc1".into(), "note".into())
        .unwrap();
    engine
        .create_block("doc1".into(), "block1".into(), "text".into())
        .unwrap();

    // peer 上线触发同步
    engine.on_peer_online("2".into()).unwrap();

    // fast-resume
    engine.request_fast_resume().unwrap();

    // 验证状态正常
    let status = engine.get_sync_status().unwrap();
    assert_eq!(status.online_peers, 1);
}

// ===== SyncEngine 依赖等待与重试 =====

#[test]
fn dependency_wait_and_retry() {
    let (ds, engine) = make_node(1);
    let doc_id = DocId::new("d1");
    let block_id = BlockId::new("b1");

    ds.create_doc(doc_id.clone(), "note").unwrap();
    ds.create_block(&doc_id, block_id.clone(), BlockKind::Text)
        .unwrap();

    // peer 2 上线
    engine
        .on_peer_summary(
            pid(2),
            tacit_core::PeerSummary {
                peer_id: pid(2),
                online: true,
                frontier: tacit_core::Frontier::new(),
                capabilities: Default::default(),
            },
        )
        .unwrap();

    // 请求同步，应产生 SendData 动作
    engine
        .request_sync(pid(2), SyncReason::UserForeground)
        .unwrap();
    let actions = engine.drain_actions();
    assert!(actions
        .iter()
        .any(|a| matches!(a, SyncAction::SendData { .. })));

    // 模拟依赖等待：入队一个 block fetch
    let now = Instant::now();
    engine
        .pending_queue()
        .enqueue(tacit_sync::PendingBlockFetch {
            doc_id: doc_id.clone(),
            block_id: block_id.clone(),
            expected_frontier: tacit_core::Frontier::new(),
            observed_frontier: tacit_core::Frontier::new(),
            peer_id: pid(2),
            retry_at: now,
            retries: 0,
            phase: tacit_sync::BackoffPhase::Normal,
        });
    assert_eq!(engine.pending_queue().len(), 1);

    // 处理到期条目，应产生 RequestDelta 并重新入队
    engine.process_pending(now).unwrap();
    let actions = engine.drain_actions();
    assert!(actions
        .iter()
        .any(|a| matches!(a, SyncAction::RequestDelta { .. })));
    assert_eq!(engine.pending_queue().len(), 1, "应重新入队等待重试");
}

// ===== 双水位 GC 计算 =====

#[test]
fn watermarks_gc_computation() {
    use std::time::{Duration, SystemTime};
    use tacit_core::{AckSummary, Frontier};
    use tacit_store::dao;

    let (ds, engine) = make_node(1);
    let doc_id = DocId::new("d1");
    ds.create_doc(doc_id.clone(), "note").unwrap();

    // 插入两个 peer 的 ack
    {
        let conn = ds.store().conn();
        dao::upsert_ack(
            &conn,
            &AckSummary {
                peer_id: pid(2),
                doc_id: doc_id.clone(),
                ack_checkpoint: None,
                ack_frontier: Frontier::from_iter([(pid(1), 10)]),
                updated_at: SystemTime::now(),
                version_override: None,
            },
        )
        .unwrap();
        dao::upsert_ack(
            &conn,
            &AckSummary {
                peer_id: pid(3),
                doc_id: doc_id.clone(),
                ack_checkpoint: None,
                ack_frontier: Frontier::from_iter([(pid(1), 7)]),
                updated_at: SystemTime::now() - Duration::from_secs(120), // stale
                version_override: None,
            },
        )
        .unwrap();
    }

    let w = engine.compute_watermarks(&doc_id).unwrap();
    // peer3 stale（120s 前），但 soft_timeout 默认 3 天，所以 peer3 仍算 active
    // hard = active peer 交集 = min(10, 7) = 7
    assert_eq!(
        w.hard_frontier.get(&pid(1)),
        Some(7),
        "hard 应为 active peer 的最小 seq"
    );
    // soft = 所有 ack 并集 = max(10, 7) = 10
    assert_eq!(
        w.soft_frontier.get(&pid(1)),
        Some(10),
        "soft 应为所有 ack 的最大 seq"
    );
}

// ===== BLE Presence 发现 =====

#[test]
fn ble_presence_discovery() {
    use tacit_core::{AnchorCapabilities, Endpoint, PresenceHint};
    use tacit_transport_ble::{BlePresence, DiscoveryEvent, MockPresenceBackend};

    let backend = Arc::new(MockPresenceBackend::new());
    let presence = Arc::new(BlePresence::new(backend.clone()));

    // 广播 presence
    let hint = PresenceHint {
        group_id: "g1".into(),
        device_id: "device-integration".into(),
        capabilities: AnchorCapabilities {
            can_anchor: true,
            can_relay: false,
            persistent: true,
        },
        endpoint: Some(Endpoint::new("192.168.1.10", 8080)),
    };
    presence.broadcast(&hint).unwrap();
    assert!(backend.is_broadcasting());

    // 扫描
    presence.start_scan().unwrap();
    assert!(backend.is_scanning());

    // 注入发现事件
    backend.inject_discovery(DiscoveryEvent {
        peer_id: pid(2),
        hint: hint.clone(),
        rssi: -55,
    });
    let events = presence.drain_discoveries();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].peer_id, pid(2));
    assert_eq!(events[0].rssi, -55);

    // 再次拉取应为空
    assert!(presence.drain_discoveries().is_empty());

    presence.stop_scan();
    assert!(!backend.is_scanning());
}

// ===== Noise 握手 + 加密通信 =====

#[test]
fn noise_handshake_and_encrypted_sync() {
    use tacit_crypto::{sign, verify, DeviceIdentity, NoiseHandshake};

    // 两个设备身份
    let id1 = DeviceIdentity::generate().unwrap();
    let id2 = DeviceIdentity::generate().unwrap();

    // Noise 握手
    let mut init = NoiseHandshake::initiator(id1.static_keypair().private.as_slice()).unwrap();
    let mut resp = NoiseHandshake::responder(id2.static_keypair().private.as_slice()).unwrap();

    let msg1 = init.step(None).unwrap();
    let msg2 = resp.step(Some(&msg1)).unwrap();
    let msg3 = init.step(Some(&msg2)).unwrap();
    let _ = resp.step(Some(&msg3)).unwrap();

    let result1 = init.into_transport().unwrap();
    let result2 = resp.into_transport().unwrap();

    // 验证对端公钥
    assert_eq!(result1.remote_static_pubkey, id2.static_keypair().public);
    assert_eq!(result2.remote_static_pubkey, id1.static_keypair().public);

    // 加密通信
    let mut session1 = result1.session;
    let mut session2 = result2.session;

    let sync_data = b"sync payload: block delta bytes";
    let encrypted = session1.encrypt(sync_data).unwrap();
    let decrypted = session2.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, sync_data);

    // 签名验证（模拟身份认证）
    let msg = b"authenticate: peer1";
    let sig = sign(&id1, msg);
    assert!(verify(msg, &sig, &id1.public_key()).is_ok());
    assert!(
        verify(msg, &sig, &id2.public_key()).is_err(),
        "错误公钥应验签失败"
    );
}
