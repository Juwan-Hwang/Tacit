//! 真实网络 QUIC 集成测试。
//!
//! 使用 localhost + 真实端口绑定验证 Quinn 在真实网络栈上的行为：
//! - 连接建立与数据传输
//! - fast-resume（网络变化重连）
//! - 控制帧与数据帧双向传输
//! - 健康检查与主动探测
//! - 并发连接与信号量限流

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tacit_core::{DataFrame, DataFrameKind, DocId, PeerId, Priority, SessionId};
use tacit_transport::{PathPreference, SyncTransport, TransportEvent};
use tacit_transport_quic::{QuicTransport, QuicTransportConfig};

/// 创建一个 server + client 对，自动完成证书信任与连接。
async fn make_pair() -> (QuicTransport, QuicTransport, PeerId) {
    // 启动 server
    let server_config = QuicTransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        is_server: true,
        ..Default::default()
    };
    let server = QuicTransport::new(server_config).await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_cert = server.cert().clone();
    server.start_accept_loop();

    // 启动 client
    let client_config = QuicTransportConfig {
        is_server: false,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).await.unwrap();
    client.trust_cert(server_cert).unwrap();

    // 注册并连接
    let peer_id = PeerId::new("server");
    client.register_peer(peer_id.clone(), server_addr);
    client.connect(&peer_id, server_addr).await.unwrap();

    (server, client, peer_id)
}

#[tokio::test]
async fn real_quic_send_data_and_receive() {
    let (server, client, peer_id) = make_pair().await;

    // 设置 server 端接收回调
    let received_count = Arc::new(AtomicUsize::new(0));
    let count_clone = received_count.clone();
    server.set_data_handler(move |event| {
        if let TransportEvent::Data { frame, .. } = event {
            assert_eq!(frame.payload.as_ref(), b"hello over real QUIC");
            count_clone.fetch_add(1, Ordering::SeqCst);
        }
    });

    // 发送数据帧
    let frame = DataFrame {
        doc_id: DocId::new("doc1"),
        actor_id: PeerId::new("client"),
        seq: 1,
        kind: DataFrameKind::Delta,
        payload: bytes::Bytes::from_static(b"hello over real QUIC"),
        session_id: SessionId::new(1),
    };
    client
        .send_data(&peer_id, frame, Priority::High, PathPreference::Any)
        .await
        .unwrap();

    // 等待接收
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(received_count.load(Ordering::SeqCst), 1, "应收到 1 帧数据");
}

#[tokio::test]
async fn real_quic_send_control_and_receive() {
    let (server, client, peer_id) = make_pair().await;

    let received_count = Arc::new(AtomicUsize::new(0));
    let count_clone = received_count.clone();
    server.set_data_handler(move |event| {
        if let TransportEvent::Control { .. } = event {
            count_clone.fetch_add(1, Ordering::SeqCst);
        }
    });

    // 发送控制帧
    let ack = tacit_core::AckSummary {
        peer_id: PeerId::new("client"),
        doc_id: DocId::new("d1"),
        ack_checkpoint: None,
        ack_frontier: tacit_core::Frontier::new(),
        updated_at: std::time::SystemTime::now(),
    };
    let msg = tacit_transport::ControlMsg::AckSummary(ack);
    client
        .send_control(&peer_id, msg, Priority::Medium)
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(received_count.load(Ordering::SeqCst), 1, "应收到 1 个控制帧");
}

#[tokio::test]
async fn real_quic_fast_resume_reconnect() {
    let (_server, client, peer_id) = make_pair().await;

    // 模拟网络变化：离线 → 在线
    client
        .notify_network_changed(false, tacit_core::NetworkType::Offline)
        .await
        .unwrap();

    // 短暂等待连接关闭
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 网络恢复，触发 fast-resume
    client
        .notify_network_changed(true, tacit_core::NetworkType::Lan)
        .await
        .unwrap();

    // 等待重连完成（指数退避第一次立即尝试）
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 验证连接已恢复：能成功发送数据
    let frame = DataFrame {
        doc_id: DocId::new("doc1"),
        actor_id: PeerId::new("client"),
        seq: 2,
        kind: DataFrameKind::Delta,
        payload: bytes::Bytes::from_static(b"after resume"),
        session_id: SessionId::new(2),
    };
    let result = client
        .send_data(&peer_id, frame, Priority::High, PathPreference::Any)
        .await;
    assert!(result.is_ok(), "fast-resume 后应能成功发送数据");
}

#[tokio::test]
async fn real_quic_health_check() {
    let (_server, client, peer_id) = make_pair().await;

    // 连接刚建立，健康检查应无死连接
    let dead = client.health_check().await;
    assert!(dead.is_empty(), "新建连接不应有死连接");

    // 关闭 peer 连接后检查
    client.close_peer(&peer_id);
    let dead = client.health_check().await;
    // close_peer 后连接已从池中移除，health_check 无需报告
    assert!(dead.is_empty(), "已关闭的连接不应出现在 health_check 中");
}

#[tokio::test]
async fn real_quic_health_probe_alive_connection() {
    let (_server, client, _peer_id) = make_pair().await;

    // 主动探测存活连接
    let dead = client.health_probe().await;
    assert!(
        dead.is_empty(),
        "存活连接的 health_probe 不应返回死连接"
    );
}

#[tokio::test]
async fn real_quic_multiple_frames_in_order() {
    let (server, client, peer_id) = make_pair().await;

    let received = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let received_clone = received.clone();
    server.set_data_handler(move |event| {
        if let TransportEvent::Data { frame, .. } = event {
            received_clone.lock().push(frame.payload.to_vec());
        }
    });

    // 发送多帧数据
    for i in 0..5u8 {
        let frame = DataFrame {
            doc_id: DocId::new("doc1"),
            actor_id: PeerId::new("client"),
            seq: i as u32,
            kind: DataFrameKind::Delta,
            payload: bytes::Bytes::from(vec![i; 10]),
            session_id: SessionId::new(i as u64),
        };
        client
            .send_data(&peer_id, frame, Priority::High, PathPreference::Any)
            .await
            .unwrap();
    }

    // 等待全部接收
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let received = received.lock();
    assert_eq!(received.len(), 5, "应收到 5 帧数据");
    for (i, payload) in received.iter().enumerate() {
        assert_eq!(payload[0], i as u8, "第 {} 帧数据应正确", i);
    }
}

#[tokio::test]
async fn real_quic_reconnect_peer() {
    let (server, client, peer_id) = make_pair().await;

    // 设置 server 接收回调
    let received = Arc::new(AtomicUsize::new(0));
    let rc = received.clone();
    server.set_data_handler(move |event| {
        if let TransportEvent::Data { .. } = event {
            rc.fetch_add(1, Ordering::SeqCst);
        }
    });

    // 主动重连
    client.reconnect_peer(&peer_id).await.unwrap();

    // 发送数据验证重连成功
    let frame = DataFrame {
        doc_id: DocId::new("doc1"),
        actor_id: PeerId::new("client"),
        seq: 3,
        kind: DataFrameKind::Delta,
        payload: bytes::Bytes::from_static(b"after reconnect"),
        session_id: SessionId::new(3),
    };
    client
        .send_data(&peer_id, frame, Priority::High, PathPreference::Any)
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(received.load(Ordering::SeqCst), 1, "重连后应收到数据");
}

#[tokio::test]
async fn real_quic_local_addr_bound() {
    let config = QuicTransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        is_server: true,
        ..Default::default()
    };
    let transport = QuicTransport::new(config).await.unwrap();
    let addr = transport.local_addr().unwrap();
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
    assert!(addr.port() > 0, "OS 应分配非零端口");
}
