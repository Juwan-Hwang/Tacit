//! 安全测试套件：伪造/重放/篡改/权限边界。
//!
//! 验证同步系统的安全机制：
//! - 批次签名防篡改
//! - Relay 准入控制
//! - Noise 握手完整性
//! - 签名验证
//! - 会话加密解密

use tacit_core::{BatchFlag, PeerId};
use tacit_crypto::DeviceIdentity;
use tacit_transport::batch::{BatchSigner, BatchVerifier, BatchVerifyResult};
use tacit_transport_relay::{generate_proof, verify_proof, RelayServer};

fn pid(n: u64) -> PeerId {
    PeerId(n.to_string())
}

/// 建立一对 Noise 会话（initiator, responder），用于加密测试。
fn establish_sessions() -> (tacit_crypto::Session, tacit_crypto::Session) {
    use std::sync::Arc;
    use tacit_crypto::{NoiseHandshake, NonceCache};

    let id1 = DeviceIdentity::generate().unwrap();
    let id2 = DeviceIdentity::generate().unwrap();

    let cache = Arc::new(NonceCache::new());
    let local_id1 = Some((id1.public_key(), *id1.binding_proof()));
    let local_id2 = Some((id2.public_key(), *id2.binding_proof()));
    let mut init = NoiseHandshake::initiator(
        id1.static_keypair().private.as_slice(),
        b"tacit-test-v1",
        cache.clone(),
        local_id1,
    )
    .unwrap();
    let mut resp = NoiseHandshake::responder(
        id2.static_keypair().private.as_slice(),
        b"tacit-test-v1",
        cache,
        local_id2,
    )
    .unwrap();

    let msg1 = init.step(None).unwrap();
    let msg2 = resp.step(Some(&msg1)).unwrap();
    let msg3 = init.step(Some(&msg2)).unwrap();
    let _ = resp.step(Some(&msg3)).unwrap();

    let r1 = init.into_transport().unwrap();
    let r2 = resp.into_transport().unwrap();
    (r1.session, r2.session)
}

/// 测试：伪造的签名被批次验证器拒绝。
#[test]
fn forged_signature_rejected() {
    let signer = BatchSigner::new();
    let verifier = BatchVerifier::new();

    let peer_id = pid(1);
    let doc_id = tacit_core::DocId::new("doc1");

    // 发送方正确签名
    signer.start_batch(&peer_id, &doc_id);
    let _ = signer.add_frame(&peer_id, &doc_id, b"legitimate");
    let real_sig = signer.end_batch(&peer_id, &doc_id).unwrap();

    // 接收方验证正确签名（BatchEnd payload 为空，因最后一帧已作为 BatchStart 发送）
    verifier.receive_frame(
        &peer_id,
        &doc_id,
        b"legitimate",
        BatchFlag::BatchStart,
        None,
    );
    let result =
        verifier.receive_frame(&peer_id, &doc_id, b"", BatchFlag::BatchEnd, Some(&real_sig));
    assert_eq!(result, BatchVerifyResult::Verified);

    // 伪造签名（全零）
    let forged_sig = vec![0u8; 32];
    verifier.clear(&peer_id, &doc_id);
    verifier.receive_frame(
        &peer_id,
        &doc_id,
        b"legitimate",
        BatchFlag::BatchStart,
        None,
    );
    let result = verifier.receive_frame(
        &peer_id,
        &doc_id,
        b"",
        BatchFlag::BatchEnd,
        Some(&forged_sig),
    );
    assert_eq!(result, BatchVerifyResult::Mismatch, "伪造签名应被拒绝");
}

/// 测试：篡改批次中间帧后签名不匹配。
#[test]
fn tampered_middle_frame_detected() {
    let signer = BatchSigner::new();
    let verifier = BatchVerifier::new();

    let peer_id = pid(1);
    let doc_id = tacit_core::DocId::new("doc1");

    // 发送方
    signer.start_batch(&peer_id, &doc_id);
    let _ = signer.add_frame(&peer_id, &doc_id, b"frame1");
    let _ = signer.add_frame(&peer_id, &doc_id, b"frame2");
    let _ = signer.add_frame(&peer_id, &doc_id, b"frame3");
    let sig = signer.end_batch(&peer_id, &doc_id).unwrap();

    // 接收方：中间帧被篡改
    verifier.receive_frame(&peer_id, &doc_id, b"frame1", BatchFlag::BatchStart, None);
    verifier.receive_frame(&peer_id, &doc_id, b"EVIL", BatchFlag::BatchMiddle, None);
    let result = verifier.receive_frame(
        &peer_id,
        &doc_id,
        b"frame3",
        BatchFlag::BatchEnd,
        Some(&sig),
    );
    assert_eq!(result, BatchVerifyResult::Mismatch, "篡改中间帧应被检测");
}

/// 测试：重放批次签名（不同 payload，相同签名）被拒绝。
#[test]
fn replayed_signature_rejected() {
    let signer = BatchSigner::new();
    let verifier = BatchVerifier::new();

    let peer_id = pid(1);
    let doc_id = tacit_core::DocId::new("doc1");

    // 第一批：正常发送和验证
    signer.start_batch(&peer_id, &doc_id);
    let _ = signer.add_frame(&peer_id, &doc_id, b"original");
    let sig1 = signer.end_batch(&peer_id, &doc_id).unwrap();

    verifier.receive_frame(&peer_id, &doc_id, b"original", BatchFlag::BatchStart, None);
    let r1 = verifier.receive_frame(&peer_id, &doc_id, b"", BatchFlag::BatchEnd, Some(&sig1));
    assert_eq!(r1, BatchVerifyResult::Verified);

    // 重放：用相同的签名但不同的 payload
    verifier.clear(&peer_id, &doc_id);
    verifier.receive_frame(&peer_id, &doc_id, b"different", BatchFlag::BatchStart, None);
    let r2 = verifier.receive_frame(&peer_id, &doc_id, b"", BatchFlag::BatchEnd, Some(&sig1));
    assert_eq!(r2, BatchVerifyResult::Mismatch, "重放签名应被拒绝");
}

/// 测试：Relay 准入控制 — 错误密钥被拒绝。
#[test]
fn relay_rejects_wrong_secret() {
    let secret = b"correct_secret".to_vec();
    let server = RelayServer::new(secret.clone());

    // 错误密钥
    let bad_proof = generate_proof(&pid(1), b"wrong_secret").unwrap();
    assert!(
        server.handle_register(&bad_proof).is_err(),
        "错误密钥应被拒绝"
    );

    // 正确密钥
    let good_proof = generate_proof(&pid(1), &secret).unwrap();
    assert!(
        server.handle_register(&good_proof).is_ok(),
        "正确密钥应通过"
    );
}

/// 测试：Relay proof 过期后验证失败。
#[test]
fn relay_proof_expiry() {
    use std::thread::sleep;
    use std::time::Duration;

    let secret = b"relay_secret".to_vec();
    let proof = generate_proof(&pid(1), &secret).unwrap();

    // 等待 2 秒，使 proof 年龄超过 1 秒 TTL
    sleep(Duration::from_secs(2));

    // 1 秒 TTL：已过期（proof 生成于 2 秒前）
    assert!(
        verify_proof(&proof, &secret, 1).is_err(),
        "1 秒 TTL 应已过期"
    );

    // 60 秒 TTL：仍有效（proof 生成于 2 秒前，60 秒内）
    assert!(
        verify_proof(&proof, &secret, 60).is_ok(),
        "60 秒 TTL 应仍有效"
    );
}

/// 测试：Relay proof 对错误密钥验证失败。
#[test]
fn relay_proof_wrong_secret_fails() {
    let secret = b"secret_a".to_vec();
    let proof = generate_proof(&pid(1), &secret).unwrap();

    assert!(verify_proof(&proof, &secret, 60).is_ok(), "正确密钥应通过");
    assert!(
        verify_proof(&proof, b"secret_b", 60).is_err(),
        "错误密钥应失败"
    );
}

/// 测试：Noise_XX 握手完成后双方获得相同的会话密钥。
#[test]
fn noise_handshake_produces_matching_keys() {
    let (mut session_i, mut session_r) = establish_sessions();

    // 双方应能互相加密解密
    let plaintext = b"hello from initiator";
    let ciphertext = session_i.encrypt(plaintext).unwrap();
    let decrypted = session_r.decrypt(&ciphertext).unwrap();
    assert_eq!(&decrypted, plaintext, "responder 应能解密 initiator 的消息");

    let plaintext2 = b"hello from responder";
    let ciphertext2 = session_r.encrypt(plaintext2).unwrap();
    let decrypted2 = session_i.decrypt(&ciphertext2).unwrap();
    assert_eq!(
        &decrypted2, plaintext2,
        "initiator 应能解密 responder 的消息"
    );
}

/// 测试：设备身份签名验证。
#[test]
fn device_identity_signature_verification() {
    let identity = DeviceIdentity::generate().unwrap();
    let message = b"test message";

    // 签名
    let signature = tacit_crypto::sign(&identity, message);

    // 用正确的公钥验证
    let pubkey = identity.public_key();
    assert!(
        tacit_crypto::verify(message, &signature, &pubkey).is_ok(),
        "正确公钥应验证通过"
    );

    // 用错误的公钥验证
    let other_identity = DeviceIdentity::generate().unwrap();
    let wrong_pubkey = other_identity.public_key();
    assert!(
        tacit_crypto::verify(message, &signature, &wrong_pubkey).is_err(),
        "错误公钥应验证失败"
    );

    // 篡改消息后验证失败
    let tampered_message = b"tampered message";
    assert!(
        tacit_crypto::verify(tampered_message, &signature, &pubkey).is_err(),
        "篡改消息应验证失败"
    );
}

/// 测试：会话加密后解密还原。
#[test]
fn session_encrypt_decrypt_roundtrip() {
    let (mut s1, mut s2) = establish_sessions();

    let messages: &[&[u8]] = &[
        b"short",
        b"a bit longer message for testing",
        b"",
        &vec![0x41u8; 1024],
    ];

    for msg in messages {
        let ciphertext = s1.encrypt(msg).unwrap();
        let decrypted = s2.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, msg, "加密解密应还原原文");
    }
}

/// 测试：篡改密文后解密失败。
#[test]
fn tampered_ciphertext_decryption_fails() {
    let (mut s1, mut s2) = establish_sessions();

    let plaintext = b"sensitive data";
    let mut ciphertext = s1.encrypt(plaintext).unwrap();

    // 篡改密文
    if let Some(byte) = ciphertext.last_mut() {
        *byte ^= 0xFF;
    }

    let result = s2.decrypt(&ciphertext);
    assert!(result.is_err(), "篡改密文应解密失败");
}

/// 测试：PeerId 从公钥派生，不同密钥对产生不同 PeerId。
#[test]
fn peer_id_derived_from_pubkey() {
    let id1 = DeviceIdentity::generate().unwrap();
    let id2 = DeviceIdentity::generate().unwrap();

    let pid1 = id1.peer_id();
    let pid2 = id2.peer_id();

    assert_ne!(pid1, pid2, "不同密钥对应产生不同 PeerId");
    assert_eq!(id1.peer_id(), id1.peer_id(), "同一身份 PeerId 应稳定");
}

/// 测试：Relay 转发 — 未注册 peer 无法转发。
#[test]
fn relay_forward_unregistered_rejected() {
    let secret = b"relay_secret".to_vec();
    let server = RelayServer::new(secret.clone());

    // 未注册的 peer 尝试转发（使用伪造的 session_id）
    let forward_req = tacit_transport_relay::ForwardRequest {
        session_id: "fake_session_id".to_string(),
        target_peer_id: "2".into(),
        data: b"hello".to_vec(),
    };
    let result = server.handle_forward(&forward_req);
    assert!(result.is_err(), "未注册 peer 转发应被拒绝");
}

/// 测试：Relay 转发 — 向不存在的 peer 转发失败。
#[test]
fn relay_forward_nonexistent_target_fails() {
    let secret = b"relay_secret".to_vec();
    let server = RelayServer::new(secret.clone());

    // peer 1 注册
    let proof = generate_proof(&pid(1), &secret).unwrap();
    let session_id = server.handle_register(&proof).unwrap();

    // 向不存在的 peer 转发（服务端返回 ForwardFailed 而非 Err）
    let forward_req = tacit_transport_relay::ForwardRequest {
        session_id,
        target_peer_id: "nonexistent".into(),
        data: b"hello".to_vec(),
    };
    let result = server.handle_forward(&forward_req);
    assert!(result.is_ok(), "handle_forward 应返回 Ok");
    assert!(
        matches!(
            result.unwrap(),
            tacit_transport_relay::RelayMessage::ForwardFailed { .. }
        ),
        "向不存在的 peer 转发应返回 ForwardFailed"
    );
}
