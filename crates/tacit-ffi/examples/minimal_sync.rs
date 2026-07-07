//! 最小集成示例：展示 Tacit 引擎的基本使用流程。
//!
//! 运行：`cargo run --example minimal_sync`
//!
//! 本示例演示：
//! 1. 创建内存引擎
//! 2. 自动生成/加载设备身份
//! 3. 创建文档和 block
//! 4. 编辑并读取内容
//! 5. 订阅事件总线
//! 6. 查看 sync 状态

use tacit_ffi::TacitEngine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Tacit 最小集成示例 ===\n");

    // 1. 创建内存引擎（生产环境用 TacitEngine::new_persisted 持久化到 SQLite）
    //    PeerId 在内部用作 actor_id，需为 u64 可解析字符串。
    let engine = TacitEngine::new_memory("1")?;
    println!("[1] 引擎已创建（内存模式）");

    // 2. 自动生成/加载设备身份
    let info = engine.ffi_generate_and_save_device_identity()?;
    println!("[2] 设备身份：PeerId = {}", info.peer_id);
    println!("    Ed25519 公钥 = {}", hex::encode(&info.verifying_key));
    println!("    X25519 公钥 = {}", hex::encode(&info.static_public));

    // 3. 创建文档和 block
    engine.create_document("doc1".into(), "note".into())?;
    engine.create_block("doc1".into(), "block1".into(), "text".into())?;
    println!("[3] 已创建文档 doc1 / block block1");

    // 4. 编辑 block 内容
    engine.apply_user_edit("doc1".into(), "block1".into(), b"Hello, Tacit!".to_vec())?;
    println!("[4] 已写入内容：\"Hello, Tacit!\"");

    // 5. 一次性读取文档（含 block 渲染内容）
    let view = engine.ffi_open_document_with_content("doc1".into())?;
    println!(
        "[5] 文档视图：{} 个 block，frontier = {}",
        view.blocks.len(),
        view.frontier_json
    );
    for block in &view.blocks {
        let content = String::from_utf8_lossy(&block.render_bytes);
        let preview = match content.char_indices().nth(60) {
            Some((idx, _)) => format!("{}...", &content[..idx]),
            None => content.to_string(),
        };
        println!(
            "    └─ block {} ({}): {}",
            block.block_id, block.kind, preview
        );
    }

    // 6. 订阅事件总线
    let (sub_id, receiver) = engine.event_bus().subscribe_with_filter(None);
    println!("[6] 已订阅事件（订阅 ID: {:?}）", sub_id);

    // 触发一个事件（创建新 block）
    engine.create_block("doc1".into(), "block2".into(), "todo".into())?;
    println!("    已创建 block2 (todo)");

    // 非阻塞检查事件
    match receiver.try_recv() {
        Ok(event) => println!("    收到事件：{:?}", event),
        Err(_) => println!("    （无事件或已处理）"),
    }

    // 7. 查看 sync 状态
    let status = engine.ffi_get_sync_status()?;
    println!(
        "[7] Sync 状态：{} 个在线 peer，{} 个待执行动作，{} 个等待中的 fetch",
        status.online_peers, status.pending_actions, status.pending_fetches
    );

    // 8. 通知网络变化（模拟上线）
    engine.ffi_notify_network_changed(true, "lan".into())?;
    println!("[8] 已通知网络变化：online = true, net_type = lan");

    println!("\n=== 示例完成 ===");
    println!("\n下一步：");
    println!("  - 在另一台设备上运行相同示例，交换 PeerId 进行配对");
    println!("  - 查看 README.md 的 Sync Protocol 章节了解同步流程");
    println!("  - 集成层（Kotlin/Swift）通过 UniFFI bindings 调用相同 API");

    Ok(())
}
