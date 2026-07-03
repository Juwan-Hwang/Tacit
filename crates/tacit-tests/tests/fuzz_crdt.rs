//! CRDT BlockDoc import 模糊测试。
//!
//! 验证 `BlockDoc::import` 在面对任意字节输入时：
//! 1. **不 panic** — 任意字节序列都安全处理（返回 Ok 或 Err）
//! 2. **幂等性** — 成功导入后重复导入同一字节不改变 frontier
//! 3. **snapshot 往返** — export → import 后渲染结果一致

use proptest::prelude::*;

use tacit_core::{BlockId, BlockKind, PeerId};
use tacit_crdt::BlockDoc;

fn pid(n: u64) -> PeerId {
    PeerId(n.to_string())
}

// ─── import 任意字节不 panic ───────────────────────────────

proptest! {
    /// 对任意字节序列调用 import，不 panic。
    #[test]
    fn fuzz_import_arbitrary(data: Vec<u8>) {
        let block = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(1)).unwrap();
        let _ = block.import(&data);
    }

    /// 对任意字节序列调用 from_snapshot，不 panic。
    #[test]
    fn fuzz_from_snapshot_arbitrary(data: Vec<u8>) {
        let _ = BlockDoc::from_snapshot(
            BlockId::new("b1"), BlockKind::Text, &pid(1), &data,
        );
    }
}

// ─── 合法 snapshot + 篡改：不 panic ───────────────────────

proptest! {
    /// 对合法 snapshot 做随机位翻转后 import，不 panic。
    #[test]
    fn fuzz_import_mutated_snapshot(
        text in "[a-z]{0,100}",
        flip_byte: usize,
        flip_mask: u8,
    ) {
        let a = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(1)).unwrap();
        a.apply_edit(text.as_bytes()).unwrap();
        let snap = a.export_snapshot().unwrap();

        if !snap.is_empty() {
            let idx = flip_byte % snap.len();
            let mut mutated = snap.clone();
            mutated[idx] ^= flip_mask;
            let b = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(2)).unwrap();
            let _ = b.import(&mutated);
        }
    }
}

// ─── 幂等性 & 往返 ─────────────────────────────────────────

proptest! {
    /// 成功导入后重复导入同一字节，frontier 不变。
    #[test]
    fn prop_import_idempotent(text in "[a-z]{0,100}") {
        let a = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(1)).unwrap();
        a.apply_edit(text.as_bytes()).unwrap();
        let snap = a.export_snapshot().unwrap();

        let b = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(2)).unwrap();
        let r1 = b.import(&snap).unwrap();
        let r2 = b.import(&snap).unwrap();
        prop_assert!(!r2.changed, "重复导入应幂等，frontier 不变");
        prop_assert_eq!(r1.new_frontier, r2.new_frontier);
    }

    /// snapshot 往返：export → from_snapshot 后渲染一致。
    #[test]
    fn prop_snapshot_roundtrip(text in "[a-z]{0,100}") {
        let a = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(1)).unwrap();
        a.apply_edit(text.as_bytes()).unwrap();
        let snap = a.export_snapshot().unwrap();

        let b = BlockDoc::from_snapshot(
            BlockId::new("b1"), BlockKind::Text, &pid(2), &snap,
        ).unwrap();
        let render_a = a.export_render_bytes().unwrap();
        let render_b = b.export_render_bytes().unwrap();
        prop_assert_eq!(render_a, render_b);
    }

    /// delta 增量同步：A 编辑 → export delta → B import，渲染一致。
    #[test]
    fn prop_delta_sync(
        text1 in "[a-z]{0,50}",
        text2 in "[a-z]{0,50}",
    ) {
        let a = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(1)).unwrap();
        a.apply_edit(text1.as_bytes()).unwrap();
        let f0 = a.frontier().unwrap();
        let snap = a.export_snapshot().unwrap();

        let b = BlockDoc::new(BlockId::new("b1"), BlockKind::Text, &pid(2)).unwrap();
        b.import(&snap).unwrap();

        a.apply_edit(text2.as_bytes()).unwrap();
        let delta = a.export_delta_since(&f0).unwrap();
        b.import(&delta).unwrap();

        let render_a = a.export_render_bytes().unwrap();
        let render_b = b.export_render_bytes().unwrap();
        prop_assert_eq!(render_a, render_b);
    }
}
