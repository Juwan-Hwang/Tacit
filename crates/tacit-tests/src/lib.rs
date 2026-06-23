//! Tacit-tests：混沌与跨平台集成测试、属性测试。
//!
//! 本 crate 仅承载集成测试与属性测试，不产出对外库。
//! 测试覆盖：
//! - 收敛性属性测试（proptest）：delta 乱序/重复导入、soft-delete、checkpoint 重建
//! - 集成测试：3 节点 LAN 同步、Anchor 切换、stale 追赶、relay 兜底、fast-resume
