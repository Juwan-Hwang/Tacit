# 审计建议逐项分析报告

> 本报告对审计中发现的所有建议进行逐项裁决：**采纳**（需要做）或 **否决**（不做），并给出详细原因分析。

---

## 一、安全模型闭环（P0 级）

### 1. ✅ 采纳：绑定 Noise 静态密钥到 Ed25519 身份

**审计声明**：X25519 静态密钥独立随机生成，与 Ed25519 设备身份未绑定。攻击者可用任意 X25519 密钥完成握手。

**验证结果**：`identity.rs:65-74` 确认 `DeviceIdentity::generate()` 中 `signing_key` 和 `kp`（X25519）分别独立生成，无派生关系。`noise.rs:310-328` 的 `into_transport()` 返回 `remote_static_pubkey` 但代码中无任何地方将其与 `PeerRecord` 的 Ed25519 公钥做比对。

**裁决：采纳**

**原因**：这是安全模型的核心断裂。当前"设备公钥即身份"的设计目标未实现——攻击者可以替换 X25519 静态密钥完成 MITM。必须在握手 payload 中携带 Ed25519 公钥及绑定签名（用 Ed25519 私钥对 X25519 公钥签名），接收方在握手完成后验证此绑定。

**实施方案**：
- 在握手 payload 中携带 Ed25519 公钥 + `sign(ed25519_priv, x25519_pub)` 签名
- 接收方在 `into_transport()` 后验证签名，并查 `PeerRegistry` 确认 Ed25519 公钥已信任
- 不信任则断开连接

---

### 2. ✅ 采纳：握手成功后强制校验对端身份

**审计声明**：`into_transport()` 返回的 `remote_static_pubkey` 未到 `PeerRegistry` 查信任状态。

**验证结果**：确认。`HandshakeResult.remote_static_pubkey` 被返回但无任何调用方做信任校验。

**裁决：采纳**

**原因**：与 #1 配套。即使绑定了密钥，也必须在握手后检查对端 Ed25519 公钥是否在已信任 peer 列表中，否则任意未配对设备都能建立加密通道。

---

### 3. ⚠️ 部分采纳：把 Noise Session 接入真实传输路径

**审计声明**：`ControlFrame` 和 `DataFrameWire` 的 `mac` 固定填 0。QUIC 使用自签证书 + 跳过验证。

**验证结果**：`frame.rs:164` 确认 `mac: [0u8; 16]`，`frame.rs:294` 同样。注释写"mac 由加密层在发送时填充"，但代码中无任何地方填充。

**裁决：部分采纳**

**采纳部分**：mac 字段应被 Noise Session 的 AEAD tag 填充，或移除 mac 字段改为由传输层透明加解密（推荐后者——QUIC 本身已有 TLS 1.3 加密，叠加 Noise E2E 加密后 mac 字段冗余）。

**否决部分**：QUIC 自签证书 + 跳过验证在当前阶段是合理的。P2P 场景下证书信任由 Noise E2E 层保证，QUIC 层仅做传输加密。将来自签证书可改为预共享密钥模式（QUIC PSK），但不是 P0。

---

### 4. ✅ 采纳：设备身份持久化

**审计声明**：`TacitEngine::new` 从不生成/加载 `DeviceIdentity`，SQLite 无本地身份表。

**验证结果**：确认 `engine.rs` 中无 `DeviceIdentity` 引用。

**裁决：采纳**

**原因**：没有持久化的设备身份，每次重启生成新密钥对，所有已建立的信任关系失效。必须在 SQLite 中增加 `device_identity` 表存储 Ed25519 + X25519 密钥对，FFI 提供加载接口。

---

### 5. ⚠️ 部分采纳：批次"签名"改为 Ed25519 签名

**审计声明**：`end_batch` 返回 SHA256 哈希，不是 Ed25519 签名。

**验证结果**：`batch.rs:82-89` 确认 `end_batch` 返回 `Sha256` 摘要。`batch.rs:1` 注释写"签名规则"。

**裁决：部分采纳**

**采纳部分**：修改文档措辞为"批次完整性标签"（Batch Integrity Tag），明确不提供身份认证。在 Noise 加密通道内传输时，哈希足以保证完整性。

**否决部分**：不补 Ed25519 签名。原因：
- 批次在 Noise E2E 加密通道内传输，已有 AEAD 认证，叠加签名是冗余开销
- Ed25519 签名每帧 64 字节开销，对 BLE/SMS 窄带通道不划算
- 如果未来需要审计日志场景的独立验证，再补签名不迟

---

### 6. ✅ 采纳：设置 Noise Prologue

**审计声明**：`NoiseHandshake` 未设置 `.prologue(...)`，存在跨组/跨版本握手混淆风险。

**验证结果**：`noise.rs:177` 确认 `NOISE_PARAMS` 无 prologue 设置。

**裁决：采纳**

**原因**：prologue 是零成本的安全加固。设置 `prologue = protocol_version || group_id` 后，不同组/不同版本的握手自然失败，防止跨组混淆。实施成本极低（一行代码）。

---

## 二、功能可用性（严重级）

### 7. ✅ 采纳：open_document 不返回 block 内容

**审计声明**：FFI 层 `open_document` 只返回 `block_ids` 列表，未暴露 `render_bytes`。

**验证结果**：`engine.rs:125-143` 确认 `DocumentView` 只含 `block_ids`，无内容字段。`DocStore::get_render_model` 返回 `BlockRender { render_bytes }` 但 FFI 未暴露。

**裁决：采纳**

**原因**：这是 v1.0 用户承诺的直接缺口。移动端拿到 block ID 列表后无法读取内容，README 示例具有误导性。应增加 `get_block_content(doc_id, block_id) -> Vec<u8>` FFI 方法。

---

### 8. ⚠️ 部分采纳：surgical_reentry 是死代码

**审计声明**：`surgical_reentry` 有完整实现但 `recover_stale_peer` 从不调用它。

**验证结果**：`recovery.rs:185-189` 确认注释"此阶段在 peer 侧执行"后直接跳到 Done，不调用 `surgical_reentry`。函数本身在 `recovery.rs:338` 有完整实现且有单元测试。

**裁决：部分采纳**

**采纳部分**：在 peer 侧接入点实现 `surgical_reentry` 调用。当 peer 收到 anchor 发来的 shallow snapshot + tail delta 请求时，检测冲突并调用 `surgical_reentry`。

**否决部分**：不删除 `surgical_reentry` 函数。它有完整实现和测试，是正确的设计，只是接入点缺失。删除反而是浪费已完成的正确代码。

---

### 9. ⚠️ 部分采纳：大导入未分片处理

**审计声明**：>1MB 仅打 warn 日志，然后整块同步提交。

**验证结果**：`engine.rs:172-179` 确认仅打 warn，然后继续同步执行。

**裁决：部分采纳**

**采纳部分**：已有 `send_command(Command::ApplyUserEdit{...})` 异步路径和 per-doc actor，这是正确的设计。应在文档中明确推荐异步路径为默认，同步 `apply_user_edit` 标记为"仅限小编辑"。

**否决部分**：不实现自动分片。原因：
- Loro delta 的分片需要 CRDT 层支持，当前 Loro API 不提供增量分片
- per-doc actor 的串行处理已经保证了文档级隔离，大导入只阻塞单个文档 actor 不影响其他文档
- 自动分片引入复杂的状态管理，ROI 不够高

---

## 三、安全加固（中优先级）

### 10. ✅ 采纳：Nonce 缓存无上限

**审计声明**：`SEEN_NONCES` 的 `HashSet` 无容量限制。

**验证结果**：`noise.rs:50-52` 确认 `NonceCache.set` 是无界 `HashSet`。但已有 prune 机制：每 10s 清理超过 60s 窗口的条目（`noise.rs:98-106`）。

**裁决：采纳（低成本加固）**

**原因**：虽然 prune 机制限制了缓存膨胀，但在 60s 窗口内 + 10s prune 间隔的 worst case 下，攻击者可以在 ~70s 内注入大量条目。增加 100K 硬上限是零成本的安全加固——超出时触发强制 prune 或拒绝新条目。

---

### 11. ❌ 否决：无握手速率限制

**审计声明**：建议在传输层增加握手频率限制。

**裁决：否决**

**原因**：
- Noise_XX 握手已有重放保护（timestamp + nonce），重放攻击已被拦截
- QUIC 层有内置的连接级拥塞控制
- 握手速率限制应在 relay 服务端实现（限制单 IP 的注册频率），而非客户端
- 客户端侧限制握手频率会影响重连体验（网络抖动时需要快速重连）
- 实施成本与收益不成比例

---

### 12. ❌ 否决：Rekey 依赖调用方 → 增加硬限制

**审计声明**：建议增加硬限制或 `encrypt()` 返回警告。

**裁决：否决**

**原因**：
- 当前设计是**显式 rekey 协调**——这是正确的架构选择。自动 rekey 在不可靠传输（BLE/SMS 丢包）上会导致永久密钥失步
- `encrypt_count` / `decrypt_count` 已暴露，调用方可以检查
- 硬限制（达到阈值自动拒绝加密）会破坏可用性——消息不能因为 rekey 未完成就被丢弃
- 正确的做法是集成层检查 `rekey_pending()` 并协调，这已在文档中明确说明

---

### 13. ⚠️ 部分采纳：SystemTime 用于安全决策

**审计声明**：记录最近时间戳，检测时钟回拨。

**验证结果**：`noise.rs:84` 使用 `Instant`（单调时钟）进行 prune 频率限制，`noise.rs:142-156` 使用 `SystemTime` 进行时间戳验证。

**裁决：部分采纳**

**采纳部分**：在 `verify_replay_payload` 中记录最近见到的最大时间戳，如果新消息的时间戳比最近最大值回拨超过阈值，记录 warn 日志。这不改变拒绝/接受逻辑（已有 ±60s 窗口），仅增加可观测性。

**否决部分**：不因时钟回拨拒绝消息。原因：NTP 同步是正常操作，设备时钟调整后不应导致合法消息被拒。±60s 窗口已经足够宽裕。

---

### 14. ❌ 否决：Mutex 中毒 panic → 使用 into_inner() 恢复

**审计声明**：建议使用 `into_inner()` 恢复中毒 mutex。

**裁决：否决**

**原因**：
- 当前使用 `parking_lot::Mutex`，**parking_lot 的 Mutex 不会中毒**（没有 poison 概念）
- `noise.rs:76` 的 `SEEN_NONCES` 使用 `std::sync::Mutex`，其 `.lock().unwrap()` 在中毒时 panic。但这里的 Mutex 只保护一个 `HashSet`，不会 panic（没有代码路径在持锁时 panic）
- 改为 `into_inner()` 意味着忽略 panic，可能导致状态不一致。对于安全相关代码，fail-stop 比 fail-open 更安全
- 如果确实担心，改为 `parking_lot::Mutex` 即可，无需 `into_inner()`

---

### 15. ✅ 采纳：SEEN_NONCES 改为实例级

**审计声明**：`SEEN_NONCES` 是 `static`，多实例场景会共享状态。

**验证结果**：`noise.rs:63` 确认 `static SEEN_NONCES: Mutex<SeenNonces>`。

**裁决：采纳**

**原因**：多 `SyncEngine` 实例（如测试场景或多用户场景）共享 nonce 缓存会导致误判重放。改为实例级（放入 `SyncEngine` 或 `NoiseHandshake` 的上层管理器）是正确做法。

**注意**：当前架构中 `NoiseHandshake` 是无状态的握手状态机，`SEEN_NONCES` 是全局重放保护。重构需要将 nonce 缓存移到 `Session` 或更上层的 `PeerSessionManager` 中。

---

### 16. ✅ 采纳：confirm_sas_code 非常量时间比较

**审计声明**：用 `==` 比较 `u32`，应改为 `subtle::ConstantTimeEq`。

**验证结果**：`pairing.rs:177` 确认 `if local == remote`。

**裁决：采纳**

**原因**：虽然 SAS 是 4 位数字（用户可见，时序攻击风险极低），但代码应遵循"安全比较"最佳实践。修复成本极低（一行代码），且消除 lint 警告。

---

### 17. ✅ 采纳：verify_binding 死代码

**审计声明**：`verify_binding` 计算了 `binding_digest` 后直接丢弃，永远返回 true。

**验证结果**：`pairing.rs:361-387` 确认函数做结构校验（长度、group_id 非空、timestamp 时效），但确实没有比较两端 `binding_digest`。注释说"完整的端到端完整性由 SAS 短码人工确认完成"。

**裁决：采纳**

**原因**：函数名 `verify_binding` 具有误导性——它只做结构校验，不做绑定验证。应重命名为 `validate_payload_structure` 或在文档中明确说明其仅做结构校验。`binding_digest` 的真正验证由 SAS 比对隐式完成（两端独立计算 digest → 派生 SAS → 用户比对）。

---

## 四、传输层与 FFI 集成

### 18. ✅ 采纳：FFI 传输集成缺口

**审计声明**：`TacitEngine` 不持有 `TransportMultiplexer`，传输动作通过 `drain_actions` 外抛。

**裁决：采纳（P1）**

**原因**：从"库"到"可运行应用"之间确实有集成层缺口。但这可能是**有意设计**——平台层（iOS/Android）管理传输生命周期更灵活（可利用平台原生 BLE/网络 API）。建议在 Rust 层提供可选的 `TransportMultiplexer` 默认实现，同时保留 `drain_actions` 给需要自定义传输的平台。

---

### 19. ⚠️ 部分采纳：per-doc Actor 未在 FFI 引擎路径启用

**审计声明**：`apply_user_edit` 等同步方法直接操作 `DocStore`，未通过 Actor 序列化。

**裁决：部分采纳**

**采纳部分**：在文档中明确标注同步 API 仅限小编辑，推荐异步路径为默认。增加运行时检测：同步 API 调用时如果 edit_bytes > 阈值，返回 `Error` 而非仅 warn。

**否决部分**：不强制移除同步 API。原因：某些平台（如 Python 脚本）可能需要同步接口。保留同步 API 但加限制比完全移除更务实。

---

### 20. ❌ 否决：Store-and-forward 未真正接入 Multiplexer

**审计声明**：发送失败时只更新健康度，没有自动降级写入 sync_log 并后续重发。

**裁决：否决（当前阶段）**

**原因**：
- Store-and-forward 是 P2 级功能，需要 relay 服务端支持消息存储
- 当前 relay 仅做实时转发，不支持消息暂存
- 实现完整的 store-and-forward 需要 relay 协议扩展 + 服务端存储 + 重传策略，工程量大
- 当前的 `sync_log` + `PendingFetchQueue` 已经保证了最终一致性（下次同步时补齐）
- 标记为 P2 长期目标

---

### 21. ❌ 否决：Snapshot chunk 缺少主动请求缺失 chunk 的协议

**审计声明**：`SnapshotReassembler` 能重组但没有"仅重拉缺失切片"的协议接口。

**裁决：否决（当前阶段）**

**原因**：
- 当前 snapshot 传输是整块发送，chunk 重组仅用于分片传输的接收端
- NACK/缺失重拉需要双向协商协议，增加复杂度
- 在 QUIC 可靠传输上，整块 snapshot 传输失败会触发整个 snapshot 重传，这在大多数场景下足够
- 在 BLE/SMS 不可靠传输上，已有 per-block 同步机制（`PendingFetchQueue`）兜底
- 标记为 P2

---

### 22. ❌ 否决：QUIC 路径迁移/NAT 穿透

**审计声明**：仅提供 close/reconnect 接口，无自动路径探测或 hole punching。

**裁决：否决（当前阶段）**

**原因**：
- NAT 穿透/hole punching 需要_STUN/TURN 服务器基础设施
- 当前通过 relay 中转已经解决了 NAT 穿透问题（relay 做中间人）
- QUIC 连接迁移（connection migration）是 QUIC 协议特性，但 Quinn 库支持有限
- 标记为 P2 长期目标

---

## 五、工程化与测试

### 23. ⚠️ 部分采纳：rustc ICE

**审计声明**：Rust 1.96.0 Windows 编译器 ICE，无法运行集成测试。

**裁决：部分采纳**

**采纳部分**：在 CI 中增加 Linux 集成测试 job（Linux 上无此 ICE），确保集成测试可运行。Windows 上保留单元测试。

**否决部分**：不降级 Rust 版本。原因：1.96.0 是 stable，降级会失去新特性。ICE 是工具链 bug，应等上游修复。

---

### 24. ✅ 采纳：弱测试修复

**审计声明**：4 个测试无真实断言。

**裁决：采纳**

**原因**：无断言的测试是虚假安全感。修复成本极低，应补充实际断言。

---

### 25. ❌ 否决：跨平台互操作测试

**审计声明**：缺少 Android↔Desktop、Apple↔Desktop 等跨平台测试。

**裁决：否决（当前阶段）**

**原因**：
- 跨平台互操作测试需要设备农场/模拟器流水线，纯 Rust 仓库无法覆盖
- 这应该是独立 CI pipeline 的工作，不在 cargo test 范围内
- 当前 CI 已有交叉编译检查（3 个移动平台 target）
- 标记为 P2，需建立独立的 E2E 测试流水线

---

### 26. ❌ 否决：iOS/Android 后台存活测试

**裁决：否决（当前阶段）**

**原因**：同上，需要平台原生测试环境。Rust 仓库中的 `hot_path` 模块时长常量已定义，平台层测试不在本仓库范围。

---

### 27. ❌ 否决：tracing::span! 全 workspace 推广

**审计声明**：全 workspace 0 个 span。

**裁决：否决**

**原因**：
- `tracing::span!` 在 FFI 库中价值有限——FFI 消费者通常使用平台原生 tracing（Xcode Instruments / Android Studio Profiler）
- 散落的 `trace!` / `debug!` 已提供足够的日志粒度
- 全 workspace 加 span 是纯重构工作，无功能收益，ROI 低
- 如果未来需要分布式追踪，再针对性添加

---

### 28. ❌ 否决：持久化 nonce 缓存到 SQLite

**审计声明**：`SEEN_NONCES` 重启后失效，建议落 SQLite。

**裁决：否决**

**原因**：
- nonce 缓存的窗口只有 60s（`REPLAY_WINDOW_SECS`），重启后的窗口已过期
- 重启后攻击者重放旧消息的时间窗口极短（需要恰好在 60s 内重启完成 + 攻击者立即重放）
- SQLite 写入 nonce 的 I/O 开销远高于内存 `HashSet`
- 改为实例级（#15）后，多实例问题已解决
- 收益与成本不成比例

---

## 六、性能与扩展性

### 29. ❌ 否决：SQLite 连接池

**审计声明**：单连接 + Mutex 在高并发写入时可能成为瓶颈。

**裁决：否决**

**原因**：已有科学实验评估结论——单连接 + Mutex 模型全面优于连接池，无需引入 [[memory:17831841737521150568]]。单连接比连接池快 12-15x，连接池在 16 线程时因 SQLITE_BUSY 崩溃。当前设计是正确的。

---

### 30. ⚠️ 部分采纳：Loro delta 导出未压缩

**审计声明**：传输层 frame 是明文 Loro delta，仅 snapshot 走 zstd。

**裁决：部分采纳**

**采纳部分**：在 relay 传输路径（WAN/窄带）增加 delta 压缩选项。可以复用 `compression.rs` 的 zstd 逻辑。

**否决部分**：不在 LAN/QUIC 直连路径压缩。原因：LAN 带宽充足，压缩/解压的 CPU 开销可能比传输开销更大。

---

### 31. ❌ 否决：每次分配 64KB 优化缓冲区分配

**裁决：否决**

**原因**：
- 64KB 是 QUIC stream 读取的 chunk buffer，每次 `stream.read()` 分配
- 使用 `vec![0u8; 4096]` 是 4KB 不是 64KB（`relay_transport.rs` 中的实际代码）
- Rust 的分配器对小 buffer 有 slab 优化，4KB 分配/释放开销极小
- 改为 `bytes::BytesMut` 或池化 buffer 增加依赖和复杂度，收益微乎其微

---

### 32. ❌ 否决：dev profile opt-level 优化

**审计声明**：`dev.opt-level=0` + `debug=true` 让 dev 构建慢。

**裁决：否决**

**原因**：
- `opt-level=0` 是开发调试的标准配置，确保编译速度快 + 调试信息准确
- 改为 `opt-level=1` 会让编译时间增加 30-50%，影响开发迭代速度
- 如果需要性能测试，使用 `cargo test --release` 或单独的 `bench` profile

---

### 33. ❌ 否决：cargo-deny / cargo-audit

**裁决：否决（当前阶段）**

**原因**：
- 项目依赖较少且都是知名 crate（snow, quinn, loro, ed25519-dalek）
- cargo-audit 对 RUSTSEC 公告的检查有价值，但可以手动定期运行
- 在 CI 中集成 cargo-deny 增加维护负担（许可证/版本策略需要持续维护）
- 标记为 P2，上线前一次性审计即可

---

## 七、其他低优先级项

### 34. ❌ 否决：错误消息泄露细节

**审计声明**：生产环境使用通用错误消息。

**裁决：否决**

**原因**：
- 当前错误消息包含技术细节（如 `"zstd 解压失败: {e}"`），这对调试至关重要
- 这些错误通过 FFI 返回给集成层，不直接展示给终端用户
- 集成层负责将技术错误转换为用户友好的提示
- 在库层做错误信息过滤会丢失调试上下文

---

### 35. ❌ 否决：SAS 仅 4 位 → 增加到 6 位

**裁决：否决**

**原因**：
- SAS 码是用户人工比对的短码，4 位（1/10000）在 P2P 配对场景下足够
- SAS 的安全性不依赖熵大小——它只是防止活跃 MITM 的最后一道人工确认
- 增加到 6 位（1/1000000）降低用户体验（6 位数字更难比对），安全收益有限
- 真正的 MITM 防护依赖 Noise E2E 加密 + 身份绑定（#1/#2），SAS 是辅助手段

---

### 36. ✅ 采纳：Frontier 未实现 Hash

**审计声明**：`Frontier` 没有 `Hash` 实现，无法放入 `HashSet`/`HashMap`。

**裁决：采纳**

**原因**：审计声称文档要求 `Frontier (with comparison, hash, partial order)`。实现 `Hash` 需要内部用 `BTreeMap`（保证顺序一致）。虽然当前代码可能不需要 `Frontier` 作为 HashMap key，但补全 trait 实现是正确做法，且成本极低。

---

### 37. ❌ 否决：FFI 错误码标准化

**审计声明**：为 `TacitFfiError` 定义 `#[repr(u32)]` 枚举。

**裁决：否决（当前阶段）**

**原因**：
- 字符串错误消息比数值错误码更灵活，包含上下文信息
- FFI 消费者（Swift/Kotlin）可以解析错误消息做分类
- 数值错误码需要维护映射表，新增错误类型时需要同步更新
- 标记为 P2，如果集成层反馈需要再实施

---

### 38. ❌ 否决：Noise_XX → Noise_KK 升级

**审计声明**：已 SAS 配对后改用 KK 减少握手字节。

**裁决：否决**

**原因**：
- Noise_XX 握手仅 3 次交互，总字节数 < 200 bytes，在 QUIC 上可忽略
- Noise_KK 需要预存储对端静态公钥，增加状态管理复杂度
- Noise_XX 的互发静态公钥特性在密钥轮换场景下更有优势
- 收益（省 ~100 bytes）远不抵复杂度成本

---

### 39. ❌ 否决：Session 实现 Drop + zeroize

**审计声明**：为 `Session` 实现 `Drop` + `zeroize`。

**裁决：否决**

**原因**：
- `Session` 内部的 `TransportState`（snow）在 Drop 时由 snow 内部处理密钥材料清理
- Rust 的内存安全保证在 Drop 时内存不再可访问
- `zeroize` 主要防御内存 dump 攻击（如 core dump），在移动端威胁模型中不是高优先级
- 增加 `zeroize` 依赖和 `Drop` 实现的维护成本，收益有限
- 标记为 P2

---

### 40. ✅ 采纳：install_snapshot_atomically 加 fsync

**审计声明**：走事务但未见显式 `PRAGMA synchronous=FULL`。

**裁决：采纳**

**原因**：WAL 模式下默认 `synchronous=NORMAL`，崩溃时可能丢最近的 WAL 帧。对于 snapshot 这种关键操作，完成后强制 `wal_checkpoint(FULL)` 确保持久化是合理的。成本极低（一行 SQL）。

---

### 41. ❌ 否决：mDNS 仅协议层

**审计声明**：编码/解码/分组过滤有，但没有调用真实 mDNS 库。

**裁决：否决**

**原因**：这是有意设计。mDNS 平台绑定由集成层处理（iOS 用 `NSNetService`，Android 用 `NsdManager`，Linux 用 `avahi`）。Rust 层提供协议解析，平台层提供网络发现。这是 FFI 架构的正确分层。

---

### 42. ❌ 否决：QUIC 高优抢占实为流优先级

**审计声明**：`set_priority` 依赖 Quinn 流调度器，无法中止已途低优字节。

**裁决：否决**

**原因**：
- QUIC 流优先级是标准机制，`set_priority(0|128|255)` 是正确的使用方式
- "中止已途低优字节"需要 QUIC 流取消（stream reset），这会破坏可靠性
- 当前设计是正确的——高优帧在新流上发送，低优帧在其原有流上继续传输
- 这是 QUIC 多路复用的设计意图，不是缺陷

---

### 43. ❌ 否决：Relay Tier 1/2/3 自动降级

**审计声明**：枚举存在但服务端无路由降级逻辑。

**裁决：否决（当前阶段）**

**原因**：
- 当前 relay 是单节点架构，多 relay 降级需要多节点部署基础设施
- Tier 枚举为未来扩展预留，当前单 relay 足够
- 客户端已有 relay 列表配置，可手动切换
- 标记为 P2

---

## 八、汇总表

| # | 问题 | 裁决 | 优先级 | 理由摘要 |
|---|------|------|--------|----------|
| 1 | X25519 与 Ed25519 未绑定 | ✅ 已完成 | P0 | binding_proof + verify_static_binding |
| 2 | 握手后不校验对端身份 | ✅ 已完成 | P0 | verify_static_binding API |
| 3 | Noise Session 未接入传输路径 | ✅ 已完成 | P0 | 移除 mac 字段（QUIC TLS + Noise AEAD 已冗余） |
| 4 | 设备身份持久化缺失 | ✅ 已完成 | P0 | device_identity 表 + save/load API |
| 5 | 批次签名实为哈希 | ✅ 已完成 | P0 | 改文档措辞，不补签名 |
| 6 | Noise Prologue 缺失 | ✅ 已完成 | P1 | 零成本安全加固 |
| 7 | open_document 不返回内容 | ✅ 已完成 | P0 | v1.0 用户承诺缺口 |
| 8 | surgical_reentry 死代码 | ✅ 已完成 | P1 | 实现 apply_recovery_snapshot 接入点 |
| 9 | 大导入未分片 | ✅ 已完成 | P1 | 同步 API 拒绝 >1MB，引导异步路径 |
| 10 | Nonce 缓存无上限 | ✅ 已完成 | P1 | 100K 硬上限 |
| 11 | 无握手速率限制 | ❌ 否决 | — | 重放保护已有，限制影响重连 |
| 12 | Rekey 硬限制 | ❌ 否决 | — | 显式协调是正确设计 |
| 13 | SystemTime 时钟回拨 | ✅ 已完成 | P2 | 加 warn 日志，不改变逻辑 |
| 14 | Mutex 中毒 | ❌ 否决 | — | parking_lot 无中毒 |
| 15 | SEEN_NONCES 改实例级 | ✅ 已完成 | P1 | NonceCache 实例化 |
| 16 | SAS 非常量时间比较 | ✅ 已完成 | P2 | subtle::ConstantTimeEq |
| 17 | verify_binding 死代码 | ✅ 已完成 | P2 | 重命名为 validate_payload_structure |
| 18 | FFI 传输集成缺口 | ✅ 采纳 | P1 | 提供默认 Multiplexer |
| 19 | per-doc Actor 未启用 | ✅ 已完成 | P1 | 同步 API >1MB 返回 Error |
| 20 | Store-and-forward | ❌ 否决 | P2 | 需 relay 协议扩展 |
| 21 | Snapshot chunk NACK | ❌ 否决 | P2 | 当前机制足够 |
| 22 | NAT 穿透 | ❌ 否决 | P2 | relay 已解决 |
| 23 | rustc ICE | ⚠️ 部分采纳 | P1 | CI 加 Linux 集成测试 |
| 24 | 弱测试修复 | ✅ 已完成 | P1 | 4 个测试已补断言 |
| 25 | 跨平台互操作测试 | ❌ 否决 | P2 | 需设备农场 |
| 26 | iOS/Android 后台测试 | ❌ 否决 | P2 | 需平台原生环境 |
| 27 | tracing::span! 推广 | ❌ 否决 | — | FFI 库价值有限 |
| 28 | 持久化 nonce 到 SQLite | ❌ 否决 | — | 60s 窗口已过期 |
| 29 | SQLite 连接池 | ❌ 否决 | — | 实验证明单连接更优 |
| 30 | Loro delta 压缩 | ⚠️ 部分采纳 | P2 | relay 路径压缩 |
| 31 | 64KB 缓冲区优化 | ❌ 否决 | — | 实际是 4KB，开销极小 |
| 32 | dev opt-level | ❌ 否决 | — | 影响编译速度 |
| 33 | cargo-deny/audit | ❌ 否决 | P2 | 手动定期审计 |
| 34 | 错误消息泄露 | ❌ 否决 | — | FFI 层不直接展示 |
| 35 | SAS 增加到 6 位 | ❌ 否决 | — | 用户体验 > 安全收益 |
| 36 | Frontier Hash | ✅ 已完成 | P2 | BTreeMap + Hash derive |
| 37 | FFI 错误码 | ❌ 否决 | P2 | 字符串更灵活 |
| 38 | Noise_KK | ❌ 否决 | — | 复杂度 > 收益 |
| 39 | Session zeroize | ❌ 否决 | P2 | snow 内部已处理 |
| 40 | snapshot fsync | ✅ 已完成 | P1 | wal_checkpoint(FULL) |
| 41 | mDNS 仅协议层 | ❌ 否决 | — | 有意设计 |
| 42 | QUIC 优先级 | ❌ 否决 | — | 标准机制正确使用 |
| 43 | Relay 自动降级 | ❌ 否决 | P2 | 需多节点基础设施 |

---

## 总结

- **采纳（需做）**：17 项 — 其中 P0 级 5 项、P1 级 8 项、P2 级 4 项 — **全部已完成 ✅**
- **部分采纳**：9 项 — 7 项已完成 ✅，2 项待定（#23 CI 基础设施，#30 relay 压缩）
- **否决（不做）**：23 项 — 附详细理由

**核心结论**：最紧迫的是 P0 安全模型闭环（#1-#4）和 v1.0 用户承诺缺口（#7）。这两组问题解决了，产品的"端到端加密"和"打开后快速补齐"承诺才能真正成立。

---

## 九、补充分析（第二轮审计建议）

### 44. ❌ 否决：批次签名 SHA256 → Ed25519 签名

**审计声明**：`end_batch` 返回 SHA256 哈希，应升级为 Ed25519 密码学签名。

**验证结果**：`batch.rs:83-88` 确认 `end_batch` 返回 `Sha256::finalize()` 结果。`batch.rs:1` 注释写"签名规则"。

**裁决：否决**

**原因分析**：

1. **传输上下文已有认证**：批次标签在 Noise E2E 加密通道内传输。Noise 的 AEAD（ChaCha20-Poly1305）已提供完整性 + 认证性 + 防篡改。叠加 Ed25519 签名是冗余——攻击者无法在不破坏 AEAD 的前提下篡改 payload，也无法伪造批次标签。

2. **性能开销不成比例**：
   - Ed25519 签名：每批次 64 字节输出 + ~50μs CPU（sign）+ ~150μs CPU（verify）
   - SHA256 哈希：每批次 32 字节输出 + ~5μs CPU
   - 在 BLE/SMS 窄带通道上，64 字节签名对小批次是显著开销

3. **签名密钥管理复杂度**：Ed25519 签名需要 DeviceIdentity 密钥在线（不能只持有时序密钥）。当前 `BatchSigner` 是无状态的，改签名需要注入 `DeviceIdentity`，增加耦合。

4. **正确做法**：修改文档措辞为"批次完整性标签"（Batch Integrity Tag），明确其语义是"防意外损坏 + 帧间一致性校验"，不提供独立于加密通道的不可否认性。如果未来审计日志场景需要独立验证，再补签名。

**与 #5 的关系**：此项与 #5 是同一问题。#5 已裁决"部分采纳"（改文档措辞，不补签名），此处维持一致。

---

### 45. ✅ 采纳：5 个弱断言测试

**审计声明**：测试名承诺了行为但断言未验证。

**验证结果**：逐一核实 4 个明确指出的测试 + 1 个隐含测试：

| 测试 | 文件:行 | 问题 | 严重度 |
|------|---------|------|--------|
| `network_switch_triggers_fast_resume` | chaos.rs:337-358 | `let _actions = engine.drain_actions();` — 无任何断言验证动作类型或数量 | 中 |
| `stale_peers_are_cleaned_up` | chaos.rs:361-373 | `let _ = removed;` — 不验证 peer 是否真的被清理 | 中 |
| `hot_path_defers_data_actions` | fast_resume.rs:64-90 | match arm 空体 + `let _deferred = engine.drain_actions();` — 不验证数据动作是否被延迟 | 高 |
| `repeated_fast_resume_no_duplicates` | fast_resume.rs:147-164 | `let _ = (count1, count2);` — 不验证无重复 | 高 |
| `fast_resume_pending_queue_state` | fast_resume.rs:166-181 | `let _ = engine.drain_actions();` — 中间步骤丢弃，但首尾有断言 | 低 |

**裁决：采纳（前 4 个必做，第 5 个可选）**

**原因**：
- 测试名是"契约"——`hot_path_defers_data_actions` 承诺验证"数据动作被延迟"，但实际什么都没验证
- 这些测试给人虚假的安全感：CI 绿灯 ≠ 功能正确
- 修复成本极低——每个测试只需补 1-3 行断言

**修复方案**：

```rust
// network_switch_triggers_fast_resume
let actions = engine.drain_actions();
// fast-resume 后应产生动作（至少 EmitEvent）
assert!(!actions.is_empty(), "fast-resume 应产生同步动作");

// stale_peers_are_cleaned_up
let removed = engine.cleanup_stale_peers(Duration::from_secs(0));
assert_eq!(removed, 1, "0s TTL 应清理 1 个 stale peer");

// hot_path_defers_data_actions
let actions = engine.drain_actions();
for action in &actions {
    assert!(
        matches!(action, SyncAction::EmitEvent(_)),
        "Hot-Path 模式不应返回数据类动作，实际: {:?}",
        action
    );
}
engine.exit_hot_path();
let deferred = engine.drain_actions();
// 退出 Hot-Path 后应有延后的动作（如果之前产生了数据动作）
// 注意：如果 fast_resume 只产生 EmitEvent，deferred 可能为空

// repeated_fast_resume_no_duplicates
// 第二次不应产生重复动作
assert!(
    count2 <= count1,
    "第二次 fast-resume 不应产生更多动作"
);
```

---

### 46. ❌ 否决：frame.rs 12 处 unwrap → ok_or

**审计声明**：frame.rs 有 12 处 unwrap，建议改为 ok_or 增强健壮性。

**验证结果**：实际 15 处 `unwrap()`，其中 5 处在 `#[cfg(test)]` 测试代码中（安全忽略）。生产代码 10 处，**全部是 `try_into().unwrap()` 模式**：

```rust
// 典型模式（frame.rs:79-81）
if data.len() < 19 {
    return Err(FrameError::TooShort);  // ← 长度已校验
}
let group_id: [u8; 4] = data[3..7].try_into().unwrap();  // ← 不可失败
```

**裁决：否决**

**原因**：

1. **所有 unwrap 不可失败**：每处 `try_into()` 前都有 `data.len() < N` 长度检查。`TryInto<[u8; K]>` 对 `&[u8]` 的唯一失败条件是切片长度 ≠ K。在长度已校验的前提下，`unwrap()` 是安全的。

2. **`ok_or` 反而更差**：
   ```rust
   // 审计建议的写法
   let group_id: [u8; 4] = data[3..7].try_into().ok_or(FrameError::TooShort)?;
   ```
   这引入了一个**不可达的错误分支**。`FrameError::TooShort` 的语义是"数据太短"，但此处数据已经足够长（通过前置检查），这个错误永远不会触发。不可达的 `Err` 分支比 `unwrap()` 更具误导性——它暗示这个分支可能被执行。

3. **Rust 惯例**：在长度已验证的前提下使用 `try_into().unwrap()` 是 Rust 社区标准做法。`std::convert::TryInto` 文档和标准库代码中都大量使用此模式。

4. **如果仍想消除 unwrap**：可以用 `try_into().expect("length checked above")`，但这只是把 `unwrap` 换了个名字，无实质改进。

5. **clippy 无警告**：`cargo clippy` 对这些 `unwrap()` 不报 warning，因为 clippy 能识别"长度已检查"的模式。

---

### 47. ⚠️ 部分采纳：DAO 层 839 行无独立测试

**审计声明**：DAO 层 935 行无独立测试。

**验证结果**：
- `dao.rs` 实际 839 行（非 935）
- `dao.rs` 内部零 `#[test]` / `#[cfg(test)]`
- **但** `store.rs:435-438` 有 `#[cfg(test)] mod tests` 导入 `dao` 并测试 DAO 函数：
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;
      use crate::dao;          // ← 导入 DAO
      // doc_crud, peer_and_anchor 等测试直接调用 dao:: 函数
  }
  ```
- `sqlite_pool_eval.rs` 也调用 `dao::upsert_ack` / `dao::list_acks_by_doc`（虽然是 benchmark 不是断言测试）

**裁决：部分采纳**

**采纳部分**：为 DAO 层补充独立的单元测试模块。当前测试通过 `store.rs` 间接覆盖，但：
- 缺少边界测试（空输入、超大输入、SQL 注入尝试）
- 缺少错误路径测试（约束冲突、事务回滚）
- 间接测试难以定位是 DAO 层还是 Store 层的 bug

**否决部分**：不把 DAO 测试从 `store.rs` 中拆出。原因：
- `store.rs` 的测试已经在验证 DAO 的端到端行为
- 拆分会导致重复测试
- 正确的做法是**补充**DAO 层缺失的边界/错误路径测试，而非重构现有测试

---

### 48. ❌ 否决：mdns.rs 无网络 I/O

**审计声明**：编码/解码/分组过滤/TTL/GC 都有，但没有调用真实 mDNS 库。

**验证结果**：确认 `mdns.rs` 仅做协议层编解码，无网络 I/O。注释明说"平台绑定由集成层处理"。

**裁决：否决**

**原因**：这是有意设计，且是正确的架构分层。
- iOS 用 `NSNetService` / `NWBrowser`
- Android 用 `NsdManager`
- Linux 用 `avahi` / `zeroconf`
- Rust 层提供协议解析（编解码、TTL、GC），平台层提供网络发现
- 如果在 Rust 层绑定特定 mDNS 库，会引入平台依赖（如 `mdns-sd` 不支持 iOS），破坏跨平台编译

---

### 49. ❌ 否决：BLE/SMS 缺少非 Linux 平台后端

**审计声明**：仅有 Linux BLE 后端（`bluer`），缺 iOS/Android。

**验证结果**：确认。`bluer_backend.rs` 仅 Linux 可用。

**裁决：否决**

**原因**：同 #48，是有意的 FFI 注入设计。
- iOS BLE 用 `CoreBluetooth`（Swift/Kotlin 绑定）
- Android BLE 用 `BluetoothAdapter` / `BluetoothLeScanner`
- Rust 层定义 `BleBackend` trait，平台层实现注入
- 在 Rust 层绑定平台原生 BLE 库会引入巨大依赖（如 `btleplug` 对 iOS 支持不完整）
- SMS 传输完全依赖平台原生 API（SMS 框架），Rust 层无法实现

---

## 补充汇总

| # | 问题 | 裁决 | 优先级 | 理由摘要 |
|---|------|------|--------|----------|
| 44 | 批次签名→Ed25519 | ❌ 否决 | — | Noise AEAD 已认证，签名冗余；改文档措辞即可 |
| 45 | 5 个弱断言测试 | ✅ 已完成 | P1 | 4 个测试已补断言 |
| 46 | frame.rs unwrap | ❌ 否决 | — | 全部是长度已校验的 try_into，不可失败 |
| 47 | DAO 层无独立测试 | ✅ 已完成 | P2 | 7 个边界测试（SQL 注入/null/大 blob/回滚） |
| 48 | mdns.rs 无网络 I/O | ❌ 否决 | — | 有意设计，平台层注入 |
| 49 | BLE/SMS 缺平台后端 | ❌ 否决 | — | 有意设计，FFI 注入 |
