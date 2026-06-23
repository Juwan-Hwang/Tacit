# Tacit v1.0 FINAL

## 1. 概述

Tacit 是一套面向单用户多设备场景的 local-first 同步系统，目标是在现有手机、平板、笔记本和桌面硬件上实现本地零等待写入、近场无网同步、广域近实时同步、断链自动补齐，以及端到端加密。[web:15][web:1]

系统不依赖中心数据库保存权威状态；每台设备都持有本地可用副本，网络只负责传播增量、快照和控制消息。[web:1]

Tacit v1.0 FINAL 的核心原则是：
- Loro 负责状态与合并。[web:139][web:122]
- Tacit 负责发现、传输、确认、压缩调度、设备信任与同步元数据。
- Desktop Anchor 是首选稳定节点，但不是唯一前提。
- iOS 不承诺后台强实时，只承诺前台强同步与恢复即补齐。[web:98][web:147][web:153]

## 2. 目标与边界

### 2.1 目标
- 本地优先：输入先落本地，再异步同步。
- 单用户多设备自动收敛。
- 同房间/同局域网极速同步。
- 跨城存在任意互联网链路时近实时。
- 完全断链时继续本地工作，恢复后自动补齐。
- 无自建真相服务器。
- 安全默认开启。

### 2.2 边界
- 不承诺“完全无链路时仍实时同步”。
- 不把 iPhone 定义为长期后台常驻 mesh 节点；iOS 的后台执行时间由系统启发式调度，频率和时长不可预测。[web:98][web:147][web:153]
- v1.0 不做多人自由富文本协同；优先做文本块、待办、设置、小型结构化对象。
- Data SMS 不进入核心路径，只保留实验性适配器。[web:16][web:110]

## 3. 系统角色

| 角色 | 定义 | 职责 |
|---|---|---|
| Mobile Node | 手机 / 平板 | 本地输入、近场发现、前台同步、恢复追赶 |
| Desktop Anchor | 笔记本 / 台式机 | 首选稳定节点、局域网广播、checkpoint 压缩、优先入口 |
| Relay Node | 自有 / 社区 / 公共转发节点 | 广域兜底转发，不保存真相内容[web:1][web:109] |

Desktop Anchor 是首选稳定节点，不是系统存在前提。它离线时，系统自动退化到手机直连、公共 relay 或完全本地模式。

### 3.1 Anchor 选举
- 每个 Anchor 周期性更新在线状态与能力位。
- 若连续多次探测失败，则标记为 `offline`。
- 所有设备基于同一份 `peers` 视图执行确定性排序，避免脑裂。
- 推荐排序键：`anchor_priority desc, nat_capability desc, success_ema desc, last_seen_at desc, peer_id asc`。
- 若无 Anchor 可用，则设备直接走 peer-to-peer 或 relay。

## 4. 核心架构

| 层 | 职责 | 关键实现 |
|---|---|---|
| 本地状态层 | 真相源与离线可用 | SQLite + Loro 文档状态 + 本地 checkpoint[web:139][web:122] |
| 复制层 | 增量同步与收敛 | Loro delta / snapshot、ack matrix、缺口拉取 |
| 传输层 | 多链路搬运 | BLE Presence、LAN QUIC、WAN QUIC、relay、store-and-forward[web:127] |
| 发现层 | 找到对等体 | BLE、mDNS、known_peers、bootstrap_hints |
| 安全层 | 身份、握手、加密 | 设备公钥身份 + Noise 会话保护[web:128][web:137] |
| 体验层 | 弱化延迟体感 | 本地乐观提交、前台强同步、恢复即补齐 |

同步语义与传输介质彻底解耦：上层只认状态、增量、快照、确认与信任；下层只负责“当前走哪条链路”。

## 5. CRDT 与状态边界

### 5.1 唯一真相源
v1.0 采用 **Loro 作为唯一状态真相源**。[web:139][web:122]

### 5.2 职责划分
| 系统 | 负责内容 |
|---|---|
| Loro | 文档状态、内部版本、增量导出/导入、snapshot/shallow snapshot、幂等合并[web:139][web:122] |
| Tacit | 发现、设备信任、传输元数据、ack、checkpoint 调度、GC 策略、relay、known peers |

### 5.3 Frontier 复用原则
所有 ack 摘要、缺口检测、checkpoint 边界、stale 判定，都优先复用 **Loro 原生 frontier/version 信息**。[web:139][web:146]

### 5.4 Meta-Document
每个 block 一个独立 Loro 实例，但 block 列表、顺序、软删除状态、块元信息由专门的 **Meta-Document** 管理。

同步顺序规则：
1. 先同步并合并 Meta-Document。
2. 再按需拉取相关 block 的具体状态。
3. 若 Meta-Document 已引用新 block，但对端 block 状态尚未可取，则进入短暂依赖等待队列，采用短退避重试，而不是报错或无限自旋。
4. 本地读取缺失 block 时，先渲染占位符骨架，再后台静默拉取实际内容。

### 5.5 同步元数据边界
`expected_frontier` 不属于文档内容真相，而属于 Tacit 的同步层元数据。它不写入 Meta-Document，而由 `Tacit-sync` 与 `Tacit-store` 按 `doc_id/block_id/peer_id` 维护。

## 6. 数据模型

v1.0 只支持四类对象：文本块、待办列表、设置项、追加式日志。

### 6.1 块级编辑
文档由 block 列表组成，每个 block 拥有独立 ID、类型与内容实例。跨 block 的操作由 Meta-Document 驱动。

### 6.2 Soft Delete
删除 block 时不立即物理擦除，而是先标记 `deleted=true`。只有在 compaction 确认安全后，才执行真正物理回收。

## 7. 本地持久化

SQLite 作为本地持久化层。Loro 负责导出快照与增量，SQLite 负责持久化元数据与最近状态。

### 7.1 推荐表结构
- `documents(doc_id, kind, current_frontier, updated_at)`
- `document_snapshots(doc_id, snapshot_id, snapshot_blob, snapshot_kind, created_at)`
- `sync_log(entry_id, doc_id, delta_id, recipient_peer_id, delivered_at, acknowledged_at, channel)`
- `checkpoint_log(doc_id, checkpoint_id, shallow_snapshot_blob, frontier, state_hash, created_at)`
- `peers(peer_id, device_pubkey, capabilities, trust_state, anchor_priority, last_seen_at, last_endpoint)`
- `acks(peer_id, doc_id, ack_checkpoint, ack_frontier, updated_at)`
- `block_sync_state(doc_id, block_id, peer_id, expected_frontier, observed_frontier, retry_after_ms, updated_at)`
- `transport_stats(peer_id, channel, success_ema, avg_latency_ms, updated_at)`

### 7.2 写放大防御
- 常规输入时，只更新 frontier、小型元数据和传输记录。
- 到达 checkpoint 条件、应用退后台、或定时窗口时，再异步导出 snapshot 并写入 `document_snapshots`。
- `documents` 表只保留轻量元数据，避免整行重写。

### 7.3 Snapshot 原子替换
下载或生成 shallow snapshot 时，必须采用 **WAL 或双缓冲机制**。[web:139][web:153]

流程：先写临时快照，校验 hash/frontier，成功后原子切换当前引用，失败则回滚。

## 8. Loro 快照与压缩

Loro 提供 **Shallow Snapshot**，可在保留当前状态的同时移除旧历史。[web:139][web:142][web:146]

### 8.1 使用原则
- 普通 checkpoint：供本地恢复或归档使用。
- shallow snapshot：供 GC/压缩和新设备追赶使用。[web:139]
- shallow snapshot 生成时必须以已协调 frontier 为边界，并先确保相关 active 设备已同步到该边界。[web:139]

### 8.2 已协调边界判定
AckSummary 控制帧必须携带最近 checkpoint_id、当前 frontier 摘要与可选版本覆盖信息。只有当所有 active 设备的 AckSummary 都覆盖某个共同 frontier 时，CheckpointManager 才允许以它为基准生成 shallow snapshot。

### 8.3 双水位 GC
为避免低频设备阻塞压缩，v1.0 定义两条水位：
- **强安全水位**：所有 active 设备都覆盖的 frontier。
- **软安全水位**：超过阈值未上线设备临时移出 active 集合后可推进的 frontier。

强安全水位用于无争议压缩；软安全水位用于实际可运转的常规 compaction。低频设备回归时通过 checkpoint 追赶或手术式重入兜底。

### 8.4 手术式重入
若长期离线设备持有旧分叉本地更新，而系统已对旧历史完成 shallow compaction，则不得直接导入其旧 delta。[web:139]

降级恢复流程：
1. 备份旧本地状态。
2. 拉取最新 shallow snapshot 重建本地文档。
3. 将旧设备中尚未同步的用户层 block 修改，重新映射为新的本地写入再导回系统。

## 9. 时钟与顺序

HLC 仅用于 UI 的近似排序、传输层缺口检测与日志观测、GC 时间窗口与 stale peer 判断、soft-delete 安全线辅助；HLC **不参与 Loro 的 CRDT 排序逻辑**。

每台设备维护本地单调递增 `seq`，仅用于检测控制层/传输层重复、辅助日志分析与链路诊断、ack 粒度统计。

## 10. 发现与引导

v1.0 **不使用 DHT 作为核心发现机制**；对 2 到 8 台设备的个人同步系统，维护成本与不确定性高于收益。[web:115][web:123]

### 10.1 发现路径
- 近场发现：BLE Presence、局域网 mDNS / 广播。
- 远场引导：`known_peers`、`bootstrap_hints`、Desktop Anchor、gossip 式在线公告与 endpoint 更新。

### 10.2 known_peers 字段建议
`peer_id`、`device_pubkey`、`capabilities`、`last_seen_at`、`last_good_endpoint`、`anchor_priority`、`relay_hint`、`nat_class`、`trust_state`。

## 11. 传输层

### 11.1 通道优先级
| 优先级 | 通道 | 正式定位 |
|---|---|---|
| 1 | BLE Presence | 发现、presence、极小 rendezvous hint |
| 2 | LAN QUIC | 近场/同网主链路[web:127] |
| 3 | WAN QUIC | 广域主链路[web:127] |
| 4 | Relay | 广域兜底[web:1][web:109] |
| 5 | Store-and-forward | 完全断链时缓存与后续传播 |
| X | Data SMS | 实验性 adapter，不纳入 v1.0 核心路径[web:16][web:110] |

### 11.2 BLE Presence
BLE 只用于广播 `group_id/device_id/capability`、标记“我在附近”、引导后续 LAN / QUIC 连接，以及可选极小 rendezvous hint。Apple 平台后台广播与扫描行为受限，不写进核心 SLA。

### 11.3 LAN / WAN QUIC
v1.0 的主数据通道是 QUIC。Rust 主实现推荐 **Quinn**，它是纯 Rust、异步友好的 IETF QUIC 实现。[web:127][web:130][web:171]

### 11.4 连接迁移与快速重连
不把 Quinn `Connection` 当作永不失效真理。[web:127][web:171]
- 监听网络路径变化或 reachability 变化。
- 触发时主动 drop 旧连接。
- 立即执行 `fast-resume`。
- 不把 QUIC 被动连接迁移写成系统级保障。

### 11.5 Relay
relay 是正式方案的一部分。

| 层级 | 来源 | 角色 |
|---|---|---|
| Tier 1 | 用户自有 Desktop Anchor | 首选 relay / bootstrap / 入口 |
| Tier 2 | 社区志愿节点 | 次选公共 relay |
| Tier 3 | 公共服务节点 | 最后兜底 |

#### relay 能力边界
- v1.0 relay 只做**实时消息转发**。
- 不做长期消息存储。
- 不做文档真相保存。
- 可见连接元数据，如对等关系、时长、流量大小、时间信息。
- 不可见内容，因为内容始终端到端加密。[web:1][web:109]

#### relay 极简协议
v1.0 relay 协议只需三类控制消息：注册 peer、转发消息、peer 上下线通知。

#### relay 轻量防滥用
客户端在 relay 首个控制阶段必须提供轻量 admission proof，例如基于 `group_id` 派生密钥的 HMAC 或等价凭证；验证通过后 relay 才分配转发资源。

#### relay 隐私边界
公共 relay 可能通过稳定标识、连接时序和流量模式推断多个设备属于同一用户。[web:1][web:109]
因此应优先使用自有 Anchor；公共 relay 连接建议使用会话级临时 ID，而不是长期稳定外显标识。

## 12. 安全模型

v1.0 采用：**设备公钥即身份，群组内预信任所有已配对设备公钥。**

### 12.1 首次配对
v1.0 仅支持**面对面配对**。二维码内容至少包括 `group_id`、发起方设备公钥、群组校验盐或绑定摘要、可选 bootstrap hints。推荐增加一步短校验码确认：扫码后两端显示同一 4 位数字，用户确认一致后再完成绑定。

### 12.2 后续扩展
协议层预留 `introduce`、`revoke`、`key_rotate`，但 v1.0 不启用远程信任链与密钥轮换。

### 12.3 会话加密
正式方案采用 **Noise Protocol Framework**，Rust 实现建议使用 **snow**。[web:128][web:137]

## 13. 协议分层

### 13.1 Discovery Frame
```text
magic(2) | version(1) | group_id(4) | device_id(8) | capability_bits(2) | checksum(2)
```

### 13.2 Control Frame
```text
magic(2) | version(1) | ctrl_type(1) | session_id(8) | payload_len(2) | payload(n) | mac(16)
```

payload 使用 TLV，类型包括 `Capabilities`、`KnownCheckpoint`、`AckSummary`、`NeedRanges`、`TransportHints`、`RelayHints`、`Introduce`、`Revoke`、`KeyRotate`。

### 13.3 Data Frame
```text
magic(2) | version(1) | flags(1) | doc_id(8) | actor_id(8) | seq(4) | kind(1) | payload_len(4) | payload(n) | ref(8) | sig(batch) | mac(16)
```

### 13.4 批次签名规则
建议同一 QUIC 流内、同一文档的连续 delta 构成一个签名批次。QUIC stream 是有序字节流，因此 `flags` 预留 2 bits 表示：单帧、批次开始、批次中间、批次结束，主要用于简化接收端批次解析与恢复状态机。[web:172][web:164][web:175]

### 13.5 Snapshot 分片
大 shallow snapshot 默认按固定 chunk 大小切片传输，并允许仅重拉缺失切片，以减少弱网断线后的整包重传成本。

## 14. 能力协商与兼容性

v1.0 采用：**主版本保底，能力协商优先。** 主版本不兼容时拒绝，次版本差异通过 capability 降级，扩展字段统一用 TLV 携带。

## 15. 后台与恢复策略

### 15.1 Apple 平台
Apple 的后台执行时间受系统启发式调度，不能依赖持续常驻。[web:98][web:147][web:153]
- 前台：全功能同步。
- 后台：尽力而为，不承诺稳定实时。
- 恢复：回前台后立即执行 fast-resume sync。
- BLE 后台能力仅作被动增强，不写进核心 SLA。

#### Hot-Path Control
若 Apple 设备因 BLE 或系统短暂被唤醒，优先只处理极小控制信息：frontier 摘要、缺口标记、同步意图，不在该短窗口内强求完整 QUIC 数据追赶。

### 15.2 Android 平台
默认 opportunistic 同步；可选高可用模式：前台服务 + 更强连接保持。

### 15.3 首屏恢复策略
前台恢复时，优先顺序为：
1. Meta-Document 骨架。
2. 当前屏幕可见 block。
3. 活跃文档剩余 block。
4. 冷文档与历史追赶。

这样可把“先能看、再补齐”作为恢复体验默认路径。

## 16. Presence 与临时状态

在线状态、正在编辑提示、光标位置等临时信息应与持久化文档历史隔离，作为 ephemeral/presence 数据通过独立通道传播，不进入 checkpoint 与 GC 水位。建议定义 TTL，并在设备离线后自然过期。

## 17. 队列与优先级

| 优先级 | 内容 |
|---|---|
| 高优 | 用户前台实时输入、活跃 block 的小增量、Meta-Document |
| 中优 | ack、控制帧、设置变更 |
| 低优 | checkpoint、冷文档追赶、压缩任务 |

高优消息优先发，必要时允许多通道竞速；低优任务不得阻塞前台输入体验。

## 18. Rust 模块拆分

建议 workspace 结构：
- `Tacit-core`
- `Tacit-crdt`
- `Tacit-store`
- `Tacit-crypto`
- `Tacit-transport`
- `Tacit-transport-ble`
- `Tacit-transport-quic`
- `Tacit-transport-relay`
- `Tacit-sync`
- `Tacit-ffi`

### 18.1 FFI 约束
平台层不应直接长期持有 Loro 文档对象。Rust 侧统一维护 `DocStore`；平台侧只通过 `doc_id` 和纯二进制 blob 接口交互。

### 18.2 命令模式
FFI 暴露接口尽量设计为命令模式：UI 线程发送命令到 Rust 内部队列；Rust 内部工作线程持有 Tokio runtime；所有网络 IO、文档修改、checkpoint 生成在 Rust 内部调度执行。这样可避免跨线程死锁或重入问题。

### 18.3 大导入防阻塞
收到较大 delta/snapshot 时，应先进入异步处理队列，再由 Rust 工作线程分片应用或分阶段提交；不得在 UI 触发路径上直接长时间执行导入合并。

## 19. 监控与可观测性

v1.0 建议内置最小本地 telemetry：sync lag、队列积压长度、每通道成功率、最近连接延迟、Anchor 在线状态。`transport_stats.success_ema` 建议使用指数移动平均更新。

## 20. 测试策略

### 20.1 收敛性测试
使用 property-based testing 验证：任意乱序导入增量后状态收敛、重复包不导致重复应用、soft-delete 不产生 orphan crash、checkpoint + tail delta 可重建当前状态。

### 20.2 网络混沌测试
模拟随机断网、高延迟、丢包、relay/直连切换、节点随机 kill/restart、Anchor 上下线切换。

### 20.3 长离线追赶
必须覆盖：设备 A 离线 3 天，设备 B / Anchor 持续编辑，A 回来后通过 shallow checkpoint + tail delta 快速追赶，全程无重复、无状态污染、无崩溃。

### 20.4 安全测试
包括伪造 peer_id 注入、未配对设备发送 Data Frame、重放旧帧、relay 篡改或丢弃消息、stale peer 重新上线后的权限边界验证。

### 20.5 跨平台互操作
至少验证 Android ↔ Desktop、Apple ↔ Desktop、Android ↔ Apple（以 LAN / Anchor 为主，不以近场 P2P 为唯一通路）。

### 20.6 后台体验测试
应尽早纳入 iOS 后台可用窗口测试、Android 主流厂商后台存活测试、回前台后的 fast-resume 时延测试。[web:98][web:153]

## 21. Phase 1 范围冻结

### 21.1 包含
- 单用户多设备，`2-8` 台。
- 文本块、待办、设置、小型结构化对象。
- Loro 作为唯一状态内核。[web:139][web:122]
- Meta-Document 管理文档结构。
- BLE Presence + mDNS 发现。
- LAN QUIC + WAN QUIC + relay。
- known_peers + bootstrap_hints + Desktop Anchor。
- Noise 会话加密。[web:128][web:137]
- shallow snapshot checkpoint/compaction。[web:139][web:146]

### 21.2 不包含
- 多人自由富文本协同。
- DHT 核心发现。
- Data SMS 主路径。
- 纯移动端无 Anchor 的强后台实时承诺。
- 附件/图片大对象同步主流程。

## 22. 用户承诺

Tacit v1.0 FINAL 对用户的承诺是：同房间且前台活跃时接近实时；同局域网时强实时；跨城且有互联网链路时近实时，必要时经 relay；手机在后台时尽力同步，打开后快速补齐；完全断链时本地照常可用，恢复后自动同步。[web:1][web:109][web:98][web:153]
