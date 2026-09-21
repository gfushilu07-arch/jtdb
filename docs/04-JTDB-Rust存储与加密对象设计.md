# JTDB 加密对象与存储加密设计

| 项 | 值 |
|---|---|
| 项目代号 | 金湯 JTDB（暂定） |
| 承接文档 | 《实现方案》v0.3 §4、《架构决策记录》ADR-007/013、《密评合规与随机数设计》docs/12 |
| 对应文档树 | docs/04-JTDB-Rust存储与加密对象设计.md |
| 文档版本 | v0.1 起草稿 |
| 日期 | 2026-09-02 |
| 状态 | 阶段 0 专项；**本文冻结 JtEncryptedObject v1 布局**，冻结前置条件见 §10 |

## 1. 目标与范围

解决评审确认的 P0-2 空洞：实现方案 §4.2 的对象格式只有单块 `header || ciphertext || tag || signature`，未回答"Layer 文件可达数百 MB，读一页是否要解密整层"。本文给出**分块 AEAD（chunked AEAD）**的字节级设计，作为对象格式冻结的基础。

职责划分不重复：《实现方案》§4 定义组件职责、nonce/generation 通用规则、WAL 集成范围；本文定义**对象磁盘格式的精确布局**与读写协议。冲突时以本文为准并回改实现方案。

## 2. 设计原则

1. **边界加密**：加密封装在存储 I/O 边界（实现方案 §4.6/规划 §3），Timeline/Layer 内部逻辑不感知密文；
2. **信封密钥**：对象携带 wrap 后的 DEK，读路径不依赖 KMS 在线；KMS 租约（ADR-013）只控制组件能否获得 KEK/新 DEK；
3. **分块不可变**：chunk 一经写入不可重写；任何修改 = 新对象新 generation（与实现方案 §4.3 一致）；
4. **原子发布**：对象以"临时文件 + 最后写头 + 原子 rename"发布，杜绝部分可见；
5. **单页读取代价恒定**：读任意一页 = 1 次定位 + 1 个 chunk 解密（O(1)），与对象大小无关。

## 3. 对象总体布局（v1）

```text
┌─────────────────────────────────────────────┐
│ Header（固定 96 B，明文）                     │ §3.1
├─────────────────────────────────────────────┤
│ Metadata（明文 TLV，变长，≤ 4 KiB）           │ §3.2
│   含 Key Envelope（wrapped DEK）             │ §6
├─────────────────────────────────────────────┤
│ Chunk 0 .. Chunk n-1（密文 + 16 B tag）       │ §4
├─────────────────────────────────────────────┤
│ Trailer：SM2 对象签名（header_digest 覆盖）   │ §3.4
└─────────────────────────────────────────────┘
```

### 3.1 Header 字段表（小端）

| 偏移 | 字段 | 类型 | 说明 |
|---|---|---|---|
| 0 | magic | `[u8;8]` | `"JTENCOBJ"` |
| 8 | format_version | u16 | 当前 = 1 |
| 10 | object_type | u8 | 1=WAL_SEG 2=LAYER 3=SNAPSHOT 4=BACKUP 5=AUDIT_JOURNAL |
| 11 | flags | u8 | bit0=chunked bit1=metadata_signed bit2=sealed |
| 12 | header_size | u16 | 头部长度（预留扩展，当前 96） |
| 14 | metadata_len | u32 | Metadata 区字节数 |
| 18 | timeline_id | `[u8;16]` | UUID |
| 34 | object_id | `[u8;16]` | UUID |
| 50 | key_epoch | u64 | 加密本对象所用 epoch |
| 58 | generation | u64 | 单调代际（实现方案 §4.3） |
| 66 | chunk_size | u32 | 0 = 单发模式；否则默认 65536 |
| 70 | chunk_count | u64 | chunk 数 |
| 78 | payload_len | u64 | 明文总长 |
| 86 | base_nonce | `[u8;12]` | 每对象随机（docs/12 §4 DRBG） |
| 98 | header_digest | `[u8;32]` | SM3(offset 0..96)，供 AAD 与签名 |

> 偏移 98 超出 96 B：实际头长 = 96 + 32 = **128 B**，`header_size` 字段承载。上表保留整数偏移可读性。

### 3.2 Metadata TLV

```text
entry := type(u16) || len(u32) || value
```

| type | 名称 | 说明 |
|---|---|---|
| 0x0001 | kek_ref | KEK 标识（cluster + kek_id） |
| 0x0002 | wrapped_dek | SM4 wrap 后的 DEK（§6） |
| 0x0003 | lsn_range | WAL/Layer 的 [start_lsn, end_lsn) |
| 0x0004 | created_at | 创建时间（UTC 秒） |
| 0x0005 | node_id | 写入节点组件 ID |
| 0x0006 | lineage_id | compaction 谱系（源对象 id 列表摘要） |
| 0x0007 | retention_hint | PITR/epoch 保留点提示 |

未知 type 必须跳过（前向兼容）。metadata_digest = SM3(Metadata 区)，进入对象签名。

### 3.4 Trailer 签名

```text
signature = SM2_sign(node_key, header_digest || metadata_digest || last_chunk_tag)
trailer 布局（2026-09-11 实现裁决）：signature(64B) || u16 sig_len（长度置尾）
```

由写入节点组件证书签名，绑定"谁写的 + 内容是什么"；验签材料来自组件证书链（docs/13）。`flags.bit1=0` 时允许无签名（仅开发模式）。trailer 有无由 `flags.bit3=TRAILER_SIGNED`（v1 定义者追加位）承载；验签策略支持全量或抽样（首次加载+审计触发，§11.4）。

## 4. 分块与随机读

### 4.1 分块参数

| 参数 | 值 | 理由 |
|---|---|---|
| chunk_size 默认 | 64 KiB | = 8 × PG 8 KiB 页；读一页至多解密 1 chunk；64 KiB 明文缓冲对 WAL 追加友好 |
| 允许范围 | 4 KiB ~ 1 MiB | 对象类型可覆盖（WAL_SEG 可用 64 KiB；SNAPSHOT 大对象可用 256 KiB） |
| chunk_count 上限 | 2^32-1 | chunk_index 用 u32；64 KiB × 2^32 = 256 TiB，覆盖所有对象 |
| 单发模式 | chunk_size=0 且 chunk_count=1 | 小对象（审计 journal 段等）省去分块开销 |

### 4.2 每_CHUNK 加密

```text
nonce(c)  = base_nonce XOR u96(c)        # RFC 8446 record-nonce 派生法
ciphertext(c) || tag(c) =
    SM4_AEAD_encrypt(dek, nonce(c), aad(c), plaintext_chunk(c))
```

**唯一性规则**（GCM 禁止 key+nonce 重用）：同一对象内 nonce(c) 由 base_nonce 与 c 一一决定，因此 chunk 内容对 index 必须不可变——重写任何 chunk = 新对象（新 base_nonce、新 generation）。base_nonce 每对象取自 DRBG（docs/12 §4），域隔离由 (timeline, object_id, epoch) 天然保证。

### 4.3 AAD 字节级布局

```text
aad(c) = header_digest(32B) || object_type(1B) || key_epoch(8B)
       || generation(8B) || chunk_index(4B) || chunk_offset(8B) || chunk_len(4B)
```

header_digest 进 AAD 使头部任何篡改导致全部 chunk 验证失败；chunk_offset/len 防止 chunk 搬移与截断重排。

### 4.4 读协议（页读取）

```text
定位：页号 → chunk_index = page_offset / chunk_size
读取：chunk_offset 处读 (chunk_size 明文对应密文 + 16B tag)
解密：SM4_AEAD_decrypt(dek, nonce(c), aad(c)) → 明文 chunk → 取页
```

Pageserver 页缓存命中时无解密；未命中时代价 = 1 chunk 解密（64 KiB SM4 硬件加速 <10 µs 量级，基准见规划 §5）。

### 4.5 与 IEEE 1619 对标及 nonce 唯一性论证（2026-09-03 依外部审计补充）

外部事实（审计 §3）：块存储加密主流是 AES-XTS（IEEE 1619），刻意不提供篡改认证；认证式变体由 IEEE 1619.1-2018 定义（GCM、CBC+HMAC、XTS-HMAC）。**本格式定位为 1619.1-2018 GCM 认证变体的对象化实例**，密评/审计对标时按此引用。

(key, nonce) 唯一性论证（GCM 安全性前提）：

| 场景 | 论证 |
|---|---|
| 同对象内 | nonce(c) = base_nonce XOR u96(c)，chunk_index c 唯一 ⇒ 对象内唯一 |
| 跨对象 | base_nonce 每对象独立取自 DRBG（96-bit）；10^9（≈2^30）个对象的生日碰撞概率约 2^-37，可忽略；且 DEK 按 epoch/timeline 隔离进一步缩小共享空间 |
| 跨 epoch | DEK 不同 ⇒ (key, nonce) 对自动不同 |
| 崩溃重写 | 未 sealed 对象不可读、不发布（§7）；重试从头写新对象（新 base_nonce），不存在"同一 nonce 写入不同内容可被观察到"的路径 |
| chunk 改写 | 禁止（chunk 不可变，§2 原则 3）；任何修改 = 新对象新 generation |

残余风险与控制：DRBG 降级到软件源时（docs/12 §4.1）KMS 拒发新 DEK，随机性前提仍受控；docs/12 密码专项评审需复核本论证（§10 冻结前置条件）。

## 5. WAL 追加语义（object_type=WAL_SEG）

- WAL 段对象为**追加式**：明文在 64 KiB chunk 缓冲内累积，攒满一个 chunk 即加密追加；
- chunk 攒满前崩溃：未落盘明文丢弃，从 Safekeeper 对端重新拉取（Neon Safekeeper 原生恢复路径，不新增协议）；
- 段写满后：写 sealed header + trailer 签名，**临时名 `.part` → fsync(数据) → fsync(头) → 原子 rename**；
- 已发布对象不可追加（chunk 不可变）；下一段 = 新对象（新 object_id）。

### 5.1 已实现范围与两处实现期裁决（2026-09-20）

**已实现**（`libs/jt-encrypted-object/src/wal.rs`，16 项测试）：

- `WalSegWriter`：追加式写入，chunk 缓冲攒满即加密落盘；未满不落盘半块明文（崩溃即丢，走 Safekeeper 原生对端重拉）；
- `seal_wal_segment` / `unseal_wal_segment`：**已完成段 ↔ 不可变对象**的转换（归档/卸载路径原语）；
- 封段：trailer 签名 + `fsync` + 原子 `rename`（`.part` → 最终名）；已发布对象不可追加。

**裁决 1：header 一次写定记"容量上界"，真实长度记在 metadata。**

约束：`header_digest = SM3(0..98)` 且读取端自校验（§3.1），chunk 的 AAD 含 `header_digest`（§4.2）而 digest 覆盖 `chunk_count`/`payload_len`。故这两个字段**必须在加密第一个 chunk 之前确定、不可事后回填**。

但段可能**未写满即封段**（如停机前最后一段）：若 header 的 `payload_len` 是容量而实际数据更少，读取端按容量读尾 chunk 会撞 `UnexpectedEof`（**实测缺陷**）。解法：metadata 用定宽 u64 记**真实**长度（`0x0010`/`0x0011`，finish 时原地更新——长度不变故不破坏布局），读取端优先采信真实值并校验 `≤` 容量上界（防御损坏 metadata 放大越界）。

**裁决 2：封段信号由原子 `rename` 承载。** `.part` 存在 = 未封段（恢复时忽略）；rename 到最终名 = 已封段。与本节"fsync → 原子 rename"给出一致的崩溃语义，且无需改动 header（否则回到裁决 1 的矛盾）。

### 5.2 活段文件加密（**已实现**，2026-09-20）

本节上文的"追加式对象"模型**不适用于 Safekeeper 的活段文件**，实测确认两点冲突：

1. **偏移恒等**：活段预分配（`set_len(wal_seg_size)`）后按任意 `xlogoff` 写（`wal_storage.rs::write_in_segment` 会 seek），且对端按任意偏移并发读（`WalReader::open_segment` seek 到 `xlogoff`）。在偏移 0 放 130B 头会**移动全部 WAL 数据**，破坏 LSN↔偏移恒等——这是复制与恢复的基础。
2. **flush 驱动**：Safekeeper 的持久性契约是"收到即 flush 并通告 `flush_lsn`"，对端会流式读**未写完的 `.partial` 段**（`open_wal_file` 优先打开 `.partial`）。64 KiB chunk 在攒满前无法封块、也就无法 flush，直接破坏提交延迟。

**结论**：本节的对象模型对应**已完成、不可变的段**（§2 原则"对象不可变"），即**归档/卸载路径**（S3 上传、base backup、归档恢复）；该路径已按 §5.1 实现。**活段文件加密是另一条路径**，需满足：

- (a) **密文与明文同偏移**（保持 LSN↔偏移恒等，头/tag 不得前置）；
- (b) **每个 flush 边界可独立认证**（不能等 64 KiB chunk 攒满）；
- (c) **对端能流式解密未写完的段**（`.partial` 语义不变）；
- (d) AAD 至少绑定 `timeline_id / wal_segment / record_lsn / key_epoch / generation`（docs/02 §4.4）。

**采用形态**（`libs/jt-encrypted-object/src/live_wal.rs`，15 项测试）：按 chunk（默认 8 KiB，PostgreSQL 页边界）做独立 AEAD，**tag 存独立 tag 区**而非就地追加（保持同偏移）；header 置于文件末尾。与 §3.1 的对象布局不同，用 `flags.LIVE_WAL`（`0b0001_0000`）区分——同一 `object_type=WalSeg`，布局不同。

```text
[0 .. S)                密文区：与明文 1:1 同偏移（S = seg_size）
[S .. S + T)            tag 区：每 chunk 32B = plain_len(4) || nonce(12) || tag(16)
[S + T .. S + T + 130)  header
```

`plain_len == 0` 兼作"未写"哨兵（预分配零填充天然表示未写，无需位图）；tag 条目按 `chunk_index` O(1) 定位（`S + c*32`）。

**尾部半块的处理（关键裁决）**：`flush_lsn` 可落在 chunk 中间（WAL 记录不按页对齐），而 GCM 禁止 `(key, nonce)` 重用。解法是**尾块每次 flush 用新 nonce 重新封装整个 chunk**并覆写密文与 tag 条目——旧密文被覆写、旧 nonce 永久废弃，故不存在二次使用；**整 chunk 写满即冻结不可变**。代价是每次 flush 至多重加密一个 chunk（≤ chunk_size）。

**崩溃一致性**：先写密文、后写 tag 条目（tag 为提交点）。崩在两者之间时，读取端用旧 nonce 解新密文 → AEAD 失败 → **检出而非静默错误**（fail-closed），随后走 Neon 原生对端重拉恢复。

**AAD**（docs/02 §4.4）：`timeline_id || seg_no || chunk_index || chunk_plain_off || key_epoch || generation || plain_len`——跨段/跨偏移/跨 epoch 搬移均可检出。

**阻塞项状态**：nonce 方案**已闭环**（S2：每 chunk 独立随机 nonce 取自 DRBG；`Sm4CtrDrbg` + `RandomSource` 已实现）。剩余为 §9.4 的**密码专项评审**（流程项，需人工评审签字）。**尚未接线**：Safekeeper 的 `wal_storage.rs` 仍写明文——格式原语已就位，接线点见 docs/16 §5.2.2。

## 6. 密钥封装（Key Envelope）

```text
wrapped_dek = SM4_wrap(kek, dek || dek_scope_digest)
dek_scope_digest = SM3(cluster_id || timeline_id || epoch || lsn_range)   # ADR-014 scope 绑定
```

- 对象携带 wrapped_dek → 读路径只需 KEK（组件租约内缓存），不依赖 KMS 在线；
- scope digest 使 wrapped_dek 无法被搬到另一 timeline/epoch 的对象里重放（对象层防回滚的补充，ADR-013）；
- Retire 销毁 DEK 后，旧对象即使密文完整也永久不可读（加密擦除，ADR-011 客体重用依据）。

## 7. 发布原子性与校验顺序

```text
写：payload chunks → metadata → sealed header → trailer 签名 → fsync → rename
读：magic/version 校验 → flags.sealed 必须为 1 → header_digest 自校验
    → chunk 验证（tag） → metadata TLV 解析 →（可选）trailer 验签
```

未 sealed 的对象一律拒绝（崩溃残留的 `.part` 由 GC 清理）。

## 8. 与 compaction / GC / rekey 的关系

- compaction 读旧对象（逐 chunk 验证解密）→ 生成新对象（新 object_id/base_nonce/epoch）→ 引用计数删除旧对象（实现方案 §4.5）；
- `jtdb rekey`（epoch 轮换的 Rekey 阶段，ADR-013）：批量"解密-重加密"为新 epoch 对象，断点续传以对象为粒度；
- GC 删除前校验 Timeline、PITR 保留点与 epoch 保留点（实现方案 §4.5），删除动作进审计。

## 9. 格式演进规则

1. 任何破坏性变更（字段增删、chunk 语义变化）必须 `format_version +1`；
2. 读者必须接受"当前版本 -1"的窗口，跨窗口由 rekey/compaction 在线迁移；
3. 未知 flags 位忽略；未知 metadata TLV 跳过（§3.2）；
4. **格式冻结前置条件**：SM4 模式与 nonce 方案经 docs/12 密码专项评审通过。

## 10. 测试标准

| 用例 | 通过标准 |
|---|---|
| 篡改 header 任一字节 | chunk 验证失败，拒绝服务并审计 |
| 篡改/交换/删除 chunk | tag 验证失败 |
| 截断尾部 | chunk_count 与实际不符 → 拒绝 |
| 重放旧 generation 对象 | manifest/防回滚计数检测（ADR-013） |
| wrapped_dek 搬移到其他对象 | scope digest 不匹配 → 拒绝 |
| 部分写/断电 | 无 sealed 对象不可见；`.part` 可清理 |
| 随机读性能 | 页读取 P99 增幅 ≤10%（规划 §5 SLO） |
| 64 KiB WAL 追加 | flush 粒度 < chunk 时缓冲正确、崩溃后对端重取 |

## 11. 待验证问题

1. SM4-GCM 与 SM4-CCM 的密评适用性对比（docs/12 §7.1 联动）；
2. chunk_size 64 KiB 的实测基准（读放大 vs 缓冲成本），SNAPSHOT/BACKUP 是否用 256 KiB；
3. TOAST 外部文件与 PG 关系文件是否统一采用本格式（倾向：统一，object_type 扩展）；
4. trailer 验签的性能代价与抽样验证策略（全验 vs 首次+审计触发）；
5. 远程对象存储的 multipart 上传与本格式 rename 语义的映射。
