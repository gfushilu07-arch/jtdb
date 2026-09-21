# ADR-016：WAL 活段加密的布局与集成面

| 项 | 值 |
|---|---|
| 日期 | 2026-09-21 |
| 状态 | 已确认（调研工业实践 + 学术/国标 + 源码核实；**推翻 docs/16 §5.10 的"页头必须明文"结论**） |
| 关联 | docs/04 §5.2（活段布局）、docs/16 §5.2.2/§5.10、ADR-007（全生命周期存储安全）、ADR-013（KMS 租约/轮换） |

## 1. 结论（先给答案）

1. **保持 `libs/jt-encrypted-object/src/live_wal.rs` 现有布局不变**：
   `[0..S) 偏移恒等密文 ‖ [S..S+T) 独立 tag 区 ‖ [S+T..) 尾部 header`，
   按 chunk 独立 AEAD（`LIVE_CHUNK_SIZE = 8192 = XLOG_BLCKSZ`，chunk 边界 = 页边界），
   尾块每次 flush 用新 nonce 重封。
   这是工业界一致做法（§2.1），**不需要改格式**。

2. **撤回 docs/16 §5.10 的"WAL 页头必须是明文"结论**。该结论基于错误的因果
   推断（§3.1）。真实约束集见 §3。

3. **集成面收敛为 5 个点**（§4），其中 3 个必须 **fail-closed** 而非静默降级。
   真正必须修的**代码**只有 1 处（`find_end_of_wal`），其余是守卫。

4. **不采用"页头明文 + 页体密文"布局**（方案 B/D），理由见 §5——它同时牺牲
   偏移恒等与分块对齐，且工业界无人这么做。

## 2. 调研证据

### 2.1 工业界：保留格式头明文 + 偏移恒等 + 长度保持是共同做法

| 系统 | 保留明文的部分 | 密文与明文同偏移 | 完整性 | 密码 |
|---|---|---|---|---|
| **SQL Server TDE** | 页头（8 KiB 页的 96 B） | 是（无填充、文件等长） | **无**（官方明说"不是密码学校验和"） | AES-128/192/256-CBC |
| **MySQL 8.0** `innodb_redo_log_encrypt` | 12 B log block header + 2 KiB 文件头 | 是（I/O 断言块对齐） | 无（校验和在密文内） | AES-256-CBC，固定 IV |
| **Percona pg_tde**（WAL） | **无——页头也加密** | 是（CTR keystream 按绝对文件位置索引） | 无 | AES-128/256-CTR |
| **Cybertec/Aasma FDE** | 无（整页 XTS 宽块） | 是 | 靠 `--data-checksums` | AES-128-XTS |
| **PG v3 TDE 补丁**（D. Christensen） | 页 LSN + 校验和 | 是（tag 塞进既有 `xl_crc` 字段） | WAL 用 GCM，tag 占 4 B | AES-XTS-128/256 |

关键引证：

- **SQL Server**（微软 TDE 白皮书，Sung Hsueh 2008）：
  > "When the database page file is written to disk, **the headers are not encrypted
  > with the rest of the data because this information is necessary for the page to
  > be reloaded**. ... This is not a cryptographic checksum; it detects only data
  > corruption ... and not data integrity."
  <https://learn.microsoft.com/en-us/previous-versions/sql/sql-server-2008/cc278098(v=sql.100)>

- **MySQL 8.0**（`storage/innobase/os/os0enc.cc`，`Encryption::encrypt_log_block`）
  是**最贴近本场景**的先例：把 12 B 块头逐字节原样拷出，只加密其余 500 B，
  且 2 KiB 文件头"Never use encryption in the header"。
  代码级证据（`LOG_BLOCK_HDR_SIZE = 12`）：
  ```c
  data_len = OS_FILE_LOG_BLOCK_SIZE - LOG_BLOCK_HDR_SIZE;        // 500
  main_len = (data_len / MY_AES_BLOCK_SIZE) * MY_AES_BLOCK_SIZE; // 496
  std::memcpy(dst_ptr, src_ptr, LOG_BLOCK_HDR_SIZE);             // 头原样拷贝
  my_aes_encrypt(src_ptr + LOG_BLOCK_HDR_SIZE, main_len, ...);   // 只加密体
  ```
  <https://raw.githubusercontent.com/mysql/mysql-server/8.0/storage/innobase/os/os0enc.cc>

- **pg_tde 是反面教材（我们的"金丝雀"）**：它加密一切（含页头），代价被它自己的
  文档逐条列出——pgBackRest 必须 `archive-header-check=n` + `checksum-page=n`，
  `pg_receivewal` **不可用**，`pg_verifybackup` 默认失败。
  <https://docs.percona.com/pg-tde/wal-encryption.html>

- **Percona 自己比较过"按页 vs 按记录"**，选了按记录：
  > `ctr_perrecord` — "**Only the record data is encrypted, headers stay plaintext**,
  > which slightly simplifies command-line tools."
  按页方案在更新密集场景损失约 20%。
  <https://www.postgresql.org/message-id/CAN4CZFN7bm+D1kDEYs=-WDNX=yatTNP=JDyPGfjWAKgeMT-TXQ@mail.gmail.com>

- **PG v3 TDE 补丁**：保留 page LSN 与校验和明文，使 `pg_checksums` 仍可离线校验；
  **GCM 被移除**，原因是"没有任何地方能放 AAD/tag 而不改页格式"。
  WAL 侧把 4 B tag 塞进既有 `xl_crc` 字段（`XL_AUTHTAG_SIZE 4`），从而不产生偏移位移。
  <https://www.postgresql.org/message-id/20231103023228.gz32vjx67jwzfh6h@alap3.anarazel.de>

- **PG 17/18 无内置 WAL/TDE 加密**；活跃的 SMGR I/O 变换钩子 RFC（2025-12）明确
  把 WAL 排除在外（"SMGR handles pages, but WAL has different characteristics"）。

**归纳（可迁移的三条）**：
1. 保留格式头明文是**常态**，不是妥协；加密页头的两个系统都为此付出了工具链代价。
2. **偏移恒等成立是因为密码长度保持**（CBC 无填充 / XTS 宽块 / CTR），无人位移字节。
3. **需要认证标签时，标签放进既有空间，绝不新增字段**——否则必须改格式。
   MySQL/SQL Server 干脆放弃认证；PG 补丁选择改格式（在页尾预留区）。

### 2.2 学术与标准：等长与完整性是硬取舍；且存在真实文献空白

- **NIST SP 800-38E**（XTS-AES，批准 IEEE 1619-2007）原文：
  > "The mode does not provide authentication of the data or its source."
  原因是 P1619 要求加密**不得扩张数据**，故任何"加认证标签"的方案被排除。
  XTS 的 tweak = **位置**（data unit 序号 + unit 内块序号），故密文等长且位置保持；
  data unit 上限 2^20 个 AES 块 = 16 MiB。
- **IEEE 1619.1** 的标题就是 *Authenticated Encryption **with Length Expansion** for
  Storage Devices*——"要认证就必须扩张"这一取舍的标准化体现。
  这与本 ADR 的结论一致：**认证标签必须落在数据区之外**（我们的独立 tag 区）。
- **wide-block 模式**（Halevi–Rogaway CMC, CRYPTO 2003；EME）把整个扇区当 mn-bit 串做
  一次可调置换，**可原地加密**且"Each ciphertext must have the same length as its
  plaintext"，并证明非可延展性。XTS 是窄块可调置换，**不认证**且允许块级剪切粘贴
  （Harnik 等，arXiv 2205.15545）。
- **WAL 加密的学术文献**：只有 Pei & Shmatikov **BigFoot**（arXiv 2111.09374）直接
  针对加密 WAL，但它解决的是**尺寸泄露**（用定长填充），**不涉及偏移保持或崩溃一致性**。
  经 Crossref/arXiv 检索，**没有任何专门研究 PostgreSQL WAL 加密的论文**；
  TDE 相关文献只有书籍，无同行评议论文讨论日志加密粒度。
- **崩溃一致性感知的认证加密**：以 "crash-consistent / torn-write / atomic /
  self-healing AEAD" 检索**无命中**——这是一个**真实的文献空白**。
  可迁移的工程推论（多份材料共同支持但无形式化）：**逐 unit 独立 tweak + 无跨 unit
  链接 + 无全局 tag ⇒ 尾部撕裂只损坏那一个 unit，早先数据仍可解**。
  这与"整条日志一个 AEAD"相反（后者一个撕裂尾部即令全日志无法验证）。
  本仓 `live_wal.rs` 正是前者：逐 chunk AEAD + tag 为提交点。
- 安全审计日志方向（Schneier–Kelsey 1999；Ma–Tsudik FssAgg）提供的是 append-only
  语义下的**前向安全认证**（密钥演化、顺序聚合），**只做认证不做加密**，
  不涉及偏移保持——对本场景的借鉴是"密钥演化"，不是布局。

### 2.3 国密合规：需修正两处常见误解

| 事项 | 核实结果 |
|---|---|
| **GM/T 0034-2014** | **不是** SM4 工作模式标准。其正式名称是《基于SM2密码算法的证书认证系统密码及其相关安全技术规范》 |
| **分组密码工作模式标准** | **GB/T 17964-2021**《信息安全技术 分组密码算法的工作模式》（2021-10-11 发布，2022-05-01 实施，代替 GB/T 17964-2008），含 9 种模式，修订说明含"增加了带密文挪用的 XEX 可调分组密码工作模式"（即 XTS 类） |
| **SM4 算法标准** | GB/T 32907-2016 / GM/T 0002-2012 |
| **SM4-XTS** | **无专门标准**；合规路径 = GB/T 17964-2021 的 XTS 模式（算法无关）+ GB/T 32907-2016 的 SM4 |
| **SM4-GCM** | 规范依据是 **RFC 8998**（`AEAD_SM4_GCM`、`TLS_SM4_GCM_SM3`），**不是** GB/T 38636-2020——后者是 TLCP，套件为 **SM4-CBC-SM3**（`0xE0,0x13`/`0xE0,0x11`） |
| **认证加密机制标准** | **GB/T 36624-2018**《信息技术 安全技术 可鉴别的加密机制》 |
| **密评基线** | **GB/T 39786-2021**《信息安全技术 信息系统密码应用基本要求》（取代 GM/T 0054-2018），应用和数据安全层含"数据存储机密性/完整性"；配套 **GM/T 0115-2021** 测评要求（从算法/技术/产品/服务/密钥管理五方面） |
| **EtM vs AEAD** | **未找到强制要求 SM4+SM3-HMAC 优先于 AEAD 的一手条款**。EtM 是国密工程实践主流形态，GB/T 36624-2018 提供 AE 路径，两者均可用 |

**对本设计的含义**：GB/T 39786 要求的是**存储机密性 + 完整性**，
故"等长但无认证"的 XTS 路线（SQL Server / MySQL 的做法）**不足以**满足密评；
必须用 AEAD（本仓用 SM4-GCM，依据 RFC 8998）。而 AEAD 必然扩张，
扩张部分即我们的独立 tag 区——这正是 IEEE 1619.1 所标准化的形态。

> 未能核实项（不得作为事实引用）：GB/T 17964-2021 的权威完整九模式清单及 GCM 是否在内；
> GB/T 36624-2018 收录的具体 AE 方案；GB/T 39786-2021 数据存储机密性条款的逐字原文
> 与等级适用表（来自二手来源）；是否存在强制 EtM 优先的一手要求。

## 3. 源码核实：推翻 docs/16 §5.10 的结论

### 3.1 被推翻的结论

docs/16 §5.10 曾写：

> **结论：WAL 页头（段首长头 + 每页短头）必须是明文**，不能纳入加密 chunk。
> 这不是可绕过的实现细节——`write_wal` 的输入要过 `WalStreamDecoder`，解码器在
> 每个页边界都要求合法明文页头。

**这两句都不成立**（除"解码器要求合法页头"本身为真，但它是对**明文流**的要求）。

### 3.2 事实 1：`write_wal` 的解码器按构造只见**网络明文**，不见文件字节

```text
safekeeper.rs:1354   self.wal_store.write_wal(msg.h.begin_lsn, &msg.wal_data)
                       └─ msg.wal_data 来自 walproposer 的 AppendRequest（网络）
wal_storage.rs:568   let write_seconds = time_io_closure(self.write_exact(startpos, buf)).await?;
wal_storage.rs:585   self.decoder.feed_bytes(buf);      // ← 同一个 buf（明文）
wal_storage.rs:591   while let Some((lsn, _rec)) = self.decoder.poll_decode()? {
```

解码器消费的是**入参 `buf`**（网络明文），写盘是**另一次调用**（`write_exact`）。
两者无数据依赖。故 `validate_page_header` 的约束对象是"**喂给解码器的流**"，
**不是"文件布局"**。加密 chunk 内部长什么样，`write_wal` 无从得知。

### 3.3 事实 2：唯一"文件字节 → 明文解码器"的消费者是 `find_end_of_wal`

全仓检索 `WalStreamDecoder::new` / `feed_bytes` 的调用点（排除测试）：

| 位置 | 喂给解码器的数据 | 是否受加密影响 |
|---|---|---|
| `wal_storage.rs:585`（`write_wal`） | 网络明文 `buf` | **否**（§3.2） |
| `send_interpreted_wal.rs:423` | `StreamingWalReader` 的输出 → 经 `WalReader`，**已解密** | 否 |
| `xlog_utils.rs:240`（`find_end_of_wal`） | **`segment.read(&mut buf)` 的原始文件字节** | **是** ← 唯一 |

而 `find_end_of_wal` 只在**启动时调用一次**
（`wal_storage.rs:218`，`PhysicalStorage::new_with_encryption`）。

### 3.3.1 先前那条错误**不是**加密的证据（按代码结构可判定）

docs/16 §5.10 把下列实测错误当作"页头必须明文"的证据：

```text
write_wal: invalid xlog page header: xlp_magic=17747, expected 53528 at 0/2000
```

该推断**不成立**，理由是 `WalDecodeError` 的**传播路径只有两条**，且**两条都在明文上**：

| 传播点 | 喂给解码器的数据 | 出错时行为 |
|---|---|---|
| `wal_storage.rs:591`（`write_wal`） | 网络明文 `buf` | `?` 向上传播为 `Err` |
| `send_interpreted_wal.rs:431` | 经 `WalReader` **已解密**的数据 | `?` 向上传播为 `Err` |
| `xlog_utils.rs:240`（`find_end_of_wal`） | **原始文件字节** | **吞掉**：`debug!` 后 `return Ok(result)` |

即：**唯一读原始文件字节的那个消费者根本不会抛出这个错误**（它把解码失败
当作"WAL 到此为止"）。故该错误必然来自一个**消费明文**的解码器。

推论（重要）：**该错误反映的是"明文流在解码器所处位置没有合法页头"**，
而不是"文件里的页头被加密了"。`at 0/2000`（段内偏移 8192 = 页边界）说明解码器
当时正期待一个**短页头**；失败说明**明文流本身**在那个位置不对齐。
这与当时被改动的 `truncate_wal` 把 `write_lsn` 置到与 walproposer 恢复点不匹配的
位置相符——**是接线改动的缺陷，不是格式约束**。

> 注：错误前缀 `write_wal:` 在当前代码中不存在（全仓无该 context/span 字符串），
> 来自当时已回退的诊断代码；`at 0/2000` 后缀由
> `WalDecodeError` 的 `#[error("{msg} at {lsn}")]`（`lib.rs:385`）生成。

**结论**：§5.10 由该错误推出的"页头必须明文"**应作废**。实现时仍需复现确认
明文流的对齐要求（见 §7 未决项 3），但**不得**再以该错误为格式依据。

### 3.4 事实 3：真正硬约束不是页头，而是**认证必然扩张**

`live_wal` 布局的数据区 `[0..S)` **与明文 1:1 同偏移**（tag 与 header 都在 S 之后），
故 LSN↔偏移恒等在**数据区**完全成立，`WalReader` 的按任意 `xlogoff` seek 读不受影响。

真正被破坏的是**"段文件长度 == wal_seg_size"**这一隐含假设。全仓检索
"读原始段文件"的位置：

| 位置 | 行为 | 加密下的后果 |
|---|---|---|
| `find_end_of_wal` | 逐字节读文件喂明文解码器 | 解出乱码 → 返回 `start_lsn`（**静默**丢掉 commit_lsn 之后的 WAL） |
| `wal_backup::backup_single_segment` | 按 `seg.size()` = **wal_seg_size** 上传前 N 字节 | 只上传密文数据区，**丢掉 tag 区与 header** → 归档**不可解** |
| `wal_backup_partial::upload_segment` | 同上（按 flush_lsn 偏移） | 同上 |
| `copy_timeline::write_segment` | 经 `WalReader`（**已解密**）读、写**明文**到目标 | **静默降级**：时间线拷贝产物是明文 |
| `pull_timeline` | `ar.append_file` 原始字节进快照 tar | 快照内是加密段，需密钥才能读 |
| `debug_dump` / `WalReader` / `send_wal` | 经 `WalReader`（解密） | 否 |

**这五处才是集成面**，不是"整个 `WalReader` 要改"。

### 3.5 附带发现：`LIVE_CHUNK_SIZE == XLOG_BLCKSZ == 8192`

chunk 边界与页边界**重合**。故"按页解密"与"按 chunk 解密"粒度一致，
`find_end_of_wal` 的页级读取可 1:1 映射到 chunk，**无需处理跨页 chunk**。

## 4. 决策：集成面清单

| # | 位置 | 处置 | 类型 |
|---|---|---|---|
| 1 | `find_end_of_wal` | 加**加密感知**变体：按页读 → 解密 → 喂解码器 | **必修** |
| 2 | `open_or_create` / `initialize_first_segment` | `open_existing` 恢复写位置；`initialize_first_segment` **保留文件句柄**（现有缺陷：写完 16 MiB 后丢弃句柄） | **必修** |
| 3 | `truncate_wal` | 布局感知：`reset_to(chunk 边界)` 回退 + 重封该 chunk（新 nonce） | **必修**（libs 侧已实现+测试） |
| 4 | `wal_backup::*` 上传 | 加密段**拒绝上传**（fail-closed），待归档路径按对象格式接线 | **守卫** |
| 5 | `copy_timeline::write_segment` | 源为加密段时**拒绝**（fail-closed），避免静默产出明文副本 | **守卫** |
| 6 | `pull_timeline` | 快照内含加密段 → 在快照元数据标记，或拒绝 | **守卫**（待定） |

**第 1 项的形态**（关键）：`find_end_of_wal` 在 `libs/postgres_ffi`，不认识
`jt-encrypted-object`。故**不改它**，而在 safekeeper 侧新增
`wal_encryption::find_end_of_wal_enc()`：同一循环（按页读、`feed_bytes`、`poll_decode`、
出错返回 `result`），但每页先经 `read_encrypted_at` 解密。明文段走原函数——
由 `is_encrypted_segment`（读文件尾 header 的 magic）判定，与 `WalReader` 现有
"按**文件格式**而非配置判定"的口径一致。

## 5. 被否决的方案

| 方案 | 否决理由 |
|---|---|
| **A. 仅段首长头明文，其余全密文** | 后续页边界短页头仍在密文里；且不解决 §3.4 的扩张问题 |
| **B/D. 页头明文 + 页体密文**（每页 24 B 明文头 + 8168 B 密文） | **同时**牺牲偏移恒等（每页错开 24 B，LSN 算术不再映射到文件偏移）与分块对齐（8168 非 2 的幂）；工业界无人采用（§2.1）；且 24 B 明文头本身不认证，比现状更弱 |
| **C. 段首 8 KiB 明文透传（同 Layer 的 ENC_START）** | 只解决段首，后续页边界仍失败；且段头**本就会被真实流覆盖**（`walproposer.c:1392`："Safekeepers don't skip header as they need continuous stream of data"） |
| **E. 改用 SM4-XTS（等长无扩张，偏移天然保持）** | 密评要求**存储完整性**（GB/T 39786-2021），XTS 明确不认证（NIST SP 800-38E）；SQL Server/MySQL 的"等长但无认证"路线在密评下不合格 |
| **F. 整段单一 AEAD** | 破坏 (b) "每个 flush 边界可独立认证"（flush_lsn 落在段中）；且一个撕裂尾部令全段不可验证（§2.2 文献空白处） |

## 6. 后果

**正面**：
- 格式**零改动**（`live_wal.rs` 15/15 保持绿），`wal.rs` 对象格式 16/16 保持绿；
- 集成面从"整个读路径"收敛为 6 个点，其中真正改代码的只有 3 个；
- 与工业界（MySQL/SQL Server/PG 补丁）与国密要求（AEAD + 独立 tag 区）双向一致；
- `find_end_of_wal` 的加密感知变体不触碰 `postgres_ffi`（`pgv` 版本分发的复杂度不外溢）。

**代价 / 遗留**：
- **Safekeeper WAL 目录内的段文件不再能被 `pg_waldump` 直接读取**（页头在密文内）。
  这是 pg_tde 同款代价，需在文档与运维手册中明示；compute 侧与 base backup 不受影响。
- **归档路径（S3 / 快照）在接线前必须 fail-closed**，否则会产出不可解归档（§3.4）。
  归档的正式形态已由 docs/04 §5.1 决定（对象格式 + trailer 签名），本 ADR 不改它，
  仅要求"未接线前拒绝"。
- `copy_timeline` 的"解密→写明文"是**保密性静默降级**，必须拒绝而非放行。

## 7. 未决项

1. 归档路径接线时，S3 对象的**远端随机读**（tag 区按 chunk O(1) 定位）需 range request；
   当前 `read_encrypted_at` 基于 `File` seek，远端需另实现。
2. `pull_timeline` 快照的处置（标记 vs 拒绝）待与恢复流程一并决定。
3. §3.3.1 所述 `xlp_magic=17747` 错误的确切成因需在实现时复现确认
   （已判定**不是**加密所致，但需确认是截断位置还是别的对齐问题）。
