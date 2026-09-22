# JTDB 实现状态与差距清单

| 项 | 值 |
|---|---|
| 项目代号 | 金湯 JTDB（暂定） |
| 承接文档 | docs/00 §6 实施路线与判定条件、docs/02 §11 文档落地清单 |
| 文档版本 | v1.0 |
| 日期 | 2026-09-20 |
| 状态 | 进度台账；**每轮开发后更新** |
| 编号说明 | 本号（16）为状态文档；03、06~11 保留给 docs/02 §11 的未来设计文档，不占用 |

## 1. 目的与方法

本文回答一个问题：**规格写了什么、代码做到哪里、还差什么**。

方法（必须遵守，否则本文会退化成"凭印象的清单"）：

1. **只记录可验证的结论**——每条"未实现"必须给出"全仓 grep 零命中"或"文件路径 + 行号"作为证据；
2. **区分三种状态**，不混为一谈：
   - **已实现**：有代码且有测试（最好有运行时验证）；
   - **部分实现**：核心路径有，但规格中的某些子项缺失——必须列出缺哪些；
   - **未实现**：零代码，或仅有占位目录；
3. **不把"规格空白"当作"实现空白"**：docs/02 §11 中尚未起草的设计文档（03、06~11）属规格缺口，单独归类；
4. 状态变更以 `docs/adr/ADR-015-PG版本策略.md` 的执行记录为准（该表是实际进度台账），本文是其汇总视图。

## 2. 总体位置

按 docs/00 §6 的六阶段判定条件：

| 阶段 | 判定条件 | 状态 | 缺口 |
|---|---|---|---|
| 0 架构冻结 | 四份 ADR 签字、对象格式文档冻结、SLO 表定稿 | **部分完成** | ADR-011~014 已成文；**对象格式未获准冻结**（docs/04 §9.4 前置条件"密码专项评审"未闭环，且 nonce 方案与规格不一致，见 §5.2）；SLO 正式数字仍待规格机 |
| 1 可运行基座 | 两平台 CI 绿线；`jtdb dev start --embedded` 可用 | **部分完成** | PG18 全链路在 macOS + Linux（基础2）跑通，版本矩阵 v14~v18 冒烟+功能套件全绿；**`jtdb` CLI 不存在**；**无 CI 配置** |
| 2 安全内核第一层 | 逃逸路径清单清零；对象级 MAC 回归 + SLO 达标 | **接近完成** | 安全上下文/三权分立/超管围栏/表级 MAC/统一错误码/E2 审计事件已落地，58 项运行时断言全绿；**逃逸清单未清零**（dblink、PL/Python、调试路径）；**对象级 MAC SLO 未测**；网关 TLCP 未实现 |
| 3 存储安全与 KMS | 轮换中断注入、KMS 断网、防回滚重放测试全绿 | **部分完成** | Layer 加密 + KMS 租约/轮换/防回滚已实现并有单测；**WAL 加密未实现**；**BranchKeyGrant 未实现**；行级标记存储未开始；三项端到端注入测试未见 |
| 4 MLS 全量与合规 | 等保四级控制项自查通过；行级 SLO 达标 | **未开始** | 行级标记、谓词下推、客体重用、逻辑复制过滤、密评自查、证据包原型全部未实现 |
| 5 产品化 | 一条命令初始化/备份/恢复演练达标 | **未开始** | CLI/控制台/敏感数据发现/动态脱敏/轻量 HA/迁移工具全部未实现 |

**一句话**：安全内核（阶段 2）是全项目最成熟的工作域，也是唯一做到运行时验证的；但它在产品整体中占比不大，存储加密（WAL）、接入平面（TLCP/wire）、身份引导（CA/enrollment）、产品化（CLI/部署）四个工作域加起来远大于内核本身。

## 3. 工作域完成度（docs/02 §10）

| 工作域 | 状态 | 说明 |
|---|---|---|
| 上游基线 | **已实现** | release-9129 固化 + PG18 fork + 补丁治理（`postgres/jtdb-patches/0001-*.patch`，3253 行，pristine 基线可 apply 且逐文件比对一致）+ 版本矩阵 5/5 |
| Compute 适配 | **部分** | 安全上下文（表级）+ MAC 钩子（读/写/COPY/TRUNCATE/DDL）+ 逃逸围栏 + 统一错误码 + E2 事件 + **逻辑复制过滤（表级，§5.11）**；缺行级、谓词注入、函数触发器（经 SPI 已覆盖） |
| Rust 存储 | **部分** | 加密对象 v1 + key epoch + **Layer 加密**（pageserver，270/270 nextest）；缺 WAL 加密、Safekeeper 加密、compaction/GC、rekey |
| 控制平面 | **部分** | jt-controller / jt-pdp / jt-kms / jt-attest 四服务（共 86 项测试）；**jt-identity 完全缺失**；jt-pdp 无服务面 |
| 审计平面 | **部分** | proto / ingest / store / tsa 四层闭环（25 项测试）；缺远程见证、离线校验器、多源实际接入、留存容量模型、查询接口 |
| 接入平面 | **未实现** | jt-gateway 仅连接池逻辑层（17 项测试）；TLCP / PG wire / SQL 防火墙 / 事务级驱动 / 内核复位例程全缺 |
| 开发体验 | **未实现** | CLI / 分支脱敏 / 迁移 / 策略即代码 / 诊断全缺 |
| 生态治理 | **未实现** | 扩展签名 / SBOM / 白名单 / 兼容矩阵全缺 |
| 交付工程 | **未实现** | `deployment/`、`packaging/` 空 |
| 合规与证据 | **未实现** | `compliance/` 空 |
| 身份与引导 | **未实现** | enrollment / CA / CRL / 三权引导全缺 |

## 4. 已实现清单（有代码 + 有测试）

| 组件 | 位置 | 测试 | 说明 |
|---|---|---|---|
| 密码抽象层 | `libs/jt-crypto-api` | — | Aead / Digest256 / SelfTest / Signature 四 trait + 上电自检 |
| 纯 Rust 密码后端 | `libs/jt-crypto-sm` | KAT | SM4-GCM（RFC 8998 向量）/ SM3 / SM2 签名 |
| 铜锁后端 | `libs/jt-crypto-tongsuo` | KAT + 双后端交叉一致 | 密评主路径；**实测链接的是 Homebrew OpenSSL 3 而非认证 Tongsuo 构建树** |
| 加密对象 v1 | `libs/jt-encrypted-object` | 11 项矩阵 | header 130B 自校验 + chunk AEAD + trailer 签名；**格式未获准冻结**（见 §5.2） |
| Key epoch | `libs/jt-key-epoch` | 含 TLA+ 骨架 | 租约 + 轮换状态机 + 防回滚计数器 |
| 共享标签类型 | `libs/jt-common` | 14 | MLS 标签语义单一来源（与 C 侧位序逐项一致） |
| 接口协议 | `libs/jt-storage-protocol` | 51 | 规范编码 + 信封校验序 + 防重放 + KMS/Audit 字段级规格 |
| 安全内核 | `pg jtsec/`（patch） | **58 项运行时** | 表级 MAC（读/写/COPY/TRUNCATE/DDL）+ 三权分立 + 超管围栏 + 逃逸围栏 + JT001-JT004 + E2 事件 |
| Layer 加密 | `pageserver/storage_encryption.rs` | 270/270 nextest | 密文原名 + 内容识别 + 三后端选择 |
| jt-kms | `services/jt-kms` | 23 + HTTP 7 步 | 密钥层级 + SM4-GCM 信封 + 租约 + 轮换 + Shamir RK 分片 + hash 链审计 |
| jt-controller | `services/jt-controller` | 33 + 冒烟 8 | 注册/心跳/生命周期/generation 围栏（write-ahead fsync）/配置租约 |
| jt-pdp | `services/jt-pdp` | 18 | Cedar 风格 permit/forbid/默认拒绝 + MLS 集成 + Policy Lease |
| jt-attest | `services/jt-attest` | 12 | 证据模型 + 五步校验链 + KMS 密钥释放门槛 |
| jt-gateway | `services/jt-gateway` | 17 | 主体亲和池 + 复位/pin 决策 + 代际化失效传播 |
| 审计四层 | `services/jt-audit-{proto,ingest,store,tsa}` | 25 | E0-E3 分级 + hash 链 + WORM + SM2 checkpoint + TSA |

## 5. 未实现清单（按工作域）

### 5.1 安全内核剩余（阶段 2/4）

| # | 缺口 | 作用 | 证据 |
|---|---|---|---|
| K1 | **行级标记存储** | MLS 核心能力：同一张表内不同行可有不同密级（对标达梦安全版、密评必备）。需 heap 元组隐藏属性 `jt_label oid` + TOAST/索引/pg_upgrade 语义 | 全仓 grep `jt_row_label` / `ENABLE ROW LEVEL LABEL` 零命中 |
| K2 | 计划期标签谓词注入 | 行级的前提；现为执行器入口表级粗筛，无谓词下推/索引利用 | `jtsec/` 无 `planner_hook`/`set_rel_pathlist` |
| K3 | `pg_jt_label`/`pg_jt_object_label` 目录表 | 带 `policy_version` / SM3 `digest`（复制端到端校验）/ `created_by`；现借 `pg_seclabel` | 全仓 grep `pg_jt` 零命中；ADR-015 裁决"两表方案延后" |
| K4 | 标签缓存与 sinval 失效（§6.3） | 现每语句实时查 `pg_seclabel`，无缓存；prepared plan 会复用旧标签 | `jtsec/` 无 `sinval`/`CacheInvalidate` |
| K6 | 函数/触发器内写、FDW 写、约束检查、备份恢复导出 | §6.2 清单剩余执行点 | 函数/触发器经 SPI 已覆盖；FDW 写与备份导出无检查 |
| K7 | §3.5 逃逸清单剩余 | `dblink`、PL/Python 等非受控语言、调试与断言路径 | 已拦：COPY/大对象/file_fdw；其余未拦 |
| K8 | §3.3 默认与继承 | CREATE TABLE 继承 schema/库默认标签；`jt_relabel_table()` 受控重标 | 无继承链、无重标工具 |
| K9 | §7 与 RLS 组合 | 标签检查与行级安全策略的 AND 语义、注册顺序 | `jtsec/` 无 `rowsecurity` |
| K10 | §3.4 达梦语义兼容 | 等级/范围/组三元组映射、按表 `ENABLE_MAC`、`jt_migrate_from_dameng` | 无 |
| K11 | 可信降标完整语义 | 降标 >1 档的双人复核 + E3 审计 | `write_label` 机制有，复核流程无 |

### 5.2 存储与密钥（阶段 3）

| # | 缺口 | 作用 | 证据 |
|---|---|---|---|
| S1 | **WAL 加密**（读写路径 + 装配均已接通） | 只加密 Layer 而 WAL 明文 = 加密承诺残缺：写前日志含全部数据变更 | **libs**：`wal.rs`（16/16）+ `live_wal.rs`（15/15）+ `kms_provider.rs`（租约驱动 DEK 供给，33/33 含 10 项新测试）。**Safekeeper 三处已接通**：写路径（WalFile 形态分派）、读路径（WalReader 解密分支 + 按格式判定）、装配（CLI 开关 + 租约 provider 注入 + flush 时序修正）。**33/33 绿**，含「落盘不含明文」判据。**剩余**见 §5.2.2 |
| S2 | ~~nonce 方案~~ **已闭环** | `base_nonce` 改为**每对象随机取自 DRBG**（符合 docs/04 §3.1 / docs/12 §4.4）；`Sm4CtrDrbg` 已实现（`libs/jt-crypto-sm/src/drbg.rs`，10/10）+ `RandomSource` trait（`jt-crypto-api`）。**格式向后兼容**（nonce 本就在 header offset 86..98，读取端从 header 取值），已落盘对象无需重加密。**剩余**：docs/04 §9.4 的"密码专项评审"仍属流程项（需人工评审签字），非代码项 | 见 ADR-015（四十六） |
| S4 | DRBG 与随机数治理 | TCM DRBG > 密码卡/HSM > OS CSPRNG 分级 + `rng_source` 标记 + 软件回退时 KMS 拒发新 DEK | **部分实现**：`Sm4CtrDrbg`（CTR_DRBG + KAT + 连续性 + 重播种周期，10/10）+ `RngSource` 三级枚举 + `is_degraded()`。**缺**：TCM/HSM 硬件源接入、KMS 侧"降级拒发新 DEK"联动 |
| S3 | **BranchKeyGrant** | ADR-014 分支授权：分支只能解密到分支点、epoch ≤ max_epoch | `services/jt-kms` grep 零命中（协议层 `libs/jt-storage-protocol` 已实现 `authorizes()`） |
| S5 | compaction/GC 与 `jtdb rekey` | 重加密时新旧对象并存、引用计数删除 | 无 |
| S6 | 签名 Manifest | §4.7 对象清单签名（防回滚计数器已有） | 无 |
| S7 | 对象 nonce 重放/搬移测试 | 重放旧 generation 对象、`wrapped_dek` 搬移到其他对象 | 矩阵 11 项未覆盖 |

#### 5.2.1 WAL 加密的架构裁决（实现期确认，重要）

docs/04 §5 把 WAL 段对象描述为"追加式、64 KiB chunk 攒满即加密追加"。把它直接套在 **Safekeeper 活段文件**上会与既有架构冲突，实测确认两点：

1. **偏移恒等**：Safekeeper 活段预分配（`set_len(wal_seg_size)`）后按任意 `xlogoff` 写（`wal_storage.rs::write_in_segment` 会 seek），且对端按任意偏移并发读（`WalReader::open_segment` seek 到 `xlogoff`）。在偏移 0 放 130B 头会**移动全部 WAL 数据**，破坏 LSN↔偏移恒等——这是复制与恢复的基础。
2. **flush 驱动**：Safekeeper 的持久性契约是"收到即 flush 并通告 `flush_lsn`"，且对端会流式读**未写完的 `.partial` 段**（`open_wal_file` 优先打开 `.partial`）。64 KiB chunk 在攒满前无法封块、也就无法 flush，直接破坏提交延迟。

**结论**：docs/04 §5 的对象模型对应**已完成、不可变的段**（docs/04 §2 原则"对象不可变"）——即**归档/卸载路径**（S3 上传、base backup、归档恢复），与 docs/02 §4.4 把"归档恢复、base backup"列入覆盖一致。本仓已实现该路径原语（`seal_wal_segment`/`unseal_wal_segment`）。

**活段文件加密是另一条路径**，需单独设计：要求页级/记录级加密（或对 WAL 页做独立 AEAD），且必须满足 (a) 密文与明文同偏移（保持 LSN↔偏移恒等）、(b) 每个 flush 边界可独立认证、(c) 对端能流式解密未写完的段。

> **本节已由 [`ADR-016`](adr/ADR-016-WAL活段加密布局与集成面.md) 取代**（2026-09-21 定案）。
> ADR-016 经工业实践（SQL Server / MySQL / PG v3 补丁 / pg_tde）+ 国密合规
> （GB/T 39786-2021 要求存储完整性 ⇒ 必须 AEAD，XTS 不合格）+ 源码核实后裁定：
> **格式零改动**，上述 (a)(b)(c) 三条现有 `live_wal` 布局**全部满足**；
> 真正的约束是"段文件长度 == wal_seg_size"被认证扩张破坏，集成面收敛为 6 点。

#### 5.2.2 活段 WAL 加密：接线状态

**已完成（写路径）**（子模块提交 `556e54c`，33/33 绿）：

- `safekeeper/src/wal_encryption.rs`：`WalEncCtx`（DEK 来源 + 布局 + 绑定字段）、`WalFile` 枚举（`Plain(File)` / `Enc(LiveWalWriter)`，让 `PhysicalStorage` 无需感知形态差异）、读取入口（`read_encrypted_at` / `read_segment_meta` / `is_encrypted_segment` 按文件头自动识别，支持迁移期混存）、进程级 DRBG 启动健康检测（fail-closed）。
- `PhysicalStorage`：`file` 字段 `File` → `WalFile`；`new()` 保留为包装（传 `None`），**既有调用方零改动**；新增 `new_with_encryption()`；`open_or_create` 分派（加密形态预分配完整布局；既有**明文段在加密启用时拒绝续写**，避免格式混用）；`write_in_segment` 经 `WalFile` 分派，加密形态 `flush()` 会封装尾块使对端可读；加密段 `set_len` 拒绝（布局长度固定）。
- **关键判据已测**：`encrypted_wal_file_does_not_contain_plaintext` —— 同一内容明文模式可直接看到、加密模式落盘字节不含明文且能解回。
- **顺序性前提已核实**：`LiveWalWriter` 要求严格顺序追加，而 `safekeeper.rs` 的 append 处理与 `wal_storage.rs::write_wal` 都显式 `bail!` 拒绝重写与 gap，故无需为「重写既有偏移」设计。

**已完成（集成面 6 点，2026-09-21，ADR-016 §4）**（子模块提交 `cbc116d`，safekeeper --lib 37/37 绿）：

- **必修 1：`find_end_of_wal` 加密感知变体**（`wal_encryption::find_end_of_wal_enc`）——上游明文版是全仓唯一"原始文件字节 → 明文解码器"的消费者，在加密段上把密文当页头解析且**吞掉错误**（`xlog_utils.rs:280` `debug!` 后 `return Ok(result)`），表现为静默返回 `commit_lsn`（"之后的 WAL 全部当作不存在"）。新变体与上游逐行同构，仅每页先解密；启动路径按**文件格式**分派（与 `WalReader` 口径一致，不依赖配置）。**不修改上游函数**：它在 `libs/postgres_ffi` 经 `pgv` 宏按版本分发，引入 `jt-encrypted-object` 依赖会把版本分发复杂度外溢。
- **必修 2：续写恢复写位置** —— `open_or_create_encrypted` 原用 `create_writer` 续写，而 `create` 会 `File::create` 截断重建、丢掉已封装 chunk 与 header。改用 `open_existing_writer`（从 tag 区反推位置）+ **epoch/generation 一致性校验**（不一致即拒绝：轮换边界，旧段只读，避免用错 DEK 或写出 AAD 不一致的 chunk）。`initialize_first_segment` 加密形态先 `reset_to(0)` 恢复上游的幂等语义。
- **必修 3：`truncate_wal` 布局感知** —— 加密形态不能用 `set_len`（布局长度固定），改用 `reset_to(xlogoff)`：把含 `xlogoff` 的 chunk 用**新 nonce 重封**为 `xlogoff % chunk_size` 并清空其后 tag ⇒ 可读区间恰为 `[0, xlogoff)`。`xlogoff` **不必 chunk 对齐**（截断点是记录对齐）。加密形态保留句柄供紧随的 `write_wal` 续写；明文形态保持上游行为（丢弃句柄）逐字节不变。
- **守卫 4：S3 上传拒绝加密段**（`wal_backup::backup_single_segment` + `wal_backup_partial::upload_segment`）——加密活段布局是「数据区 ‖ tag 区 ‖ header」，而上传按 `seg.size() = wal_seg_size` 只传前 S 字节 ⇒ **丢掉 tag 区与 header**，产物既非明文 WAL 也无法解密，归档**静默损坏**且要等恢复时才发现。
- **守卫 5：`copy_timeline` 拒绝加密源** —— 该路径经 `WalReader` 读（已解密）再把明文写进目标段 ⇒ 目标以**明文**存有源的全部 WAL，是**静默的保密性降级**。判断在读之前做（一旦开始拷贝就已写出明文）。
- **守卫 6：`WalReader` 加密段无 ctx 时 fail-closed** —— 原实现把整段逻辑放在 `if self.enc.is_some()` 内，于是"文件是加密的、但本进程没有加密上下文"（配置漂移、拉取/恢复来的时间线、CLI 漏传）会**落到明文路径**，把密文当明文 WAL 发给 compute。改为先探格式：加密则必须有 ctx。

**libs 侧配套**（`jt-encrypted-object`，55/55，+8 项测试）：`LiveWalWriter::open_existing`（恢复写位置；用"第一段连续已写区间"而非"最后一个已写 chunk"——后者在 `reset_to` 中途崩溃留下空洞时会取到不可信区间；尾块明文**解密恢复**而非丢弃）、`LiveWalWriter::reset_to`（**任意偏移**；重封含截断点的 chunk 使可读区间恰为 `[0, offset)`——只清 tag 不够，旧尾部仍可读则截断失去意义；`offset > written` 时补零对齐上游 `set_len` 语义）、`create()` 改读写打开（原 `File::create` 只写，`reset_to` 读回密文报 "Bad file descriptor"）、`tail_buf` 改 `Zeroizing`（持有未加密 WAL 明文）。

**实现期发现并修正的两处缺陷**：① 整段仅 1 个 chunk 且写了部分长度时，"无未写条目"被误判为"段写满"（`durable_len` 报 `seg_size` 而非真实值）——由新增集成测试 `open_existing_writer_continues_without_truncating` 抓出；② `walproposer_sim` 测试装置缺 `wal_encryption` 字段（**基线即编译失败**）。

**真实 SafeKeeper 全生命周期端到端验证已完成**（2026-09-21，`wal_encryption::e2e_tests`，`--lib` **41/41 绿**）：

- `encrypted_safekeeper_full_lifecycle`：Elected → truncate → append 真实记录 → 断言段文件是**加密布局**（末尾 130B 以 `JTENCOBJ` 开头）且**数据区不含明文写入内容**（直接字节比对，比 grep 特征串更强）。这条路径正是"活段加密与就地覆盖语义冲突"的发生地（§5.10）。
- `encrypted_safekeeper_restart_and_continue`：写入若干**合法 WAL 记录**（`WalGenerator` 产出）→ 用**加载路径**重建 → 断言写位置从磁盘恢复 → 重发 Elected → 继续 append 成功。实测 `before restart: write_lsn=0/1320` / `after restart: write_lsn=0/1320`，即 `find_end_of_wal_enc` 确实从加密段里定位到了 WAL 末尾。
- **关键装置要求**：必须用 `restore_safekeeper_with_encryption`（`FileStorage::restore_new` 加载）而非 `create_new`——后者的 `commit_lsn == 0` 会让 `PhysicalStorage` 直接返回 `Lsn(0)`、**根本不读段文件**，测试会"重启成功"但从未验证恢复逻辑（第一版即如此，实测 `write_lsn` 停在 `start_lsn` 才发现）。
- 三处装置陷阱（已记录在提交信息）：起点 LSN 必须页对齐（`generate_wal_segment` 断言 `seg_off >= 40`）；重启后必须重发 Elected；`start_streaming_at` 与 term_history 末项必须一致（否则触发 "attempt to truncate committed data" 保护）——后者恰好证明恢复出的写位置被真正使用。

**已在基础2 真实 Linux x86_64 上跑通**（2026-09-21）：交叉编译 `--lib` 测试目标（`cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.28 -p safekeeper --no-default-features --lib`），传输后在真机执行——**41/41 全绿**（含上述两组 e2e）。这是目前最强的验证：真实 `SafeKeeper` + `PhysicalStorage` 的加密写入与恢复路径，跑在真实生产平台上（非 mock、非模拟）。
- 为何用 `--lib` 而非全量：`tests/*.rs` 会链 `walproposer_sim`（引用 walproposer 符号），而 `build/walproposer-lib/libwalproposer.a` 是**交叉构建残留**（Linux aarch64），macOS 与 x86_64 交叉构建都无法链接；`--lib` 不引用那些符号，故可用。加密路径本身与平台无关。

**剩余（一项）**：

1. **neon_local 全链路验证未做**（真实 KMS + compute + pageserver 全链路，**release 构建**，见 §5.9 OOM 教训）。上面已验证"加密写入 + 恢复"的真实代码路径，但未覆盖**跨组件装配**（neon_local 转发 `--safekeeper-extra-opt`、storcon 建 timeline、compute 经 pageserver 读回）。
   - 分阶段脚本已备：`scripts/wal-enc-staged-b2.sh`（只起 KMS + storcon + broker + safekeeper，不起 pageserver/compute，以适配基础2 的 3GB 可用内存）。
   - **未跑的原因（诚实记录）**：基础2 可用内存 3087MB（业务容器占 4GB），全链路脚本的 3000MB 阈值刚好卡在边界；上一轮全链路已导致整机 OOM（§5.9）。故本轮选择"在真机跑真实代码路径的测试二进制"这条零风险路径，把跨组件装配留到有更大规格机器或业务低峰期。
   - **环境阻塞（需修，否则 macOS 上跑不了 safekeeper 集成测试）**：`build/walproposer-lib/{libwalproposer,libpgport,libpgcommon}.a` 与 `pg_install/v17`、`pgxs-pg18-fork` 均为 **aarch64**，需用 x86_64 PG 安装树重建这三份归档。
2. **key_epoch 轮换未接入** —— 当前 `WalEncryptionConfig.key_epoch` 为静态配置；ADR-013 的轮换状态机（`jt-key-epoch::rotation`）与 KMS `RotateNotify` 尚未驱动它。轮换时需按 epoch 切换 DEK 并处理旧段（旧段用旧 epoch 读，新段用新 epoch 写）——`open_existing_writer` 的 epoch 校验已为此准备好边界语义。

**已完成（更早一轮）**：装配层注入（`WalEncryptionConfig::build_ctx` + CLI 六个参数 + `timeline.rs` 接线）、读路径切换（`WalReader` 解密分支 + `is_encrypted_segment` 按格式判定 + DEK/header 按段缓存）、flush 时序（`seal_tail` 与 fsync 分离，修正我引入的"每次写都 fsync"性能缺陷）。

**迁移约束**：加密与明文段混存时读端能自动识别，但**同一段不得中途改形态**（加密启用后拒绝续写既有明文段，已实现）。

### 5.3 身份引导（完全缺失，阶段 2/3）

| # | 缺口 | 作用 |
|---|---|---|
| I1 | **jt-identity 组件** | 不存在。enrollment token（一次性 + CSR + 度量绑定 → Component CA 签 90 天）、Component/User CA、CRL/OCSP、Root CA 离线保管、撤销传播 ≤5min |
| I2 | **三权分离引导** | `jtdb init --bootstrap-admins`、三份密封凭据信封、首次强制改密、口令 SM3+盐+KDF。现 `jt_sec.role` 是 GUC 自设，非凭据派生 |
| I3 | 离线（air-gapped）部署 | 离线 enrollment/attestation/CRL 流程 |

**注意**：jt-attest 与 jt-kms 已就位，但**无签发方**——attest 要验构建身份签名、KMS 要验 mTLS 客户端证书，而证书由谁签、节点如何取得第一份凭据，这条链是断的（"鸡生蛋"问题）。

### 5.4 接入平面（整体未开工，阶段 2/5）

| # | 缺口 | 作用 |
|---|---|---|
| A1 | **TLCP 握手**（GB/T 38636-2020） | 信创传输层合规：双证书、SM4-CBC/HMAC-SM3/SM4-GCM、证书撤销、互操作矩阵 |
| A2 | **PG wire 协议编解码** | 没有它 gateway 接不了真实客户端，池化逻辑无法落地 |
| A3 | SQL 防火墙 | 危险函数/高风险对象/管理操作/异常模式/消息大小/会话速率；覆盖 simple/extended/prepared/COPY/函数/动态 SQL/binary/多语句/cursor |
| A4 | 事务级池化驱动 | 配置位已有，缺事务边界驱动与 **Sync 划界**（pipeline 中间不得归还连接） |
| A5 | Compute 内核侧会话复位例程 | gateway 能算出"该复位什么"，但**无人执行** |
| A6 | 队列公平调度/超时、连接生命周期、pg cancel 映射 | §5 剩余 |
| A7 | 复用 Neon proxy 基础 | `proxy/` 空 |

### 5.5 控制/审计平面剩余

| # | 缺口 | 作用 |
|---|---|---|
| C1 | jt-pdp 服务面 + Policy Compiler | 现为 lib-only；缺 Compute/Gateway/管理三类下发产物、完整 Cedar 语法解析 |
| C2 | jt-controller 剩余 | 备份策略编排、安全管理员操作、进程生命周期驱动、mTLS 鉴权、多实例共识 |
| C3 | 审计平面剩余 | 远程见证、离线校验器、多源（Gateway/Pageserver/Safekeeper/PDP/KMS）实际接入、6 个月留存容量模型、查询接口 |
| C4 | jt-audit-store 未接 TSA | `Checkpoint.tsa_token` 字段存在但未接线 |
| C5 | jt-kms 未接审计平面 | 只有本地 hash 链日志，未接 jt-audit-ingest |

### 5.6 产品化（阶段 5，未开始）

`cli/`、`sdk/{rust,java,go,python}`、`extensions/`、`deployment/*`、`compliance/`、`packaging/`、`tests/`、`proxy/`、`pageserver/`、`safekeeper/`、`libs/jt-postgres-ffi/` **全部仅 `.gitkeep`**。

关键影响：
- **`jtdb` CLI 不存在** —— 阶段 1 判定条件 `jtdb dev start --embedded` 与阶段 5 全部依赖它；
- **无 CI 配置**；
- **密评证据链自动化**（`jtdb compliance report --framework gb39786`）不存在；
- 部署形态（单机/主备/分离平面/集群）、离线安装升级包无实现。

### 5.7 规格空白（非实现空白）

docs/02 §11 列的 12 份文档中 **7 份尚未起草**：03-Compute 内核改造、06-控制平面、07-审计平面、08-国密与可信验证、09-开发体验与扩展生态、10-部署升级备份恢复、11-测试兼容性供应链。这些领域连规格都没有。

## 5.8 挂账：等硬件（TCM/TPCM）支持

**结论：暂时跳过，不阻塞其他开发**（2026-09-21 决策）。

### 事实核实（基础2 实测）

在 snsc-prod-基础2（47.122.4.83）上探测，**无 TCM/TPCM**：

```text
DMI:     Alibaba Cloud ECS（KVM 虚拟机）
dmesg:   ima: No TPM chip found, activating TPM-bypass!
lspci:   无 crypto/security/tpm 设备
/dev:    无 /dev/tcm* /dev/tpm*
内核:    CONFIG_TCG_TPM=y（驱动齐备，但无硬件可驱动）
IMA:     仅 boot_aggregate 一条，且聚合值为全零（无硬件根）
```

**根因是虚拟化，不是缺驱动**：TCM 是独立物理安全芯片（自有 CPU/存储/密码单元，挂 LPC/SPI 总线），
云上需厂商提供 vTPM 或设备直通，阿里云 ECS 默认不提供。且 **TCM 是国密标准（GM/T 0011/0012），
与 TPM 2.0 不是一回事**——即便云上给 vTPM 也不能直接用于密评。

### 为什么不阻塞其他开发（关键：证明不在关键路径上）

| 事实 | 证据 |
|---|---|
| KMS 收到 `attestation_digest` **只做防重放检查**，不校验证明内容（不看 tier/PCR/度量） | `services/jt-kms/src/state.rs::check_attestation_fresh` 仅查摘要是否见过 |
| `KeyReleaseGate` **未接入 KMS**（docs/02 §6.4 要求"证明参与密钥释放"，门槛已实现且有测试，但无人调用） | `grep KeyReleaseGate services/` 于 jt-kms 零命中 |
| **KMS 没有 `require_tier1` 开关** | grep 零命中。**更正**：ADR-015（四十九/五十）中"KMS 侧配 `require_tier1 = off` 放行"的表述**不准确**，该开关不存在；如需开发模式放行，须先实现它 |

故无 TCM 时：`SoftwareOnly` 证据照样能取到 DEK，全链路可跑通（功能验证有效），
只是**不能声称满足生产承诺**（`effective_tier()` 已修为如实报 `SoftwareOnly`）。

### 挂账项（等有 TCM 的服务器后一起做）

| # | 项 | 说明 |
|---|---|---|
| H1 | 采集器硬件分支 | 读 `/dev/tcm0` 的 PCR 与 NV 防回滚计数器。接口已留好（`CollectorConfig.tcm_available` + `pcr_reader` 闭包），接硬件只需替换采集实现，不动协议与 KMS |
| H2 | KMS 接 `KeyReleaseGate` | 让证明结论真正参与密钥释放（而非仅写日志）。**必须同时实现 H3**，否则无 TCM 的机器全被拒 |
| H3 | `require_tier1` 开关 | KMS 侧显式开关：`true` = 生产（要求 Tier1），`false` = 开发/降级放行。当前不存在，需新写 |
| H4 | 真实证明链路端到端 | Tier1 证据 → KMS 门槛 → 租约签发的完整验证（含 PCR 不匹配、计数器回退的拒绝路径） |
| H5 | 密评材料中的证明章节 | 依赖 H1~H4 |

### 明确不做（避免留下假证据）

**不**在基础2 上模拟 TCM 设备（如 `swtpm`）。那会产出"看起来有硬件根信任"的证据，
正是 `effective_tier` 自我夸大那类问题，密评时是硬伤。降级环境的正确定位是
**如实标注 `SoftwareOnly`**，与 docs/12 §4.1 对软件熵源的处理同构
（标 `rng_source=software` + 降级告警，而非伪装成硬件源）。

## 5.10 架构发现：活段 WAL 加密与"就地覆盖"语义冲突（2026-09-21）

> **状态：已定案 → [`ADR-016`](adr/ADR-016-WAL活段加密布局与集成面.md)。**
> 本节保留根因定位过程；其中"WAL 页头必须是明文"的结论**已作废**（ADR-016 §3）。
> 定案结论：**格式零改动**，集成面收敛为 6 点（其中必修 3 点、守卫 3 点）。
> 真正需要改代码的只有 `find_end_of_wal` 的加密感知变体 + 两个既有缺陷。

**结论：现有活段加密实现（`live_wal.rs`，15/15 绿）无法直接接入 Safekeeper 的
`PhysicalStorage`**，需先解决一处语义冲突。相关改动已回退（保留已验证的
libs 15/15 + safekeeper 33/33 基线），仅保留本结论。

### 冲突

WAL 的固有语义是**就地覆盖**：

```text
1. HandleElected → initialize_first_segment(start_lsn)
     └─ generate_wal_segment 返回**整段**（16 MiB：长页头 + 零填充），
        经 write_at_abs(0, ...) 一次写入 offset 0..16MiB
2. truncate_wal(start_lsn)  → write_lsn = start_lsn（典型 Lsn(1)）
3. write_wal(Lsn(1), ...)   → **从 offset 1 起覆盖**刚写入的预填内容
```

而现有加密实现的约束是**chunk 不可变 + GCM 禁 nonce 重用**：一旦某 chunk 被
封装，就不能再改写（否则同一 (key, nonce) 加密不同内容，灾难性）。步骤 1
封装了 0..16MiB，步骤 3 却要改写 offset 1 所在的 chunk 0 → **冲突**。

### 已尝试的方案与失败原因（记录以免重走）

| 方案 | 结果 |
|---|---|
| 截断时删段重建 | 段头（`initialize_first_segment` 写的合法页头）随之丢失，后续 `write_wal` 报 "invalid xlog page header" |
| 重建后重写段头 | writer 位置推进到 8 KiB，与 `write_lsn`（Lsn(1)）脱节，报 "must be sequential" |
| 加 `reset_to(offset)` 重置位置 | 位置可重置，但截断点落在 chunk 0 内部时仍需改写已封装 chunk → 回到原冲突 |
| 段头区（0..8 KiB）明文透传（同 Layer 的 `ENC_START`） | **方向正确**（段头本就不该被覆盖），但引入 `enc_start` 需同步改布局/读写/probe/测试四处，改动面大且引入新缺陷（`chunk_of` underflow、probe 口径不一致），本轮未收敛 |

### 根因已定位（2026-09-21，读 walproposer 源码 + 逐层诊断）

**冲突的本质已查清，且解法明确**。关键事实（均有代码/实测依据）：

**事实 1：WAL 截断点必然页对齐** —— `startStreamingAt` 的三个来源
（`GetRedoStartLsn()`、`voteResponse.flushLsn`、`Min(propEndLsn, skEndLsn)`，
见 `pgxn/neon/walproposer.c:1469-1495`）**都是页边界对齐的 LSN**；而 PostgreSQL
页大小（8 KiB）与本 writer 的 chunk 大小一致 ⇒ **截断点必然落在 chunk 边界**。
故"回退到 chunk 边界 + 重新封装该 chunk（新 nonce）"足以支撑 WAL 的就地覆盖语义。

**事实 2：段头会被真实流覆盖** —— 源码注释明确："Safekeepers don't skip header
as they need continuous stream of data"（`walproposer.c:1392-1394`）。故"段头区
明文透传"的设想**不成立**（段头本就会被覆盖）。**真正的解法是事实 1 的 chunk
边界回退**，不需要引入 `enc_start`。

**事实 3（真正的阻塞点）：`initialize_first_segment` 不保存文件句柄** ——
`wal_storage.rs:531` 取 `open_or_create` 的 file、写完 16 MiB 后**直接丢弃**
（未 `self.file = Some(file)`）。于是紧随其后的 `truncate_wal` 里
`open_or_create` 会**新建一个 writer**，其位置为 0，与 `write_lsn`（截断点）
脱节 → 报 "must not move forward past written data"。

**已实测确认的中间结论**（诊断输出）：
- `initialize_first_segment` 确实写出了**加密段**：文件 `0000...000.partial`
  大小 16,842,882 B = 16 MiB 数据区 + 2048×32 B tag 区 + 130 B header ✓
- 全部 2048 个 chunk 的 tag 条目 `plain_len=8192`（已封装）✓
- 若 `open_existing` 正确恢复位置，应得 `written=16 MiB`，则回退到 8 KiB 合法 ✓

### ~~又一层发现：WAL 页头必须是明文~~（**已作废**，见 ADR-016 §3）

> **本节结论已于 2026-09-21 被 ADR-016 推翻，保留原文仅为记录推理过程。**
> 核心错误：把"喂给解码器的流"当成"文件布局"。`write_wal` 的解码器按构造
> 只见**网络明文**（`safekeeper.rs:1354` → `wal_storage.rs:585`，同一个 `buf`），
> 文件字节根本不进入它；而唯一读原始文件字节的 `find_end_of_wal`
> **吞掉**解码错误（`xlog_utils.rs:280` `return Ok(result)`）而非抛出。
> 故 `xlp_magic=17747` 反映的是**明文流自身不对齐**（接线改动缺陷），
> **不是**"页头被加密"。格式约束的正解见 **ADR-016**（结论：格式零改动，
> 集成面 6 点）。以下原文保留。

按上述单点修复（`open_existing` 恢复位置 + 截断改为"位置重置"）后，实测错误
从"位置脱节"变为：

```text
write_wal: invalid xlog page header: xlp_magic=17747, expected 53528 at 0/2000
```

`at 0/2000` 说明**位置已正确**（8 KiB = 0x2000），`write_wal` 已进入正常流程；
失败在**页头校验**：`WalStreamDecoder::validate_page_header`
（`libs/postgres_ffi/src/waldecoder_handler.rs:40-70`）要求

- 段首（`lsn.block_offset() == 0` 且 segment 起点）：**长页头**（`XLogLongPageHeaderData`），
- 其后每个页边界（`lsn.block_offset() == 0`）：**短页头**（`XLogPageHeaderData`），

并校验 `xlp_magic == XLOG_PAGE_MAGIC`（0xD118）与 `xlp_pageaddr == lsn`。
而"位置重置"把截断点处的密文留在了页边界上 → 校验失败。

**~~结论：WAL 页头（段首长头 + 每页短头）必须是明文~~**，不能纳入加密 chunk。
~~这不是可绕过的实现细节——`write_wal` 的输入要过 `WalStreamDecoder`，解码器在
每个页边界都要求合法明文页头。~~

**~~这与 Layer 的处理同构~~**：Layer 格式已有 `ENC_START = 8192`（blk0 summary 明文
透传），WAL 需要类似的"页头区明文"设计。差别在于 WAL 的页头**周期性出现**
（每 8 KiB 一个短页头），而非仅段首一次。

### 设计决策（**已定案 → ADR-016**）

**2026-09-21 定案**：格式**零改动**（保留 `live_wal` 现有"偏移恒等密文 + 独立
tag 区 + 尾部 header"布局），集成面收敛为 6 个点，详见
[`ADR-016-WAL活段加密布局与集成面.md`](adr/ADR-016-WAL活段加密布局与集成面.md)。

依据：工业界一致做法（SQL Server 96 B 页头明文 / MySQL 12 B 块头明文 /
PG v3 补丁 page LSN 明文；唯一加密页头的 pg_tde 代价是 `pg_receivewal` 不可用）
+ 密评要求 AEAD（GB/T 39786-2021 要求存储完整性，XTS 明确不认证故不可用）
+ 源码核实（§3 推翻上述页头结论）。

以下原表保留（记录曾被考虑的方案及否决理由）：

| 方案 | 做法 | 代价 |
|---|---|---|
| A. 仅段首长头明文，其余全密文 | 段首 40B 长头明文，其后整段加密 | **不可行**：后续页边界的短页头也在密文里 |
| B. 页头明文 + 页体密文 | 每 8 KiB 页：前 24B（短头）明文 + 余下 8168B 加密 | 密文与明文**不同偏移**（每页错开 24B），破坏"LSN↔偏移恒等" |
| C. 页头区明文透传（同 Layer 的 ENC_START） | 段首 8 KiB 明文（含长头 + 首页头），其后加密 | 只解决**段首**；且段头**本就会被真实流覆盖** |
| D. 按页独立加密，页头保留明文 | 同 B，但 tag 另置区 | 同 B 的偏移问题 |

**~~建议方向~~（已被 ADR-016 取代）**：~~需先确认一个前提——Safekeeper 读路径是否
真的需要"LSN↔偏移恒等"~~。ADR-016 已核实：数据区 `[0..S)` 与明文 **1:1 同偏移**，
故偏移恒等**成立**；真正的硬约束是"认证必然扩张"，被破坏的是
"段文件长度 == wal_seg_size"这一隐含假设（集成面见 ADR-016 §3.4/§4）。

### 已回退

上述接线改动（`open_existing` + `reset_to` + 截断位置重置）已回退，基线干净
（libs 15/15、safekeeper 33/33）。`libs` 侧的两处能力（`open_existing` 恢复位置、
`reset_to` chunk 边界回退）本身是正确的、有测试价值的，可在设计定案后直接复用。

### 影响

- **不阻塞其他开发**：活段加密未接入不影响 Layer 加密、KMS、安全内核等；
- **WAL 加密现状**：格式原语已实现且测试充分（`wal.rs` 16/16、`live_wal.rs` 15/15），
  **归档路径可用**；活段路径待上述"续写恢复位置"完成（单点，方向明确）；
- 相关改动已回退，基线干净（libs 15/15、safekeeper 33/33）。

## 5.11 K5 逻辑复制 MLS 过滤：已实现（2026-09-21）

**结论：主出口已封堵**（子模块提交 `51dfede`，运行时 **72 PASS / 0 FAIL / 1 诚实 SKIP**）。

### 为什么这是优先项

逻辑解码是**独立的数据出口**：它不"读表"而是读 WAL，故 `ExecutorStart` /
`ProcessUtility` 的全部 MAC 检查都管不到它。不加过滤则高密表的数据被原样发到
任意订阅端，绕过整套 MAC——这是已实现 MAC 的**唯一已知后门**。

### 过滤点选在 `ReorderBufferProcessTXN`（而非 pgoutput）

| 事实 | 影响 |
|---|---|
| `pgoutput` 是**共享库**（Makefile 用 `all-shared-lib`） | 只能调用后端导出符号，不能调 jtsec 内部函数 |
| `reorderbuffer.c` **在后端二进制内**（`logical/Makefile` 的 `reorderbuffer.o`） | 可直接调 jtsec 内部函数 |
| `ReorderBufferProcessTXN` 是**唯一收口点** | 所有带数据的变更（`apply_change`/`stream_change`、`apply_truncate`/`stream_truncate`）都经它分派 |
| **跳过是协议安全的** | pgoutput 本身多处静默 return；BEGIN/COMMIT **惰性**发出（只在首个存活变更时发），故整事务被跳过后对端收到"空事务"，与"本来就是空事务"不可区分 |

**为什么不报错而是静默跳过**：报错会（a）向订阅端泄漏"存在更高密级数据"这一
事实（存在性侧信道）；（b）中断整条复制流，使低密数据也停止同步——过度拒绝
变成拒绝服务。

### 语义：BLP 读方向 + 等级与类别**正交**

用读方向（订阅端=主体，被复制对象=客体）：逻辑复制是数据**出口**，风险是
"低密对端收到高密数据"，正是简单安全属性（不下读）约束的那件事。用 *-属性
会得到相反且错误的结论。

两条判据都必须满足：`level <= jt_sec.replication_max_level` **且** 对象类别位
全部落在 `jt_sec.replication_max_categories` 内。**类别必须单独授权**：类别
表达"需额外授权的领域"（finance/hr），与等级正交——只按等级放行会让"把
max_level 提到 40"顺带把所有领域都放出去，是权限的隐式放大。

默认 `max_level = JT_LEVEL_PUBLIC`（10）+ 类别空集 ⇒ 只放行"公开且无类别"对象。

> **默认值必须是真实等级（10）而非 0**：等级取值从 `JT_LEVEL_PUBLIC` 起，
> `max=0` 会让所有合法标签都 `level > 0` 而恒被拒——连公开表都出不去，
> "默认只放行公开"反而变成"默认全拒"。**实测踩到**。

### 覆盖范围（docs/02 §3.6 四条）

| 条款 | 状态 |
|---|---|
| 变更集外发（行数据 + TRUNCATE relids） | **已实现**（reorderbuffer 主过滤点） |
| publication 创建/变更标签检查 | **已实现**（`T_CreatePublicationStmt`/`T_AlterPublicationStmt` 需 secadmin 或 sysadmin） |
| slot 操作进审计 | **已实现**（physical/logical 创建与 drop 发 E2 事件 `event:"replication_slot"`；槽是出口的**持久句柄**，建后即使 publication 被删仍可被推进读取，故必须留痕） |
| 按**行**标签裁剪 | **未做**——依赖行级标签（K1，批次 5 未实现），本批为**表级**粒度 |

### 顺带修一处真实缺陷：`jt_sec_check_role` 的 all-of 语义

原实现 `(roles & required) == required` 要求**同时持有全部**指定角色；而调用点
写 `check_role(JT_ROLE_SECADMIN | JT_ROLE_SYSADMIN)` 意图是"**或**"，且
`jt_sec.role` 是单值 GUC（后设覆盖先设）⇒ 任何会话都不可能同时持两角色 ⇒
该检查**恒为假** ⇒ **DROP TABLE / ALTER TABLE 对 secadmin 与 sysadmin 都被拒**，
而错误消息还写着 "requires secadmin or sysadmin"（**消息与行为相反**，正是
难察觉的原因）。修正为 any-of：`(roles & required) != 0`——安全性上是放宽，
但只放宽到调用点本来声明的语义（按 ADR-012，sysadmin 本就应能执行 DDL）。

### 可验证性设计

新增 SQL 接口 `jt_sec_replication_may_emit(text)` / `jt_sec_replication_skipped()`
（OID 8429/8430）。**为什么必须暴露判定**：完整解码链路在某些构建上跑不通
（见下），若只能端到端验证，则"判定是否正确"永远无法独立确认。有了它，判定
矩阵可在任何构建上验证，运维也可用它审计"某张表会不会被复制出去"。

### 遗留：解码链路端到端在本构建不可验（如实记录）

`pg_logical_slot_get_binary_changes` 报 `resource manager with ID 134 not
registered`——Neon fork 的 `RM_NEON` 未注册（`heapam.c` 里
`XLogInsert(RM_NEON_ID, ...)`），而 macOS 侧没有可加载的 `neon.so`（只有
aarch64 交叉产物）。**该阻塞与过滤逻辑无关**，故标注为 SKIP 而非 PASS。

**接线已用目标码验证**（不依赖解码可运行）：`llvm-nm` 显示 `reorderbuffer.o`
对 `jt_sec_emit_replication_denied` / `jt_sec_get_table_label` /
`jt_sec_replication_may_emit` 有未定义引用，且在链接后的 postgres 二进制中
全部解析——即过滤确实在解码路径上。要在有 `neon.so` 的构建上补端到端验证。

## 5.9 事故记录：基础2 全链路 OOM（2026-09-21）

**现象**：在基础2（2C/7.3G）上启动 WAL 加密端到端验证时，全链路组件
（pageserver + safekeeper + storcon + storcon 内部 PG + jt-kms + compute +
broker + endpoint_storage）同时运行，随后 **SSH 断开、ping 100% 丢包、
TCP 22 可连但立即关闭**——典型内存耗尽症状。机器需重启（或等待平台回收
策略介入）才能恢复。

**根因**：基础2 只有 7.3GB 内存，且机上已有 snsc 业务容器。全链路叠加
我新部署的 debug 构建二进制（未 strip 时 safekeeper 单个 577MB 常驻
RSS 更大）超出可用内存。

**我的失误**（记录以免重犯）：
1. **未做内存预检**就启动全链路——脚本直接跑，没有"可用内存不足则拒绝"
   的闸门；
2. 明知本机是**生产机（含 snsc 业务）**，却没有对资源占用设限；
3. 二进制是 debug 构建，内存占用显著高于 release（虽已 strip debug 符号，
   但仍是 debug profile 的代码生成）。

**已做的补救**（脚本已加，待机器恢复后生效）：
- 内存预检：可用内存 < 3000MB 直接拒绝运行（`free -m` 第 7 列）；
- 检测 docker 容器并提示"本机含 snsc 业务"；
- 清理逻辑覆盖任意 JTDB 相关 postgres（不只本脚本目录）——此前踩到旧会话
  残留占端口。

**后续要求**：
- 全链路验证**改用 release 构建**（内存占用显著更低）；
- 或换更大规格机器（≥8GB 可用）；
- 或分阶段验证（先单独验证 safekeeper + KMS 的加密写入，再跑完整链路）。

**已确认有效的部分**（在 OOM 前已跑通）：
- 二进制部署正确（safekeeper 含 `wal-encryption-kms-endpoint`）
- **加密参数确实到达 safekeeper 进程**（`/proc/<pid>/cmdline` 验证，3 处命中）
- storcon + broker + endpoint_storage + pageserver 全部启动成功
- 真实 jt-kms 实例就绪

即：**装配链路本身已验证可用**，未完成的是"真实 WAL 流下的加密判据"
（段文件含 JTENCOBJ 头 + 不含明文标记）。

## 6. 优先级排序

### 6.1 排序准则

按四项打分（各 1~5，分数越低越优先）：

- **阻塞度**：不做的后果有多严重（是否使已实现的能力失效）
- **返工成本**：越晚做代价越大（涉及已落盘数据格式、已定接口的排前面）
- **复用度**：能否复用已有基础设施（复用度高则性价比高）
- **判定条件**：是否为 docs/00 §6 某阶段的验收条件

### 6.2 排序结果

| 序 | 项 | 阻塞度 | 返工成本 | 复用度 | 判定条件 | 综合 | 理由 |
|---|---|---|---|---|---|---|---|
| **1** | **S1 WAL 加密** | 5 | 4 | 5 | 阶段 3 | **最优** | 不加密 WAL 则"全生命周期加密"承诺残缺（WAL 含全部变更）；`jt-encrypted-object` 已有完整追加式语义与 `seal_chunk` 流式封装，Safekeeper 侧主要是接线而非新建 |
| ~~2~~ | ~~**K5 逻辑复制 MLS 过滤**~~ **已完成（§5.11）** | — | — | — | 阶段 4 | — | 主出口已封堵（表级）；仅"按行裁剪"待批次 5 的行级标签。**顺带修掉 `jt_sec_check_role` 的 all-of 语义缺陷**（该缺陷使 DROP/ALTER TABLE 对 secadmin 与 sysadmin 都恒被拒） |
| **3** | **S2 nonce 方案闭环** | 4 | 5 | 4 | 阶段 0 冻结条件 | 优 | **越晚改代价越大**：已落盘对象需重加密。且它同时是对象格式冻结的阻塞项——格式不冻结，行级存储与 rekey 都缺基础 |
| **4** | **I1+I2 身份引导** | 4 | 3 | 3 | 阶段 2 验收 | 良 | attest/KMS 已就位却无签发方，信任链断裂；三权分离目前靠 GUC 自设而非凭据派生，与 ADR-012 原意有距离 |
| **5** | **K1 行级标记存储** | 5 | 4 | 2 | 阶段 4 判定 | 良 | 战略上最重要，但工作量最大（heap 元组 + 计划期注入 + 目录表 + 缓存失效四层联动），且依赖 K2/K3/K4，宜作为一组推进 |
| **6** | A1+A2 TLCP + PG wire | 4 | 2 | 3 | 阶段 2/5 | 中 | 接入平面整体未开工；TLCP 是信创合规硬要求，但无已落盘格式耦合，可后置 |
| **7** | K4 标签缓存与 sinval | 2 | 3 | 3 | — | 中 | 当前每语句查目录，性能与 prepared plan 正确性都有隐患；但无数据格式耦合 |
| **8** | C1~C5 控制/审计剩余 | 2 | 2 | 4 | — | 中 | 多为接线与补齐（TSA 接线、多源接入），可增量做 |
| **9** | K7~K11 内核剩余小项 | 3 | 1 | 3 | 阶段 2 判定 | 中 | dblink/PL-Python/调试路径属"逃逸清单清零"的验收条件，单项工作量小 |
| **10** | 阶段 5 产品化全家桶 | 2 | 1 | 2 | 阶段 5 | 低 | 依赖前序工作域稳定；CLI 可先做最小骨架以解除阶段 1 判定阻塞 |

### 6.3 执行顺序与理由

```text
批次 1（本批）：S1 WAL 加密
    → 复用 libs/jt-encrypted-object 已有基础设施；补齐"全生命周期加密"最后一块
    → 交付物：Safekeeper WAL 段加密 + 追加式语义 + 运行时验证
    → 设计已定案（ADR-016，2026-09-21）：格式零改动
    → 集成面 6 点已完成（§5.2.2，libs 55/55 + safekeeper 37/37）
    → 仅剩：基础2 端到端验证（release 构建）+ key_epoch 轮换接入

批次 2：K5 逻辑复制 MLS 过滤 —— **已完成（2026-09-21，§5.11）**
    → 堵住已实现 MAC 的唯一已知后门
    → 收口点实为 reorderbuffer.c（后端内）而非 pgoutput（共享库），见 §5.11
    → 表级粒度；"按行裁剪"随批次 5 的行级标签一并做
    → 遗留：解码链路端到端需在有 neon.so 的构建上补验证（RMGR 134 阻塞）

批次 3：S2 nonce 方案闭环 + 对象格式冻结
    → 冻结前置条件；越晚做已落盘对象越多，返工越贵

批次 4：I1+I2 身份引导（enrollment + CA + 三权引导凭据）
    → 闭合 attest/KMS 的信任链

批次 5：K1+K2+K3+K4 行级标记存储（一组推进）
    → 阶段 4 判定条件；四层联动，单独做任一层都会返工

后续：A1/A2 接入平面、C1~C5 补齐、K7~K11 小项、阶段 5 产品化
```

**关于"为什么 WAL 加密排第一"**：项目已实现 Layer 加密并做了性能基准，但 WAL 是明文。WAL 记录全部数据变更，是比 Layer 更直接的敏感数据载体——只加密 Layer 而 WAL 明文，等于把加密承诺做成半成品。且 `jt-encrypted-object` 已实现追加式 chunk 语义（`seal_chunk` 流式封装、`.part` → rename 原子发布），Safekeeper 侧主要是接线工作，复用度最高、返工成本中等的组合。

## 7. 维护约定

1. **每轮开发后更新本文**：状态变更同步到 `docs/adr/ADR-015-PG版本策略.md` 执行记录，本文 §4/§5 相应调整；
2. **新发现"规格已写但未实现"时**：先探测确认（实测优先于读代码），再登记到 §5，并在 ADR-015 记录探测方法——本项目多次出现"编译通过但功能未生效"的静默失效，仅读代码不足以定论；
3. **完成一项时**：从 §5 移除，加入 §4，并在 §6.2 重新评估排序（依赖关系会变）；
4. **禁止**把"部分实现"简单标成"已实现"——必须列出缺失子项（本文 §5 的 K6/K7 即为此类）。
