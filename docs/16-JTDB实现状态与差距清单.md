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
| Compute 适配 | **部分** | 安全上下文（表级）+ MAC 钩子（读/写/COPY/TRUNCATE/DDL）+ 逃逸围栏 + 统一错误码 + E2 事件；缺行级、谓词注入、逻辑复制过滤、函数触发器（经 SPI 已覆盖） |
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
| K5 | **逻辑复制与 CDC 的 MLS 过滤**（§3.6） | **未设防数据出口**：逻辑复制可把高密行原样发到低密订阅端，绕过全部 MAC | `jtsec/` 无 `logical`/`pgoutput`/`publication` |
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

**活段文件加密是另一条路径**，需单独设计：要求页级/记录级加密（或对 WAL 页做独立 AEAD），且必须满足 (a) 密文与明文同偏移（保持 LSN↔偏移恒等）、(b) 每个 flush 边界可独立认证、(c) 对端能流式解密未写完的段。**docs/04 §5 未描述此形态，属规格缺口**（见 §5.7），需补设计后实施。

#### 5.2.2 活段 WAL 加密：接线状态

**已完成（写路径）**（子模块提交 `556e54c`，33/33 绿）：

- `safekeeper/src/wal_encryption.rs`：`WalEncCtx`（DEK 来源 + 布局 + 绑定字段）、`WalFile` 枚举（`Plain(File)` / `Enc(LiveWalWriter)`，让 `PhysicalStorage` 无需感知形态差异）、读取入口（`read_encrypted_at` / `read_segment_meta` / `is_encrypted_segment` 按文件头自动识别，支持迁移期混存）、进程级 DRBG 启动健康检测（fail-closed）。
- `PhysicalStorage`：`file` 字段 `File` → `WalFile`；`new()` 保留为包装（传 `None`），**既有调用方零改动**；新增 `new_with_encryption()`；`open_or_create` 分派（加密形态预分配完整布局；既有**明文段在加密启用时拒绝续写**，避免格式混用）；`write_in_segment` 经 `WalFile` 分派，加密形态 `flush()` 会封装尾块使对端可读；加密段 `set_len` 拒绝（布局长度固定）。
- **关键判据已测**：`encrypted_wal_file_does_not_contain_plaintext` —— 同一内容明文模式可直接看到、加密模式落盘字节不含明文且能解回。
- **顺序性前提已核实**：`LiveWalWriter` 要求严格顺序追加，而 `safekeeper.rs` 的 append 处理与 `wal_storage.rs::write_wal` 都显式 `bail!` 拒绝重写与 gap，故无需为「重写既有偏移」设计。

**剩余（两项，均非代码阻塞）**：

1. **端到端运行验证未做** —— 需真实 KMS 实例 + 真实 WAL 写入流（neon_local 全链路）。当前验证停在单元/集成层：加密写出的段不含明文、读回一致、格式自动识别。**这是"声称完成"与"证实完成"的差距**，应在下一轮补 neon_local 全链路冒烟（带 `--wal-encryption-kms-endpoint`）。
2. **key_epoch 轮换未接入** —— 当前 `WalEncryptionConfig.key_epoch` 为静态配置；ADR-013 的轮换状态机（`jt-key-epoch::rotation`）与 KMS `RotateNotify` 尚未驱动它。轮换时需按 epoch 切换 DEK 并处理旧段（旧段用旧 epoch 读，新段用新 epoch 写）。

**已完成（三项，本轮）**：装配层注入（`WalEncryptionConfig::build_ctx` + CLI 六个参数 + `timeline.rs` 接线）、读路径切换（`WalReader` 解密分支 + `is_encrypted_segment` 按格式判定 + DEK/header 按段缓存）、flush 时序（`seal_tail` 与 fsync 分离，修正我引入的"每次写都 fsync"性能缺陷）。

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
| **2** | **K5 逻辑复制 MLS 过滤** | 5 | 3 | 4 | 阶段 4 | 优 | **已实现的 MAC 有一个明确后门**：高密行可原样复制到低密订阅端。pgoutput 的 `pgoutput_change()` 是单一收口点，改动面小、收益直接 |
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

批次 2：K5 逻辑复制 MLS 过滤
    → 堵住已实现 MAC 的唯一已知后门；pgoutput 单一收口点，改动可控

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
