# JTDB 信创安全数据库总体架构设计

| 项 | 值 |
|---|---|
| 项目代号 | 金湯 JTDB（暂定） |
| 文档版本 | v0.4 讨论稿 |
| 日期 | 2026-09-02 |
| 状态 | 架构评审结论已合入（2026-09-02），待技术评审 |
| 架构基座 | 直接使用并修改 Neon 源码；Neon PostgreSQL Compute + Rust 存储体系 |
| 目标市场 | 信创环境中的中小企业，优先单机/主备部署，同时保留存算分离和多节点扩展能力 |

> 本文描述 JTDB 的完整目标架构，不把目标架构拆分成 V1/V2/V3 产品版本。实施时按依赖关系推进，但所有目标能力属于同一套架构。

## 修订记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v0.1 | 2026-09-01 | 初稿 |
| v0.2 | 2026-09-02 | 增加 MLS、TEE、TCM 等四级方向 |
| v0.3 | 2026-09-02 | 确认直接使用并修改 Neon 源码；确认 Rust 存储为核心；补充三平面单机/多进程/集群部署模型；补充开发体验、扩展治理、可观测性和产品化能力；修正“零内核补丁”“三平面必须集群”等表述 |
| v0.4 | 2026-09-02 | 合入架构评审结论：MLS 对象级+行级双层标签（ADR-011）、超级用户围栏与三权分立（ADR-012）、KMS 租约/轮换/防回滚（ADR-013）、分支密钥作用域（ADR-014）、动态脱敏与合规指标 |

---

## 0. 架构摘要

JTDB 的定位是：

> **面向信创和中小企业的 PostgreSQL 兼容安全数据库平台。以 Neon 源码为存算分离和 Rust 存储基础，以 PostgreSQL 生态为开发兼容基础，以 JTDB 安全内核、国密、密钥、MLS、审计、可信验证和开发工具形成产品差异化。**

JTDB 不是简单的 Neon fork，也不是 PostgreSQL 外挂几个安全服务，而是由以下部分共同组成：

```text
JTDB
├── Neon PostgreSQL Compute：SQL、事务、优化器、执行器和 PostgreSQL 生态
├── Neon Rust Storage：WAL、Safekeeper、Pageserver、Timeline、Layer、PITR
├── JTDB 安全内核：可信身份上下文、MLS/MAC、内核审计、WAL 安全集成
├── JTDB 控制平面：PDP、KMS、可信验证、实例/存储编排
├── JTDB 审计平面：多源审计、可靠落盘、锚定、WORM/远程见证
└── JTDB 开发与生态能力：CLI、控制台、迁移、分支、脱敏复制、扩展治理、可观测性
```

### 0.1 已确认的总体决策

| 问题 | 设计结论 |
|---|---|
| 数据库基座 | 直接 fork Neon，并在其 PostgreSQL Compute、Pageserver、Safekeeper 和相关库上修改 |
| 是否继续使用 Rust 存储 | 是。Rust 是 JTDB 存储和安全服务的主要实现语言 |
| 是否自研 Neon 已有存储能力 | 不重复开发 Timeline、Layer、WAL Redo、PageServer 等已有基础能力；重点做安全化、国产化和产品化改造 |
| 是否允许修改源码 | 允许，且安全边界和存储协议所需修改必须进入源码 |
| 是否维护自己的源码分支 | 是。建立 JTDB fork、上游同步机制和 JTDB 补丁系列 |
| 三平面是否必须集群 | 否。三平面是职责/信任边界，不等于三套集群或三台机器 |
| 是否支持单机 | 必须支持。单机默认采用多进程三平面；开发体验可提供单进程嵌入模式 |
| 是否允许正式生产单进程 | 不建议。KMS、审计存储、PDP 不得与数据库 Compute 共用进程地址空间 |
| 是否前期做分布式 | 不以分布式为前提；目标架构保留 Neon 的存算分离和高可用能力 |
| PostgreSQL 与 TiDB 的选择 | 选择 PostgreSQL/Neon 生态；TiDB/TiKV 作为 Rust 分布式存储和故障恢复的参考，不作为 JTDB 基座 |

---

## 1. 产品目标与边界

### 1.1 产品目标

| 编号 | 目标 |
|---|---|
| G1 | 尽可能保持 PostgreSQL 的 SQL、协议、驱动、ORM、工具和扩展开发体验 |
| G2 | 对数据、控制、审计职责进行逻辑和进程级隔离；支持单机、多节点和高安全部署 |
| G3 | 对 WAL、Timeline、Layer、快照、备份和对象存储实现全生命周期的机密性、完整性和可恢复性保护 |
| G4 | 在 PostgreSQL/Neon 可信执行边界内实现不可绕过的身份上下文和 MLS/MAC；RLS 作为纵深防御 |
| G5 | 支持 TLCP、SM2、SM3、SM4 以及可插拔的 TCM/TPCM、TEE、UKey/SKF 适配 |
| G6 | 通过独立 KMS、可信验证和审计平面实现密钥、策略、可信状态和审计证据闭环 |
| G7 | 具备本地开发、数据库分支、脱敏复制、迁移、策略即代码和自动诊断能力 |
| G8 | 具备信创平台适配、离线构建、可重复构建、SBOM、扩展白名单和供应链治理能力 |

### 1.2 产品形态

```text
单机安全部署       一台服务器，多进程三平面
主备部署           数据库/存储具备主备，控制和审计可独立部署
分离部署           数据、控制、审计平面位于不同节点或安全域
高可用部署         Pageserver、Safekeeper、控制和审计组件按需配置副本
开发嵌入部署       面向本地开发和测试的单进程/轻量模式，不作为安全等级承诺
```

### 1.3 非目标

- 不重写 PostgreSQL 的 SQL 解析、查询优化和普通执行语义；
- 不以 MySQL 兼容为主线，不转向 TiDB 的 SQL/生态路线；
- 不把“四级技术控制项”表述为所有硬件平台都具备相同的 TEE 强举证能力；
- 不允许未经治理的第三方 native extension 破坏 JTDB 的可信边界；
- 不把三平面强制解释为必须三台物理服务器；
- 不引入与中小企业无关的云计费、云租户和公有云控制面。

---

## 2. 技术路线与基座选择

### 2.1 总体路线

```text
Neon PostgreSQL Compute
        + JTDB 安全内核补丁
        + Neon Rust Pageserver/Safekeeper/Timeline/Layer
        + JTDB WAL/Layer/快照/备份安全
        + JTDB 控制平面
        + JTDB 审计平面
        + JTDB 开发与生态能力
```

直接使用 Neon 源码，避免重复实现：

- PostgreSQL Compute 与远程存储集成；
- Pageserver、Safekeeper；
- Timeline、不可变 Layer；
- WAL 接收、WAL Redo 和页面重建；
- Page-at-LSN、缓存、PITR 和快照基础；
- 远程对象存储抽象；
- 存算分离相关测试基础。

JTDB 的主要创新集中在安全化、国密化、国产化、三平面控制、开发体验和可交付性，而不是重新实现 Neon 已有存储能力。

### 2.2 Neon 继承边界

| 代码/能力 | JTDB 做法 |
|---|---|
| PostgreSQL Compute 修改 | 继承并叠加 JTDB 安全、审计、国密和存储补丁 |
| Pageserver/Safekeeper | 作为 Rust 存储基础，增加加密、密钥、可信验证和审计 |
| Timeline/Layer/WAL Redo | 直接使用并扩展，不重复实现同类机制 |
| Remote Storage | 保留抽象，增加本地磁盘、国产对象存储和加密对象封装 |
| Neon Proxy | 复用连接管理/路由思想或代码，产品入口由 jt-gateway 负责 |
| Neon Cloud Control Plane | 不直接照搬；由 JTDB 控制平面替代或适配 |
| Neon 云租户/计费逻辑 | 不纳入 JTDB 基础产品 |

### 2.3 源码治理

JTDB 建立自己的 fork 和补丁系列：

```text
Neon/PG 固定上游基线
        ↓
JTDB upstream sync
        ├── Neon 原有修改
        ├── JTDB 安全补丁
        ├── JTDB 存储加密补丁
        ├── JTDB 国密/信创补丁
        └── JTDB 产品能力
```

每个修改必须记录来源、上游 commit、许可证、修改原因、是否可回合上游、对升级和安全证据的影响。

---

## 3. 三平面模型与部署

### 3.1 三平面定义

```text
数据平面：运行数据库和存储，处理业务数据
控制平面：管理身份、策略、密钥、可信状态和生命周期
审计平面：接收、保存、校验和提供审计证据
```

三平面是职责、身份、密钥、数据访问路径和审计责任的隔离模型，**不等于必须三台机器、三个集群或三个 Kubernetes 集群**。

### 3.2 数据平面

```text
jt-gateway
Neon PostgreSQL Compute
jt-pageserver
jt-safekeeper
数据平面缓存和临时文件
```

最终的安全上下文和 MAC 决策在 Compute 内核内执行。

### 3.3 控制平面

```text
jt-controller
jt-pdp
jt-kms
jt-attest
jt-identity
jt-admin-api
```

控制平面负责实例、Timeline、策略、标签、密钥、可信验证和管理生命周期。

### 3.4 审计平面

```text
jt-audit-ingest
jt-audit-store
jt-tsa
jt-audit-console
WORM/远程见证适配器
```

审计平面接收 Compute、Gateway、Pageserver、Safekeeper、PDP、KMS 和 Attest 的多源事件。

### 3.5 单机正式部署

中小企业默认支持一台服务器上的多进程三平面：

```text
jtdb-gateway      jtdb-compute      jtdb-pageserver
jtdb-safekeeper   jt-controller     jt-pdp
jt-kms            jt-attest         jt-audit-ingest
jt-audit-store    jt-tsa
```

通过独立 OS 用户、目录、systemd 服务、服务证书、Unix socket/loopback 端口、Capability、资源限额和安全增强 Linux 策略实现进程级隔离。KMS、PDP 和审计存储不得与 Compute 共用地址空间。

### 3.6 单进程嵌入模式

开发和测试可以提供：

```bash
jtdb dev start --embedded
```

该模式允许聚合开发 KMS、轻量控制服务和本地审计模拟器，但必须明确标记为开发模式，不宣称三平面进程隔离、硬件根隔离或生产安全等级。

### 3.7 多节点和集群

需要更强隔离、可用性或容量时，数据、控制、审计平面可分别放置在不同节点，并且各组件按需集群化。集群化是部署能力，不是三平面定义的前提。

单机模式不能对宿主机 root、宿主机内核或 hypervisor 承诺与多节点/TEE 相同的隔离强度。

---

## 4. 安全模型与可信边界

### 4.1 信任边界

```text
不可信：外部客户端、业务应用、普通数据库用户
部分可信：Gateway、Compute、Pageserver、Safekeeper
高可信：KMS、Attest、审计存储、TCM/HSM/TEE
最终决策点：PostgreSQL/Neon Compute 内核安全检查
```

网关是入口和第一层策略执行点，但不是最终安全边界。

### 4.2 安全上下文

每个数据库会话绑定：

```text
subject_id
roles
security_label
policy_version
authentication_method
gateway_session_id
key_epoch
issued_at/expires_at
nonce/attestation_binding
```

普通 SQL 用户不能通过普通 GUC 直接修改主体、角色、标签和策略版本。上下文由网关提供材料，由 Compute 内核验证、绑定和撤销。

### 4.3 MLS/MAC

```text
Cedar：主体/动作/资源/上下文策略
JTDB MLS：Level/Categories、支配关系和标签传播
Compute：最终不可绕过的执行检查
RLS/安全视图：纵深防御和业务可见性
```

标签粒度采用对象级（库/模式/表/列）+ 行级双层模型（ADR-011）：行级标签通过元组隐藏列携带（约 +4B/行），TOAST、WAL、逻辑复制与 dump/restore 均携带；读路径在计划期注入标签谓词以利用索引，写路径按 Bell-LaPadula 简单安全属性（不下读）、*-属性（不上写）与类别支配检查；受控降标需 jt_secadmin 审批并强制审计。

MLS 覆盖 SELECT、INSERT、UPDATE、DELETE、MERGE、COPY、TRUNCATE、DDL、函数、触发器、分区、FDW、外键、备份、恢复、复制、快照和分支等路径。RLS 不作为唯一 MAC 实现。

### 4.4 扩展治理

生产环境实行扩展签名、来源白名单、SBOM、许可证和漏洞检查、能力声明、版本矩阵和绕过测试。`LOAD`、`shared_preload_libraries` 和 `CREATE EXTENSION` 受控；关键安全路径不能由普通扩展覆盖。

### 4.5 超级用户围栏与三权分立

以可信角色体系替代单一 superuser（ADR-012）：

```text
jt_sysadmin   实例/存储/备份/扩容，无标签与审计权限
jt_secadmin   账户、标签、策略、扩展白名单，无审计查询与存储权限
jt_auditor    审计查询/校验/导出，只读；配置变更需双人复核
```

内核所有 `superuser()` 判定点替换为基于 JtSecurityContext 的 `jt_role_check()`；`COPY PROGRAM`、`file_fdw`/`pg_read_server_files`、`dblink`、非受控服务端语言、大对象服务端任意读写等逃逸路径默认禁用，需扩展能力声明 + secadmin 白名单开启（与 4.4 衔接）。首次初始化即三权分离，凭据密封分发并强制首次改密；OS root 无法直接获得任一数据库角色。

### 4.6 动态脱敏

在生产访问路径上按主体标签与策略对敏感列动态脱敏（掩码/哈希/截断/置空），与脱敏克隆（静态）形成闭环；脱敏规则纳入策略即代码治理，效果可被 `jt_explain_policy` 解释。列级密钥钩子同步预留，为全密态（密钥在客户端的字段级加密）演进留出路径。

---

## 5. 存储与数据生命周期安全

### 5.1 Neon 存储链路

```text
PostgreSQL WAL
    ↓
Safekeeper 持久化
    ↓
Pageserver 接收和重放 WAL
    ↓
Timeline / immutable Layer
    ↓
Page-at-LSN / Page Cache
    ↓
Snapshot / PITR / Branch / Object Storage
```

### 5.2 加密范围

必须覆盖 Compute 本地 WAL、Safekeeper WAL、Pageserver Layer、临时文件、快照、Branch、PITR、备份和对象存储。运行时明文页面可能存在于 Compute/Pageserver 内存，内存防护需要 TEE/CSV 或平台级能力。

### 5.3 密钥层次

```text
RK（TCM/HSM/受控分片）
└── Cluster KEK
    ├── WAL DEK（timeline + epoch）
    ├── Layer DEK（timeline/layer + epoch）
    ├── Snapshot DEK
    ├── Backup DEK
    └── Audit DEK
```

组件只获得作用域受限、带租约的 DEK。DEK 作用域统一定义为 (cluster, timeline, epoch, lsn_range)（ADR-014）：分支/快照/备份通过 BranchKeyGrant 获得父层受限只读授权（epoch ≤ 分支点、LSN ≤ 分支点），新写入使用自身 DEK 链，共享 Layer 不重加密。旧 epoch 在备份、PITR 和主备恢复完成前不得删除；DEK 按保留策略销毁即实现旧数据加密擦除，与客体重用要求协同。KMS 失效、轮换与防回滚协议见 ADR-013。

### 5.4 加密对象封装

```text
JtEncryptedObject
├── magic / format_version
├── object_type
├── timeline_id / object_id
├── key_epoch / generation
├── nonce
├── ciphertext / authentication_tag
└── metadata_signature
```

禁止直接使用“BlockNo + LSN 低位”作为 GCM nonce。nonce、generation、compaction、GC、回放和恢复必须具备明确的持久化和防回退规则。

每个 timeline 维护签名对象清单（对象集 + generation + key epoch），恢复时先校验清单与对象代际再进入 Redo，防止旧 epoch 密文被重放；远程对象存储建议启用版本化或 WORM（ADR-013）。

### 5.5 WAL 安全

WAL 加密单独覆盖 WAL writer、Safekeeper、Pageserver WAL ingestion/redo、startup/recovery、归档恢复、streaming replication、base backup 和诊断工具。恢复必须先验证顺序、代际、密钥 epoch 和完整性，再进入 WAL Redo。

---

## 6. 开发与生态能力

### 6.1 PostgreSQL 开发体验

优先保持 psql、JDBC、ODBC、Npgsql、psycopg、pgx、主流 ORM、pg_dump、pg_restore、COPY、prepared statements、事务和常用 PostgreSQL 管理命令的使用方式。

### 6.2 本地开发

```bash
jtdb init
jtdb dev start
jtdb status
jtdb connect
jtdb doctor
jtdb logs
```

自动处理开发证书、开发 KMS、默认策略、初始化、测试数据和 CI 清理。

### 6.3 分支、快照和脱敏复制

```bash
jtdb branch create feature-order --from main
jtdb branch reset feature-order --to <lsn-or-time>
jtdb clone production --target test --mask-policy ./masking.yaml
```

分支继承策略和安全标签，新数据使用独立 DEK 链，共享父层通过 KMS 受限授权只读（ADR-014）；生产到测试必须支持格式、唯一性和外键关系保持的脱敏复制。

### 6.4 Schema 迁移和策略即代码

```bash
jtdb migrate validate
jtdb migrate plan
jtdb migrate apply
jtdb policy check
jtdb policy test
jtdb policy diff
jtdb policy simulate
```

迁移和策略支持 Git、CI、审批、影响分析、预演、回滚和审计。

### 6.5 可解释安全与可观测性

提供 `jt_explain_policy` 和 `EXPLAIN (ANALYZE, JTDB_SECURITY, JTDB_STORAGE)`，同时关联：

```text
request_id / session_id / transaction_id / query_id
policy_version / key_epoch / timeline_id / lsn / audit_event_id
```

形成从 SQL 到策略、WAL、Timeline/Layer、KMS、审计和复制的端到端诊断链路。

### 6.6 受控扩展生态

官方扩展、认证第三方扩展和普通第三方 native extension 分级管理。扩展可声明读写对象、网络、文件系统和是否绕过 MLS 等能力；生产环境默认只允许签名白名单扩展。

---

## 7. 国密、可信验证和审计

### 7.1 国密

| 场景 | 设计 |
|---|---|
| 传输 | TLCP，标准编号统一核对为 GB/T 38636-2020 |
| 身份 | SM2 证书、SM3 口令、可选 UKey/SKF |
| 数据 | SM4 及合规模式 |
| 完整性 | SM3、AEAD Tag、对象签名 |
| 锚点 | SM2 签名、TSA |

通过 `jt-crypto-api` 隔离 Tongsuo 适配和纯 Rust `jt-tlcp` 实现。

### 7.2 可信验证

```text
软件度量 → TCM/TPCM PCR或TEE证明 → Attest验证 → KMS释放受限DEK
```

证明绑定二进制、配置、策略版本、实例身份、key epoch 和防回滚计数器。

### 7.3 审计

审计采用多源事件、可靠本地 journal、SM3 哈希链、SM2 锚点、TSA、WORM/远程见证、离线校验和恢复演练。哈希链用于发现篡改，不单独宣称可以防止整个日志被删除或重建。

---

## 8. 技术先进性指标

| 领域 | 指标方向 |
|---|---|
| 存储 | Timeline/Layer/PITR/Branch + 加密对象和 key epoch |
| 安全 | 内核不可绕过 MAC（对象级 + 行级）、超级用户围栏与三权分立、可信身份、默认审计、KMS 绑定验证与防回滚 |
| 可靠性 | WAL、Layer、快照、备份全生命周期保护；恢复可验证 |
| 开发体验 | 一条命令启动、分支、脱敏复制、迁移、策略测试和诊断 |
| 可观测性 | SQL→策略→WAL→Timeline/Layer→KMS→审计关联 |
| 生态 | PostgreSQL 扩展兼容 + 签名、白名单、SBOM、能力声明 |
| 合规 | 等保/密评证据包自动化、GB/T 39786 指标映射、GM/T 0028 二级起步、随机数来源治理 |
| 国产化 | 多架构、离线安装、国产对象存储、TCM/TEE/UKey 适配 |
| 工程 | 上游 commit 固化、补丁可追踪、可重复构建、故障注入和恢复测试 |

---

## 9. 实施工作域

整体架构按依赖关系推进，而不是按产品版本拆分：

```text
上游基线和源码治理
→ Neon Compute/Pageserver/Safekeeper 编译运行
→ 安全上下文、审计和存储边界
→ 国密、KMS、WAL/Layer 加密
→ MLS/MAC、可信验证和扩展治理
→ CLI、迁移、分支、脱敏复制、可观测性
→ 单机、主备、分离和集群部署验证
```

每个能力域必须同时具备设计、接口、威胁模型、恢复方案、测试标准、运维手册和测评证据。

---

## 10. 关键架构决策

| 编号 | 决策 | 状态 |
|---|---|---|
| ADR-001 | JTDB 直接使用并修改 Neon 源码 | 已确认 |
| ADR-002 | Neon PostgreSQL Compute 作为 SQL/事务基座 | 已确认 |
| ADR-003 | Neon Rust 存储体系作为 JTDB 存储基础 | 已确认 |
| ADR-004 | JTDB 维护自己的 fork、补丁系列和上游同步机制 | 已确认 |
| ADR-005 | 三平面是逻辑/职责边界，不强制三台机器或三套集群 | 已确认 |
| ADR-006 | 正式单机采用多进程；单进程只用于开发/测试嵌入 | 已确认 |
| ADR-007 | KMS、PDP、审计存储不得与 Compute 共用进程地址空间 | 已确认 |
| ADR-008 | Compute 是最终 MAC 和关键审计执行边界 | 已确认 |
| ADR-009 | JTDB 不只是 Neon fork，增加安全、国密、国产化、开发体验和运维产品层 | 已确认 |
| ADR-010 | TiDB/TiKV 不作为基座，仅作为分布式 Rust 存储参考 | 已确认 |
| ADR-011 | MLS 采用对象级 + 行级双层标签模型 | 已确认 |
| ADR-012 | 超级用户围栏与三权分立角色矩阵 | 已确认 |
| ADR-013 | KMS 租约、轮换与防回滚协议 | 已确认 |
| ADR-014 | 分支/时间线密钥作用域（timeline + epoch + LSN） | 已确认 |

> 注：本表编号沿用总体架构讨论稿的历史顺序，与《JTDB-架构决策记录》的编号不一一对应（例如本表 ADR-005"三平面边界"对应决策记录 ADR-003，本表 ADR-006"单机多进程"对应决策记录 ADR-004）。**正式编号一律以《JTDB-架构决策记录》为准**，本表仅作决策摘要索引。

## 附录：专项文档

1. 《JTDB 技术路线与 Neon 源码继承策略》
2. 《JTDB PostgreSQL/Neon Compute 内核改造设计》
3. 《JTDB Rust 存储、WAL 与加密对象设计》
4. 《JTDB MLS/MAC 与安全上下文设计》
5. 《JTDB 控制平面设计》
6. 《JTDB 审计平面与证据链设计》
7. 《JTDB 开发者体验、扩展生态与可观测性设计》
8. 《JTDB 部署、升级、备份恢复与运维设计》
9. 《JTDB 兼容性、测试与供应链治理设计》
