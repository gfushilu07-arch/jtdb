# JTDB 架构决策记录（讨论确认版）

| 项 | 值 |
|---|---|
| 日期 | 2026-09-02 |
| 状态 | 讨论确认；2026-09-02 增补 ADR-011~014（决策记录见《JTDB-架构评审意见与改进规划》§8） |
| 关联文档 | `信创安全数据库-三平面零信任架构.md`、`信创安全数据库-实现方案.md`、`JTDB-架构评审意见与改进规划.md` |

## 1. 总体定位

JTDB 定位为：

> 面向信创和中小企业的 PostgreSQL 兼容安全数据库平台。以 Neon 源码为存算分离和 Rust 存储基础，以 PostgreSQL 生态为兼容基础，以 JTDB 自研安全、国密、控制、审计、开发体验和运维能力形成差异化。

JTDB 不是“只加安全功能的 Neon fork”，也不是重新实现 PostgreSQL。

## 2. 已确认决策

### ADR-001：直接使用并修改 Neon 源码

**结论**：直接 fork Neon 源码，保留并修改 Neon PostgreSQL Compute、Pageserver、Safekeeper、Timeline、Layer、WAL Redo、Page Cache 和 Remote Storage 等能力。

**原因**：避免重复实现已经存在的 Rust 存储和存算分离能力；JTDB 的研发重点转向安全化、国密、国产化、开发体验和交付产品化。

### ADR-002：Rust 作为存储核心实现语言

**结论**：Rust 继续作为 JTDB 存储、安全服务、控制平面、审计平面和工具链的主要实现语言。

**边界**：PostgreSQL/Neon 原有 C 代码仍保留；C 主要承担 Compute 内核边界和必要的 FFI 适配，安全逻辑和新服务优先由 Rust 实现。

### ADR-003：三平面是职责/信任边界，不等于集群

**结论**：三平面不要求三台机器、三个集群或每个平面都高可用集群化。

支持：

- 单机多进程三平面；
- 多节点三平面；
- 数据/控制/审计分别按需集群化。

### ADR-004：生产单机采用多进程

**结论**：单机正式部署使用多个受限服务进程；开发和测试可提供单进程嵌入模式。

**禁止的生产形态**：KMS、PDP、审计存储与 PostgreSQL Compute 共用一个进程地址空间。

**边界补充（2026-09-02）**：允许 profile 化部署将 controller、PDP、attest、gateway 合并为少量二进制，前提是进程间保持服务身份与协议级认证（如 mTLS over Unix socket）；KMS 与审计存储始终独立进程。

### ADR-005：Compute 是最终安全执行边界

**结论**：网关负责认证、连接治理和粗粒度策略；PostgreSQL/Neon Compute 内核负责可信身份上下文、MLS/MAC 和关键审计事件。

**原因**：防止本地连接、函数、触发器、COPY、复制、备份、管理路径或被攻破网关绕过安全控制。

### ADR-006：Rust 存储直接复用 Neon 存储体系

**结论**：不重新开发 Timeline、Layer、WAL Redo、Pageserver 和 Safekeeper；在 Neon 基础上增加 JTDB 加密对象、WAL/Layer 安全、密钥 epoch、KMS 租约和审计。

### ADR-007：全生命周期存储安全

**结论**：加密范围包括 WAL、Safekeeper 数据、Timeline/Layer、快照、Branch、PITR、备份、对象存储和恢复路径，而非只加密 PostgreSQL 8KB 页面。

### ADR-008：扩展受控开放

**结论**：保留 PostgreSQL 扩展生态，但对 native extension 实行签名、SBOM、许可证检查、白名单、能力声明和安全测试；关键安全控制不能由普通扩展覆盖。

### ADR-009：开发体验是正式架构能力

**结论**：JTDB 必须包含 CLI、本地开发模式、数据库分支、快照、脱敏复制、Schema 迁移、策略即代码、可解释授权、诊断工具和统一可观测性。

### ADR-010：TiDB/TiKV 不作为 JTDB 基座

**结论**：JTDB 继续采用 PostgreSQL/Neon 路线；TiKV 仅参考其 Rust 存储、Raft、快照和故障恢复经验。

### ADR-011：MLS 采用对象级 + 行级双层标签模型

**结论**：JTDB MLS 采用对象级（库/模式/表/列）+ 行级双层标签模型。对象级 MAC 执行点先行落地；行级标记为目标架构，通过元组隐藏列（jt_label Oid，约 +4B/行）实现，TOAST、WAL、索引、逻辑复制和 dump/restore 均携带标签。访问控制采用 Bell-LaPadula 简单安全属性（不下读）、*-属性（不上写）与类别支配；受控降标需安全管理员审批并强制审计。读路径在计划期注入标签谓词以利用索引。

**原因**：表级 MAC 达不到等保四级/分保对细粒度标记和客体重用的要求；RLS 可被表 owner 绕过，仅作纵深防御。标签粒度决定元组格式与目录设计，必须在内核编码前冻结，否则返工成本最高。

**边界**：行级标签存储格式与谓词下推方案在存储专项中冻结；行级开启的 SLO 为合计 TPS 开销 ≤10%（基线待阶段 0 复核）；列级密钥钩子同步预留，为全密态演进留出路径。

### ADR-012：超级用户围栏与三权分立

**结论**：以可信角色体系替代单一 superuser：jt_sysadmin（实例/存储/备份/扩容）、jt_secadmin（账户、标签、策略、扩展白名单）、jt_auditor（审计查询/校验/导出，只读，配置变更双人复核）。内核所有 `superuser()` 判定点替换为基于 JtSecurityContext 的 `jt_role_check()`；`COPY PROGRAM`、`file_fdw`/`pg_read_server_files`、`dblink`、非受控服务端语言、大对象服务端任意读写等逃逸路径默认禁用，需扩展能力声明 + secadmin 白名单开启。初始化即三权分离，凭据密封分发并强制首次改密。

**原因**：PostgreSQL 超级用户可绕过一切安全检查，是安全数据库最大的围栏缺口；三权分立必须落到角色与权限矩阵，而非仅靠审计兜底。

**边界**：KMS 管理操作需 secadmin 与 KMS 管理员双人授权；OS root 无法直接获得任一数据库角色。

### ADR-013：KMS 租约、轮换与防回滚协议

**结论**：
- 组件持有 wrap 后 DEK + 租约（默认 15 分钟，可配），续租携带新鲜 attestation 摘要；
- 失效矩阵：租约过期后拒绝新会话、存量会话默认转只读（可配置）；审计中断时高危事件阻断、普通摘要本地 journal 排队（默认 fail-closed，降级配置变更需双人复核）；时间源异常拒绝签发新租约；
- 密钥轮换采用 journal 化状态机 Sealed → Prepare → Cutover → Drain → Rekey → Retire，崩溃后重放到确定状态，容忍混合 epoch；
- 每个 timeline 维护签名清单（对象集 + generation + key epoch），恢复先校验清单与对象代际再进入 Redo；防回滚计数器持久化于 KMS + 本地 TCM NV/安全文件双份；
- 可信时间采用 NTS/认证 NTP，RTC 跳变检测。

**原因**：KMS 失效语义、轮换崩溃一致性、对象层防回滚和可信时间四项不冻结，存储格式和协议接口无法定稿；旧 epoch 密文仍然有效，无防回滚则拿到存储访问权的攻击者可重放旧 Layer 版本。

**边界**：协议先经 TLA+/模型检查验证再实现；各默认值可配置。

### ADR-014：分支与时间线密钥作用域

**结论**：DEK 作用域定义为 (cluster, timeline, epoch, lsn_range)。分支创建时获得 BranchKeyGrant { parent_timeline, up_to_lsn, max_epoch, expires_at }，KMS 仅对 epoch ≤ max_epoch 且 LSN ≤ up_to_lsn 的父层 DEK 提供该分支的 unwrap；分支新写入使用自身 DEK 链；快照、备份、PITR 同理按 LSN/epoch 范围 scope。共享 Layer 不重加密。

**原因**：Neon 分支是 copy-on-write，父子 timeline 共享分支点之前的 immutable Layer，共享层只能有一个加密身份，"分支完全独立密钥"与之结构性冲突；按 LSN/epoch scope 既保持 CoW 经济性，又通过密钥授权边界实现隔离。

## 3. 尚需验证但不改变总体路线的问题

| # | 待验证问题 | 当前处置 |
|---|---|---|
| 1 | Neon 固定 commit 与 JTDB Compute 补丁的最小冲突面 | 锁定 Neon release 标签；加密下沉存储 I/O 边界、补丁 crate 化收窄冲突面 |
| 2 | WAL/Layer 加密具体源码位置和对象格式 | WAL 进 Compute/Safekeeper 内核；Layer 加密封装在存储 I/O 边界；对象格式冻结前完成密码专项评审 |
| 3 | Pageserver/Safekeeper 的 KMS 租约和恢复协议 | 已由 ADR-013 给出方案，剩余为实现级验证 |
| 4 | PostgreSQL 全访问路径的 MLS 覆盖 | 执行点矩阵由 ADR-011 固化；逻辑复制/CDC 过滤已补入实现方案 §3.6 |
| 5 | TLCP 纯 Rust 后端与 Tongsuo 后端的互操作和合规边界 | 保留为专项验证项 |
| 6 | 信创平台的 SM4、TCM、TEE 和对象存储适配 | 保留，随基座阶段双平台 CI 推进 |
| 7 | 单机嵌入模式和服务化模式的统一协议 | 保留，随单机多进程/profile 化验证推进 |
| 8 | Neon 上游同步、升级和长期维护机制 | 锁定与 rebase CI 已定；长期人力风险需管理层持续决策 |
