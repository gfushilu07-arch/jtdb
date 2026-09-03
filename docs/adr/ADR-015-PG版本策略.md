# ADR-015：PG 版本策略——第一版必须支持最新大版本

| 项 | 值 |
|---|---|
| 日期 | 2026-09-03 |
| 状态 | 已确认（决策方要求：v1 支持最新 PG 大版本；性能为一级约束） |
| 关联 | ADR-001（上游失活条款）、《外部技术审计》§9 决策门、规划 §9.2/§5 |

## 结论

1. **JTDB v1 必须支持 PostgreSQL 最新大版本（当前 PG 18）**，版本矩阵目标：PG 18 + 17（14~16 是否保留待工作量评估，默认保留但不作承诺）。
2. 路径：**postgres 侧复用 Neon 官方 fork 分支**，neon 仓库侧 JTDB 自研回合。
3. 性能为一级约束：PG 18 的异步 I/O（AIO）等新特性收益不得被 JTDB 安全层（MAC/行级标记/加密/审计）吃掉，SLO 以 PG 18 基线重新校准。

## 事实基础（2026-09-03 核实）

| 事实 | 来源 |
|---|---|
| 公开 Neon 仓库（冻结 main）**没有 PG 18 支持**：revisions.json 止步 17.5，.gitmodules 无 postgres-v18 | upstream/neon FETCH_HEAD 实测 |
| neon.com 的"Postgres 18 is out"博客指其托管服务，PG18 集成在 Databricks 私有 fork，未进公开仓库 | 同上（公开 pgxn/neon 无 PG18 兼容提交） |
| **neon postgres fork 的 `REL_18_STABLE_neon` 分支公开且活跃**：基于 PG 18.2，含 Neon RMGR（RM_NEON_ID=134）、smgr/md.c 钩子、lwlock 扩展、PG18 FPI 优化（LKB-5974），2026-02 仍在合并 upstream REL_18_STABLE，最后提交 2026-04-08 | github.com/neondatabase/postgres 分支实测（a616eef） |
| release-9129 的 postgres_ffi 为 v14~v17 硬编码（for_all_postgres_versions 宏、PgMajorVersion 枚举、pg_constants_vXX 模块） | libs/postgres_ffi 实测 |

## 责任分层

| 层 | 来源 | 工作量归属 |
|---|---|---|
| PG 源码（vendor/postgres-v18） | Neon fork REL_18_STABLE_neon（18.2，a616eef），JTDB 跟随其小版本节奏 | 复用 + pin 管理 |
| postgres_ffi / postgres_versioninfo | JTDB：枚举加 PG18、宏分发加 V18、pg_constants_v18（WAL 格式/控制文件差异按 PG18 头文件核实）、PgVersionId 上界 190000 | **已完成第一层接线**，剩余由编译器驱动 |
| pgxn/neon C 扩展（pagestore_smgr 等） | **JTDB 自研 PG18 兼容**：smgr 与 PG18 AIO/read-stream 的对接是核心难点（私有 fork 已证明可行，公开代码缺位） | 最大工作量项 |
| compute_tools / control_plane | 跟随 PgMajorVersion 枚举的机械适配 | 小 |

## 风险与对策

1. **pgxn/neon × PG18 AIO**（最大技术风险）：PG18 的 pgaio 层改变了本地 I/O 路径，Neon 远程页读取（自定义 smgr）需要与 AIO worker 模式共存。对策：以私有 fork 已存在的事实为可行性依据；先编译后基准；基准必须覆盖 AIO on/off × Neon 存储路径。
2. **公开 pgxn/neon 冻结点缺 PG18 修复**：上游公开 pgxn 在 2025-07 冻结于 PG17 兼容态，2025-09 起私有 fork 的适配未公开。JTDB 按"编译错误清单驱动"自研，工作量按周计。
3. **v18 常量占位**：pg_constants_v18.rs 当前从 v17 复制（占位），XACT_XINFO_HAS_DROPPED_STATS 等位偏移必须逐项对照 PG18 头文件核实后才能用于 WAL 解析——在 WAL 解析路径启用 v18 前这是**硬门禁**。
4. **bindgen 头文件来源**：编译验证阶段 v18 头文件可用官方 18.2 tarball；**正式 compute 构建必须用 vendor/postgres-v18（fork）源码**，两者 core 结构以 fork 为准。

## 执行记录

| 日期 | 进展 |
|---|---|
| 2026-09-03 | 第一层接线完成（子模块提交 4dc611e，分支 jtdb/release-9129-pg18）：postgres_versioninfo 加 PG18 变体（含 PgVersionId 上界 190000）；postgres_ffi 三个宏分发 + build.rs 五版本循环 + pg_constants_v18（占位）；wal_decoder 三处 match 补 PG18 臂（heap/neon/dbase 结构经 vendor/postgres-v18 头文件核实与 PG17 一致）；pageserver walingest CheckPoint 补 V18 臂；revisions.json 加 v18=18.2@a616eef；workspace `cargo check`（除 safekeeper/walproposer C 库项）绿线 |
| 待办 | ②pgxn/neon C 扩展 PG18 兼容（smgr×AIO 对接，最大项）③safekeeper/walproposer C 库构建后补入检查范围 ④v18 常量逐项核实（WAL 解析启用前硬门禁）⑤PG18 compute 实构建（用 fork 源码）⑥四象限基准 |

## 性能约束（响应"注意性能问题"）

- 规划 §5 SLO 基线环境升级为 PG 18（基准方法见规划 §9.3），所有安全层开销数字在 PG18 上重测；
- 新增基准维度：`AIO on/off × 本地存储/Neon 存储路径 × 安全层 on/off` 四象限；
- 行级标记谓词不得阻断 PG18 read-stream 预读的批量化收益（谓词下推实现需在 read-stream 批量路径验证）；
- 验收顺序：先证明"JTDB on PG18 ≈ vanilla PG18"，再证明"安全层增量 ≤ SLO"。
