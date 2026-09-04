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
| 2026-09-03 | **pgxn/neon PG18 编译驱动建立**（scripts/pgxn-pg18-driver.sh，三阶段容器：PG 18.2 fork pgxs 持久化构建 / communicator Rust 桥 / C 编译错误收集；全部产物在缓存卷）。**真实错误清单定性**：①f_smgr 函数表变化——PG18 新增 `smgr_startreadv(PgAioHandle)`（异步 AIO 启动）、`smgr_maxcombine`，同时移除 `smgr_start_unlogged_build/finish_unlogged_build_phase_1/end_unlogged_build/smgr_read_slru_segment`（改为 smgr.h 钩子指针 start_unlogged_build_hook 等）；②lwlsn 钩子类型随"Move LastWrittenLsnLock to neon extension"迁移，需在扩展内定义；③INT64_HEX_FORMAT/UINT64_HEX_FORMAT 需适配 PG18 的 INT64_MODIFIER；④Custom_XLogReaderRoutines 从 xlogreader.h 移至 replication/logical.h（fork 已提供，include 调整即可）；⑤privileged_role_name 等 fork GUC 符号——用官方 tarball 头文件编译时误报，**必须用 vendor/postgres-v18（fork）头文件**（驱动已改为 fork 源码 VPATH 构建） |
| 2026-09-03 | **v18 常量硬门禁第一轮核实完成**：XACT_XINFO_HAS_DROPPED_STATS(1<<8)、XLOG_DBASE_*(0x00/0x10/0x20)、BKPIMAGE_*(0x02/0x04/0x08/0x10)、PGDATA_SUBDIRS（23 项逐字比对）全部与 PG17 一致；SIZEOF_RELMAPFILE=524 维持有效（MAX_MAPPINGS=64 与 PG17 相同；期间一次误判 532 已按源码回滚——门禁流程生效的例证）。剩余待核：XlHeapInsert 等 WAL 解析启用前的逐项核对 |
| 2026-09-03 | 工程环境事实：Docker VM 默认内存下 make 会在 C 编译阶段被 OOM 静默击杀（两次复现，均死于 communicator_process.c 之后的文件）；驱动已改为分阶段容器缓解，正式构建建议在 CI Linux 原生环境执行（规划 §9.3 CI 最小集） |
| 2026-09-03 | **pgxn/neon PG18 兼容第一层完成（子模块提交 ac201a5）**：全部 22 个 C 文件在 fork PG18 头文件下编译通过，**neon.so 链接产出（199MB）**。修复清单：①smgr 注册制（smgrregister + neon_owns 谓词 + unlogged/SLRU 全局钩子挂载，libpagestore 注册点改造）②neon_startreadv 同步语义 AIO 适配（PGAIO_HF_SYNCHRONOUS + set_target_smgr，真异步为第二层）③neon_maxcombine（保守返回 1）④lwlsn：block 级钩子降级为扩展内部函数 + LastWrittenLsnLock 改 named tranche（neon_lwlsn）⑤INT64_MODIFIER→<inttypes.h> 版本分支 ⑥WL_ 标志头文件迁移 ⑦ReplicationSlotAcquire 新签名。**工程教训**：pgxn/neon/Makefile 默认目标不是 all（首 target 是 communicator_process.o），必须显式 `make all`——此前多轮"构建中断"实为此假象 |
| 2026-09-04 | **Neon 存储全链路推进**：①Rust 五件套容器构建完成（neon_local/pageserver/safekeeper/compute_ctl/storage_controller，构建 24 分钟，产物在缓存卷 target/neon-full，约 2.3GB）；②pageserver/safekeeper 成功启动运行（pageserver HTTP 9898、safekeeper 5454/7676）；③neon_local 拓扑约定摸清：POSTGRES_DISTRIB_DIR 指向 distrib 树（storcon 只认 v16/v15/v14/v17，用符号链接 v16→fork PG18 解决）、neon_local 二进制同目录需放 storage_controller、Makefile 默认目标非 all。④**受阻点**：`neon_local storage-controller start` 在读取 `.neon` 后无输出退出（strace 取证：读 .neon 目录后 rt_sigsuspend，不进入 initdb/监听；NEON_REPO_DIR 两种取值均复现）——neon_local 包装与 storage_controller 二进制的 repo/config 路径约定待源码级核对（storage_controller 包 main 的 config 解析）。其余组件就绪，此为全链路最后一环 |
| 待办 | ①storage_controller 启动修复（repo-dir 约定）→ tenant/endpoint 全链路 SQL ②startreadv 真异步第二层 ③四象限基准 |
| 2026-09-03（续） | **Rust 侧 PG18 闭环**：①`libwalproposer.a` 按 fork PG18 头文件重编产出（walproposer_compat 的 pq_copymsgbytes 签名随 PG18 改 void*）；②walproposer Rust 绑定 build.rs 切 v18 + compat 头补 `storage/smgr.h`（PG18 SmgrId 声明需要）；③**工程规则落地：`pg_install/v18` 已替换为 fork 安装树头文件**（官方 tarball 头缺 NEON_SMGR/SmgrId 符号导致 bindgen 失败——印证"compute 构建必须用 fork 源码"规则，build-pg.sh 的 v18 官方 tarball 产物仅保留做对照）；④**全 workspace `cargo check` 绿线（含 safekeeper/walproposer，无排除项）——决策门任务 1 完全闭环** |
| 2026-09-04 | **PG18 compute 实装载冒烟通过**（scripts/compute-smoke-pg18.sh）：fork PG18 + `shared_preload_libraries='neon'` 启动成功，`CREATE EXTENSION neon`（v1.6）+ 建表/插入/查询全通过，server 存活确认。预加载链逐级解决：①libpagestore 跨文件引用 static AtEOXact_neon → 注册逻辑收敛进 neon_register_smgr_pg18；②neon_rmgr.so 需单独构建安装（neon.c 会 load_file）；③符号改名跟随 fork：ReorderBufferGetChange→AllocChange、GetTupleBuf→AllocTupleBuf、==17 守卫扩为 >=17；④PG18 LWLock 请求时机新规：必须在 shmem_request_hook（LwLsnCacheShmemRequest）内，_PG_init 阶段请求被内核拒绝。内核日志确认 `registered custom resource manager "neon" with ID 134`。注：当前冒烟为无 pageserver 的 vanilla 模式（smgr 不注册），Neon 存储路径全链路属 compute_tools/控制面阶段 |

## 性能约束（响应"注意性能问题"）

- 规划 §5 SLO 基线环境升级为 PG 18（基准方法见规划 §9.3），所有安全层开销数字在 PG18 上重测；
- 新增基准维度：`AIO on/off × 本地存储/Neon 存储路径 × 安全层 on/off` 四象限；
- 行级标记谓词不得阻断 PG18 read-stream 预读的批量化收益（谓词下推实现需在 read-stream 批量路径验证）；
- 验收顺序：先证明"JTDB on PG18 ≈ vanilla PG18"，再证明"安全层增量 ≤ SLO"。
