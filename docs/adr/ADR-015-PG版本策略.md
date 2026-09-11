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
| 2026-09-04（续） | **全链路冒烟推进与受阻**：①neon_local 包装 bug 修复绕过——storcon 二进制需手动 bootstrap（initdb→createdb→direct binary + `--use-local-compute-notifications --neon-local-repo-dir`），包装器 `storage-controller start` 对 repo-dir 约定不一致（ADR 遗留问题）；②tenant 创建成功（经 storcon→pageserver 路径）；③**timeline create 受阻**：pageserver spawn initdb ENOENT——distrib 符号链接已改为相对路径（`../pgxs-pg18-fork`，宿主/容器双端可解析）待重验；④**工程环境事实：Docker Desktop 本日两次崩溃**（全容器 SIGKILL，含用户自有容器），单容器 20 分钟级全链路冒烟在本机不可持续，应在 CI Linux 环境执行（build/README.md 与规划 §9.3 已注明）。脚本修复已入库 |
| 2026-09-05 | **全链路冒烟深度推进**（本机多轮迭代）：①修复 distrib 符号链接宿主/容器路径不一致（改相对链接 `../pgxs-pg18-fork`）；②发现并修复 **distrib/v17 语义错误**——曾被链接到 fork PG18.2 导致 initdb 产物 CRC 错位，已改为真实 PG17.5 完整安装；③safekeeper 注册成功（control API POST + version 字段 + Active 策略，心跳确认 "1 safekeepers, 0 offline"）；④**tenant 创建成功、timeline 创建成功**（重试幂等报错已确认为正常）；⑤endpoint 创建成功、endpoint start 已启动 compute_ctl。当前卡点：endpoint start 编排在 timeline 幂等重试后仍有残余失败路径，导致 compute 未完全拉起——下一轮从 ep.log/compute.log 取证定位。**环境事实：Docker Desktop 当日两次崩溃（全容器 SIGKILL 含用户自有容器），长时冒烟应迁 CI Linux** |
| 待办 | ①endpoint start 编排修复（timeline 幂等处理）→ 全链路 SQL 走通 ②startreadv 真异步第二层 ③四象限基准 |
| 2026-09-03（续） | **Rust 侧 PG18 闭环**：①`libwalproposer.a` 按 fork PG18 头文件重编产出（walproposer_compat 的 pq_copymsgbytes 签名随 PG18 改 void*）；②walproposer Rust 绑定 build.rs 切 v18 + compat 头补 `storage/smgr.h`（PG18 SmgrId 声明需要）；③**工程规则落地：`pg_install/v18` 已替换为 fork 安装树头文件**（官方 tarball 头缺 NEON_SMGR/SmgrId 符号导致 bindgen 失败——印证"compute 构建必须用 fork 源码"规则，build-pg.sh 的 v18 官方 tarball 产物仅保留做对照）；④**全 workspace `cargo check` 绿线（含 safekeeper/walproposer，无排除项）——决策门任务 1 完全闭环** |
| 2026-09-04 | **PG18 compute 实装载冒烟通过**（scripts/compute-smoke-pg18.sh）：fork PG18 + `shared_preload_libraries='neon'` 启动成功，`CREATE EXTENSION neon`（v1.6）+ 建表/插入/查询全通过，server 存活确认。预加载链逐级解决：①libpagestore 跨文件引用 static AtEOXact_neon → 注册逻辑收敛进 neon_register_smgr_pg18；②neon_rmgr.so 需单独构建安装（neon.c 会 load_file）；③符号改名跟随 fork：ReorderBufferGetChange→AllocChange、GetTupleBuf→AllocTupleBuf、==17 守卫扩为 >=17；④PG18 LWLock 请求时机新规：必须在 shmem_request_hook（LwLsnCacheShmemRequest）内，_PG_init 阶段请求被内核拒绝。内核日志确认 `registered custom resource manager "neon" with ID 134`。注：当前冒烟为无 pageserver 的 vanilla 模式（smgr 不注册），Neon 存储路径全链路属 compute_tools/控制面阶段 |

## 性能约束（响应"注意性能问题"）

- 规划 §5 SLO 基线环境升级为 PG 18（基准方法见规划 §9.3），所有安全层开销数字在 PG18 上重测；
- 新增基准维度：`AIO on/off × 本地存储/Neon 存储路径 × 安全层 on/off` 四象限；
- 行级标记谓词不得阻断 PG18 read-stream 预读的批量化收益（谓词下推实现需在 read-stream 批量路径验证）；
- 验收顺序：先证明"JTDB on PG18 ≈ vanilla PG18"，再证明"安全层增量 ≤ SLO"。

## 执行记录（续）

| 日期 | 事项 |
|---|---|
| 2026-09-06 | **macOS 原生全链路 SQL 全绿**：storcon→broker→endpoint_storage→pageserver→safekeeper→PG18.2 compute（含 neon.dylib 全家桶）；CREATE TABLE/INSERT/SELECT 通过。累计修复 PG18 移植缺陷 12 项（详见 build/README.md 陷阱 8~16）：僵尸 postmaster 清理、endpoint_storage/broker 二进制、timeline PG 版本、ControlFileData 版本分派、neon smgr owns/fd、AIO 读状态机（call_stage→prepare_submit→process_completion，result=块数）、walredo 四项（smgr_name/owns、PMChildSlots、InitLockManagerAccess、io_method=sync+AioShmemInit）、smgrinit 无 guard 的 on_proc_exit 泄漏、inmem smgr startreadv/maxcombine、**data checksums 服务端盖章**（fork 开启校验和后 pageserver 重建页须重算 pd_checksum，算法离线验证 6/6） |
| 2026-09-06 | **功能测试套件 22/22**：scripts/test-suite-pg18.sh（DDL/序列/JSON/numeric/bytea/事务回滚/冲突中止/GIN/VACUUM/2 万行跨页读/CHECKPOINT/ALTER/4 并发/kill -9 崩溃恢复/恢复后可写） |
| 2026-09-06 | **单元测试**：postgres_ffi 13、wal_decoder 6、control_plane 1、safekeeper 24、pageserver_api 51 全绿；pageserver lib 组跑 200/264（64 失败为 macOS eviction/upload 测试隔离类，单跑均过，非 PG18 改动路径——遗留跟踪） |
| 2026-09-06 | **四象限基准（macOS debug 构建，仅相对值）**：pgbench s10/4c/30s。本地-sync 1221/9221（混合/只读 TPS）、本地-worker 1720/14538、Neon-sync 86.9/510.8、Neon-worker 157.9/524.3。Neon 路径 1/7~1/18 于 vanilla：debug 构建放大 CPU 开销 + 页重建/传输/盖章；正式数字按 §9.3 Linux NVMe + release 复测。Neon 内部 worker 略优于 sync（157.9 vs 86.9），待 release 构建复核 |
| 遗留 | ①正式基准待 Linux NVMe（用户已提出可提供）②startreadv 真异步第二层 ③PG17 对照与 PG14/15/16 compute 验证（macOS pgxn v14~v17 构建未做）④pgbench -i 过程暴露 walredo 大负载稳定性已修复，持续观察 |
| 2026-09-06 | **版本矩阵范围判定**：pgxn v14~v17 构建需对应版本的 Neon fork 安装树（access/neon_xlog.h、f_smgr 为 fork 专有；官方 tarball 不可用）。macOS 侧 fork 仅 v18；v14~v17 fork 安装树在 Linux 构建产物（JTDB_PG_INSTALL）。版本矩阵回归归入 Linux/CI 环境（规划 §9.3），macOS 验收聚焦 PG18 |
| 2026-09-07 | **版本矩阵全绿（macOS 原生）**：v14.18/v15.13/v16.9/v17.5 四个 fork 经 worktree 共享对象库检出（revisions.json pinned SHA）→ 原生 release 构建 → pgxn 全家桶 → 全链路 SQL 冒烟，5/5 版本（含 v18.2）全部通过。修复项：①neon_rmgr_decode reorderbuffer API 宏映射（<18 Get* / ≥18 Alloc*）②PG18 专有 include（aio/latch/waiteventset/guc_hooks）版本守卫 ③inmem/pagestore smgr_name 守卫 ④endpoint.rs effective_io_concurrency macOS 平台守卫（PG17 无 posix_fadvise 拒绝非 0）⑤冒烟脚本 SMOKE_PG_VERSION 参数化 + neon 扩展名 .dylib/.so 兼容 ⑥多版本 .o 残留陷阱确认（切版本前必须 clean，陷阱 2 变体）。v14~v17 源码经 git worktree 共享 v18 对象库（零拷贝），磁盘紧张时的推荐做法 |
| 2026-09-09 | **Linux 真机验收（snsc-prod-基础2，CentOS 系 Alibaba Cloud Linux 3，x86_64，2C/7.3G/148G 盘，内核 5.10 io_uring 就绪）**：①千橙产出的 glibc 2.28 zigbuild 七件套 + fork 安装树直接复用（传输经 electerm zmodem 117M，md5 一致；两台云主机间安全组不通，HTTP 中转被拦）；②部署修复：v18 软链指向、fork 二进制 RUNPATH 硬编码 /root/jt（LD_LIBRARY_PATH 兜底）、**memlock 64KB→256MB**（tokio-epoll-uring 锁定内存不足导致 basebackup 无限重试，limits.d 配置）；③**全链路冒烟 FULLPATH_SMOKE_DONE + 功能套件 22/22 SUITE_OK**（含 kill -9 崩溃恢复）；④**四象限 release 基准（正式数字，pgbench s10/4c/60s，混合/只读 TPS）**：本地-sync 886/6269、本地-worker 887/6433、Neon-worker 124/404、Neon-sync 144/405。Neon 路径约 1/7（混合）~1/16（只读）于 vanilla——release 构建下比率与 macOS debug 一致，确认开销主要在页重建/传输/盖章的架构性成本而非构建优化；⑤pageserver virtual_file_io_mode=DirectRw（io_uring direct IO）在生产路径运行确认。工程事实：Linux 下 neon.so 必须静态链 FRONTEND libpq.a + 编码函数别名包装 + 前端 canary（子模块 6eb8bb6），否则动态 libpq 被主程序后端符号插值 |
| 遗留（更新） | ①startreadv 真异步第二层（neon_startreadv 当前 PGAIO_HF_SYNCHRONOUS 同步语义，基础2 io_uring 环境已就绪可开发）②安全层 on/off 象限叠加 ③PG14~v17 fork 安装树 Linux 侧复验 |
| 2026-09-10 | **startreadv 真异步第二层实验闭环（实测否定批量化，保持单块）**：①机制核实——read_at_lsnv 批内注册即并发在途，maxcombine=1 迫使 read-stream 每块独立 1 RTT 为串行点假设；②A/B 实测（基础2）：放开 maxcombine=PG_IOV_MAX 后 seq scan 100 万行 28.7s vs 单块 3.9s（7 倍退化），pgbench 点查 152/418 vs 基线 124/404（噪声级）；③归因——read-stream 在 HF_SYNCHRONOUS 下 lookahead 失效，批化放大整批同步阻塞；communicator ring 单请求单 slot 无并发收包收益；④结论：单块同步语义为实测最优（fork 5e50b48），handle 级真异步需 ring 共享化+独立接收线程（跨进程完成驱动），列为后续工作；②基础2 交付态：maxcombine=1 neon.so + 冒烟/套件/基准脚本可复跑 |
| 遗留（更新） | ①handle 级真异步（communicator ring 共享化 + 独立接收线程）②安全层 on/off 象限叠加 ③PG14~v17 fork 安装树 Linux 侧复验 |
| 2026-09-10（续） | **版本矩阵 Linux 复验全绿（ADR-015 遗留③闭环）**：基础2（Alibaba Cloud Linux 3，x86_64）从 vendor pinned commit 构建 v14.18/v15.13/v16.9/v17.5 四个 fork 安装树 + pgxn 全家桶，全链路冒烟 5/5 版本通过（含 v18，PG_VERSION 逐一实证）。逐版本踩坑清单：①tar 打包的 macOS 构建产物（Mach-O 可执行/死 symlink/header-stamp 时间戳）必须清理——generated-header-symlinks 被 stale stamp 挡住致 errcodes.h 缺失；②PG14 make install 不装 libpq-fe.h/internal 头与 initdb/psql/scripts 等 bin（-k 跳过所致）需从源码补；③**PG14 的 walproposer 借 walsender 路径，需 libpqwalreceiver.so 在 $libdir**（v15+ 用 Neon 直连模式不需要；缺失时 dfmgr 下载钩子请求 compute_ctl 的 remote_ext_base_url，本地环境未配置而失败）；④**neon.so 加 -Wl,-Bsymbolic-functions**：静态链 libpq.a 的 canary/编码符号在运行期被主程序 --export-dynamic 后端版插值，PG14~16 全触发（v17/v18 因 neon_compat 自绑定未暴露），Bsymbolic 一招根治；⑤neon_compat.c 拆分：canary 全版本需要，编码转发仅 PG17+。git 路径弃用（1G 内存机 pack-objects 卡死 40 分钟），vendor 源码包 + zmodem 传输（35M/版本）为可靠通路 |
| 遗留（更新） | ①handle 级真异步（communicator ring 共享化 + 独立接收线程）②安全层 on/off 象限叠加 |
| 2026-09-11 | **版本矩阵套件级复验（Linux，升格）**：冒烟级之上，22 断言套件（含 kill -9 崩溃恢复/恢复后可写）逐版本跑通——v14.18/v15.13/v16.9/v17.5 各 22/22 SUITE_OK（v18 此前已绿）。test-suite-qc.sh 完成 SMOKE_PG_VERSION 参数化（与冒烟脚本同级）。至此 Linux 侧版本矩阵复验达"冒烟+套件"双级全绿。挂账项状态更新：①安全层 on/off 象限——libs/extensions 仍为骨架占位（.gitkeep），挂账至安全层主工程启动；②handle 级真异步——批量化实验已证无点查收益且 read-stream 同步结构未变，挂账至 SLO 验收阶段（触发条件：实测 GetPage RTT 占比超阈值且可量化并行收益） |
| 2026-09-11（续） | **安全层主工程启动（ADR-015 遗留①首个交付）**：libs/ 独立 workspace 建立，jt-crypto-api（Aead/Digest256/SelfTest trait + power_on_self_test fail-closed）与 jt-crypto-sm（pure-rust-backend）落地：Sm4Gcm 自含 GHASH 组装、AAD/CT 域隔离补零（跨域混块被 RFC 8998 实测捕获并修复）、KAT 三件全部用权威向量（GB/T 32907/32905 附录 A + RFC 8998 附录 A.1，密文+tag 逐字节一致；过程中纠正了两处凭记忆写的错误向量——教训：密码测试向量必须以标准文本/权威 RFC 为准，禁止凭记忆填写）。测试 6/6 绿。Tongsuo backend（密评主路径）与 jt-encrypted-object v1 读写协议（docs/04 冻结布局）为下一步 |
| 2026-09-11（二） | **jt-encrypted-object v1 读写协议落地（安全层第二交付）**：header（130B，含 header_digest=SM3(0..98) 自校验；文档 04 头长矛盾按无重叠原则裁决 130 并回写文档）/Metadata TLV（未知 type 前向兼容）/chunk AEAD（nonce=base_nonce XOR u96(c)，AAD 按 §4.3 字节级布局绑定 digest/type/epoch/generation/index/offset/len）/发布原子性（.part → sealed → rename）。§10 测试矩阵 8/8：随机页读（跨 chunk 边界）+ 篡改 header/chunk/交换 chunk/截断/.part/错 DEK/nonce 唯一性全部按预期拒绝或通过。实现期抓到 3 个真实缺陷：①chunk 读取偏移未计入 tag 16B（密文布局偏移错位）；②GHASH AAD/CT 跨域混块（RFC 8998 捕获）；③测试并行目录冲突。Tongsuo backend 与 SM2 trailer 签名为下一步 |
| 2026-09-11（三） | **SM2 trailer 签名落地（安全层第三交付）**：jt-crypto-api 增 SignatureKey/SignatureVerifier trait；jt-crypto-sm 增 Sm2Signer/Sm2Verifier（libsm 适配，私钥 Drop 零化，r||s 各 32B 定长编码）；jt-encrypted-object 集成 trailer：布局裁决 signature(64B)||u16 sig_len（长度置尾），flags.bit3=TRAILER_SIGNED，Writer 可选签名（msg=header_digest||metadata_digest||last_chunk_tag），Reader 延迟验签（verify_trailer，对应 §11.4 抽样策略）+ sig_len 越界防御（篡改 len 字段不可 panic）。测试 20/20（crypto-sm 9 + encrypted-object 11，含签名回环/异钥拒绝/篡改 sig 内部字节检出/无签名兼容）。Tongsuo backend 与 pageserver 边界加密接入为下一步 |
