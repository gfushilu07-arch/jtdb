# 构建系统说明

本文是 JTDB 构建系统的文档。配置的**单一事实源是 `scripts/env.sh`**——所有构建容器与脚本必须 `source scripts/env.sh` 后工作，禁止各自定义 CARGO_HOME/PATH/头文件路径。

## 1. 为什么构建产物在缓存卷

主机主盘空间有限（曾只剩个位数 GB），**一切构建产物（Rust target、PG 安装树、日志、容器工具链）都落在缓存卷 `/Volumes/fushilu/.caches/jtdb/`**。仓库工作树内禁止出现 `target/` 目录。

## 2. 三条原则

1. **PG 头文件唯一来源 = fork 安装树**（`pg_install/`，其中 v18 已替换为 fork 安装树头文件）。官方 tarball 头文件缺 fork 符号（NEON_SMGR/SmgrId/privileged_role_name），只能作对照——此规则被 bindgen 失败实证两次（2026-09-03/04）。
2. **环境统一来自 env.sh**，新增脚本时禁止重新发明路径常量。
3. **Rust 工具链版本钉死 1.98.0**（`RUSTUP_TOOLCHAIN`），禁止 stable 漂移；与 `upstream/NEON_COMMIT` 的 BUILD_TOOLCHAIN 字段一致。

## 3. 缓存卷目录契约（`/Volumes/fushilu/.caches/jtdb/`）

| 目录 | 内容 | 生成者 |
|---|---|---|
| `rustup/`、`cargo/` | 主机侧 Rust 工具链与 crate 缓存 | rustup（env.sh 指定路径安装） |
| `rustup-container/`、`cargo-container/` | 容器侧 Rust 工具链与 crate 缓存（Linux aarch64） | 驱动脚本容器内自动安装 |
| `target/rust/` | Rust 统一 target（2026-09-04 合并原 neon-9129/neon-full 两套） | cargo（env.sh 的 CARGO_TARGET_DIR） |
| `target/c-pgxn/` | pgxn C 扩展构建（communicator 桥等，Linux） | pgxn-pg18-driver |
| `target/neon-9129/`、`target/neon-full/` | 旧双 target（只读保留作增量回退，勿再写入） | 已合并 |
| `pg_install/` | bindgen 用 PG 头文件树 v14~v18；**v18 = fork 安装树头文件**（含 NEON_SMGR/SmgrId，已打 strl 补丁） | scripts/build-pg.sh |
| `pgxs-pg18-fork/` | fork PG18 完整安装（bin/lib/pgxs，含 neon*.so；Linux 二进制） | pgxn-pg18-driver 阶段 0 |
| `distrib/` | neon_local distrib 树：`v18`（→pgxs-pg18-fork）+ `v16` 符号链接（storcon 只认 v16/v15/v14/v17） | full-path-smoke 建链 |
| `builds/neon-build/walproposer-lib/` | libwalproposer.a + libpgport.a + libpgcommon.a（供 Rust walproposer 链接） | pgxn 容器构建 |
| `logs/` | 全部构建与冒烟日志（cargo-check-*.log、pgxn-pg18-errors.log、compute-smoke-pg18.log 等） | 各脚本 |
| `repos/` | 上游共享克隆（预留） | — |
| `builds/` 其余 | 预留：容器镜像 tar、增量产物 | — |

`upstream/neon/build` 是指向 `builds/neon-build` 的符号链接（build.rs 需要的 `build/walproposer-lib/` 相对路径）。

## 4. 脚本清单

| 脚本 | 用途 | 前置 |
|---|---|---|
| `scripts/env.sh` | 单一事实源（本文件 §2） | — |
| `scripts/build-pg.sh` | 容器构建 PG 17.5/16.9/15.13/14.18 头文件安装树（含 macOS strl 补丁、删 Linux bin） | docker |
| `scripts/pgxn-pg18-driver.sh` | 三阶段：PG18.2-fork pgxs 持久化构建 → communicator Rust 桥 → pgxn/neon C 编译错误收集 | docker + 缓存卷 |
| `scripts/compute-smoke-pg18.sh` | 实装载冒烟：neon/pgxn 链安装进 fork PG18 → initdb → shared_preload → CREATE EXTENSION + SQL | pgxs-pg18-fork |
| `scripts/full-path-smoke-pg18.sh` | Neon 存储全链路冒烟：neon_local 拓扑（storcon/ps/sk/endpoint）→ SQL | Rust 五件套 + pgxs-pg18-fork |

## 5. 构建镜像

`Dockerfile.jtbuild` 定义 `jtbuild:bookworm-20260904` 镜像（固化 apt 依赖层：build-essential/clang/libclang-dev/protobuf-compiler/libcurl4-openssl-dev/strace/procps），取代浮动的 `debian:bookworm` + 每次在线 apt。构建：

```bash
source scripts/env.sh
docker build -t "$JTDB_BUILD_IMAGE" -f Dockerfile.jtbuild .
```

容器内 Rust 工具链仍走缓存卷挂载（`rustup-container/cargo-container`），镜像只固化系统依赖层。

## 6. 已知约定陷阱（踩过的坑，勿再踩）

1. **pgxn/neon/Makefile 默认目标不是 `all`**（首 target 是 `communicator_process.o`）——必须显式 `make all`，否则只构建默认目标即正常退出（2026-09-03 多轮"构建中断"假象的根因）。
2. **Linux 构建的 `pg_install/*/bin` 必须删除**：postgres_ffi build.rs 检测到 pg_config 会尝试执行（Linux 二进制在 macOS 上必败），删除后走头文件 fallback。
3. **pg_config.h 的 strl 补丁**：Linux 构建头的 `HAVE_DECL_STRLCAT/STRLCOPY=0` 在 macOS bindgen 时与 Apple libc 冲突，需置 1（build-pg.sh 已固化）。
4. **neon_rmgr 等模块需显式安装**：neon.c 预加载链会 `load_file("$libdir/neon_rmgr")`；`neon_test_utils/neon_walredo/neon_utils` 供 compute 全链使用。
5. **PG18 reorderbuffer API 改名**：GetChange→AllocChange、GetTupleBuf→AllocTupleBuf（跟随 vendor/postgres-v18）。
6. **PG18 LWLock tranche 请求必须在 shmem_request_hook 内**（_PG_init 阶段请求直接 FATAL）。
7. **storage_controller 二进制需与 neon_local 同目录**；storcon 只认 distrib 下 v16/v15/v14/v17 布局。
8. **macOS 冒烟的僵尸 postmaster**：storcon 内部 PG（`postgres -D .../storage_controller_db`，端口 1235）不在旧 pkill 模式内——残留进程占端口后，新 initdb 的数据目录被 storcon 连接时报 `pg_filenode.map missing` 退出，全链路卡死。清理必须含该模式并轮询确认端口释放（full-path-smoke-macos.sh §0）。
9. **endpoint_storage/storage_broker 二进制缺失**：`neon_local init` 会启动 endpoint_storage(9993) 且约定 broker(50051)；cargo 五件套（neon_local/pageserver/safekeeper/storage_controller/compute_ctl）之外需补 `cargo build -p endpoint_storage -p storage_broker`，endpoint start 会连 9993。
10. **timeline 版本由 tenant create 决定**：`neon_local init/tenant create` 自动创建初始时间线并映射为 main，默认 PG17；单独 `timeline create --branch-name main` 必撞 "branch already mapped"。要 PG18 时间线必须 `tenant create --pg-version 18`（endpoint 也要 `--pg-version 18`，否则 basebackup 是 PG17 镜像、compute 起不来）。
11. **PG18 注册制 smgr 必填字段**：f_smgr 新增 `.smgr_owns/.smgr_fd`，内核 smgropen 逆序遍历 owns 决定归属——漏赋值即空指针 SIGSEGV（neon_smgr 与 walredo inmem_smgr 双双踩过）；smgrregister 还会 strcmp smgr_name，NULL 同样崩。
12. **PG18 AIO 读状态机**：neon_startreadv 不能只同步读+打 HF_SYNCHRONOUS 标志——handle 停在 HANDED_OUT 时 pgaio_io_wait 直接 PANIC（owner 要求 SUBMITTED/COMPLETED_*）。正确序列：call_stage（buffer 引针，与完成回调对称）→ 清 handed_out_io → prepare_submit → process_completion（**result 单位是块数不是字节**，md 的字节→块换算在 MD_READV 完成回调里，neon 未注册须自己给块数；传字节→nblocks_done 越界→随机 SIGBUS）。
13. **PG18 walredo 独立进程启动适配**：CalculateShmemSize/PMSignalShmemInit→MaxLivePostmasterChildren 依赖 num_pmchild_slots，须在 InitializeShmemGUCs 之前 InitPostmasterChildSlots()；LOCALLOCK 哈希（PG18 移入 BaseInit→InitLockManagerAccess）须自补，否则 redo 触及 vm_extend 锁路径即 hash_search(NULL) 崩。
14. **ControlFileData 布局版本相关**：postgres_ffi 顶层 re-export 的是 v14 绑定；PG18 起结构有变（crc 偏移 292 vs 288），pageserver 导入 initdb 产物必须按 PG_VERSION 分派解码，否则 "invalid CRC in control file"。
15. **data checksums 与 Neon 架构冲突（ADR-015 关键决策）**：fork initdb 默认 `data_checksums=true`，而 Neon 把"磁盘"上移到 pageserver——delta 应用/walredo 产出的页镜像 pd_checksum 是旧值（原版 PG 在 FlushBuffer→PageSetChecksumCopy 才计算），compute 读回校验必失败且失败页随机。修复=pageserver 在 GetPage 应答时对非全零页按 checksum_impl.h 算法（32 路 FNV-1a、pd_checksum 置零保留 pd_flags、混 blkno、(x%65535)+1）重算盖章；索引构建走 smgrextend 绕过 FlushBuffer，需在 neon_extend 的 lfc_write 前补盖章。上游 Neon 靠默认关闭校验和规避，此为 fork 校验和增强的必配项。
16. **walredo 进程必须 io_method=sync**（PG18）：模拟 shmem 无 AIO worker 队列，默认 worker 下 vm_extend 读路径 AsyncReadBuffers→pgaio_io_acquire_nb 直接段错误；在 InitAuxiliaryProcess 后 SetConfigOption("io_method","sync") 强制。
