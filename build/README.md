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
| `scripts/full-path-smoke-qc.sh` | Linux 真机全链路冒烟（jtuser 运行、/usr/sbin/ss 端口检查、LD_LIBRARY_PATH 兜底） | 千橙/基础2 布局（§6 陷阱 19） |
| `scripts/test-suite-qc.sh` | 22 断言功能套件 Linux 适配版（含 kill -9 崩溃恢复） | full-path-smoke-qc.sh 全绿后 |
| `scripts/full-path-smoke-macos.sh` | macOS 原生全链路冒烟（SMOKE_PG_VERSION 参数化，v14~v18 矩阵） | mac-pg-install |
| `scripts/test-suite-pg18.sh` | 22 断言功能套件 macOS 版 | full-path-smoke-macos.sh 全绿后 |
| `scripts/benchmark-quadrant-macos.sh` | 四象限基准（macOS debug，仅相对值；Linux 正式数字见 ADR-015） | full-path-smoke-macos.sh |

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
17. **Linux 后端扩展必须静态链 FRONTEND 版 libpq.a**（fork Makefile Linux 分支已处理，勿改回）：动态 libpq.so 在 postgres 进程内经平面命名空间被主程序的后端版 link-canary 插值，PQconnect 直接报 "libpq is incorrectly linked to backend functions"；同族问题还有编码函数（后端只导出 `pg_char_to_encoding_private` 等 `*_private` 版）——`pgxn/neon/neon_compat.c` 提供公共名转发 + 前端语义 canary（见子模块 6eb8bb6）。macOS 靠 two-level namespace 天然免疫，保持动态链。
18. **zigbuild 交叉产物在老 binutils 上的 ar 长名表失效**：rustc 打包的 `.a` 长名表 CentOS 8 binutils 2.30 解析错位（符号明明在，ld 找不到成员，报 undefined symbol），千橙实证。修复=本机 `llvm-ar x` 解包后 `llvm-ar rcs` 重建标准 GNU 格式（binutils 2.35+ 无此问题，基础2 直接可用）。
19. **云主机两道 ulimit/路径坑**（基础2 实证）：① fork PG 二进制 RUNPATH 硬编码构建机路径（`/root/jt/pg18/lib`），挪机后 initdb 报 libpq.so.5 找不到——`LD_LIBRARY_PATH=<部署>/pg18/lib` 兜底；② memlock 默认 64KB，tokio-epoll-uring 锁定内存不足导致 pageserver basebackup 无限重试（"not enough locked memory"）——`/etc/security/limits.d/*.conf` 给运行用户 `memlock 262144` 并重登会话。
20. **cross-build 传输路径**：云主机间安全组默认不通（ICMP/HTTP 全拦），electerm SFTP 需 UI 手动开面板；**zmodem（rz）是最可靠通道**（走既有 SSH 会话，117M 实测无损）。zmodem 落盘位置是 SSH 会话当前目录（通常 $HOME）。MCP 命令通道单请求 ~64KB 上限，base64 注入只适合小文件。
21. **neon_maxcombine 批量化实测否定**（2026-09-10，勿再试同款）：放开到 PG_IOV_MAX 让 read-stream 整批进单个 startreadv，seq scan 百万行 7 倍退化（28.7s vs 3.9s）——read-stream 在 HF_SYNCHRONOUS 下 lookahead 失效，批化放大整批同步阻塞。单块同步语义为当前架构实测最优；handle 级真异步需 communicator ring 共享化+独立接收线程（ADR-015 遗留）。A/B 全程冒烟+22 断言护航。
