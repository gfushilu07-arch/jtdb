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
