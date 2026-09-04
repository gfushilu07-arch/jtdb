#!/bin/zsh
# ============================================================================
# JTDB 构建环境 —— 单一事实源（build/README.md 是本文件的文档）
#
# 原则（build/README.md §2）：
#   1. PG 头文件唯一来源 = fork 安装树（JTDB_PG_INSTALL）；官方 tarball 仅对照
#   2. 任何构建容器必须 source 本文件；禁止脚本内自定义 CARGO_HOME/PATH
#   3. 仓库工作树禁止出现 target/（.gitignore 已挡）
#
# 用法：source scripts/env.sh
# ============================================================================
export JTDB_CACHE_ROOT="/Volumes/fushilu/.caches/jtdb"

# ---- 路径契约（build/README.md §3 有完整说明） ----
export JTDB_NEON_WT="/Users/fushilu/workspace/revocloud/JTDB/upstream/neon"  # Neon 子模块工作树
export JTDB_PG_INSTALL="$JTDB_CACHE_ROOT/pg_install"        # bindgen 用 PG 头文件（v14~v18；v18=fork 安装树）
export JTDB_PGXS_FORK="$JTDB_CACHE_ROOT/pgxs-pg18-fork"     # fork PG18 完整安装（含 pgxs/lib/neon*.so）
export JTDB_DISTRIB="$JTDB_CACHE_ROOT/distrib"              # neon_local distrib 树（v18 实体 + v16 符号链接）
export JTDB_BUILDS="$JTDB_CACHE_ROOT/builds"                # 中间构建产物（walproposer-lib 等）
export JTDB_LOGS="$JTDB_CACHE_ROOT/logs"                    # 全部构建/冒烟日志

# ---- Rust target 统一（合并原 neon-9129 与 neon-full 两套，省约 8GB） ----
# 旧两套目录保留只读一段时间作增量回退，新构建一律用 JTDB_TARGET_RUST
export JTDB_TARGET_RUST="$JTDB_CACHE_ROOT/target/rust"
export JTDB_TARGET_C="$JTDB_CACHE_ROOT/target/c-pgxn"
export CARGO_TARGET_DIR="$JTDB_TARGET_RUST"
export JTDB_NEON_TARGET_DIR="$JTDB_TARGET_RUST"             # 兼容旧脚本引用

# ---- Rust 工具链：版本钉死（与 upstream/NEON_COMMIT 的 BUILD_TOOLCHAIN 一致） ----
export RUSTUP_HOME="$JTDB_CACHE_ROOT/rustup"                # 主机侧工具链
export CARGO_HOME="$JTDB_CACHE_ROOT/cargo"
export RUSTUP_TOOLCHAIN="1.98.0"                            # 禁止 stable 漂移
export CCACHE_DIR="$JTDB_CACHE_ROOT/ccache"
export PATH="$CARGO_HOME/bin:$PATH"

# ---- 容器侧工具链（构建容器挂载缓存卷后自动可用的固定工具链） ----
export JTDB_CONTAINER_RUSTUP_HOME="$JTDB_CACHE_ROOT/rustup-container"
export JTDB_CONTAINER_CARGO_HOME="$JTDB_CACHE_ROOT/cargo-container"

# ---- Neon 约定变量（local_env.rs / postgres_ffi build.rs 读取） ----
export POSTGRES_INSTALL_DIR="$JTDB_PG_INSTALL"              # postgres_ffi bindgen 头文件
export POSTGRES_DISTRIB_DIR="$JTDB_DISTRIB"                 # neon_local 定位 PG 安装树

# ---- 构建镜像（build/README.md §5） ----
export JTDB_BUILD_IMAGE="jtbuild:bookworm-20260904"

mkdir -p "$JTDB_TARGET_RUST" "$JTDB_TARGET_C" "$JTDB_LOGS"
