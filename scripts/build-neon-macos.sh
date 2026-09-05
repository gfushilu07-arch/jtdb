#!/bin/bash
# macOS 原生一键构建 pgxn/neon 扩展（含 communicator Rust 桥）并安装进 mac-pg-install/v18
# 用法: source scripts/env.sh && zsh scripts/build-neon-macos.sh
set -euo pipefail

PGROOT="$JTDB_CACHE_ROOT/mac-pg-install/v18"
export PG_CONFIG="$PGROOT/bin/pg_config"
export PATH="$PGROOT/bin:$PATH"

# macOS 原生 communicator Rust 桥（产物为 macOS .a）
COMM_DIR="/Users/fushilu/workspace/revocloud/JTDB/upstream/neon/pgxn/neon/communicator"
export CARGO_TARGET_DIR="$JTDB_CACHE_ROOT/target/mac-communicator"
cd "$COMM_DIR"
cargo build 2>&1 | tail -1

LIBCOMM="/Volumes/fushilu/.caches/jtdb/target/mac-communicator/debug/libcommunicator.a"
NEON_DIR="/Users/fushilu/workspace/revocloud/JTDB/upstream/neon/pgxn/neon"

cd "$NEON_DIR"
make clean PG_CONFIG="$PG_CONFIG" >/dev/null 2>&1 || true
# 清掉 /tmp 里可能残留的旧 Linux 版产物
rm -f /tmp/neon-local-artifacts/libcommunicator.a
# 分发 Rust 产物到 Makefile 期望路径
mkdir -p "$(dirname "$LIBCOMM")"
cp "$LIBCOMM" /tmp/libcommunicator-staged.a
# 用 make 直接编（.o 全新 macOS 编译），libcommunicator.a 通过 NEON_CARGO_ARTIFACT_TARGET_DIR 提供
mkdir -p /tmp/neon-local-artifacts
cp "$LIBCOMM" /tmp/neon-local-artifacts/libcommunicator.a
make -j8 NEON_CARGO_ARTIFACT_TARGET_DIR="/tmp/neon-local-artifacts" PG_CONFIG="$PG_CONFIG" all 2>&1 | grep -vE "^gcc" | tail -4
make install NEON_CARGO_ARTIFACT_TARGET_DIR="/tmp/neon-local-artifacts" PG_CONFIG="$PG_CONFIG" 2>&1 | tail -2
# 全家桶校验：neon(rmgr/walredo/utils/test_utils) 缺一即败（neon.c 会 load_file("$libdir/neon_rmgr")）
for ext in neon.dylib neon_rmgr.dylib neon_walredo.dylib neon_utils.dylib neon_test_utils.dylib; do
  ls "$PGROOT/lib/postgresql/$ext" >/dev/null || { echo "FAIL: $ext 缺失"; exit 1; }
done
echo "=== pgxn 全家桶 OK ==="
ls "$PGROOT/lib/postgresql/neon.dylib" && echo "=== neon.dylib 安装完成 ==="
