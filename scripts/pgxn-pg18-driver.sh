#!/bin/zsh
# pgxn/neon PG18 兼容驱动 v3（ADR-015 待办②）：
#   阶段 0：PG 18.2 + pgxs 持久化构建（缓存卷 /jtdb/pgxs-pg18，跨运行复用）
#   阶段 1：communicator Rust 桥（独立容器，rustc 内存压力不带入 C 阶段）
#   阶段 2：pgxn/neon C 编译（全新容器 + make -k，收集 PG18 API 错误清单）
# 用法: source scripts/env.sh && scripts/pgxn-pg18-driver.sh
set -uo pipefail
: "${JTDB_CACHE_ROOT:?请先 source scripts/env.sh}"
LOG="$JTDB_CACHE_ROOT/logs/pgxn-pg18-errors.log"
NEON_WT="$(pwd)/upstream/neon"

DOCKER_ENV=(-e RUSTUP_HOME=/jtdb/rustup-container -e CARGO_HOME=/jtdb/cargo-container -e PATH=/jtdb/cargo-container/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)

echo "=== 阶段 0：PG 18.2 fork（vendor/postgres-v18）+ pgxs（持久化） ==="
docker run --rm -v "$NEON_WT/vendor/postgres-v18":/pgsrc:ro -v "$JTDB_CACHE_ROOT":/jtdb debian:bookworm bash -c '
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq build-essential bison flex perl pkg-config ca-certificates curl bzip2 >/dev/null
if [ ! -x /jtdb/pgxs-pg18-fork/bin/pg_config ]; then
  mkdir -p /tmp/pgbuild && cd /tmp/pgbuild
  /pgsrc/configure --prefix=/jtdb/pgxs-pg18-fork --without-readline --without-zlib --without-icu --without-openssl >/dev/null 2>&1
  make -j"$(nproc)" -C src >/dev/null 2>&1
  make -C src install >/dev/null 2>&1
  make -C src/include install >/dev/null 2>&1
  make -C config install >/dev/null 2>&1
  echo "PG18 fork 构建 OK"
else
  echo "PG18 fork 复用缓存"
fi'


echo "=== 阶段 1：communicator Rust 桥 ==="
docker run --rm -v "$NEON_WT":/neon -v "$JTDB_CACHE_ROOT":/jtdb "${DOCKER_ENV[@]}" debian:bookworm bash -c '
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq build-essential pkg-config ca-certificates curl >/dev/null
test -x "$CARGO_HOME/bin/cargo" || curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path >/dev/null
cd /neon/pgxn/neon
export CARGO_TARGET_DIR=/jtdb/target/pgxn
make NEON_CARGO_ARTIFACT_TARGET_DIR=/jtdb/target/pgxn PG_CONFIG=/jtdb/pgxs-pg18-fork/bin/pg_config communicator/communicator_bindings.h
make NEON_CARGO_ARTIFACT_TARGET_DIR=/jtdb/target/pgxn PG_CONFIG=/jtdb/pgxs-pg18-fork/bin/pg_config "$(find /jtdb/target/pgxn -name libcommunicator.a | head -1 || true)" 2>/dev/null || \
make NEON_CARGO_ARTIFACT_TARGET_DIR=/jtdb/target/pgxn PG_CONFIG=/jtdb/pgxs-pg18-fork/bin/pg_config'
touch "$NEON_WT/pgxn/neon/communicator/communicator_bindings.h"
echo "阶段 1 rc=$?"

echo "=== 阶段 2：C 编译（新容器，收集错误清单） ==="
: > "$LOG"
docker run --rm -v "$NEON_WT":/neon -v "$JTDB_CACHE_ROOT":/jtdb "${DOCKER_ENV[@]}" debian:bookworm bash -c '
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq build-essential pkg-config ca-certificates curl >/dev/null
test -x "$CARGO_HOME/bin/cargo" || curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path >/dev/null
cd /neon/pgxn/neon
export CARGO_TARGET_DIR=/jtdb/target/pgxn
# 注意：Makefile 默认目标不是 all（首目标是 communicator_process.o），必须显式 all
make all NEON_CARGO_ARTIFACT_TARGET_DIR=/jtdb/target/pgxn PG_CONFIG=/jtdb/pgxs-pg18-fork/bin/pg_config 2>&1
rc=$?
# debug 产物在 $(TARGET_DIR)/debug；链接器按传入路径找 libcommunicator.a（不带 /debug），补拷
if [ -f /jtdb/target/pgxn/debug/libcommunicator.a ] && [ ! -f /jtdb/target/pgxn/libcommunicator.a ]; then
  cp /jtdb/target/pgxn/debug/libcommunicator.a /jtdb/target/pgxn/libcommunicator.a
  make all NEON_CARGO_ARTIFACT_TARGET_DIR=/jtdb/target/pgxn PG_CONFIG=/jtdb/pgxs-pg18-fork/bin/pg_config 2>&1
  rc=$?
fi
echo "MAKE_DONE rc=$rc"
ls -la /neon/pgxn/neon/neon.so 2>/dev/null || true
' >> "$LOG" 2>&1

echo "=== 错误摘要（完整日志: $LOG）==="
grep -E "error:" "$LOG" | sed 's|/neon/pgxn/neon/||' | sort -u | head -30
echo "---- error 总数: $(grep -c 'error:' "$LOG")；MAKE 结果: $(grep MAKE_DONE "$LOG" | tail -1)"
