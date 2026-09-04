#!/bin/zsh
# PG18 compute 实装载冒烟（ADR-015 待办①第一层）：
#   1) neon 扩展 make install 进 fork PG18 安装树（/jtdb/pgxs-pg18-fork）
#   2) initdb + shared_preload_libraries='neon' 启动（无 pageserver，smgr 不注册，vanilla 行为）
#   3) CREATE EXTENSION neon + 基本查询
# 产物全部在缓存卷；用法: source scripts/env.sh && scripts/compute-smoke-pg18.sh
set -uo pipefail
: "${JTDB_CACHE_ROOT:?请先 source scripts/env.sh}"
LOG="$JTDB_CACHE_ROOT/logs/compute-smoke-pg18.log"
NEON_WT="$(pwd)/upstream/neon"
: > "$LOG"

docker run --rm -v "$NEON_WT":/neon -v "$JTDB_CACHE_ROOT":/jtdb debian:bookworm bash -c '
set -u
export RUSTUP_HOME=/jtdb/rustup-container CARGO_HOME=/jtdb/cargo-container RUSTUP_TOOLCHAIN=1.98.0
export PATH="$CARGO_HOME/bin:$PATH"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq build-essential pkg-config ca-certificates curl libcurl4-openssl-dev locales >/dev/null 2>&1
test -x "$CARGO_HOME/bin/cargo" || curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path >/dev/null

# 与宿主同 uid，避免挂载卷权限问题；postgres 拒绝 root
groupadd -g 501 pg 2>/dev/null || true
useradd -u 501 -g 501 -m pg 2>/dev/null || true

PGROOT=/jtdb/pgxs-pg18-fork
PGDATA=/jtdb/data-pg18-smoke

echo "=== 1) neon 扩展安装进 fork PG18 ==="
cd /neon/pgxn/neon
export CARGO_TARGET_DIR=/jtdb/target/pgxn
[ -f /jtdb/target/pgxn/libcommunicator.a ] || cp /jtdb/target/pgxn/debug/libcommunicator.a /jtdb/target/pgxn/libcommunicator.a
make install NEON_CARGO_ARTIFACT_TARGET_DIR=/jtdb/target/pgxn PG_CONFIG="$PGROOT/bin/pg_config" 2>&1 | tail -2
# neon 预加载链的其他模块（neon.c 会 load_file neon_rmgr；walredo/test_utils 供 compute 全链）
for M in neon_rmgr neon_utils neon_test_utils neon_walredo; do
  make -C /neon/pgxn/$M install NEON_CARGO_ARTIFACT_TARGET_DIR=/jtdb/target/pgxn PG_CONFIG="$PGROOT/bin/pg_config" >/dev/null 2>&1 || echo "!! $M 安装失败"
done
ls "$PGROOT/lib/postgresql/" | grep -E "neon" | head -6
ls -la "$PGROOT/lib/postgresql/neon.so" "$PGROOT/share/postgresql/extension/neon.control" 2>/dev/null

echo "=== 2) initdb + 启动 ==="
rm -rf "$PGDATA"
mkdir -p "$PGDATA" && chown -R 501:501 "$PGDATA" "$PGROOT"
su pg -c "$PGROOT/bin/initdb -D $PGDATA --no-locale --encoding=UTF8 -A trust" 2>&1 | tail -2
cat >> "$PGDATA/postgresql.conf" <<EOF
shared_preload_libraries = '"'"'neon'"'"'
listen_addresses = '"'"''"'"'
unix_socket_directories = '"'"'/tmp'"'"'
EOF
su pg -c "$PGROOT/bin/pg_ctl -D $PGDATA -l /jtdb/logs/pg18-smoke-server.log -w start" 2>&1 | tail -2

echo "=== 3) CREATE EXTENSION neon + 冒烟查询 ==="
su pg -c "$PGROOT/bin/psql -h /tmp -d postgres -v ON_ERROR_STOP=1 -c \"CREATE EXTENSION IF NOT EXISTS neon;\" -c \"SELECT extname, extversion FROM pg_extension;\" -c \"CREATE TABLE smoke_t(id int primary key, v text); INSERT INTO smoke_t VALUES (1,'\''hello-pg18-neon'\''); SELECT * FROM smoke_t;\"" 2>&1 | tail -12

echo "=== 4) 服务进程存活确认 ==="
su pg -c "$PGROOT/bin/pg_ctl -D $PGDATA status" 2>&1 | tail -1
echo "SMOKE_DONE"
' >> "$LOG" 2>&1

echo "=== 冒烟结果（完整日志: $LOG）==="
grep -E "===|extname|smoke_t|hello-pg18-neon|ERROR|FATAL|SMOKE_DONE|neon.so" "$LOG" | head -25
