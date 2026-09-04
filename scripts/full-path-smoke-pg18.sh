#!/bin/zsh
# Neon 存储全链路冒烟（ADR-015 待办①）：容器内拉起 neon_local 拓扑
#   safekeeper → pageserver → PG18 compute（v18 fork 安装树 + neon.so）
# 走通 WAL → safekeeper → pageserver → compute 读路径。
# 前置：/jtdb/target/neon-full 四件套 + /jtdb/pgxs-pg18-fork（含 neon.so）已就位。
# 用法: source scripts/env.sh && scripts/full-path-smoke-pg18.sh
set -uo pipefail
: "${JTDB_CACHE_ROOT:?请先 source scripts/env.sh}"
LOG="$JTDB_CACHE_ROOT/logs/full-path-smoke-pg18.log"
: > "$LOG"

docker run --rm -v "$(pwd)/upstream/neon":/neon -v "$JTDB_CACHE_ROOT":/jtdb debian:bookworm bash -c '
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq build-essential pkg-config ca-certificates curl libcurl4-openssl-dev procps >/dev/null 2>&1
groupadd -g 501 pg 2>/dev/null || true; useradd -u 501 -g 501 -m pg 2>/dev/null || true

BIN=/jtdb/target/neon-full/debug
PGROOT=/jtdb/pgxs-pg18-fork
export NEON_LOCAL_BIN="$BIN/neon_local"
export PG_CONFIG="$PGROOT/bin/pg_config"
export PGDATA=unused
export PSQL="$PGROOT/bin/psql"
# neon_local 定位 PG 安装树：POSTGRES_DISTRIB_DIR/<vN>/{bin,lib}（local_env.rs 约定）
export POSTGRES_DISTRIB_DIR=/jtdb/distrib
# pg_install 残余路径兜底（部分代码路径硬编码 cwd/pg_install）
mkdir -p /tmp/neonhome/pg_install && [ -e /tmp/neonhome/pg_install/v18 ] || ln -s "$PGROOT" /tmp/neonhome/pg_install/v18

echo "=== 1) neon 扩展与 compute 安装树就位检查 ==="
ls "$PGROOT/lib/postgresql/neon.so" >/dev/null && echo "neon.so OK"
"$PGROOT/bin/postgres" --version

echo "=== 2) neon_local init + 后台启动 pageserver/safekeeper/storage_controller ==="
# storcon 按 v16/v15/v14/v17 找 PG bin（不认 v18）——符号链接借 fork PG18 的工具
ln -sfn "$PGROOT" /jtdb/distrib/v16
mkdir -p /tmp/neonhome && chown -R 501:501 /tmp/neonhome
su pg -c "cd /tmp/neonhome && $BIN/neon_local init" 2>&1 | tail -3
su pg -c "cd /tmp/neonhome && nohup $BIN/neon_local pageserver start >/tmp/neonhome/ps.log 2>&1 &" 
su pg -c "cd /tmp/neonhome && nohup $BIN/neon_local safekeeper start >/tmp/neonhome/sk.log 2>&1 &"
su pg -c "cd /tmp/neonhome && nohup $BIN/neon_local storage-controller start >/tmp/neonhome/storcon.log 2>&1 &"
for i in $(seq 1 45); do
  curl -s -o /dev/null -m 2 http://127.0.0.1:1234 2>/dev/null && STORCON_UP=1 && break
  sleep 2
done
[ "${STORCON_UP:-0}" = "1" ] && echo "storage_controller 端口就绪" || echo "storage_controller 未就绪"
for i in $(seq 1 30); do
  curl -s -o /dev/null -m 2 http://127.0.0.1:9898/v1/status && PS_UP=1 && break
  sleep 2
done
[ "${PS_UP:-0}" = "1" ] && echo "pageserver HTTP 就绪" || echo "pageserver 未就绪"
(echo > /dev/tcp/127.0.0.1/7676) 2>/dev/null && echo "safekeeper 端口就绪" || echo "safekeeper 端口未探活（可能日志缓冲）"

echo "=== 3) tenant + endpoint（PG18 compute） ==="
su pg -c "cd /tmp/neonhome && $BIN/neon_local tenant create --set-default" 2>&1 | tail -2
TENANT=$(su pg -c "cd /tmp/neonhome && $BIN/neon_local tenant list" 2>/dev/null | grep -oE "[0-9a-f]{32}" | head -1)
echo "tenant=$TENANT"
su pg -c "cd /tmp/neonhome && $BIN/neon_local endpoint create main" 2>&1 | tail -2
su pg -c "cd /tmp/neonhome && nohup $BIN/neon_local endpoint start main >/tmp/neonhome/ep.log 2>&1 &"
for i in $(seq 1 45); do
  su pg -c "$PGROOT/bin/pg_isready -h 127.0.0.1 -p 55432" >/dev/null 2>&1 && EP_UP=1 && break
  sleep 2
done
[ "${EP_UP:-0}" = "1" ] && echo "compute 就绪" || { echo "compute 未就绪"; tail -5 /tmp/neonhome/ep.log; }

echo "=== 4) SQL 冒烟（走 Neon 存储路径） ==="
su pg -c "$PSQL -h 127.0.0.1 -p 55432 -d postgres -v ON_ERROR_STOP=1 -c \"CREATE TABLE t_full(id int primary key, v text); INSERT INTO t_full VALUES (1,'neon-pg18-full-path');\"" 2>&1 | tail -3
su pg -c "$PSQL -h 127.0.0.1 -p 55432 -d postgres -c \"SELECT * FROM t_full;\"" 2>&1 | tail -4

echo "=== 5) 组件存活确认 ==="
su pg -c "ps aux | grep -E \"pageserver|safekeeper\" | grep -v grep | wc -l"

echo "FULLPATH_SMOKE_DONE"
' >> "$LOG" 2>&1

echo "=== 结果（完整日志: $LOG）==="
grep -E "===|neon-pg18-full-path|OK|ERROR|FATAL|error|FULLPATH_SMOKE_DONE" "$LOG" | head -30
