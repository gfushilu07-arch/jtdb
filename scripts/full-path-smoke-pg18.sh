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
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq build-essential pkg-config ca-certificates curl libcurl4-openssl-dev openssl procps >/dev/null 2>&1
which openssl >/dev/null || { echo FATAL-openssl-missing; exit 1; }
groupadd -g 501 pg 2>/dev/null || true; useradd -u 501 -g 501 -m pg 2>/dev/null || true

BIN=/jtdb/target/neon-full/debug
PGROOT=/jtdb/pgxs-pg18-fork
export NEON_LOCAL_BIN="$BIN/neon_local"
export PG_CONFIG="$PGROOT/bin/pg_config"
export PGDATA=unused
export PSQL="$PGROOT/bin/psql"
# neon_local 定位 PG 安装树：POSTGRES_DISTRIB_DIR/<vN>/{bin,lib}（local_env.rs 约定）
export POSTGRES_DISTRIB_DIR=/jtdb/distrib
# storcon 只认 v16/v15/v14/v17；pageserver timeline create 要在 v18/bin 下找 initdb
ln -sfn ../pgxs-pg18-fork /jtdb/distrib/v16
ln -sfn ../pgxs-pg18-fork /jtdb/distrib/v18
# v18 必须是完整安装树（pageserver timeline create 时要在 v18/bin 下找 initdb）
# pg_install 残余路径兜底（部分代码路径硬编码 cwd/pg_install）
mkdir -p /tmp/neonhome/pg_install && [ -e /tmp/neonhome/pg_install/v18 ] || ln -s "$PGROOT" /tmp/neonhome/pg_install/v18

echo "=== 1) neon 扩展与 compute 安装树就位检查 ==="
ls "$PGROOT/lib/postgresql/neon.so" >/dev/null && echo "neon.so OK"
"$PGROOT/bin/postgres" --version

echo "=== 2) neon_local init + pageserver/safekeeper ==="
mkdir -p /tmp/neonhome && chown -R 501:501 /tmp/neonhome
su pg -c "cd /tmp/neonhome && $BIN/neon_local init" 2>&1 | tail -2
su pg -c "cd /tmp/neonhome && nohup $BIN/neon_local pageserver start >/tmp/neonhome/ps.log 2>&1 &"
su pg -c "cd /tmp/neonhome && nohup $BIN/neon_local safekeeper start >/tmp/neonhome/sk.log 2>&1 &"
sleep 2
cp /tmp/neonhome/.neon/config /jtdb/logs/neon-config-dump.toml
cp /tmp/neonhome/.neon/config /jtdb/logs/neon-config-dump.toml
PS_HTTP_PORT=$(grep -oE "listen_http_addr = .*:([0-9]+)" /tmp/neonhome/.neon/pageserver_1/pageserver.toml 2>/dev/null | grep -oE "[0-9]+$" | head -1)
echo "pageserver http_port=$PS_HTTP_PORT"
for i in $(seq 1 20); do sleep 2; curl -s -m 2 -o /dev/null "http://127.0.0.1:$PS_HTTP_PORT/v1/status" && break; done
curl -s -m 2 -o /dev/null -w "pageserver=%{http_code}\n" "http://127.0.0.1:$PS_HTTP_PORT/v1/status"

echo "=== 3) storcon 手动 bootstrap（neon_local storage-controller start 存在 repo-dir 约定 bug，见 ADR-015） ==="
su pg -c "$PGROOT/bin/initdb -D /tmp/neonhome/.neon/storage_controller_db --username=pg --no-sync --no-instructions" >/dev/null 2>&1 && echo "initdb OK"
echo "port = 1235
fsync = off" >> /tmp/neonhome/.neon/storage_controller_db/postgresql.conf
su pg -c "$PGROOT/bin/pg_ctl -D /tmp/neonhome/.neon/storage_controller_db -l /tmp/neonhome/.neon/storage_controller_db/pg.log -w -o \"-p 1235\" start" >/dev/null 2>&1
su pg -c "$PGROOT/bin/createdb -h localhost -p 1235 -U pg storage_controller" && echo "createdb OK"
su pg -c "nohup $BIN/storage_controller --dev --database-url=postgresql://pg@localhost:1235/storage_controller --listen 127.0.0.1:1234 --neon-local-repo-dir /tmp/neonhome --max-offline-interval 10s --max-warming-up-interval 30s --heartbeat-interval 1s --address-for-peers http://127.0.0.1:1234 --timelines-onto-safekeepers --use-local-compute-notifications > /tmp/neonhome/.neon/storcon.log 2>&1 &"
sleep 6
curl -s -m 2 -o /dev/null -w "storcon=%{http_code}\n" http://127.0.0.1:1234

echo "=== 4) tenant/timeline/endpoint ==="
su pg -c "cd /tmp/neonhome && $BIN/neon_local tenant create --set-default" 2>&1 | tail -1
TENANT=$(su pg -c "cd /tmp/neonhome && $BIN/neon_local tenant list" 2>/dev/null | grep -oE "[0-9a-f]{32}" | head -1)
echo "tenant=$TENANT"
TL_OK=0
for i in $(seq 1 15); do
  OUT=$(su pg -c "cd /tmp/neonhome && $BIN/neon_local timeline create --branch-name main --tenant-id $TENANT" 2>&1 | tail -1)
  echo "$OUT" | grep -qE "timeline|main" && { TL_OK=1; echo "timeline OK(第${i}次): $OUT"; break; }
  echo "timeline 重试 ${i}: $OUT"; sleep 4
done
if [ "${TL_OK:-0}" != "1" ]; then
  echo "--- 取证: pageserver.log 尾部 ---"; tail -6 /tmp/neonhome/.neon/pageserver_1/pageserver.log 2>/dev/null
  echo "--- 取证: storcon.log 尾部 ---"; tail -6 /tmp/neonhome/.neon/storcon.log 2>/dev/null
fi
for i in $(seq 1 10); do
  OUT=$(su pg -c "cd /tmp/neonhome && $BIN/neon_local endpoint create main --tenant-id $TENANT" 2>&1 | tail -1)
  echo "$OUT" | grep -q "command failed" || { echo "endpoint OK(第${i}次): $OUT"; break; }
  echo "endpoint 重试 ${i}: $OUT"; sleep 4
done
su pg -c "cd /tmp/neonhome && nohup $BIN/neon_local endpoint start main --tenant-id $TENANT >/tmp/neonhome/ep.log 2>&1 &"
for i in $(seq 1 45); do sleep 2; su pg -c "$PGROOT/bin/pg_isready -h 127.0.0.1 -p 55432" >/dev/null 2>&1 && break; done
su pg -c "$PGROOT/bin/pg_isready -h 127.0.0.1 -p 55432" 2>&1 | tail -1

echo "=== 5) SQL 全链路冒烟（WAL→safekeeper→pageserver→compute） ==="
su pg -c "$PGROOT/bin/psql -h 127.0.0.1 -p 55432 -d postgres -v ON_ERROR_STOP=1 -c \"CREATE TABLE t_full(id int primary key, v text); INSERT INTO t_full VALUES (1,'neon-pg18-full-path');\"" 2>&1 | tail -2
su pg -c "$PGROOT/bin/psql -h 127.0.0.1 -p 55432 -d postgres -c \"SELECT * FROM t_full;\"" 2>&1 | tail -4

echo "=== 6) 组件确认 ==="
su pg -c "ps aux | grep -cE \"pageserver -D|safekeeper -D|storage_controller --dev|postgres -D\""

echo "FULLPATH_SMOKE_DONE"
' >> "$LOG" 2>&1

echo "=== 结果（完整日志: $LOG）==="
grep -E "===|neon-pg18-full-path|OK|ERROR|FATAL|error|FULLPATH_SMOKE_DONE" "$LOG" | head -30
