#!/bin/zsh
# ============================================================================
# macOS 原生全链路冒烟（v2，重写）
#   storcon(内部PG) → broker → pageserver → safekeeper → endpoint(PG18 compute)
#   → SQL 全链路（WAL→safekeeper→pageserver→compute）
#
# 本版修复（build/README.md §7 同步更新）：
#   R1 僵尸 postmaster：上一轮 storcon 内部 PG(1235) 不在旧 pkill 模式内，
#      新 initdb 后 storcon 连上数据目录已删的僵尸 → pg_filenode.map 缺失退出。
#      清理改为 pkill "postgres -D /tmp/neonhome-macos" + 端口忙等检查。
#   R2 endpoint_storage / storage_broker 二进制缺失（cargo 五件套漏了），
#      endpoint start 需 9993 endpoint storage；init 约定拉起 broker(50051)。
#   R3 timeline 幂等：branch 'main' 已映射视为成功（避免误判失败）。
#   R4 输出直写文件不再经 tail 管道（避免缓冲导致现场不可见）。
# 用法: source scripts/env.sh && zsh scripts/full-path-smoke-macos.sh
# ============================================================================
set -uo pipefail
: "${JTDB_CACHE_ROOT:?请先 source scripts/env.sh}"
LOG="$JTDB_CACHE_ROOT/logs/full-path-smoke-macos.log"
mkdir -p "$(dirname "$LOG")"

exec > >(tee "$LOG") 2>&1

SMOKE_PG_VERSION="${SMOKE_PG_VERSION:-18}"
BIN="$JTDB_CACHE_ROOT/target/rust-macos/debug"
PGROOT="$JTDB_CACHE_ROOT/mac-pg-install/v$SMOKE_PG_VERSION"
HOME_DIR=/tmp/neonhome-macos
export POSTGRES_DISTRIB_DIR="$JTDB_CACHE_ROOT/mac-pg-install"   # neon_local 定位 PG 安装树（local_env.rs）

fail() { echo "FAIL: $*"; exit 1; }

echo "=== 0) 清理旧运行（含 R1 僵尸 postmaster） ==="
pkill -9 -f "$BIN/pageserver" 2>/dev/null
pkill -9 -f "$BIN/safekeeper" 2>/dev/null
pkill -9 -f "$BIN/storage_controller" 2>/dev/null
pkill -9 -f "$BIN/neon_local" 2>/dev/null
pkill -9 -f "$BIN/endpoint_storage" 2>/dev/null
pkill -9 -f "$BIN/storage_broker" 2>/dev/null
pkill -9 -f "postgres -D $HOME_DIR" 2>/dev/null
pkill -9 -f "postgres -D /private/tmp/neonhome-macos" 2>/dev/null
sleep 2
for port in 1234 1235 9898 7676 64000 50051 9993 55432; do
  for i in $(seq 1 10); do
    lsof -nP -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1 || break
    sleep 1
  done
  if lsof -nP -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1; then
    echo "端口 $port 仍被占用:"; lsof -nP -iTCP:$port -sTCP:LISTEN
    fail "端口 $port 无法释放"
  fi
done
echo "端口全部空闲"

echo "=== 1) 前置检查 ==="
for b in compute_ctl endpoint_storage storage_broker neon_local pageserver safekeeper storage_controller; do
  [ -x "$BIN/$b" ] || fail "$BIN/$b 缺失（需补构建）"
done
echo "Rust 二进制 7 件套 OK"
NEON_EXT="$PGROOT/lib/postgresql/neon.dylib"; [ -f "$NEON_EXT" ] || NEON_EXT="$PGROOT/lib/postgresql/neon.so"
ls "$NEON_EXT" >/dev/null || fail "neon 扩展缺失"
"$PGROOT/bin/postgres" --version || fail "v18 postgres 不可执行"

echo "=== 2) neon_local init ==="
rm -rf "$HOME_DIR"
mkdir -p "$HOME_DIR"
cd "$HOME_DIR"
"$BIN/neon_local" init 2>&1 | tail -2 || fail "neon_local init"

echo "=== 3) storcon 内部 PG + storcon（--dev 本地 upcall 模式） ==="
STORCON_DB="$HOME_DIR/.neon/storage_controller_db"
"$PGROOT/bin/initdb" -D "$STORCON_DB" --username=$(whoami) --no-sync --no-instructions >/dev/null 2>&1 || fail "storcon initdb"
printf 'port = 1235\nfsync = off\n' >> "$STORCON_DB/postgresql.conf"
"$PGROOT/bin/pg_ctl" -D "$STORCON_DB" -l "$STORCON_DB/pg.log" -w -o "-p 1235" start >/dev/null 2>&1 || fail "storcon 内部 PG 启动（pg_ctl）"
"$PGROOT/bin/pg_isready" -h 127.0.0.1 -p 1235 -t 2 >/dev/null || fail "内部 PG 1235 未就绪"
"$PGROOT/bin/createdb" -h 127.0.0.1 -p 1235 -U $(whoami) storage_controller >/dev/null 2>&1 || fail "createdb storage_controller"
nohup "$BIN/storage_controller" --dev \
  --database-url="postgresql://$(whoami)@localhost:1235/storage_controller" \
  --listen 127.0.0.1:1234 --address-for-peers http://127.0.0.1:1234 \
  --neon-local-repo-dir "$HOME_DIR" \
  --max-offline-interval 10s --max-warming-up-interval 30s --heartbeat-interval 1s \
  --timelines-onto-safekeepers --timeline-safekeeper-count 1 \
  --use-local-compute-notifications \
  > "$HOME_DIR/.neon/storcon.log" 2>&1 &
for i in $(seq 1 30); do sleep 1; curl -s -m 2 -o /dev/null http://127.0.0.1:1234 && break; done
curl -s -m 2 -o /dev/null http://127.0.0.1:1234 || { tail -20 "$HOME_DIR/.neon/storcon.log"; fail "storcon 1234 未就绪"; }
echo "storcon OK"

echo "=== 4) broker + endpoint_storage（init 约定组件） + pageserver + safekeeper ==="
nohup "$BIN/storage_broker" --listen-addr 127.0.0.1:50051 > "$HOME_DIR/.neon/broker.log" 2>&1 &
for i in $(seq 1 15); do sleep 1; lsof -nP -iTCP:50051 -sTCP:LISTEN >/dev/null && break; done
lsof -nP -iTCP:50051 -sTCP:LISTEN >/dev/null || { tail -10 "$HOME_DIR/.neon/broker.log"; fail "broker 50051 未监听"; }
echo "broker OK"
nohup "$BIN/endpoint_storage" "$HOME_DIR/.neon/endpoint_storage/endpoint_storage.json" \
  > "$HOME_DIR/.neon/eps.log" 2>&1 &
for i in $(seq 1 10); do sleep 1; lsof -nP -iTCP:9993 -sTCP:LISTEN >/dev/null && break; done
lsof -nP -iTCP:9993 -sTCP:LISTEN >/dev/null || { tail -10 "$HOME_DIR/.neon/eps.log"; fail "endpoint_storage 9993 未监听"; }
echo "endpoint_storage OK"
nohup "$BIN/neon_local" pageserver start > "$HOME_DIR/ps.log" 2>&1 &
for i in $(seq 1 30); do sleep 2; curl -s -m 2 -o /dev/null http://127.0.0.1:9898/v1/status && break; done
curl -s -m 2 -o /dev/null -w "pageserver=%{http_code}\n" http://127.0.0.1:9898/v1/status
nohup "$BIN/neon_local" safekeeper start > "$HOME_DIR/sk.log" 2>&1 &
for i in $(seq 1 30); do sleep 2; curl -s -m 2 -o /dev/null http://127.0.0.1:7676/v1/status && break; done
curl -s -m 2 -o /dev/null -w "safekeeper=%{http_code}\n" http://127.0.0.1:7676/v1/status

echo "=== 5) safekeeper 注册进 storcon ==="
printf '{"id":1,"region_id":"local","version":5957,"host":"127.0.0.1","port":5454,"http_port":7676,"availability_zone_id":"sk-1"}' > /tmp/sk_reg.json
curl -s -m 5 -X POST http://127.0.0.1:1234/control/v1/safekeeper/1 -H "Content-Type: application/json" \
  --data @/tmp/sk_reg.json -o /dev/null -w "sk_register=%{http_code}\n"
curl -s -m 5 -X PUT http://127.0.0.1:1234/control/v1/safekeeper/1/scheduling_policy \
  -H "Content-Type: application/json" -d '{"scheduling_policy":"Active"}' -o /dev/null -w "sk_policy=%{http_code}\n"
sleep 3

echo "=== 6) tenant / endpoint（PG18） ==="
# tenant create 会创建初始时间线并映射为 main；--pg-version 18 决定其版本
# （timeline create 单独建 main 会与该初始时间线冲突：branch 已映射）
T_OUT=$("$BIN/neon_local" tenant create --set-default --pg-version "$SMOKE_PG_VERSION" 2>&1 | tail -1)
echo "tenant create: $T_OUT"
case "$T_OUT" in *"command failed"*) fail "tenant create 失败: $T_OUT";; esac
TENANT=$("$BIN/neon_local" tenant list 2>/dev/null | grep -oE "[0-9a-f]{32}" | head -1)
echo "tenant=$TENANT"
[ -n "$TENANT" ] || fail "tenant 创建失败"
EP_OUT=$("$BIN/neon_local" endpoint create main --tenant-id "$TENANT" --pg-version "$SMOKE_PG_VERSION" 2>&1 | tail -1)
echo "endpoint create: $EP_OUT"
case "$EP_OUT" in *"command failed"*) fail "endpoint create 失败: $EP_OUT";; esac

echo "=== 7) endpoint start（PG18 compute + neon.dylib 全链路） ==="
nohup "$BIN/neon_local" endpoint start main > "$HOME_DIR/ep.log" 2>&1 &
for i in $(seq 1 90); do
  sleep 2
  "$PGROOT/bin/pg_isready" -h 127.0.0.1 -p 55432 -t 1 >/dev/null 2>&1 && break
  if grep -q "command failed" "$HOME_DIR/ep.log" 2>/dev/null; then break; fi
done
"$PGROOT/bin/pg_isready" -h 127.0.0.1 -p 55432 -t 1 || {
  echo "--- ep.log 尾部 ---"; tail -15 "$HOME_DIR/ep.log"
  echo "--- compute.log 尾部 ---"
  tail -30 "$HOME_DIR/.neon/endpoints/main/compute.log" 2>/dev/null
  fail "compute 55432 未就绪"
}
echo "compute OK"

echo "=== 8) SQL 全链路冒烟（WAL→safekeeper→pageserver→compute） ==="
"$PGROOT/bin/psql" -h 127.0.0.1 -p 55432 -U cloud_admin -d postgres -v ON_ERROR_STOP=1 \
  -c "CREATE TABLE t_full(id int primary key, v text); INSERT INTO t_full VALUES (1,'neon-pg18-full-path');" 2>&1 | tail -2
"$PGROOT/bin/psql" -h 127.0.0.1 -p 55432 -U cloud_admin -d postgres -c "SELECT * FROM t_full;" 2>&1 | tail -4

echo "=== 9) 组件清点 ==="
ps ax -o command | grep -cE "$BIN/pageserver|$BIN/safekeeper -D|$BIN/storage_controller|$BIN/storage_broker|$BIN/endpoint_storage|postgres -D"

echo "FULLPATH_SMOKE_DONE"
