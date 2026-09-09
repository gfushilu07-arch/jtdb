#!/bin/bash
# JTDB 千橙冒烟 —— 全程以 jtuser 运行（PG 拒绝 root initdb）
# ============================================================================
# 千橙(CentOS8 x86_64, glibc 2.28) 全链路冒烟 v1
#   storcon(内部PG) → broker → pageserver → safekeeper → endpoint(PG18 compute)
#   → SQL 全链路（WAL→safekeeper→pageserver→compute）
# 用法: bash full-path-smoke-qc.sh
# ============================================================================
set -uo pipefail
[ "$(whoami)" = "jtuser" ] || { echo "请以 jtuser 运行: su - jtuser -c 'bash $0'"; exit 1; }
BIN=/root/jt/bin
PGROOT=/root/jt/pg18
HOME_DIR=/home/jtuser/neonhome-qc
export POSTGRES_DISTRIB_DIR=/root/jt/pgdistrib
LOG=/tmp/neonhome-qc-smoke.log
exec > >(tee "$LOG") 2>&1
fail() { echo "FAIL: $*"; exit 1; }
wait_port() { # port timeout_sec
  for i in $(seq 1 "$2"); do
    /usr/sbin/ss -ltn 2>/dev/null | grep -q ":$1 " && return 0
    sleep 1
  done
  return 1
}
echo "=== 0) 清理旧运行 ==="
pkill -9 -f "$BIN/pageserver" 2>/dev/null
pkill -9 -f "$BIN/safekeeper" 2>/dev/null
pkill -9 -f "$BIN/storage_controller" 2>/dev/null
pkill -9 -f "$BIN/neon_local" 2>/dev/null
pkill -9 -f "$BIN/endpoint_storage" 2>/dev/null
pkill -9 -f "$BIN/storage_broker" 2>/dev/null
pkill -9 -f "postgres -D $HOME_DIR" 2>/dev/null
pkill -9 -f "postgres -D /tmp/neonhome-qc" 2>/dev/null
sleep 2
for port in 1234 1235 9898 7676 64000 50051 9993 55432; do
  if /usr/sbin/ss -ltn 2>/dev/null | grep -q ":$port "; then
    for i in $(seq 1 10); do
      /usr/sbin/ss -ltn 2>/dev/null | grep -q ":$port " || break
      sleep 1
    done
    /usr/sbin/ss -ltn 2>/dev/null | grep -q ":$port " && fail "端口 $port 无法释放"
  fi
done
echo "端口全部空闲"

echo "=== 1) 前置检查 ==="
for b in compute_ctl endpoint_storage storage_broker neon_local pageserver safekeeper storage_controller; do
  [ -x "$BIN/$b" ] || fail "$BIN/$b 缺失"
done
echo "Rust 二进制 7 件套 OK"
ls "$PGROOT/lib/postgresql/neon.so" >/dev/null || fail "neon.so 缺失"
"$PGROOT/bin/postgres" --version || fail "v18 postgres 不可执行"

echo "=== 2) neon_local init ==="
rm -rf "$HOME_DIR"
mkdir -p "$HOME_DIR"
cd "$HOME_DIR"
"$BIN/neon_local" init 2>&1 | tail -2 || fail "neon_local init"

echo "=== 3) storcon 内部 PG + storcon（--dev 本地 upcall 模式） ==="
STORCON_DB="$HOME_DIR/.neon/storage_controller_db"
"$PGROOT/bin/initdb" -D "$STORCON_DB" --username=jtuser --no-sync --no-instructions >/dev/null 2>&1 || fail "storcon initdb"
printf 'port = 1235\nfsync = off\n' >> "$STORCON_DB/postgresql.conf"
"$PGROOT/bin/pg_ctl" -D "$STORCON_DB" -l "$STORCON_DB/pg.log" -w -o "-p 1235" start >/dev/null 2>&1 || { tail -20 "$STORCON_DB/pg.log"; fail "storcon 内部 PG 启动"; }
"$PGROOT/bin/pg_isready" -h 127.0.0.1 -p 1235 -t 5 >/dev/null || fail "内部 PG 1235 未就绪"
"$PGROOT/bin/createdb" -h 127.0.0.1 -p 1235 -U jtuser storage_controller >/dev/null 2>&1 || fail "createdb storage_controller"
nohup "$BIN/storage_controller" --dev \
  --database-url="postgresql://jtuser@localhost:1235/storage_controller" \
  --listen 127.0.0.1:1234 --address-for-peers http://127.0.0.1:1234 \
  --neon-local-repo-dir "$HOME_DIR" \
  --max-offline-interval 10s --max-warming-up-interval 30s --heartbeat-interval 1s \
  --timelines-onto-safekeepers --timeline-safekeeper-count 1 \
  --use-local-compute-notifications \
  > "$HOME_DIR/.neon/storcon.log" 2>&1 &
for i in $(seq 1 30); do sleep 1; curl -s -m 2 -o /dev/null http://127.0.0.1:1234 && break; done
curl -s -m 2 -o /dev/null http://127.0.0.1:1234 || { tail -20 "$HOME_DIR/.neon/storcon.log"; fail "storcon 1234 未就绪"; }
echo "storcon OK"

echo "=== 4) broker + endpoint_storage + pageserver + safekeeper ==="
nohup "$BIN/storage_broker" --listen-addr 127.0.0.1:50051 > "$HOME_DIR/.neon/broker.log" 2>&1 &
wait_port 50051 15 || { tail -10 "$HOME_DIR/.neon/broker.log"; fail "broker 50051 未监听"; }
echo "broker OK"
nohup "$BIN/endpoint_storage" "$HOME_DIR/.neon/endpoint_storage/endpoint_storage.json" \
  > "$HOME_DIR/.neon/eps.log" 2>&1 &
wait_port 9993 10 || { tail -10 "$HOME_DIR/.neon/eps.log"; fail "endpoint_storage 9993 未监听"; }
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
T_OUT=$("$BIN/neon_local" tenant create --set-default --pg-version 18 2>&1 | tail -1)
echo "tenant create: $T_OUT"
case "$T_OUT" in *"command failed"*) fail "tenant create 失败: $T_OUT";; esac
TENANT=$("$BIN/neon_local" tenant list 2>/dev/null | grep -oE "[0-9a-f]{32}" | head -1)
echo "tenant=$TENANT"
[ -n "$TENANT" ] || fail "tenant 创建失败"
EP_OUT=$("$BIN/neon_local" endpoint create main --tenant-id "$TENANT" --pg-version 18 2>&1 | tail -1)
echo "endpoint create: $EP_OUT"
case "$EP_OUT" in *"command failed"*) fail "endpoint create 失败: $EP_OUT";; esac

echo "=== 7) endpoint start（PG18 compute + neon.so 全链路） ==="
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

echo "=== 8) SQL 全链路冒烟 ==="
"$PGROOT/bin/psql" -h 127.0.0.1 -p 55432 -U cloud_admin -d postgres -v ON_ERROR_STOP=1 \
  -c "CREATE TABLE t_full(id int primary key, v text); INSERT INTO t_full VALUES (1,'neon-pg18-qc-full-path');" 2>&1 | tail -2
"$PGROOT/bin/psql" -h 127.0.0.1 -p 55432 -U cloud_admin -d postgres -c "SELECT * FROM t_full;" 2>&1 | tail -4

echo "=== 9) 组件清点 ==="
ps ax -o command | grep -cE "$BIN/pageserver|$BIN/safekeeper -D|$BIN/storage_controller|$BIN/storage_broker|$BIN/endpoint_storage|postgres -D"

echo "FULLPATH_SMOKE_DONE"
