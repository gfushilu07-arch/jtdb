#!/bin/zsh
# ============================================================================
# 四象限性能基线（ADR-015）：存储路径(本地/Neon) × io_method(sync/worker)
#
# 定位（重要）：本机为 debug 构建（cargo dev + PG --enable-debug），绝对数值无意义；
# 本脚本建立"方法学 + 相对对比"基线：Neon 路径相对 vanilla PG18 本地路径的开销比，
# 以及 PG18 io_method 对 Neon 路径的影响。正式数字按规划 §9.3 在 Linux NVMe 环境测。
#
# 负载：pgbench 默认 TPC-B-like 混合 + -S 只读；scale 10；4 客户端 30s×2。
# 用法: source scripts/env.sh && zsh scripts/benchmark-quadrant-macos.sh
# 前置: full-path-smoke-macos.sh 已跑过（Neon 环境存活，endpoint main 在 55432）
# ============================================================================
set -uo pipefail
: "${JTDB_CACHE_ROOT:?请先 source scripts/env.sh}"
RES="$JTDB_CACHE_ROOT/logs/benchmark-quadrant.log"
PGROOT="$JTDB_CACHE_ROOT/mac-pg-install/v18"
BIN="$JTDB_CACHE_ROOT/target/rust-macos/debug"
NEON_HOME=/tmp/neonhome-macos
SCALE=10
CLIENTS=4
DURATION=30

mkdir -p "$(dirname "$RES")"
echo "=== 四象限基线 $(date '+%F %T') | scale=$SCALE clients=$CLIENTS t=${DURATION}s（debug 构建，只看相对值）===" | tee -a "$RES"

run_pgbench() { # $1=标签 $2=端口 $3=用户
  local label=$1 port=$2 user=$3
  echo "--- $label: 混合读写 ---" | tee -a "$RES"
  "$PGROOT/bin/pgbench" -h 127.0.0.1 -p "$port" -U "$user" -c $CLIENTS -j 2 -T $DURATION \
    -M simple -n bench 2>&1 | grep -E "number of transactions|latency average|tps =" | tee -a "$RES"
  echo "--- $label: 只读(-S) ---" | tee -a "$RES"
  "$PGROOT/bin/pgbench" -S -h 127.0.0.1 -p "$port" -U "$user" -c $CLIENTS -j 2 -T $DURATION \
    -M simple -n bench 2>&1 | grep -E "number of transactions|latency average|tps =" | tee -a "$RES"
}

# ---------- 象限 1/2：vanilla PG18 本地存储（io_method=sync / worker） ----------
LOCAL_IDX=0
for mode in sync worker; do
  LOCAL_IDX=$((LOCAL_IDX+1))
  DIR=/tmp/pgbench-local-$mode
  PORT=$((17800+LOCAL_IDX))
  echo "=== 本地-$mode init ===" | tee -a "$RES"
  rm -rf "$DIR"
  "$PGROOT/bin/initdb" -D "$DIR" --username=$(whoami) --no-sync >/dev/null 2>&1
  { echo "port = $PORT"; echo "io_method = $mode"; echo "fsync = off"; echo "synchronous_commit = off"; } >> "$DIR/postgresql.conf"
  "$PGROOT/bin/pg_ctl" -D "$DIR" -l "$DIR/pg.log" -w -o "-p $PORT" start >/dev/null 2>&1
  "$PGROOT/bin/createdb" -h 127.0.0.1 -p "$PORT" -U $(whoami) bench
  "$PGROOT/bin/pgbench" -i -s $SCALE -h 127.0.0.1 -p "$PORT" -U $(whoami) bench >/dev/null 2>&1
  run_pgbench "本地-$mode" "$PORT" $(whoami)
  "$PGROOT/bin/pg_ctl" -D "$DIR" -m fast stop >/dev/null 2>&1
done

# ---------- 象限 3：Neon 路径 io_method=worker（endpoint 默认） ----------
echo "=== Neon-worker（复用存活 endpoint，默认 worker）===" | tee -a "$RES"
P=/tmp/neonhome-macos/.neon/endpoints/main/postgresql.conf
grep -q "^io_method" "$P" && sed -i '' '/^io_method/d' "$P"
"$BIN/neon_local" endpoint stop main >/dev/null 2>&1
pkill -9 -f "compute_ctl --external" 2>/dev/null; sleep 2
rm -rf /tmp/neonhome-macos/.neon/endpoints/main/pgdata
(cd "$NEON_HOME" && nohup "$BIN/neon_local" endpoint start main > ep.log 2>&1 &)
sleep 20
"$PGROOT/bin/pg_isready" -h 127.0.0.1 -p 55432 -t 3 >/dev/null || { echo "compute 未就绪"; exit 1; }
"$PGROOT/bin/psql" -h 127.0.0.1 -p 55432 -U cloud_admin -d postgres -c "DROP TABLE IF EXISTS t_full, pgbench_accounts, pgbench_branches, pgbench_tellers, pgbench_history CASCADE" >/dev/null 2>&1
"$PGROOT/bin/pgbench" -i -s $SCALE -h 127.0.0.1 -p 55432 -U cloud_admin bench >/dev/null 2>&1
run_pgbench "Neon-worker" 55432 cloud_admin

# ---------- 象限 4：Neon 路径 io_method=sync ----------
echo "=== Neon-sync ===" | tee -a "$RES"
echo "io_method = sync" >> "$P"
"$BIN/neon_local" endpoint stop main >/dev/null 2>&1
pkill -9 -f "compute_ctl --external" 2>/dev/null; sleep 2
rm -rf /tmp/neonhome-macos/.neon/endpoints/main/pgdata
(cd "$NEON_HOME" && nohup "$BIN/neon_local" endpoint start main > ep.log 2>&1 &)
sleep 20
"$PGROOT/bin/pg_isready" -h 127.0.0.1 -p 55432 -t 3 >/dev/null || { echo "compute 未就绪"; exit 1; }
run_pgbench "Neon-sync" 55432 cloud_admin
# 恢复 worker 默认
sed -i '' '/^io_method/d' "$P"

echo "QUADRANT_BENCH_DONE" | tee -a "$RES"
