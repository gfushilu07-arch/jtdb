#!/bin/zsh
# ============================================================================
# PG18 全链路功能测试套件（v1 存储链路验收）
# 覆盖：DDL / 事务 / 回滚 / 序列 / 索引 / JSON / 大对象 / VACUUM / CHECKPOINT
#       / 并发写 / 读放大（walredo）/ 崩溃恢复（compute kill -9）/ endpoint 重启
# 用法: source scripts/env.sh && zsh scripts/test-suite-pg18.sh
# 前置: full-path-smoke-macos.sh 已跑过（endpoint main 在 55432）
# ============================================================================
set -uo pipefail
: "${JTDB_CACHE_ROOT:?请先 source scripts/env.sh}"
RES="$JTDB_CACHE_ROOT/logs/test-suite-pg18.log"
PGROOT="$JTDB_CACHE_ROOT/mac-pg-install/v18"
BIN="$JTDB_CACHE_ROOT/target/rust-macos/debug"
PORT=55432
PSQL=( "$PGROOT/bin/psql" -h 127.0.0.1 -p $PORT -U cloud_admin -d postgres -v ON_ERROR_STOP=1 )

PASS=0; FAIL=0
check() { # $1=名称 $2=期望 $3=实际
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "PASS: $1"; else FAIL=$((FAIL+1)); echo "FAIL: $1 (期望 $2, 实际 $3)"; fi
}
conn() { "$PGROOT/bin/pg_isready" -h 127.0.0.1 -p $PORT -t 5 >/dev/null 2>&1; }

echo "=== PG18 功能测试套件 $(date '+%F %T') ===" | tee "$RES"
conn || { echo "compute 不可达"; exit 1; }

q() { "${PSQL[@]}" -Atc "$1" 2>&1; }

# ---------- 1. DDL / CRUD ----------
q "DROP TABLE IF EXISTS tsuite CASCADE" >/dev/null
q "CREATE TABLE tsuite(id serial PRIMARY KEY, k text UNIQUE, v jsonb, n numeric(20,4), t timestamp default now(), b bytea)" >/dev/null
check "建表+序列+唯一约束" "t" "$(q "SELECT to_regclass('tsuite') IS NOT NULL")"

q "INSERT INTO tsuite(k,v,n,b) VALUES ('a','{\"x\":1}',1.5,'\xdeadbeef'),('b','{\"x\":2}',2.25,'\xcafe'),('c','{\"x\":3}',3.125,'\xba')" >/dev/null
check "插入 3 行" "3" "$(q "SELECT count(*) FROM tsuite")"

check "jsonb 查询" "2" "$(q "SELECT count(*) FROM tsuite WHERE (v->>'x')::int > 1")"
check "numeric 精度" "6.8750" "$(q "SELECT sum(n) FROM tsuite")"
check "bytea roundtrip" "deadbeef" "$(q "SELECT encode(b,'hex') FROM tsuite WHERE k='a'")"

q "UPDATE tsuite SET v='{\"y\":9}' WHERE k='a'" >/dev/null
check "UPDATE" "9" "$(q "SELECT (v->>'y')::int FROM tsuite WHERE k='a'")"
q "DELETE FROM tsuite WHERE k='c'" >/dev/null
check "DELETE" "2" "$(q "SELECT count(*) FROM tsuite")"

# ---------- 2. 事务 / 回滚 ----------
"${PSQL[@]}" -q -c "BEGIN; INSERT INTO tsuite(k) VALUES ('tx1'); INSERT INTO tsuite(k) VALUES ('tx2'); ROLLBACK;" >/dev/null 2>&1
check "事务回滚" "2" "$(q "SELECT count(*) FROM tsuite")"

"${PSQL[@]}" -q -c "BEGIN; INSERT INTO tsuite(k) VALUES ('tx3'); COMMIT;" >/dev/null 2>&1
check "事务提交" "1" "$(q "SELECT count(*) FROM tsuite WHERE k='tx3'")"

# 冲突回滚
"${PSQL[@]}" -q -c "BEGIN; INSERT INTO tsuite(k) VALUES ('dup'); INSERT INTO tsuite(k) VALUES ('dup');" >/dev/null 2>&1
check "冲突中止" "0" "$(q "SELECT count(*) FROM tsuite WHERE k='dup'")"

# ---------- 3. 索引 / 执行计划 ----------
q "CREATE INDEX idx_tsuite_v ON tsuite USING gin(v)" >/dev/null
check "GIN 索引创建" "t" "$(q "SELECT to_regclass('idx_tsuite_v') IS NOT NULL")"
check "GIN 索引命中" "1" "$(q "SELECT count(*) FROM tsuite WHERE v @> '{\"y\":9}'")"
q "VACUUM tsuite" >/dev/null && check "VACUUM" "0" "$?"

# ---------- 4. 大数据量（跨页 + walredo 读放大） ----------
q "DROP TABLE IF EXISTS big CASCADE" >/dev/null
q "CREATE TABLE big(id int GENERATED ALWAYS AS IDENTITY, payload text)" >/dev/null
"${PSQL[@]}" -q -c "INSERT INTO big(payload) SELECT repeat(md5(g::text), 32) FROM generate_series(1,20000) g" >/dev/null 2>&1
check "2 万行写入" "20000" "$(q "SELECT count(*) FROM big")"
check "大页读聚合" "1024000" "$(q "SELECT length(string_agg(payload,'')) FROM (SELECT payload FROM big ORDER BY id LIMIT 1000) t")"
check "索引扫描" "12345" "$(q "SELECT id FROM big ORDER BY id OFFSET 12344 LIMIT 1")"

# ---------- 5. CHECKPOINT / DDL 混合 ----------
q "CHECKPOINT" >/dev/null && check "CHECKPOINT" "0" "$?"
q "ALTER TABLE big ADD COLUMN extra int DEFAULT 42" >/dev/null
check "ALTER TABLE" "42" "$(q "SELECT extra FROM big LIMIT 1")"

# ---------- 6. 并发写（4 后端并发插入同一表） ----------
q "DROP TABLE IF EXISTS conc CASCADE" >/dev/null
q "CREATE TABLE conc(id int)" >/dev/null
for i in 1 2 3 4; do
  ( "${PSQL[@]}" -q -c "INSERT INTO conc SELECT generate_series(1,500)" >/dev/null 2>&1 ) &
done
wait
check "4 并发插入 2000 行" "2000" "$(q "SELECT count(*) FROM conc")"

# ---------- 7. 崩溃恢复（kill -9 compute → 重启 → 数据完好） ----------
KEYMARK="crashmark-$(date +%s)"
q "CREATE TABLE crashy(k text)" >/dev/null
q "INSERT INTO crashy VALUES ('$KEYMARK')" >/dev/null
BEFORE_CRASH_ROWS=$(q "SELECT count(*) FROM crashy")
# 顺序敏感：先杀 compute_ctl（避免它感知 postmaster 死亡后发起注销又被 -9 打断，
# 导致 storcon 注册状态悬空），再杀 postgres
pkill -9 -f "compute_ctl --external" 2>/dev/null
pkill -9 -f "postgres -D /private/tmp/neonhome-macos/.neon/endpoints" 2>/dev/null
sleep 3
# SIGKILL 后 compute_ctl 无法向 storcon 注销，须显式 endpoint stop 解除
# duplicate-primary 守卫（storcon 侧 endpoint 注册仍在）
"$BIN/neon_local" endpoint stop main >/dev/null 2>&1 || true
sleep 2
# 关键：kill -9 后 pgdata/postmaster.pid 残留，neon_local 据此判 Crashed(≠Stopped)
# 而拒绝重启（duplicate primary）。pgdata 本就由 basebackup 重建，直接删除。
rm -rf /tmp/neonhome-macos/.neon/endpoints/main/pgdata
# storcon 的 duplicate-primary 守卫需要 lease 过期（max_offline 10s），重试式恢复
RESTORED=0
for attempt in 1 2 3 4; do
  ( cd /tmp/neonhome-macos && nohup "$BIN/neon_local" endpoint start main > ep.log 2>&1 & )
  for i in $(seq 1 20); do sleep 2; conn && break; done
  if conn; then RESTORED=1; break; fi
  if ! grep -q "command failed" /tmp/neonhome-macos/ep.log 2>/dev/null; then
    for i in $(seq 1 15); do sleep 2; conn && break; done
    conn && { RESTORED=1; break; }
  fi
  pkill -9 -f "compute_ctl --external" 2>/dev/null
  sleep 6
done
if [ "$RESTORED" = "1" ]; then check "崩溃后 compute 恢复" "1" "1"; else echo "FAIL: 崩溃后 compute 未恢复"; FAIL=$((FAIL+1)); fi
check "崩溃后数据完好" "t" "$(q "SELECT EXISTS(SELECT 1 FROM crashy WHERE k='$KEYMARK')")"

# ---------- 8. 新写入继续可用（恢复后写路径） ----------
q "INSERT INTO crashy VALUES ('post-crash')" >/dev/null
check "恢复后可写" "$((BEFORE_CRASH_ROWS+1))" "$(q "SELECT count(*) FROM crashy")"

echo "=== 结果: PASS=$PASS FAIL=$FAIL ===" | tee -a "$RES"
[ "$FAIL" = "0" ] && echo "SUITE_OK" || echo "SUITE_FAILED"
