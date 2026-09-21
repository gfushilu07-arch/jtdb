#!/usr/bin/env bash
# WAL 加密端到端验证（基础2 真实 Linux + 真实 WAL 流）
#
# 验证目标：这几轮实现的 WAL 段加密在**真实 Linux + 真实 WAL 写入流**下工作。
# 单元/集成层已在 macOS 验证"加密段不含明文、读回一致、格式识别"；
# 本脚本补端到端：neon_local 全链路 + 真实 KMS 租约 + 真实 WAL 流。
#
# 用法（以 jtuser 运行）：
#   su - jtuser -c 'bash /home/jtuser/jt/wal-encryption-e2e.sh'
#
# 关键：加密开关通过 neon_local 的 --safekeeper-extra-opt 传给 safekeeper
# （neon_local 不会自动转发自定义参数；不加这一步测试会"静默跑明文"，
#  从而得出错误的"未加密"结论——这是本脚本必须显式传递的原因）。
set -uo pipefail

BIN="${BIN:-/home/jtuser/jt/bin}"
HOME_DIR="${HOME_DIR:-/home/jtuser/neonhome-enc-e2e}"
KMS_PORT="${KMS_PORT:-7710}"
SK_PG_PORT="${SK_PG_PORT:-6501}"
KMS_DATA=/tmp/kms-e2e-b2
KMS_LOG=/tmp/kms-e2e-b2.log
LOG=/tmp/wal-enc-e2e.log
TL_ID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

export LD_LIBRARY_PATH="${PGROOT:-/home/jtuser/jt/pgdistrib/v18}/lib:${LD_LIBRARY_PATH:-}"
exec > >(tee "$LOG") 2>&1

fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "  PASS  $*"; }

wait_port() {
  for _ in $(seq 1 "$2"); do
    /usr/sbin/ss -ltn 2>/dev/null | grep -q ":$1 " && return 0
    sleep 1
  done
  return 1
}

cleanup() {
  [ -n "${KMS_PID:-}" ] && kill "$KMS_PID" 2>/dev/null
  if [ -d "$HOME_DIR/.neon" ]; then
    (cd "$HOME_DIR" && "$BIN/neon_local" stop >/dev/null 2>&1) || true
  fi
}
trap cleanup EXIT

echo "=== 0. 前置检查 ==="
for b in neon_local safekeeper pageserver; do
  [ -x "$BIN/$b" ] || fail "缺 $b（$BIN）"
done
KMS_BIN="$(command -v jt-kms || echo "$BIN/jt-kms")"
[ -x "$KMS_BIN" ] || fail "缺 jt-kms（$KMS_BIN）—— 需先部署"
echo "  neon_local: $BIN/neon_local"
echo "  jt-kms:     $KMS_BIN"
# 确认二进制含 WAL 加密代码（防"用了旧二进制"的假失败/假通过）
if strings "$BIN/safekeeper" 2>/dev/null | grep -q "wal-encryption-kms-endpoint"; then
  pass "safekeeper 含 WAL 加密 CLI（新构建）"
else
  fail "safekeeper 不含 wal-encryption-kms-endpoint —— 二进制过旧，需重新构建部署"
fi

echo
echo "=== 1. 启动真实 jt-kms ==="
rm -rf "$KMS_DATA"
"$KMS_BIN" --listen "127.0.0.1:${KMS_PORT}" --data-dir "$KMS_DATA" > "$KMS_LOG" 2>&1 &
KMS_PID=$!
wait_port "$KMS_PORT" 30 || { cat "$KMS_LOG"; fail "KMS 未就绪"; }
curl -sf "http://127.0.0.1:${KMS_PORT}/health" >/dev/null || fail "KMS health 失败"
pass "KMS 就绪（端口 ${KMS_PORT}）"

echo
echo "=== 2. 初始化 neon_local ==="
rm -rf "$HOME_DIR"
mkdir -p "$HOME_DIR"
cd "$HOME_DIR" || fail "无法进入 $HOME_DIR"
"$BIN/neon_local" init > init.log 2>&1 || { tail -20 init.log; fail "neon_local init 失败"; }
pass "neon_local init"

echo
echo "=== 3. 启动 safekeeper（带 WAL 加密参数）==="
# 证明摘要每次由采集器生成（动态）；此处给一个初值，KMS 只做防重放检查
ATT_DIGEST="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
"$BIN/neon_local" safekeeper start \
  --safekeeper-extra-opt="--wal-encryption-kms-endpoint=http://127.0.0.1:${KMS_PORT}" \
  --safekeeper-extra-opt="--wal-encryption-node-id=sk-e2e-b2" \
  --safekeeper-extra-opt="--wal-encryption-attestation-digest=${ATT_DIGEST}" \
  --safekeeper-extra-opt="--wal-encryption-key-epoch=1" \
  --safekeeper-extra-opt="--wal-encryption-generation=1" \
  > sk.log 2>&1 || { tail -25 sk.log; fail "safekeeper 启动失败"; }
wait_port "$SK_PG_PORT" 30 || { tail -20 sk.log; fail "safekeeper(6501) 未就绪"; }
pass "safekeeper 启动（加密参数已传）"

echo
echo "=== 4. 启动其余组件 ==="
"$BIN/neon_local" start > start.log 2>&1 || { tail -30 start.log; fail "全链路启动失败"; }
wait_port 6400 60 || fail "pageserver(6400) 未就绪"
pass "全链路启动"

echo
echo "=== 5. 建 tenant + timeline ==="
"$BIN/neon_local" tenant create --tenant-id "$TL_ID" --pg-version 18 > tenant.log 2>&1 \
  || { tail -20 tenant.log; fail "tenant create 失败"; }
pass "tenant created"

echo
echo "=== 6. 写真实 WAL 流 ==="
"$BIN/neon_local" endpoint start main > ep.log 2>&1 || { tail -20 ep.log; fail "endpoint start 失败"; }
sleep 6
PGPORT=$(grep -oE 'port = [0-9]+' "$HOME_DIR/endpoints/main/postgresql.conf" 2>/dev/null | head -1 | grep -oE '[0-9]+')
PGPORT=${PGPORT:-55432}
psql -h 127.0.0.1 -p "$PGPORT" -U cloud_admin -d postgres \
  -c "CREATE TABLE t(id int, payload text);" \
  -c "INSERT INTO t SELECT g, repeat('SECRET_PAYLOAD_', 8) FROM generate_series(1,5000) g;" \
  > sql.log 2>&1 || { tail -10 sql.log; fail "SQL 写入失败"; }
pass "写入 5000 行（产生真实 WAL）"

echo
echo "=== 7. 验证 WAL 段已加密（关键判据）==="
SK_DIR="$HOME_DIR/safekeepers/sk1"
FOUND=0; ENCRYPTED=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  FOUND=$((FOUND + 1))
  SIZE=$(stat -c%s "$f" 2>/dev/null || echo 0)
  # 加密活段判据：文件尾 130B header 的 magic = "JTENCOBJ"
  if [ "$SIZE" -gt 130 ] && tail -c 130 "$f" | head -c 8 | grep -q "JTENCOBJ"; then
    ENCRYPTED=$((ENCRYPTED + 1))
  fi
done < <(find "$SK_DIR" -name "*.partial" -o -name "0000*" 2>/dev/null | head -20)

echo "  段文件 $FOUND 个，带加密头 $ENCRYPTED 个"
[ "$ENCRYPTED" -gt 0 ] || { ls -la "$SK_DIR" 2>/dev/null | head -5; fail "WAL 段未加密（装配参数未生效？）"; }
pass "WAL 段已加密（文件尾含 JTENCOBJ header）"

echo
echo "=== 8. 明文泄漏检查（核心判据）==="
LEAK=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -q "SECRET_PAYLOAD_" "$f" 2>/dev/null; then
    echo "  ⚠ 段 $f 含明文标记"
    LEAK=$((LEAK + 1))
  fi
done < <(find "$SK_DIR" -name "*.partial" -o -name "0000*" 2>/dev/null | head -20)
[ "$LEAK" -eq 0 ] || fail "$LEAK 个段含明文（加密未生效！）"
pass "段文件不含明文标记（加密确实生效）"

echo
echo "=== 9. 系统仍可正常工作（加密后数据可读）==="
ROWS=$(psql -h 127.0.0.1 -p "$PGPORT" -U cloud_admin -d postgres -tAc "SELECT count(*) FROM t;" 2>/dev/null)
[ "$ROWS" = "5000" ] && pass "数据读回正确（$ROWS 行）" || fail "数据读回错误：$ROWS"

# 重启后仍可读（验证读路径解密 + 段持久化）
"$BIN/neon_local" endpoint stop main >/dev/null 2>&1
"$BIN/neon_local" endpoint start main >/dev/null 2>&1
sleep 5
ROWS2=$(psql -h 127.0.0.1 -p "$PGPORT" -U cloud_admin -d postgres -tAc "SELECT count(*) FROM t;" 2>/dev/null)
[ "$ROWS2" = "5000" ] && pass "重启后数据仍可读（读路径解密生效）" || fail "重启后读回错误：$ROWS2"

echo
echo "WAL_ENCRYPTION_E2E_OK"
