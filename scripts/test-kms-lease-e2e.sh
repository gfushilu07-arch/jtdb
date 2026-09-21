#!/usr/bin/env bash
# KMS 租约端到端验证（真实 jt-kms 实例 + KmsLeaseProvider）
#
# 验证两件事（其中第 1 项是修复前会失败的回归判据）：
#   1. Dynamic 摘要下**连续多次**取 DEK 都成功
#      —— 修复前装配用静态摘要，第二次必被 KMS 防重放拒绝（409）
#   2. Fixed 摘要第二次**必须**失败（反向验证，确认判据有效而非"恰好能跑"）
#
# 前置：jt-kms 已构建（scripts/env.sh 已 source）
# 用法: source scripts/env.sh && bash scripts/test-kms-lease-e2e.sh
set -u

KMS_BIN="${JTDB_CACHE_ROOT:?请先 source scripts/env.sh}/target/rust/debug/jt-kms"
PORT="${KMS_E2E_PORT:-7799}"
DATA=/tmp/kms-e2e-data
LOG=/tmp/kms-e2e.log

if [ ! -x "$KMS_BIN" ]; then
  echo "FAIL: jt-kms 未构建（$KMS_BIN）"
  echo "      先运行: cargo build -p jt-kms"
  exit 1
fi

cleanup() {
  [ -n "${KMSPID:-}" ] && kill "$KMSPID" 2>/dev/null
  wait "$KMSPID" 2>/dev/null
}
trap cleanup EXIT

rm -rf "$DATA"
echo "=== 启动真实 jt-kms（端口 ${PORT}）==="
"$KMS_BIN" --listen "127.0.0.1:$PORT" --data-dir "$DATA" > "$LOG" 2>&1 &
KMSPID=$!

for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
if ! curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
  echo "FAIL: KMS 未就绪"; tail -5 "$LOG"; exit 1
fi
echo "  health=ok"

echo
echo "=== 1. Dynamic 摘要：连续 3 次取 DEK（应全成功）==="
if ! KMS_ENDPOINT="http://127.0.0.1:$PORT" \
     cargo run -q --manifest-path "$(dirname "$0")/../tests/e2e/Cargo.toml" 2>/dev/null | grep -q "E2E_OK"; then
  echo "  FAIL: Dynamic 摘要路径未通过"
  KMS_ENDPOINT="http://127.0.0.1:$PORT" \
    cargo run -q --manifest-path "$(dirname "$0")/../tests/e2e/Cargo.toml" 2>&1 | tail -12
  exit 1
fi
echo "  PASS 连续 3 次成功（含续租场景）"

echo
echo "=== 2. Fixed 摘要反向验证：第二次必须失败 ==="
# 换新端口重开（避免上轮的 seen 摘要干扰）
cleanup
rm -rf "$DATA"
"$KMS_BIN" --listen "127.0.0.1:$PORT" --data-dir "$DATA" > "$LOG" 2>&1 &
KMSPID=$!
for _ in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
  sleep 0.25
done

out=$(USE_FIXED=1 KMS_ENDPOINT="http://127.0.0.1:$PORT" \
      cargo run -q --manifest-path "$(dirname "$0")/../tests/e2e/Cargo.toml" 2>&1 || true)
if printf '%s' "$out" | grep -q "FAIL: kms unavailable.*409"; then
  echo "  PASS Fixed 摘要第二次被拒（409 防重放）——判据有效"
else
  echo "  FAIL: Fixed 摘要未被拒（防重放失效？）"
  printf '%s\n' "$out" | tail -8
  exit 1
fi

echo
echo "KMS_E2E_OK"
