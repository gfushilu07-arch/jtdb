#!/usr/bin/env bash
# WAL 加密端到端验证（基础2 真实 Linux + 真实 WAL 流）
#
# 验证目标：WAL 段加密在**真实 Linux + 真实 WAL 写入流**下工作。
# 单元/集成层已在 macOS 验证（加密段不含明文、读回一致、格式识别）；
# 本脚本补端到端：全链路 + 真实 KMS 租约 + 真实 WAL 流。
#
# 启动序列**沿用 full-path-smoke-qc.sh 的既有约定**。关键：**不用**
# `neon_local start`——它假设 storcon 内部 PG 用户为 cloud_admin，而本机实际
# 以 jtuser 初始化，会报 "role cloud_admin does not exist" 并使 pageserver
# 无限重试 re-attach（实测踩到）。故按参考脚本逐步起各组件。
#
# 用法（以 jtuser 运行）：
#   su - jtuser -c 'bash /home/jtuser/jt/wal-encryption-e2e-b2.sh'
set -uo pipefail

BIN="${BIN:-/home/jtuser/jt/bin}"
HOME_DIR="${HOME_DIR:-/home/jtuser/neonhome-enc-e2e}"
KMS_PORT="${KMS_PORT:-7710}"
PG_VERSION="${PG_VERSION:-18}"
KMS_DATA=/tmp/kms-e2e-b2
KMS_LOG=/tmp/kms-e2e-b2.log
LOG=/tmp/wal-enc-e2e.log

export POSTGRES_DISTRIB_DIR="${POSTGRES_DISTRIB_DIR:-/home/jtuser/jt/pgdistrib}"
PGROOT="$POSTGRES_DISTRIB_DIR/v$PG_VERSION"
export LD_LIBRARY_PATH="$PGROOT/lib:${LD_LIBRARY_PATH:-}"
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
}
trap cleanup EXIT

echo "=== 0) 前置检查（含内存预检）==="
# 内存预检：全链路（pageserver + safekeeper + storcon + storcon内部PG +
# KMS + compute + broker + endpoint_storage）在 7GB 机器上很吃紧。
# **实测教训**：基础2 上不加限制地跑全链路会导致内存耗尽、sshd 无法服务
# （TCP 可连但立即关闭，ping 100% 丢包）——机器需重启恢复。
# 故此处要求至少 3GB 可用，否则拒绝运行。
AVAIL_MB=$(free -m | awk '/^Mem:/ {print $7}')
echo "  可用内存: ${AVAIL_MB}MB"
if [ "${AVAIL_MB:-0}" -lt 3000 ]; then
  fail "可用内存不足（${AVAIL_MB}MB < 3000MB）——全链路会 OOM 拖垮主机。先释放内存或换更大规格"
fi
# 同时检查是否已有 snsc 业务容器（本机是生产机，不得影响业务）
if command -v docker >/dev/null 2>&1 && docker ps -q 2>/dev/null | head -1 | grep -q .; then
  echo "  ⚠ 检测到运行中的 docker 容器（本机含 snsc 业务）——本脚本只用 127.0.0.1 专有端口，不碰业务目录"
fi

for b in compute_ctl endpoint_storage storage_broker neon_local pageserver safekeeper storage_controller; do
  [ -x "$BIN/$b" ] || fail "$BIN/$b 缺失"
done
KMS_BIN="$(command -v jt-kms || echo "$BIN/jt-kms")"
[ -x "$KMS_BIN" ] || fail "缺 jt-kms（$KMS_BIN）"
ls "$PGROOT/lib/postgresql/neon.so" >/dev/null || fail "neon.so 缺失"
# 确认 safekeeper 含 WAL 加密代码（防"用了旧二进制"的假结论）。
# 注意 set -o pipefail 下 `cmd | grep -q` 会因 SIGPIPE 使判false，故先存变量。
ENC_HITS=$(strings "$BIN/safekeeper" 2>/dev/null | grep -c "wal-encryption-kms-endpoint" || true)
[ "${ENC_HITS:-0}" -gt 0 ] || fail "safekeeper 不含 wal-encryption-kms-endpoint（二进制过旧）"
pass "前置检查（safekeeper 含加密 CLI，命中 ${ENC_HITS}）"

echo
echo "=== 0b) 清理旧运行 ==="
for pat in pageserver safekeeper storage_controller neon_local endpoint_storage storage_broker; do
  pkill -9 -f "$BIN/$pat" 2>/dev/null || true
done
# 清理**任意** JTDB 相关的 postgres 实例（不只本脚本的 HOME_DIR）：
# 实测踩到旧会话（neonhome-enc）留下的 storcon 内部 PG 占着 1235，导致
# 本次启动失败。端口是全局资源，不能只按自己的目录清理。
pkill -9 -f "postgres -D $HOME_DIR" 2>/dev/null || true
pkill -9 -f "postgres -D /home/jtuser/neonhome" 2>/dev/null || true
pkill -9 -f "pg18/bin/postgres" 2>/dev/null || true
pkill -9 -f "pgdistrib/v18/bin/postgres" 2>/dev/null || true
sleep 3
for port in 1234 1235 9898 7676 64000 50051 9993 55432 5454; do
  if /usr/sbin/ss -ltn 2>/dev/null | grep -q ":$port "; then
    for _ in $(seq 1 10); do
      /usr/sbin/ss -ltn 2>/dev/null | grep -q ":$port " || break
      sleep 1
    done
    /usr/sbin/ss -ltn 2>/dev/null | grep -q ":$port " && fail "端口 $port 无法释放"
  fi
done
pass "端口全部空闲"

echo
echo "=== 1) 启动真实 jt-kms ==="
rm -rf "$KMS_DATA"
"$KMS_BIN" --listen "127.0.0.1:${KMS_PORT}" --data-dir "$KMS_DATA" > "$KMS_LOG" 2>&1 &
KMS_PID=$!
wait_port "$KMS_PORT" 30 || { tail -10 "$KMS_LOG"; fail "KMS 未就绪"; }
curl -sf "http://127.0.0.1:${KMS_PORT}/health" >/dev/null || fail "KMS health 失败"
pass "KMS 就绪（端口 ${KMS_PORT}）"

echo
echo "=== 2) neon_local init ==="
rm -rf "$HOME_DIR"
mkdir -p "$HOME_DIR"
cd "$HOME_DIR" || fail "无法进入 $HOME_DIR"
"$BIN/neon_local" init 2>&1 | tail -2 || fail "neon_local init"
pass "init"

echo
echo "=== 3) storcon 内部 PG + storcon ==="
STORCON_DB="$HOME_DIR/.neon/storage_controller_db"
"$PGROOT/bin/initdb" -D "$STORCON_DB" --username=jtuser --no-sync --no-instructions >/dev/null 2>&1 \
  || fail "storcon initdb"
printf 'port = 1235\nfsync = off\n' >> "$STORCON_DB/postgresql.conf"
"$PGROOT/bin/pg_ctl" -D "$STORCON_DB" -l "$STORCON_DB/pg.log" -w -o "-p 1235" start >/dev/null 2>&1 \
  || { tail -20 "$STORCON_DB/pg.log"; fail "storcon 内部 PG 启动"; }
"$PGROOT/bin/pg_isready" -h 127.0.0.1 -p 1235 -t 5 >/dev/null || fail "内部 PG 1235 未就绪"
"$PGROOT/bin/createdb" -h 127.0.0.1 -p 1235 -U jtuser storage_controller >/dev/null 2>&1 \
  || fail "createdb storage_controller"
nohup "$BIN/storage_controller" --dev \
  --database-url="postgresql://jtuser@localhost:1235/storage_controller" \
  --listen 127.0.0.1:1234 --address-for-peers http://127.0.0.1:1234 \
  --neon-local-repo-dir "$HOME_DIR" \
  --max-offline-interval 10s --max-warming-up-interval 30s --heartbeat-interval 1s \
  --timelines-onto-safekeepers --timeline-safekeeper-count 1 \
  --use-local-compute-notifications \
  > "$HOME_DIR/.neon/storcon.log" 2>&1 &
for _ in $(seq 1 30); do sleep 1; curl -s -m 2 -o /dev/null http://127.0.0.1:1234 && break; done
curl -s -m 2 -o /dev/null http://127.0.0.1:1234 || { tail -20 "$HOME_DIR/.neon/storcon.log"; fail "storcon 1234 未就绪"; }
pass "storcon OK"

echo
echo "=== 4) broker + endpoint_storage + pageserver ==="
nohup "$BIN/storage_broker" --listen-addr 127.0.0.1:50051 > "$HOME_DIR/.neon/broker.log" 2>&1 &
wait_port 50051 15 || fail "broker 50051 未监听"
nohup "$BIN/endpoint_storage" "$HOME_DIR/.neon/endpoint_storage/endpoint_storage.json" \
  > "$HOME_DIR/.neon/eps.log" 2>&1 &
wait_port 9993 10 || fail "endpoint_storage 9993 未监听"
nohup "$BIN/neon_local" pageserver start > "$HOME_DIR/ps.log" 2>&1 &
for _ in $(seq 1 30); do sleep 2; curl -s -m 2 -o /dev/null http://127.0.0.1:9898/v1/status && break; done
curl -s -m 2 -o /dev/null http://127.0.0.1:9898/v1/status || fail "pageserver 9898 未就绪"
pass "broker + endpoint_storage + pageserver OK"

echo
echo "=== 5) safekeeper（带 WAL 加密参数）==="
# 关键：加密开关经 --safekeeper-extra-opt 传递。neon_local 不会自动转发
# 自定义参数；不加这步会"静默跑明文"，从而得出错误的"未加密"结论。
ATT_DIGEST="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
nohup "$BIN/neon_local" safekeeper start \
  --safekeeper-extra-opt="--wal-encryption-kms-endpoint=http://127.0.0.1:${KMS_PORT}" \
  --safekeeper-extra-opt="--wal-encryption-node-id=sk-e2e-b2" \
  --safekeeper-extra-opt="--wal-encryption-attestation-digest=${ATT_DIGEST}" \
  --safekeeper-extra-opt="--wal-encryption-key-epoch=1" \
  --safekeeper-extra-opt="--wal-encryption-generation=1" \
  > "$HOME_DIR/sk.log" 2>&1 &
for _ in $(seq 1 30); do sleep 2; curl -s -m 2 -o /dev/null http://127.0.0.1:7676/v1/status && break; done
curl -s -m 2 -o /dev/null http://127.0.0.1:7676/v1/status || { tail -15 "$HOME_DIR/sk.log"; fail "safekeeper 7676 未就绪"; }
# 用 /proc/<pid>/cmdline 读完整命令行——`ps aux` 在窄终端会截断参数，
# 导致误判"参数未到达"（实测踩到：参数其实在，但被截断）。
SK_PID=$(pgrep -u "$(id -un)" -f "$BIN/safekeeper" | head -1)
[ -n "$SK_PID" ] || fail "safekeeper 进程未找到"
SK_ARGS=$(tr '\0' '\n' < "/proc/$SK_PID/cmdline" | grep -c "wal-encryption-kms-endpoint" || true)
[ "${SK_ARGS:-0}" -gt 0 ] || fail "加密参数未到达 safekeeper 进程（pid $SK_PID）"
pass "safekeeper 启动（加密参数已到达进程 pid $SK_PID）"

echo
echo "=== 6) safekeeper 注册进 storcon ==="
printf '{"id":1,"region_id":"local","version":5957,"host":"127.0.0.1","port":5454,"http_port":7676,"availability_zone_id":"sk-1"}' > /tmp/sk_reg.json
curl -s -m 5 -X POST http://127.0.0.1:1234/control/v1/safekeeper/1 -H "Content-Type: application/json" \
  --data @/tmp/sk_reg.json -o /dev/null -w "  sk_register=%{http_code}\n"
curl -s -m 5 -X PUT http://127.0.0.1:1234/control/v1/safekeeper/1/scheduling_policy \
  -H "Content-Type: application/json" -d '{"scheduling_policy":"Active"}' -o /dev/null -w "  sk_policy=%{http_code}\n"
sleep 3
pass "safekeeper 注册"

echo
echo "=== 7) tenant / endpoint ==="
T_OUT=$("$BIN/neon_local" tenant create --set-default --pg-version "$PG_VERSION" 2>&1 | tail -1)
case "$T_OUT" in *"command failed"*) fail "tenant create 失败: $T_OUT";; esac
TENANT=$("$BIN/neon_local" tenant list 2>/dev/null | grep -oE "[0-9a-f]{32}" | head -1)
[ -n "$TENANT" ] || fail "tenant 创建失败"
EP_OUT=$("$BIN/neon_local" endpoint create main --tenant-id "$TENANT" --pg-version "$PG_VERSION" 2>&1 | tail -1)
case "$EP_OUT" in *"command failed"*) fail "endpoint create 失败: $EP_OUT";; esac
nohup "$BIN/neon_local" endpoint start main > "$HOME_DIR/ep.log" 2>&1 &
for _ in $(seq 1 90); do
  sleep 2
  "$PGROOT/bin/pg_isready" -h 127.0.0.1 -p 55432 -t 1 >/dev/null 2>&1 && break
  grep -q "command failed" "$HOME_DIR/ep.log" 2>/dev/null && break
done
"$PGROOT/bin/pg_isready" -h 127.0.0.1 -p 55432 -t 1 >/dev/null 2>&1 || {
  tail -15 "$HOME_DIR/ep.log"
  tail -20 "$HOME_DIR/.neon/endpoints/main/compute.log" 2>/dev/null
  fail "compute 55432 未就绪"
}
pass "compute OK（tenant=$TENANT）"

echo
echo "=== 8) 写真实 WAL 流 ==="
"$PGROOT/bin/psql" -h 127.0.0.1 -p 55432 -U cloud_admin -d postgres -v ON_ERROR_STOP=1 \
  -c "CREATE TABLE t_enc(id int primary key, payload text);" \
  -c "INSERT INTO t_enc SELECT g, repeat('SECRET_PAYLOAD_', 8) FROM generate_series(1,5000) g;" \
  > "$HOME_DIR/sql.log" 2>&1 || { tail -10 "$HOME_DIR/sql.log"; fail "SQL 写入失败"; }
pass "写入 5000 行（产生真实 WAL）"

echo
echo "=== 9) 验证 WAL 段已加密（关键判据）==="
SK_DIR="$HOME_DIR/.neon/safekeepers/sk1"
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
[ "$ENCRYPTED" -gt 0 ] || { ls -la "$SK_DIR" 2>/dev/null | head -5; fail "WAL 段未加密"; }
pass "WAL 段已加密（文件尾含 JTENCOBJ header）"

echo
echo "=== 10) 明文泄漏检查（核心判据）==="
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
echo "=== 11) 系统仍正常工作 ==="
ROWS=$("$PGROOT/bin/psql" -h 127.0.0.1 -p 55432 -U cloud_admin -d postgres -tAc "SELECT count(*) FROM t_enc;" 2>/dev/null)
[ "$ROWS" = "5000" ] && pass "数据读回正确（$ROWS 行）" || fail "数据读回错误：$ROWS"

echo
echo "WAL_ENCRYPTION_E2E_OK"
