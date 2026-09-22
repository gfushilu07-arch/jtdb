#!/usr/bin/env bash
# jt-kms mTLS 端到端验证（真 TLS + 真客户端证书）
#
# 背景：本脚本所验证的缺口是**实测发现**的——jt-kms 的 `--client-ca` 此前
# 只填充了一个从未被读取的字段（`require_client_cert` 除定义处零引用），
# `rustls`/`tokio-rustls` 在 Cargo.toml 里声明但 src/ 零引用，服务始终以
# **明文 HTTP** 提供且**无任何鉴权**。实测：带 `--auth-token SECRET123`
# 启动后，不带任何凭据的请求仍能抵达业务逻辑（返回 409 "stale attestation"
# 而非 401）——即所有端点（含 `/v1/dek/unwrap`）完全没有鉴权。
#
# 判据设计（**每条都必须可证伪**，且成对出现）：
#   A. 配置自洽性：不完整/无鉴权的配置必须**拒绝启动**（3 项）
#   B. 传输层：明文被拒、无客户端证书被拒、错误 CA 被拒（3 项）
#   C. 应用层：有证书无 token 被拒、有证书有 token 通过（2 项）
#
# 为什么 A/B/C 都要：只测 C 的"通过"无法区分"鉴权生效"与"根本没鉴权"；
# 只测拒绝无法区分"拒绝正确"与"服务起不来"。
#
# 用法：source scripts/env.sh && bash scripts/test-kms-mtls.sh

set -uo pipefail

KMS_BIN="${KMS_BIN:-$JTDB_CACHE_ROOT/target/rust/debug/jt-kms}"
WORK="${WORK:-/tmp/jt-kms-mtls-test}"
PORT="${PORT:-7810}"
TOKEN="SECRET-$RANDOM$RANDOM"

pass=0; fail=0
ok() { pass=$((pass+1)); echo "  PASS  $1"; }
no() { fail=$((fail+1)); echo "  FAIL  $1"; echo "        $2"; }

cleanup() {
  [ -n "${KMS_PID:-}" ] && kill "$KMS_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "=== 0. 准备：证书与配置 ==="
[ -x "$KMS_BIN" ] || { echo "FAIL: $KMS_BIN 不存在（先 cargo build -p jt-kms）"; exit 1; }

# 用项目自带的 Tongsuo 生成证书——**不用系统 openssl**，因为本项目的合规主路径
# 是 Tongsuo，且系统 openssl 可能缺 SM2/TLCP 支持（那样测的不是生产形态）。
TONGSUO_BIN="${TONGSUO_BIN:-$JTDB_CACHE_ROOT/builds/tongsuo/bin}"
[ -x "$TONGSUO_BIN/openssl" ] || { echo "FAIL: 缺 Tongsuo openssl（$TONGSUO_BIN/openssl）"; exit 1; }
OSSL="$TONGSUO_BIN/openssl"

rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK" || exit 1

# Tongsuo 安装树未带 ssl/openssl.cnf，需自带（否则 req 命令报 "Can't open ... openssl.cnf"）
cat > openssl.cnf <<'EOF'
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = JTDB-Test
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
[ v3_server ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1,DNS:localhost
[ v3_client ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
EOF
export OPENSSL_CONF="$WORK/openssl.cnf"

gen_ca() { # $1=name
  $OSSL genrsa -out "$1.key" 2048 2>/dev/null
  $OSSL req -x509 -new -nodes -key "$1.key" -sha256 -days 30 \
    -subj "/CN=$1" -extensions v3_ca -out "$1.crt" 2>/dev/null
}
gen_leaf() { # $1=name $2=ca $3=ext $4=cn
  $OSSL genrsa -out "$1.key" 2048 2>/dev/null
  $OSSL req -new -key "$1.key" -subj "/CN=$4" -out "$1.csr" 2>/dev/null
  $OSSL x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial \
    -days 30 -sha256 -extensions "$3" -extfile "$WORK/openssl.cnf" -out "$1.crt" 2>/dev/null
}

gen_ca ca                    || { echo "FAIL: CA 生成失败"; exit 1; }
gen_leaf server ca v3_server localhost   || { echo "FAIL: 服务端证书生成失败"; exit 1; }
gen_leaf client ca v3_client jt-pageserver-node01 || { echo "FAIL: 客户端证书生成失败"; exit 1; }
gen_ca evil-ca               || { echo "FAIL: 第二个 CA 生成失败"; exit 1; }
gen_leaf evil-client evil-ca v3_client attacker || { echo "FAIL: 敌意客户端证书生成失败"; exit 1; }
ok "证书就绪（真 CA + 服务端 + 客户端 + 另一 CA）"

echo
echo "=== A. 配置自洽性：不完整配置必须拒绝启动 ==="
# 这一组验证"声明了但未实现的参数必须拒绝启动"——否则运维会以为启用了 TLS/mTLS
run_expect_refuse() { # $1=label $2=pattern $3...=args
  local label="$1" pattern="$2"; shift 2
  local out
  out=$("$KMS_BIN" --listen "127.0.0.1:$((PORT+100))" --data-dir "$WORK/refuse-$$" "$@" 2>&1)
  if printf '%s' "$out" | grep -qE "$pattern"; then ok "$label"
  else no "$label" "期望匹配 /$pattern/，实际：$out"; fi
}

run_expect_refuse "无任何鉴权配置被拒（jt-kms 暴露 /v1/dek/unwrap）" \
  "no authentication configured"
run_expect_refuse "只给 --tls-cert 不给 --tls-key 被拒" \
  "tls-cert given without --tls-key" \
  --tls-cert server.crt
run_expect_refuse "只给 --client-ca 不给 TLS 被拒（否则以为有 mTLS 实为明文）" \
  "client-certificate verification requires TLS" \
  --client-ca ca.crt --auth-token x

echo
echo "=== B/C. 启动真实 mTLS 服务并逐项验证 ==="
"$KMS_BIN" --listen "127.0.0.1:$PORT" --data-dir "$WORK/data" \
  --tls-cert server.crt --tls-key server.key --client-ca ca.crt \
  --auth-token "$TOKEN" > "$WORK/srv.log" 2>&1 &
KMS_PID=$!

# 等就绪（TLS 起不来时不能干等）
ready=0
for _ in $(seq 1 30); do
  if grep -q "listening on" "$WORK/srv.log" 2>/dev/null; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = "1" ] || { echo "FAIL: 服务未就绪"; tail -5 "$WORK/srv.log"; exit 1; }
# 启动日志必须如实反映传输层（防"以为启用了 mTLS"）
if grep -q "TLS+mTLS" "$WORK/srv.log"; then ok "启动日志如实标注 TLS+mTLS"
else no "启动日志如实标注 TLS+mTLS" "$(grep listening "$WORK/srv.log")"; fi

U="https://127.0.0.1:$PORT"
BODY='{"timeline_id":"11111111222233334444555566667777","key_epoch":1,"node_id":"n1","attestation_digest":"aa"}'
code() { printf '%s' "$1" | grep -oE 'HTTP=[0-9]+' | tail -1 | cut -d= -f2; }

# --- B1: 明文 HTTP 必须失败（服务是 TLS）---
r=$(curl -s -m 5 "http://127.0.0.1:$PORT/health" -w " HTTP=%{http_code}" 2>&1 | tail -1)
[ "$(code "$r")" = "000" ] && ok "明文 HTTP 被拒（HTTP=000）" \
  || no "明文 HTTP 被拒" "got HTTP=$(code "$r")"

# --- B2: TLS 但无客户端证书必须失败（mTLS 强制）---
r=$(curl -s -m 5 -k "$U/health" -w " HTTP=%{http_code}" 2>&1 | tail -1)
[ "$(code "$r")" = "000" ] && ok "无客户端证书被拒（握手期）" \
  || no "无客户端证书被拒" "got HTTP=$(code "$r")"

# --- B3: 错误 CA 签发的证书必须失败 ---
r=$(curl -s -m 5 --cert evil-client.crt --key evil-client.key --cacert ca.crt \
      "$U/health" -w " HTTP=%{http_code}" 2>&1 | tail -1)
[ "$(code "$r")" = "000" ] && ok "错误 CA 签发的证书被拒（握手期）" \
  || no "错误 CA 签发的证书被拒" "got HTTP=$(code "$r")"

# --- C1: 有效证书但无 bearer token 必须 401 ---
r=$(curl -s -m 5 --cert client.crt --key client.key --cacert ca.crt \
      "$U/v1/lease/issue" -X POST -H "Content-Type: application/json" \
      -d "$BODY" -w " HTTP=%{http_code}" 2>&1 | tail -1)
[ "$(code "$r")" = "401" ] && ok "有证书无 token 被拒（401，两道门独立）" \
  || no "有证书无 token 被拒" "got HTTP=$(code "$r"): $r"

# --- C2: 证书 + 正确 token 必须通过（**这一条证明服务真的在工作**）---
r=$(curl -s -m 5 --cert client.crt --key client.key --cacert ca.crt \
      "$U/v1/lease/issue" -X POST -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" -d "$BODY" -w " HTTP=%{http_code}" 2>&1 | tail -1)
if [ "$(code "$r")" = "200" ] && printf '%s' "$r" | grep -q "dek_hex"; then
  ok "证书 + 正确 token 通过并返回 DEK（200）"
else
  no "证书 + 正确 token 通过并返回 DEK" "got HTTP=$(code "$r"): $r"
fi

# --- C3: 错误 token 必须 401（证明 token 真在校验，而非只看有无）---
r=$(curl -s -m 5 --cert client.crt --key client.key --cacert ca.crt \
      "$U/v1/lease/issue" -X POST -H "Authorization: Bearer WRONG" \
      -H "Content-Type: application/json" -d "$BODY" -w " HTTP=%{http_code}" 2>&1 | tail -1)
[ "$(code "$r")" = "401" ] && ok "错误 token 被拒（401）" \
  || no "错误 token 被拒" "got HTTP=$(code "$r"): $r"

echo
echo "=== 结果 ==="
echo "  PASS=$pass  FAIL=$fail"
[ "$fail" = "0" ] && echo "KMS_MTLS_OK" || echo "KMS_MTLS_FAILED"
exit "$fail"
