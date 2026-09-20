#!/usr/bin/env bash
# jtsec 安全内核运行时验证（scripts/test-jtsec-runtime.sh）
#
# 前置：
#   1) 带安全内核 patch 的 PG 构建（见 postgres/jtdb-patches/0001-*.patch）；
#   2) 该构建已 initdb 并启动，监听 Unix socket（默认 /tmp，端口 5451）；
#   3) 环境变量 JTDB_CACHE_ROOT 指向缓存卷（scripts/env.sh）。
#   可覆盖 PG_BIN / PGPORT / PGDATABASE 指向自己的构建。
#
# 覆盖：标签谓词语义、解析 fail-closed（含 4 个历史缺陷回归）、标签写入校验、
#       权限提升防护、三权分立、BLP 强制访问控制（MAC on 下的不下读）。
#
# 用法: source scripts/env.sh && zsh scripts/test-jtsec-runtime.sh
set -u
RT="${PG_BIN:-${JTDB_CACHE_ROOT:?}/pg-jtsec-rt/install}"
P="${PGPORT:-5451}"
DB="${PGDATABASE:-jtsecdb}"
PSQL="$RT/bin/psql -h /tmp -p $P -X -q -t -A"

pass=0; fail=0
say() { printf '%s\n' "$*"; }
ok()  { pass=$((pass+1)); say "  PASS  $1"; }
no()  { fail=$((fail+1)); say "  FAIL  $1"; say "        $2"; }

as() { local u=$1; shift; $PSQL -U "$u" -d "$DB" -c "$*" 2>&1; }
expect_ok()  { local l=$1 u=$2 s=$3 o; o=$(as "$u" "$s")
  if printf '%s' "$o" | grep -qiE "ERROR|FATAL"; then no "$l" "$o"; else ok "$l"; fi }
expect_err() { local l=$1 u=$2 s=$3 p=$4 o; o=$(as "$u" "$s")
  if printf '%s' "$o" | grep -qiE "$p"; then ok "$l"; else no "$l" "期望 /$p/，实际: $o"; fi }
expect_val() { local l=$1 u=$2 s=$3 want=$4 o; o=$(as "$u" "$s")
  if [ "$o" = "$want" ]; then ok "$l"; else no "$l" "期望 '$want'，实际 '$o'"; fi }

say "=== 1. 标签谓词语义（dominate / 类别子集）==="
expect_val "dominate('30:finance','10:') = t"        jtadmin "SELECT jt_label_dominate('30:finance','10:')" "t"
expect_val "dominate('10:','30:finance') = f"        jtadmin "SELECT jt_label_dominate('10:','30:finance')" "f"
expect_val "类别不全不支配 = f"                       jtadmin "SELECT jt_label_dominate('30:finance','30:finance,hr')" "f"
expect_val "类别超集支配 = t"                         jtadmin "SELECT jt_label_dominate('30:finance,hr','30:finance')" "t"
expect_val "空标签视为最低密级 = t"                    jtadmin "SELECT jt_label_dominate('10:','')" "t"

say "=== 2. 解析 fail-closed（缺陷修复回归）==="
# (c) 拼错类别名：修复前静默忽略 → 静默降密。谓词包装按 fail-closed 返回 false
#（关键是**不得返回 true**；true 就等于把拼错当成"无类别"放行）
expect_val "拼错类别名不返回 true（静默降密修复）" jtadmin "SELECT jt_label_dominate('30:finace','10:') IS NOT TRUE" "t"
expect_val "拼错类别名返回 false"                  jtadmin "SELECT jt_label_dominate('30:finace','10:')" "f"
# (a)(b) 第 8 位类别：修复前 NULL 解引用崩 backend
expect_ok  "custom8（第 8 位）不崩溃（NULL 解引用修复）" jtadmin "SELECT jt_label_dominate('30:custom8','10:')"
expect_val "custom8 参与支配运算 = t"                 jtadmin "SELECT jt_label_dominate('30:custom8','30:custom8')" "t"
expect_val "越界 level 不返回 true"                   jtadmin "SELECT jt_label_dominate('5:','10:') IS NOT TRUE" "t"
# 会话标签写入遇非法值必须报错（写入路径 fail-closed，不能静默降密）
expect_err "非法会话标签写入被拒"                     jtadmin "SELECT jt_sec_set_session_label('30:finace')" "invalid label format"

say "=== 3. 标签写入校验（provider 钩子）==="
expect_ok  "合法标签可写入"   jtadmin "SECURITY LABEL FOR jt ON TABLE public_tbl IS '10:'"
expect_err "非法标签写入被拒" jtadmin "SECURITY LABEL FOR jt ON TABLE public_tbl IS '30:finace'" "not a valid JTDB security label"

say "=== 4. 权限提升防护（GUC 上下文）==="
# 修复前 PGC_USERSET：任意用户可关 MAC 再读高密数据
expect_err "普通用户不得关闭 MAC（PGC_SUSET）" low_u "SET jt_sec.mac_enabled=off" "ERROR|FATAL|permission"
expect_err "普通用户不得开启 MAC"              low_u "SET jt_sec.mac_enabled=on" "ERROR|FATAL|permission"
# 修复前 PGC_USERSET：任意用户可自封 secadmin
expect_err "普通用户不得自封 secadmin"         low_u "SET jt_sec.role='secadmin'" "ERROR|FATAL|permission"
expect_ok  "超级用户可设置角色"                jtadmin "SET jt_sec.role='auditor'"

say "=== 5. 三权分立（ADR-012）==="
# role 为单值枚举，后设覆盖先设 —— 因此**不可能同时持有** secadmin 与 sysadmin
#（jt_sec_set_roles 里的互斥 ereport 经由 GUC 路径不可达，属纵深防御）
expect_val "后设角色覆盖先设（不可能同时持有两角色）" jtadmin "SET jt_sec.role='secadmin'; SET jt_sec.role='sysadmin'; SHOW jt_sec.role" "sysadmin"
expect_err "非法 role 值被拒" jtadmin "SET jt_sec.role='bogus'" "ERROR|FATAL"

say "=== 6. BLP 强制访问控制（MAC on）==="
val=$(as low_u "SHOW jt_sec.mac_enabled")
if [ "$val" = "on" ]; then ok "MAC 处于开启状态（前置条件）"
else no "MAC 前置条件" "mac_enabled=$val"; fi
# 不下读：低密主体读高密表
expect_err "低密主体读秘密表被拒（不下读）" low_u "SELECT count(*) FROM secret_tbl" "MAC: read denied"
# 公开表放行
expect_ok  "低密主体读公开表放行"           low_u "SELECT count(*) FROM public_tbl"
# 高密主体读秘密表（会话标签需先提升）
expect_err "未提标签主体仍不能读秘密表"     high_u "SELECT count(*) FROM secret_tbl" "MAC: read denied"

say "=== 结果 ==="
say "  PASS=$pass  FAIL=$fail"
[ "$fail" = "0" ] && say "RUNTIME_OK" || say "RUNTIME_FAILED"
exit "$fail"
