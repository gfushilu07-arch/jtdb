#!/usr/bin/env bash
# jtsec 安全内核运行时验证（scripts/test-jtsec-runtime.sh）
#
# 前置：
#   1) 带安全内核 patch 的 PG 构建（见 postgres/jtdb-patches/0001-*.patch）；
#   2) 该构建已 initdb 并启动，监听 Unix socket（默认 /tmp）；
#   3) 环境变量 JTDB_CACHE_ROOT 指向缓存卷（scripts/env.sh）；
#   4) 实例以 -c jt_sec.superuser_fence=on 启动（围栏项验证需要；
#      围栏为 PGC_SIGHUP，运行期不可 SET，故只能启动时给）。
#   可覆盖 PG_BIN / PGPORT / PGDATABASE / PGUSER 指向自己的构建。
#
# 覆盖：
#   §1 标签谓词语义（dominate / 类别子集）
#   §2 解析 fail-closed（含历史缺陷回归：拼错不降密、高位不崩）
#   §3 标签写入校验（provider 钩子）
#   §4 权限提升防护（GUC 上下文 PGC_SUSET）
#   §5 三权分立（ADR-012）
#   §6 BLP 读路径（不下读）
#   §7 BLP 写路径（* 属性：向上写允许 / 向下写禁止）
#   §8 超管围栏（ADR-012：围栏下 superuser 不再构成管理权限）
#
# 用法: source scripts/env.sh && bash scripts/test-jtsec-runtime.sh
set -u
RT="${PG_BIN:-${JTDB_CACHE_ROOT:?}/pg-jtsec-rt/install}"
P="${PGPORT:-5451}"
DB="${PGDATABASE:-jtsecdb}"
ADMIN="${PGUSER:-jtadmin}"
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
expect_val() { local l=$1 u=$2 s=$3 w=$4 o; o=$(as "$u" "$s")
  if [ "$o" = "$w" ]; then ok "$l"; else no "$l" "期望 '$w'，实际 '$o'"; fi }

# ---------------------------------------------------------------------------
# §0 准备：角色、库、表、标签
# ---------------------------------------------------------------------------
say "=== 0. 准备 ==="
for r in low_u high_u sec_a sys_a aud_a; do
  "$RT/bin/psql" -h /tmp -p $P -U "$ADMIN" -d postgres -X -q \
    -c "CREATE ROLE $r LOGIN;" >/dev/null 2>&1
done
"$RT/bin/psql" -h /tmp -p $P -U "$ADMIN" -d postgres -X -q \
  -c "CREATE DATABASE $DB;" >/dev/null 2>&1

as "$ADMIN" "DROP TABLE IF EXISTS public_tbl, secret_tbl;" >/dev/null 2>&1
as "$ADMIN" "CREATE TABLE public_tbl(id int);" >/dev/null 2>&1
as "$ADMIN" "CREATE TABLE secret_tbl(id int);" >/dev/null 2>&1
as "$ADMIN" "INSERT INTO public_tbl VALUES(1); INSERT INTO secret_tbl VALUES(1);" >/dev/null 2>&1
as "$ADMIN" "GRANT ALL ON public_tbl, secret_tbl TO low_u, high_u, sec_a, sys_a, aud_a;" >/dev/null 2>&1
as "$ADMIN" "SECURITY LABEL FOR jt ON TABLE public_tbl IS '10:';" >/dev/null 2>&1
as "$ADMIN" "SECURITY LABEL FOR jt ON TABLE secret_tbl IS '30:finance';" >/dev/null 2>&1
say "  标签: $(as "$ADMIN" "SELECT string_agg(c.relname||'='||s.label, ', ' ORDER BY c.relname) FROM pg_seclabel s JOIN pg_class c ON c.oid=s.objoid WHERE s.provider='jt';")"
say "  mac=$(as "$ADMIN" 'SHOW jt_sec.mac_enabled;')  fence=$(as "$ADMIN" 'SHOW jt_sec.superuser_fence;')"

# ---------------------------------------------------------------------------
say "=== 1. 标签谓词语义（dominate / 类别子集）==="
expect_val "dominate('30:finance','10:') = t"  "$ADMIN" "SELECT jt_label_dominate('30:finance','10:')" "t"
expect_val "dominate('10:','30:finance') = f"  "$ADMIN" "SELECT jt_label_dominate('10:','30:finance')" "f"
expect_val "类别不全不支配 = f"                 "$ADMIN" "SELECT jt_label_dominate('30:finance','30:finance,hr')" "f"
expect_val "类别超集支配 = t"                   "$ADMIN" "SELECT jt_label_dominate('30:finance,hr','30:finance')" "t"
expect_val "空标签视为最低密级 = t"              "$ADMIN" "SELECT jt_label_dominate('10:','')" "t"

# ---------------------------------------------------------------------------
say "=== 2. 解析 fail-closed（历史缺陷回归）==="
# 拼错类别名：修复前"宽容解析"→ 静默降密。关键是**不得返回 true**。
expect_val "拼错类别名不返回 true（静默降密修复）" "$ADMIN" "SELECT jt_label_dominate('30:finace','10:') IS NOT TRUE" "t"
expect_val "拼错类别名返回 false"                  "$ADMIN" "SELECT jt_label_dominate('30:finace','10:')" "f"
# 第 8 位类别（custom8）：修复前 jt_category_names[32] 只初始化 8 项 → NULL 解引用崩 backend
expect_ok  "custom8（第 8 位）不崩溃（NULL 解引用修复）" "$ADMIN" "SELECT jt_label_dominate('30:custom8','10:')"
expect_val "custom8 参与支配运算 = t"              "$ADMIN" "SELECT jt_label_dominate('30:custom8','30:custom8')" "t"
expect_val "越界 level 不返回 true"                "$ADMIN" "SELECT jt_label_dominate('5:','10:') IS NOT TRUE" "t"
# 非法标签写入需先具管理权限（围栏下 superuser 不够）→ 显式持 secadmin 角色
expect_err "非法会话标签写入被拒"                  "$ADMIN" "SET jt_sec.role='secadmin'; SELECT jt_sec_set_session_label('30:finace')" "invalid label format"

# ---------------------------------------------------------------------------
say "=== 3. 标签写入校验（provider 钩子）==="
expect_ok  "合法标签可写入"   "$ADMIN" "SECURITY LABEL FOR jt ON TABLE public_tbl IS '10:'"
expect_err "非法标签写入被拒" "$ADMIN" "SECURITY LABEL FOR jt ON TABLE public_tbl IS '30:finace'" "not a valid JTDB security label"

# ---------------------------------------------------------------------------
say "=== 4. 权限提升防护（GUC 上下文 PGC_SUSET）==="
expect_err "普通用户不得关闭 MAC"     low_u "SET jt_sec.mac_enabled=off" "ERROR|FATAL|permission"
expect_err "普通用户不得开启 MAC"     low_u "SET jt_sec.mac_enabled=on"  "ERROR|FATAL|permission"
expect_err "普通用户不得自封 secadmin" low_u "SET jt_sec.role='secadmin'" "ERROR|FATAL|permission"
expect_ok  "超级用户可设置角色"       "$ADMIN" "SET jt_sec.role='auditor'"

# ---------------------------------------------------------------------------
say "=== 5. 三权分立（ADR-012）==="
expect_val "后设角色覆盖先设（不可能同时持有两角色）" "$ADMIN" "SET jt_sec.role='secadmin'; SET jt_sec.role='sysadmin'; SHOW jt_sec.role" "sysadmin"
expect_err "非法 role 值被拒" "$ADMIN" "SET jt_sec.role='bogus'" "ERROR|FATAL"

# ---------------------------------------------------------------------------
say "=== 6. BLP 读路径（不下读）==="
expect_err "低密主体读秘密表被拒（不下读）" low_u "SELECT count(*) FROM secret_tbl" "MAC: read denied"
expect_ok  "低密主体读公开表放行"           low_u "SELECT count(*) FROM public_tbl"
expect_err "未提标签主体仍不能读秘密表"     high_u "SELECT count(*) FROM secret_tbl" "MAC: read denied"

# ---------------------------------------------------------------------------
say "=== 7. BLP 写路径（* 属性：向上写允许 / 向下写禁止）==="
# 公式 docs/05 §6.2：dominate(object_label, subject_label)
# 1a 向上写：低密主体 INSERT 高密表 → 允许（BLP * 属性不禁止向上写）
expect_ok  "低密 INSERT 高密表放行（向上写）" low_u "INSERT INTO secret_tbl VALUES(2)"
# UPDATE/DELETE 需读既有行 → 读检查拒之（写-读混淆防护）
expect_err "低密 UPDATE 高密表被拒（需读既有行）" low_u "UPDATE secret_tbl SET id=9" "MAC: read denied"
expect_err "低密 DELETE 高密表被拒（需读既有行）" low_u "DELETE FROM secret_tbl" "MAC: read denied"
# 1b 低密写公开表
expect_ok  "INSERT 公开表放行" low_u "INSERT INTO public_tbl VALUES(2)"
expect_ok  "UPDATE 公开表放行" low_u "UPDATE public_tbl SET id=3 WHERE id=2"
expect_ok  "DELETE 公开表放行" low_u "DELETE FROM public_tbl WHERE id=3"
# 1c 向下写：高密主体写低密对象 → 拒（"未标记=公开即放行"曾使此路径漏检）
# 提标签需 secadmin 角色（围栏下 superuser 不构成管理权限）；同一会话内生效
expect_err "高密主体写公开表被拒（不上写=禁止向下写）" "$ADMIN" \
  "SET jt_sec.role='secadmin'; SELECT jt_sec_set_session_label('30:finance'); INSERT INTO public_tbl VALUES(5);" "MAC: write denied"
expect_ok  "高密主体读公开表放行（向下读允许）" "$ADMIN" \
  "SET jt_sec.role='secadmin'; SELECT jt_sec_set_session_label('30:finance'); SELECT count(*) FROM public_tbl;"

# ---------------------------------------------------------------------------
say "=== 8. 超管围栏（ADR-012）==="
# 围栏开启 + MAC 开启 → superuser 不再构成管理权限（只认 jt_secadmin）
expect_err "围栏下 superuser 不得自提会话标签" "$ADMIN" "SELECT jt_sec_set_session_label('30:finance')" "fenced|only jt_secadmin"
expect_err "围栏下 superuser 不得设写标签"     "$ADMIN" "SELECT jt_sec_set_write_label('30:finance')" "only jt_secadmin"
expect_err "围栏下 superuser 不得标记可信主体" "$ADMIN" "SELECT jt_sec_set_trusted(true)" "only jt_secadmin"
expect_err "围栏下 superuser 读高密表被拒"     "$ADMIN" "SELECT count(*) FROM secret_tbl" "MAC: read denied"
expect_val "可信标志默认为 false"              "$ADMIN" "SELECT jt_sec_get_trusted()" "f"
# 围栏是 PGC_SIGHUP：运行期不可 SET（可被随手关掉的围栏不是围栏）
expect_err "围栏不可运行期关闭（PGC_SIGHUP）"  "$ADMIN" "SET jt_sec.superuser_fence=off" "cannot be changed now"

# ---------------------------------------------------------------------------
say "=== 结果 ==="
say "  PASS=$pass  FAIL=$fail"
[ "$fail" = "0" ] && say "RUNTIME_OK" || say "RUNTIME_FAILED"
exit "$fail"
