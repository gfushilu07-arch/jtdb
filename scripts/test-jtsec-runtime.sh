#!/usr/bin/env bash
# jtsec 安全内核运行时验证（scripts/test-jtsec-runtime.sh）
#
# 前置：
#   1) 带安全内核 patch 的 PG 构建（见 postgres/jtdb-patches/0001-*.patch）；
#   2) 该构建已 initdb 并启动，监听 Unix socket（默认 /tmp）；
#   3) 环境变量 JTDB_CACHE_ROOT 指向缓存卷（scripts/env.sh）；
#   4) 实例以如下参数启动（缺一不可）：
#        -c jt_sec.superuser_fence=on   （围栏项验证需要；PGC_SIGHUP，只能启动时给）
#        -c jt_sec.mac_enabled=on       （缺则 §6~§11 的拒绝类断言全部假失败）
#        -c wal_level=logical           （§13 逻辑复制需要）
#        -c shared_preload_libraries=neon_rmgr
#           （**§13 解码端到端的前置条件**：Neon fork 的 heapam 会写
#            XLogInsert(RM_NEON_ID,...) 记录，解码读到它需要 rmgr 实现，
#            否则报 "resource manager with ID 134 not registered"。
#            neon_rmgr 必须针对本 PG 构建编译——PG18 的符号是
#            ReorderBufferAllocChange，v17 及以下是 ReorderBufferGetChange，
#            用错版本会报 Symbol not found。）
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
#   §8 COPY/TRUNCATE 执行点
#   §9 超管围栏（ADR-012：围栏下 superuser 不再构成管理权限）
#   §10 逃逸路径围栏（docs/02 §3.5）
#   §11 统一错误码 JT001-JT004（docs/05 §6.2）
#   §12 E2 审计事件（docs/02 §7.2）
#   §13 逻辑复制与 CDC 的 MLS 过滤（docs/02 §3.6）
#   §14 逃逸清单剩余项（扩展/过程语言/C 函数；docs/02 §3.5）
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
say "=== 8. COPY / TRUNCATE 执行点（不经 ExecutorStart 的写路径）==="
# 本节测 COPY 的 **MAC 方向语义**；逃逸路径围栏（§10）默认会先拦下文件形式
# 的 COPY，故此处显式开白名单，使测试聚焦在 MAC 判定上。
as "$ADMIN" "SET jt_sec.allow_escape_paths=on;" >/dev/null 2>&1
# copyfrom.c 自建 ModifyTableState 直接调 table AM，不经 ExecutorStart；
# TRUNCATE 是 utility 语句同样不经 ModifyTable。二者曾完全漏检（实测高密
# 会话可 COPY FROM 写低密表、TRUNCATE 清空低密表）。
as "$ADMIN" "CREATE TABLE pub_copy(id int);" >/dev/null 2>&1
as "$ADMIN" "SECURITY LABEL FOR jt ON TABLE pub_copy IS '10:';" >/dev/null 2>&1
as "$ADMIN" "GRANT ALL ON pub_copy TO low_u;" >/dev/null 2>&1
as "$ADMIN" "GRANT pg_read_server_files TO low_u, $ADMIN;" >/dev/null 2>&1
printf '5\n' > /tmp/jtsec-copy-src.txt
"$RT/bin/psql" -h /tmp -p $P -U "$ADMIN" -d $DB -X -q -t -A \
  -c "COPY pub_copy FROM '/tmp/jtsec-copy-src.txt';" >/dev/null 2>&1
# 向下写：高密会话写低密表 → 全拒
expect_err "COPY FROM 向下写被拒" "$ADMIN" \
  "SET jt_sec.allow_escape_paths=on; SET jt_sec.role='secadmin'; SELECT jt_sec_set_session_label('30:finance'); COPY pub_copy FROM '/tmp/jtsec-copy-src.txt';" "MAC: write denied"
expect_err "TRUNCATE 向下写被拒" "$ADMIN" \
  "SET jt_sec.allow_escape_paths=on; SET jt_sec.role='secadmin'; SELECT jt_sec_set_session_label('30:finance'); TRUNCATE pub_copy;" "MAC: write denied"
# 向下读：放行
expect_ok  "COPY TO 向下读放行" "$ADMIN" \
  "SET jt_sec.allow_escape_paths=on; SET jt_sec.role='secadmin'; SELECT jt_sec_set_session_label('30:finance'); COPY pub_copy TO '/tmp/jtsec-copy-out.txt';"
# 向上写：低密主体 COPY FROM 高密表 → 放行（与 INSERT 一致，追加不读既有行）
expect_ok  "COPY FROM 向上写放行" low_u "COPY secret_tbl FROM STDIN;"
# 不下读：低密主体 COPY TO 高密表 → 拒
expect_err "COPY TO 读高密表被拒" low_u "COPY secret_tbl TO STDOUT;" "MAC: read denied"

# ---------------------------------------------------------------------------
say "=== 9. 超管围栏（ADR-012）==="
# 围栏开启 + MAC 开启 → superuser 不再构成管理权限（只认 jt_secadmin）
expect_err "围栏下 superuser 不得自提会话标签" "$ADMIN" "SELECT jt_sec_set_session_label('30:finance')" "fenced|only jt_secadmin"
expect_err "围栏下 superuser 不得设写标签"     "$ADMIN" "SELECT jt_sec_set_write_label('30:finance')" "only jt_secadmin"
expect_err "围栏下 superuser 不得标记可信主体" "$ADMIN" "SELECT jt_sec_set_trusted(true)" "only jt_secadmin"
expect_err "围栏下 superuser 读高密表被拒"     "$ADMIN" "SELECT count(*) FROM secret_tbl" "MAC: read denied"
expect_val "可信标志默认为 false"              "$ADMIN" "SELECT jt_sec_get_trusted()" "f"
# 围栏是 PGC_SIGHUP：运行期不可 SET（可被随手关掉的围栏不是围栏）
expect_err "围栏不可运行期关闭（PGC_SIGHUP）"  "$ADMIN" "SET jt_sec.superuser_fence=off" "cannot be changed now"

# ---------------------------------------------------------------------------
say "=== 10. 逃逸路径围栏（docs/02 §3.5）==="
# 默认禁用 COPY PROGRAM 与 COPY 文件形式（可绕过内核直接接触文件系统/执行程序）
expect_err "COPY FROM 文件被禁用" "$ADMIN" "COPY public_tbl FROM '/tmp/jtsec-copy-src.txt';" "JT004|escape"
expect_err "COPY TO 文件被禁用"   "$ADMIN" "COPY public_tbl TO '/tmp/jtsec-esc-out.txt';" "JT004|escape"
expect_err "COPY FROM PROGRAM 被禁用" "$ADMIN" "COPY public_tbl FROM PROGRAM 'echo 1';" "JT004|escape"
expect_err "COPY TO PROGRAM 被禁用"   "$ADMIN" "COPY public_tbl TO PROGRAM 'cat';" "JT004|escape"
# 普通用户不得开启白名单（PGC_SUSET）
expect_err "普通用户不得开启逃逸白名单" low_u "SET jt_sec.allow_escape_paths=on" "ERROR|FATAL|permission"

say "=== 10b. 大对象与 file_fdw 逃逸路径（§3.5 清单其余项）==="
# 这两条在 PG 里**本来就没有权限门**（实测 lo_import/lo_export 对任意角色
# 开放；file_fdw 只有 DBA 可控的角色门），故必须由内核统一把关。
as "$ADMIN" "DROP FOREIGN TABLE IF EXISTS ft_esc;" >/dev/null 2>&1
as "$ADMIN" "DROP FOREIGN TABLE IF EXISTS ft_esc_p;" >/dev/null 2>&1
as "$ADMIN" "DROP FOREIGN TABLE IF EXISTS ft_esc_ok;" >/dev/null 2>&1
expect_err "lo_import 被禁用（服务端文件读）" "$ADMIN" \
  "SELECT lo_import('/tmp/jtsec-copy-src.txt');" "JT004|disabled"
expect_err "lo_export 被禁用（服务端文件写）" "$ADMIN" \
  "SELECT lo_export(0, '/tmp/jtsec-lo-out.txt');" "JT004|disabled"
# 装载 file_fdw 本身现在受逃逸围栏管（§14 的 CREATE EXTENSION 分支），
# 故**先开白名单装载扩展**，再关掉白名单测"选项被拦"——否则扩展装不上，
# 下面的断言会因 "server does not exist" 而假失败（实测踩到）。
as "$ADMIN" "SET jt_sec.role='secadmin'; SET jt_sec.allow_escape_paths=on; CREATE EXTENSION IF NOT EXISTS file_fdw;" >/dev/null 2>&1
as "$ADMIN" "SET jt_sec.allow_escape_paths=off;" >/dev/null 2>&1
as "$ADMIN" "CREATE SERVER IF NOT EXISTS ffs_esc FOREIGN DATA WRAPPER file_fdw;" >/dev/null 2>&1
expect_err "file_fdw filename 选项被禁用" "$ADMIN" \
  "CREATE FOREIGN TABLE ft_esc(f text) SERVER ffs_esc OPTIONS (filename '/tmp/jtsec-copy-src.txt', format 'text');" "JT004|disabled"
expect_err "file_fdw program 选项被禁用" "$ADMIN" \
  "CREATE FOREIGN TABLE ft_esc_p(f text) SERVER ffs_esc OPTIONS (program 'echo hi', format 'text');" "JT004|disabled"
# 受控放行：secadmin 开白名单后可用
expect_ok  "开白名单后 lo_import 放行" "$ADMIN" \
  "SET jt_sec.allow_escape_paths=on; SELECT lo_import('/tmp/jtsec-copy-src.txt');"
expect_ok  "开白名单后 file_fdw 可用" "$ADMIN" \
  "SET jt_sec.allow_escape_paths=on; CREATE FOREIGN TABLE ft_esc_ok(f text) SERVER ffs_esc OPTIONS (filename '/tmp/jtsec-copy-src.txt', format 'text');"

say "=== 11. 统一错误码（docs/05 §6.2）==="
# 客户端/审计采集器应能按 SQLSTATE 稳定识别 MAC 拒绝，而不必解析文本
code=$("$RT/bin/psql" -h /tmp -p $P -U low_u -d $DB -X 2>&1 <<'SQLEOF' | grep -oE "JT[0-9]{3}" | head -1
\set VERBOSITY verbose
SELECT count(*) FROM secret_tbl;
SQLEOF
)
[ "$code" = "JT001" ] && ok "读拒绝 SQLSTATE = JT001" || no "读拒绝 SQLSTATE = JT001" "got=$code"
code=$("$RT/bin/psql" -h /tmp -p $P -U "$ADMIN" -d $DB -X 2>&1 <<'SQLEOF' | grep -oE "JT[0-9]{3}" | head -1
\set VERBOSITY verbose
SET jt_sec.role='secadmin';
SELECT jt_sec_set_session_label('30:finance');
INSERT INTO public_tbl VALUES(1);
SQLEOF
)
[ "$code" = "JT002" ] && ok "写拒绝 SQLSTATE = JT002" || no "写拒绝 SQLSTATE = JT002" "got=$code"
code=$("$RT/bin/psql" -h /tmp -p $P -U "$ADMIN" -d $DB -X 2>&1 <<'SQLEOF' | grep -oE "JT[0-9]{3}" | head -1
\set VERBOSITY verbose
COPY public_tbl TO '/tmp/jtsec-esc-out2.txt';
SQLEOF
)
[ "$code" = "JT004" ] && ok "逃逸路径 SQLSTATE = JT004" || no "逃逸路径 SQLSTATE = JT004" "got=$code"

say "=== 12. E2 审计事件（docs/02 §7.2）==="
# MAC 拒绝必须产生机器可读事件（内核产出、审计平面链化）
LOGF="${JTDB_JTSEC_LOGFILE:-/tmp/jtsec-runtime.log}"
if [ -f "$LOGF" ]; then
  ev=$(grep -o 'JTDB-AUDIT-E2 {[^}]*}' "$LOGF" 2>/dev/null | tail -1)
  if [ -n "$ev" ]; then ok "MAC 拒绝产生 E2 审计事件"
  else no "MAC 拒绝产生 E2 审计事件" "日志 $LOGF 中无 JTDB-AUDIT-E2"; fi
  if printf '%s' "$ev" | grep -q '"event":"mac_denied"'; then ok "事件类型为 mac_denied"
  else no "事件类型为 mac_denied" "$ev"; fi
  # 不含业务明文（只放标签/主体/摘要）
  if printf '%s' "$ev" | grep -qE '"detail"|VALUES'; then no "事件不含业务明文" "$ev"
  else ok "事件不含业务明文"; fi
else
  say "  SKIP  E2 事件验证（未设 JTDB_JTSEC_LOGFILE）"
fi


# ---------------------------------------------------------------------------
say "=== 13. 逻辑复制与 CDC 的 MLS 过滤（docs/02 §3.6）==="
# 逻辑解码是独立数据出口：它不"读表"，而是读 WAL，故 ExecutorStart/
# ProcessUtility 的全部 MAC 检查都管不到它。不加过滤则高密表的数据会被
# 原样发到任意订阅端，绕过整套 MAC。
#
# 本段验证四件事：
#   a) publication DDL 需要 secadmin/sysadmin（出口的建立受控）
#   b) 复制槽操作产生 E2 审计事件（出口的持久句柄留痕）
#   c) **核心判据**：默认上限 0 时，高密表的变更**不被解码输出**
#   d) **可证伪性**：把上限提高后，同一张表的变更**能够**被解码输出
#      —— 若只验 c) 不验 d)，无法区分"过滤生效"与"解码根本没跑起来"
#
# 用 pg_logical_slot_get_changes 直接在发布端解码（不需要第二个实例），
# 它走的是与逻辑复制**完全相同**的 reorderbuffer 路径。

# 清掉历史遗留的 jt_* 槽：默认 max_replication_slots=10，泄漏会耗尽并让后续
# 断言假失败；槽还会钉住 WAL 不回收。
as "$ADMIN" "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name LIKE 'jt_%';" >/dev/null 2>&1
as "$ADMIN" "DROP TABLE IF EXISTS lr_public, lr_secret;" >/dev/null 2>&1
as "$ADMIN" "CREATE TABLE lr_public(id int);" >/dev/null 2>&1
as "$ADMIN" "CREATE TABLE lr_secret(id int);" >/dev/null 2>&1
as "$ADMIN" "SECURITY LABEL FOR jt ON TABLE lr_public IS '10:';" >/dev/null 2>&1
as "$ADMIN" "SECURITY LABEL FOR jt ON TABLE lr_secret IS '30:finance';" >/dev/null 2>&1

# a) publication DDL 受控
expect_err "普通用户不得 CREATE PUBLICATION" low_u \
  "CREATE PUBLICATION p_low FOR TABLE lr_public" "requires secadmin or sysadmin"
expect_ok  "secadmin 可 CREATE PUBLICATION"  "$ADMIN" \
  "SET jt_sec.role='secadmin'; CREATE PUBLICATION p_lr FOR TABLE lr_public, lr_secret"

expect_err "普通用户不得提高外发上限" low_u \
  "SET jt_sec.replication_max_level=40" "ERROR|FATAL|permission"
expect_err "普通用户不得提高外发类别授权" low_u \
  "SET jt_sec.replication_max_categories=1" "ERROR|FATAL|permission"

# b) 复制槽操作审计
as "$ADMIN" "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name='jt_lr_slot';" >/dev/null 2>&1
as "$ADMIN" "SELECT * FROM pg_create_logical_replication_slot('jt_lr_slot','pgoutput');" >/dev/null 2>&1
LOGF2="${JTDB_JTSEC_LOGFILE:-/tmp/jtsec-runtime.log}"
if [ -f "$LOGF2" ]; then
  if grep -q '"event":"replication_slot"' "$LOGF2" 2>/dev/null; then
    ok "复制槽创建产生 E2 审计事件"
  else no "复制槽创建产生 E2 审计事件" "日志无 replication_slot 事件"; fi
else
  say "  SKIP  复制槽审计（未设 JTDB_JTSEC_LOGFILE）"
fi

# c) 核心判据：判定矩阵（直接调用判定函数，不依赖解码链路）
#
# **为什么改为直接验证判定**：完整链路（pg_logical_slot_get_changes →
# reorderbuffer → 过滤）在本构建上跑不通——Neon fork 的 RMGR 134 未注册
# （逻辑解码读 WAL 即报 "resource manager with ID 134 not registered"），
# 而本测试构建没有可加载的 neon.so（macOS 侧只有 aarch64 的交叉产物）。
# 该阻塞与过滤逻辑无关，但会掩盖判定是否正确。故判定本身用 SQL 接口
# 直接验证（jt_sec_replication_may_emit），解码链路单独标注为环境阻塞。
expect_val "默认（max_level=10）公开对象可外发" "$ADMIN" \
  "SELECT jt_sec_replication_may_emit('10:')" "t"
expect_val "默认高密对象不外发（fail-closed）" "$ADMIN" \
  "SELECT jt_sec_replication_may_emit('30:finance')" "f"
expect_val "默认未标记对象可外发" "$ADMIN" \
  "SELECT jt_sec_replication_may_emit('')" "t"
expect_val "默认 max_level = 10（真实等级，非 0）" "$ADMIN" \
  "SELECT current_setting('jt_sec.replication_max_level')" "10"
expect_val "默认 max_categories = 0（不允许任何类别）" "$ADMIN" \
  "SELECT current_setting('jt_sec.replication_max_categories')" "0"
# 等级与类别正交：仅提等级不足以放行带类别的对象
expect_val "仅提等级仍不放行带类别对象" "$ADMIN" \
  "SET jt_sec.replication_max_level=40; SELECT jt_sec_replication_may_emit('30:finance')" "f"
expect_val "显式授权类别后放行" "$ADMIN" \
  "SET jt_sec.replication_max_level=40; SET jt_sec.replication_max_categories=1; SELECT jt_sec_replication_may_emit('30:finance')" "t"
expect_val "未授权的其他类别仍拒绝" "$ADMIN" \
  "SET jt_sec.replication_max_level=40; SET jt_sec.replication_max_categories=1; SELECT jt_sec_replication_may_emit('30:hr')" "f"
expect_val "损坏标签不外发（fail-closed）" "$ADMIN" \
  "SELECT jt_sec_replication_may_emit('30:finace')" "f"

# d) **解码链路端到端**：真正的可证伪判据
#
# 这是本段最重要的一组：前面的判定矩阵只证明"判定函数正确"，不证明
# "过滤点真的接在解码路径上、且真的拦住了数据"。故这里必须跑完整链路
# （pg_logical_slot_get_binary_changes → reorderbuffer → 过滤）。
#
# **前置条件：Neon RMGR 134 必须已注册**。Neon fork 的 heapam 会写
# `XLogInsert(RM_NEON_ID, ...)` 记录，逻辑解码读到它时需要对应的 rmgr 实现，
# 否则报 "resource manager with ID 134 not registered"。注册发生在
# `pgxn/neon_rmgr` 模块的 `_PG_init`（`RegisterCustomRmgr(RM_NEON_ID, ...)`），
# 故服务必须以 `shared_preload_libraries=neon_rmgr` 启动，且该模块要**针对
# 本 PG 构建**编译（PG18 的符号是 ReorderBufferAllocChange，v17 及以下是
# ReorderBufferGetChange；用错版本的 .dylib 会报 Symbol not found）。
#
# 判据设计（两组互补，缺一不可）：
#   - 低上限：高密行的**值**不得出现（过滤生效），公开行的值必须出现
#     （证明解码链路本身在工作——否则"过滤生效"与"根本没解码"不可区分）
#   - 高上限 + 授权类别：同一高密行的值**必须**出现（反证过滤按上限生效）
#
# 为什么用"行的值"而不是"消息条数"：pgoutput 每次变更会发 B/R/I/C 多条消息
# （Begin/Relation/Insert/Commit），按条数判断会把元数据消息误当成数据。
# 必须直接查数据值是否出现在解码输出里。

lr_decode() {   # $1=max_level  $2=max_categories  $3=公开行值  $4=高密行值  $5=slot
  "$RT/bin/psql" -h /tmp -p $P -U "$ADMIN" -d $DB -X -t -A 2>&1 <<SQLEOF
SET jt_sec.mac_enabled=on;
SET jt_sec.role='secadmin';
SET jt_sec.replication_max_level=$1;
SET jt_sec.replication_max_categories=$2;
SELECT pg_drop_replication_slot('$5') FROM pg_replication_slots WHERE slot_name='$5';
SELECT slot_name FROM pg_create_logical_replication_slot('$5','pgoutput');
INSERT INTO lr_public VALUES($3);
INSERT INTO lr_secret VALUES($4);
SELECT count(*) FILTER (WHERE encode(data,'escape') LIKE '%$4%') || '|' ||
       count(*) FILTER (WHERE encode(data,'escape') LIKE '%$3%')
FROM pg_logical_slot_get_binary_changes('$5', NULL, NULL,
     'proto_version','1','publication_names','p_lr');
SELECT pg_drop_replication_slot('$5') FROM pg_replication_slots WHERE slot_name='$5';
SQLEOF
}

# 前置：确认 RMGR 已注册（否则解码必然失败，后面的断言会误报为"过滤失效"）
rmgr_probe=$("$RT/bin/psql" -h /tmp -p $P -U "$ADMIN" -d $DB -X -t -A 2>&1 <<'SQLEOF'
SET jt_sec.role='secadmin';
SELECT pg_drop_replication_slot('jt_rmgr_probe') FROM pg_replication_slots WHERE slot_name='jt_rmgr_probe';
SELECT slot_name FROM pg_create_logical_replication_slot('jt_rmgr_probe','pgoutput');
INSERT INTO lr_public VALUES(1);
SELECT count(*) FROM pg_logical_slot_get_binary_changes('jt_rmgr_probe', NULL, NULL,
       'proto_version','1','publication_names','p_lr');
SELECT pg_drop_replication_slot('jt_rmgr_probe') FROM pg_replication_slots WHERE slot_name='jt_rmgr_probe';
SQLEOF
)
if printf '%s' "$rmgr_probe" | grep -q "resource manager with ID 134 not registered"; then
  no "Neon RMGR 134 已注册（解码前置条件）" \
     "服务需以 shared_preload_libraries=neon_rmgr 启动，且 neon_rmgr 须针对本 PG 构建编译"
else
  ok "Neon RMGR 134 已注册（解码前置条件）"

  # d-1) 低上限：高密行被过滤、公开行通过
  r_low=$(lr_decode 10 0 2101 2202 jt_lr_low)
  got_low=$(printf '%s' "$r_low" | grep -oE '^[0-9]+\|[0-9]+$' | tail -1)
  if [ "$got_low" = "0|1" ]; then
    ok "解码端到端：低上限下高密行被过滤、公开行通过（secret|public = ${got_low}）"
  else
    no "解码端到端：低上限下高密行被过滤、公开行通过" "期望 0|1，实际 ${got_low}（原始：${r_low}）"
  fi

  # d-2) 高上限 + 授权类别：同一高密行必须出现（反证）
  r_high=$(lr_decode 40 1 2303 2404 jt_lr_high)
  got_high=$(printf '%s' "$r_high" | grep -oE '^[0-9]+\|[0-9]+$' | tail -1)
  if [ "$got_high" = "1|1" ]; then
    ok "解码端到端：上限提高+类别授权后同一高密行可外发（反证过滤按上限生效）"
  else
    no "解码端到端：上限提高+类别授权后同一高密行可外发" "期望 1|1，实际 ${got_high}（原始：${r_high}）"
  fi

  # d-3) 仅提等级、不授权类别：仍不得外发（正交性在解码链路上也成立）
  r_mid=$(lr_decode 40 0 2505 2606 jt_lr_mid)
  got_mid=$(printf '%s' "$r_mid" | grep -oE '^[0-9]+\|[0-9]+$' | tail -1)
  if [ "$got_mid" = "0|1" ]; then
    ok "解码端到端：仅提等级未授权类别时高密行仍被过滤（正交性）"
  else
    no "解码端到端：仅提等级未授权类别时高密行仍被过滤" "期望 0|1，实际 $got_mid"
  fi

  # d-4) 过滤必须留下**可共享**的观测痕迹
  #
  # 注意不能用 `jt_sec_replication_skipped()` 断言：它是 **per-backend 内存
  # 计数器**（static），而解码发生在 psql 的临时后端里，外部会话读到的永远是
  # 0（实测踩到）。真正跨进程可观测的载体是 E2 审计事件——它写 PG 日志，
  # 而日志是所有后端共享的。故这里断言日志里出现了 action=replication_emit
  # 且带正确的对象标签与当时的 max_level。
  LOGF3="${JTDB_JTSEC_LOGFILE:-/tmp/jtsec-runtime.log}"
  if [ -f "$LOGF3" ]; then
    if grep -q '"action":"replication_emit"' "$LOGF3" 2>/dev/null; then
      ok "过滤产生 E2 审计事件（action=replication_emit，跨进程可观测）"
    else
      no "过滤产生 E2 审计事件" "日志无 action=replication_emit"
    fi
    # 事件必须带对象标签与当时的策略上限（可追溯"按什么规则被拦"）
    ev_rep=$(grep '"action":"replication_emit"' "$LOGF3" 2>/dev/null | tail -1)
    if printf '%s' "$ev_rep" | grep -q '"object_label":"30:finance"'; then
      ok "事件含被拦对象的标签"
    else
      no "事件含被拦对象的标签" "$ev_rep"
    fi
    if printf '%s' "$ev_rep" | grep -qE '"max_level":[0-9]+'; then
      ok "事件含当时的外发上限（可追溯判定依据）"
    else
      no "事件含当时的外发上限" "$ev_rep"
    fi
  else
    say "  SKIP  过滤 E2 事件（未设 JTDB_JTSEC_LOGFILE）"
  fi
fi

# 清理：槽会持续持有 WAL，不删会拖住后续测试
as "$ADMIN" "SELECT pg_drop_replication_slot('jt_lr_slot') FROM pg_replication_slots WHERE slot_name='jt_lr_slot';" >/dev/null 2>&1
as "$ADMIN" "SET jt_sec.role='secadmin'; DROP PUBLICATION IF EXISTS p_lr;" >/dev/null 2>&1


# ---------------------------------------------------------------------------
say "=== 14. 逃逸清单剩余项（docs/02 §3.5）==="
# docs/02 §3.5 原文列举的逃逸路径中，已拦：COPY PROGRAM、COPY 文件形式、
# 大对象服务端读写、file_fdw 的 filename/program 选项（§10/§10b）。
# 本段覆盖**其余四项**，它们的共同性质是：不"读表"，故 ExecutorStart 的
# MAC 检查完全管不到，而一旦装载即可绕过内核把数据搬出去或执行任意代码。
#
# **为什么必须放在逃逸围栏（而非 MAC 块）内**：这些能力拦的是"绕过内核直接
# 接触外部系统/执行代码"，与标签检查是否启用无关——MAC 处于阶段 0 兼容模式
# （off）时同样危险。与 COPY PROGRAM 的判据一致。
#
# 实测过的真实风险（本段写之前先探测）：
#   - 围栏开启 + MAC 开启下，superuser 仍能 `CREATE EXTENSION dblink`，
#     随后高密会话（40:）能成功 `dblink_connect` 到**外部**数据库（返回 OK）。
#     这是与逻辑复制同类的数据出口，且目标完全不受本实例管控。
#   - 围栏开启下 superuser 仍能 `CREATE LANGUAGE`（任意服务端代码执行）。

# 14.1 扩展装载（dblink/postgres_fdw 是数据出口；file_fdw 读服务器文件）
expect_err "默认禁用 CREATE EXTENSION（dblink 是数据出口）" "$ADMIN" \
  "SET jt_sec.allow_escape_paths=off; CREATE EXTENSION IF NOT EXISTS dblink" \
  "CREATE EXTENSION .* is disabled"

# 14.2 非受控过程语言（服务端任意代码执行）
expect_err "默认禁用 CREATE LANGUAGE" "$ADMIN" \
  "SET jt_sec.allow_escape_paths=off; CREATE LANGUAGE jt_t14_lang HANDLER plpgsql_call_handler" \
  "CREATE LANGUAGE .* is disabled"

# 14.3 C 语言函数（装载任意 .so，等效任意代码执行）
expect_err "默认禁用 CREATE FUNCTION ... LANGUAGE C" "$ADMIN" \
  "SET jt_sec.allow_escape_paths=off; CREATE FUNCTION jt_t14_cfn() RETURNS int AS 'libc.dylib' LANGUAGE C" \
  "LANGUAGE C is disabled"

# 14.4 受控语言不得误拦（sql/plpgsql 经 SPI 走 ExecutorStart，已被 MAC 覆盖）
#      这一条很重要：围栏若把 sql 函数也拦了，业务会被无谓打断。
expect_ok "受控语言 sql 函数不被误拦" "$ADMIN" \
  "SET jt_sec.allow_escape_paths=off; CREATE OR REPLACE FUNCTION jt_t14_sqlfn() RETURNS int AS 'SELECT 1' LANGUAGE sql"
expect_ok "受控语言 plpgsql 函数不被误拦" "$ADMIN" \
  "SET jt_sec.allow_escape_paths=off; CREATE OR REPLACE FUNCTION jt_t14_plfn() RETURNS int AS 'BEGIN RETURN 1; END' LANGUAGE plpgsql"

# 14.5 白名单可放行（secadmin 开启后 dblink 可装）
#      必须验证"放行"这一侧，否则无法区分"围栏生效"与"扩展本来装不上"。
expect_ok "白名单开启后 dblink 可装载" "$ADMIN" \
  "SET jt_sec.role='secadmin'; SET jt_sec.allow_escape_paths=on; CREATE EXTENSION IF NOT EXISTS dblink"

# 14.6 普通用户不得自行开白名单（权限提升防护，与 §10 呼应）
expect_err "普通用户不得开启逃逸白名单（扩展侧）" low_u \
  "SET jt_sec.allow_escape_paths=on" "ERROR|FATAL|permission"

# 14.7 收尾：关掉白名单并卸掉扩展，避免影响后续/重跑
as "$ADMIN" "SET jt_sec.role='secadmin'; SET jt_sec.allow_escape_paths=on; DROP EXTENSION IF EXISTS dblink;" >/dev/null 2>&1
as "$ADMIN" "SET jt_sec.allow_escape_paths=off; DROP FUNCTION IF EXISTS jt_t14_sqlfn(); DROP FUNCTION IF EXISTS jt_t14_plfn();" >/dev/null 2>&1

# ---------------------------------------------------------------------------
say "=== 结果 ==="
say "  PASS=$pass  FAIL=$fail"
[ "$fail" = "0" ] && say "RUNTIME_OK" || say "RUNTIME_FAILED"
exit "$fail"
