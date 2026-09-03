# JTDB 安全上下文与 MLS 设计

| 项 | 值 |
|---|---|
| 项目代号 | 金湯 JTDB（暂定） |
| 承接文档 | 《架构决策记录》ADR-011/012、《实现方案》v0.3 §3、《三平面零信任架构》v0.4 §4 |
| 对应文档树 | docs/05-JTDB-安全上下文与MLS设计.md |
| 文档版本 | v0.1 起草稿 |
| 日期 | 2026-09-02 |
| 状态 | 阶段 0 专项，待技术评审 |
| 已确认决策 | 对象级 + 行级双层标签（ADR-011）；超级用户围栏与三权分立（ADR-012） |

## 1. 目标与范围

展开 ADR-011/012 的可编码设计：安全上下文生命周期、标签模型与目录、行级标记的存储实现、强制访问的执行方式、与 RLS/复制/备份的交互。

不含：执行点清单（实现方案 §3.2 已定义）、审计事件格式（实现方案 §7.2）、KMS/策略租约协议（ADR-013）。

## 2. 安全上下文生命周期

```text
创建：网关认证 → 短期上下文材料（docs/13 身份 + nonce + policy_version）
      → Compute 内核验证签名/freshness → 绑定为 JtSecurityContext（实现方案 §3.1）
携带：绑定到会话；事务级池化场景按事务传递（docs/14 §4）
失效：租约过期 / policy_version 撤销 / 证书撤销 / key_epoch 轮换 → 会话失效或降级
销毁：会话结束内核主动清除；池化复位例程覆盖（docs/14 §3）
```

内核保证：上下文不可通过 GUC 伪造；`expires_at` 用可信时间校验（ADR-013 §4）；失效检查点为每事务开始 + 每 E3 操作前。

## 3. 标签模型

### 3.1 结构

```text
Label = (Level, Categories)
Level：     全序整数集合，默认 4 档（10=公开 20=内部 30=秘密 40=机密），secadmin 可扩展
Categories：字符串集合（如 {财务, 人事}），domination 要求包含关系
dominate(a, b) = a.Level >= b.Level AND a.Categories ⊇ b.Categories
```

### 3.2 访问规则（BLP）

| 规则 | 含义 | JTDB 执行 |
|---|---|---|
| 简单安全属性（不下读） | 主体标签须支配对象标签才可读 | 读路径标签谓词（§6） |
| \*-属性（不上写） | 对象标签须支配主体标签才可写 | 写路径检查（§6） |
| 类别支配 | Categories 包含关系 | dominate 函数统一实现 |
| 可信降标 | 受控主体可降标写 | jt_secadmin 白名单 + E3 审计 + 双人复核（降标>1档时） |

### 3.3 默认与继承

- CREATE TABLE：继承 schema 默认标签（无则取库默认，库默认缺省为最低档）；
- INSERT：行标签 = 主体标签（若主体支配表默认）或表默认标签；
- ALTER TABLE ... SET LABEL：E3 事件；已有行不自动重标（提供 `jt_relabel_table()` 受控重标工具，逐批 + 可中断 + 审计）。

### 3.4 达梦安全版语义兼容（2026-09-03 补充，迁移目标）

外部核实（审计 §1.2）：达梦 DM8 安全版行级 MAC 标签为"等级：范围：组"三元组、每行携带标记列、由 SYSSSO 管理、初始化时 `ENABLE_MAC=1` 开启，且达梦 MPP 场景不支持 MAC。JTDB 作为替换目标提供语义映射：

| 达梦概念 | JTDB 对应 |
|---|---|
| 等级 | Level（有序档位，数值化映射） |
| 范围 / 组 | Categories（集合包含语义对齐） |
| SYSSSO（安全标记管理员） | jt_secadmin（ADR-012） |
| ENABLE_MAC 初始化开关 | 按表启用行级标记（§5.1） |
| 每行标记列 | jt_label 隐藏属性（§5.2 方案 A） |

替换论证要点：达梦 MPP 不支持 MAC，JTDB 统一语义覆盖。存量标签与用户标记迁移由 `jt_migrate_from_dameng` 工具承接（迁移工具工作域）。

## 4. 目录设计

```sql
CREATE TABLE pg_catalog.pg_jt_label (
    oid        oid        PRIMARY KEY,     -- 标签 ID（行级列引用它）
    level      int4       NOT NULL,
    categories text[]     NOT NULL DEFAULT '{}',
    policy_version xid8   NOT NULL,        -- 创建时的策略版本
    digest     bytea      NOT NULL,        -- SM3(level||categories)，复制校验用
    created_by name,
    created_at timestamptz,
    comment    text
);
CREATE TABLE pg_catalog.pg_jt_object_label (   -- 对象级（库/模式/表/列）
    classoid oid, objoid oid, objsubid int4,
    label_oid oid NOT NULL REFERENCES pg_jt_label(oid)
);
```

- 写权限：仅 jt_secadmin（ADR-012 围栏），超级用户不可写（逃逸清单覆盖）；
- 失效：变更走 sinval 广播，各 Compute 进程标签缓存（决策 memoization）失效（实现方案 §3.2 缓存策略）；
- 逻辑复制：两张目录表作为受控复制对象，digest 端到端校验。

## 5. 行级标记的存储实现

### 5.1 启用粒度（关键决策）

**行级标记按表启用**：`CREATE TABLE ... WITH (jt_row_label = on)` 或 `ALTER TABLE ... ENABLE ROW LEVEL LABEL`。未启用的表零存储与零执行开销；SLO ≤10% 仅约束启用的表。启用操作为 E3 事件。

### 5.2 方案比较

| 方案 | 做法 | 结论 |
|---|---|---|
| A. 隐藏系统属性 | 启用的表追加固定位置属性 `jt_label oid`，内核管理、`SELECT *` 不可见、普通 UPDATE 不可改 | **采用**：与元组同行存储（4B），计划器/执行器自然可见，TOAST/复制/恢复路径同构 |
| B. 独立映射表 | (ctid → label) 目录 | 否决：ctid 随 VACUUM/全页写漂移，映射不可靠 |
| C. 复用旧 OID 系统槽 | 利用 PG12 移除的 WITH OIDS 槽位 | 否决：跨 PG 大版本兼容风险，语义含混 |

### 5.3 方案 A 细则

```text
元组布局：[HeapTupleHeader][jt_label oid][用户属性...]   -- 属性号置于用户属性之前
不可见性：Parse/analyze 层过滤该属性；\d 与 information_schema 不展示；
          显式引用报权限错误（非 secadmin 且非内核路径）
不可变性：无 UPDATE 直接路径；重标只经 jt_relabel 工具或 COPY WITH JTLABEL（restore）
NULL 语义：属性 NOT NULL，缺省值 = 表默认标签 oid
```

- TOAST：外部 toast 行不携带标签，访问必须经主行（主行验证先行，天然满足）；
- 索引：索引项不带标签；热点场景可为 `jt_label` 建索引或建 partial index，谓词下推可利用（§6）；
- pg_upgrade：二进制升级保留属性号与目录（验证项，§10）。

## 6. 强制访问执行

### 6.1 读路径（不下读）

计划期注入标签谓词（机制同 RLS qual 注入）：

```text
扫描任何启用表 → Planner 附加  jt_dominates(subject_label, jt_label) = true
形式：内联支持函数（避免每行 SQL 调用开销）+ 可选标签索引
```

覆盖：顺序扫描、索引扫描（索引后过滤）、位图扫描、JOIN 内外表、子查询、FDW（FDW 数据不落地，扫描结果统一过滤）、分区路由。

### 6.2 写路径（不上写）

执行点复用实现方案 §3.2 清单：ModifyTable/Copy/Merge/Truncate/DDL/函数触发器/FDW 写/约束检查/备份恢复导出。写前校验 `dominate(object_label, subject_label)`；新行标签按 §3.3 继承。**执行点返回统一错误码 + E2 审计事件（MAC 拒绝）**，拒绝不回滚整个事务（语句级），保持与 PG 错误语义一致。

### 6.3 计划缓存与失效

- 注入的标签谓词绑定 policy_version 与标签目录版本；
- 任一变更（PDP 撤销 / pg_jt_label 变更 / 对象标签变更）→ sinval → 相关 prepared plan 失效或执行期复查（实现方案 §3.2）；
- 事务内 subject×object×action 决策 memoization，变更点统一失效。

## 7. 与 RLS 的组合

- 语义：RLS policy 与标签谓词取 **AND**；RLS 先于标签过滤注册（标签为强制层，RLS 为自主层）；
- RLS 规则中引用 jt_label 函数是允许的（把标签作为 RLS 的输入），但**不能反向用 RLS 实现 MAC**（ADR-011 否决项）；
- 性能：两者叠加预算包含在 ≤10% SLO 内，基准用例须含"RLS+标签"组合场景。

## 8. 备份、恢复与复制

| 路径 | 规则 |
|---|---|
| pg_dump | 新选项 `--jt-labels`：导出标签目录 + 每表 ENABLE 语句 + 行内标签（COPY 二进制扩展列） |
| pg_restore / COPY | 带 `WITH JTLABEL` 的导入需 jt_secadmin 身份；标签不存在于目标库则拒绝（不自动建标签） |
| 逻辑复制 | 发布端按行标签裁剪（实现方案 §3.6）；订阅端写入按 §6.2 校验 |
| 物理恢复/PITR | 标签在 WAL 元组数据内，随存储加密体系（docs/04）自然恢复 |
| 快照/分支克隆 | 标签随数据复制；分支标签目录继承（ADR-014 密钥 scope 不影响标签语义） |

## 9. 性能设计

| 手段 | 说明 |
|---|---|
| 内联支配函数 | C 内核函数，非 SQL pl 调用；dominate 用整数比较 + 位图包含，避免字符串归一化 |
| 标签缓存 | per-process 标签目录缓存 + sinval 失效；决策 memoization（§6.3） |
| 谓词下推 | 利用 (jt_label) 索引或 partial index；EXPLAIN 可见（jt_explain_policy 关联） |
| 预算 | 启用行级标记的表：合计 TPS 开销 ≤10%（规划 §5；含 RLS 叠加场景） |

## 10. 测试标准

- **全路径矩阵**：§6.1/6.2 全部路径 × {允许, 下读拒绝, 上写拒绝, 类别不支配} 四类用例；
- **绕过尝试集**：函数内动态 SQL、触发器内写、临时表、大对象、COPY PROGRAM（已禁）、游标、prepared plan 复用旧标签、并发 ALTER LABEL 与读事务交错；
- **隐匿性**：`SELECT *`、`\d`、`information_schema.columns`、逻辑复制 DDL 均不泄漏 jt_label 属性；
- **升级**：pg_upgrade 后标签目录与行级属性完整；
- **性能**：SLO 场景（含 RLS 叠加、标签索引、多类别）基准入规划 §5 基准方法。

## 11. 待验证问题

1. 隐藏属性在 TupleDesc/扩展（plpgsql 记录、JDBC getMetaData）中的呈现边界；
2. `OR` 分支、`IN` 子查询中标签谓词的泄漏路径（计划器改造范围）；
3. 计划期注入对 planner 本身的开销（目标 <1%）；
4. 类别数量上限与位图编码（text[] vs 固定位图）的取舍；
5. jt_relabel_table 大表逐批重标的事务边界与复制延迟影响。
