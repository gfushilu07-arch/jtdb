# JTDB 正式开发前外部技术审计

| 项 | 值 |
|---|---|
| 日期 | 2026-09-02 |
| 文档版本 | v1.0 |
| 审计方法 | 三路并行调研：①Neon/PG 生态 ②国密信创竞品 ③存储加密/策略/形式化验证技术栈 |
| 证据形态 | GitHub/crates.io/官方文档/新闻的实测抓取（URL 随文标注）；无法核实的明确标注 |
| 触发原因 | 开发启动前最终审计；决策方对现有规划的信心需要建立在可核实的外部事实上 |
| 性质 | 本文档不改决策，只呈报事实、修订建议与决策门；方向级变更待拍板 |

## 1. 改变判断的三个事实

### 1.1 Neon 上游已经实质停滞（最高优先级）

- Databricks 于 2025-05-14 宣布以约 10 亿美元收购 Neon（reuters.com，2025-05-14）；
- 开源仓库未归档、许可证仍 Apache-2.0（github.com/neondatabase/neon，2026-09-02 实测），**但最后一个 release tag 是 release-9129（2025-07-25），此后无版本发布；2026 年 master 公开提交仅 4-5 次**；
- 产品方向并入 Databricks Lakebase（neon.com 2026-09 实测），团队转向 AI agent 后端、Electric 并入（2026-08）。

**含义**：ADR-001 的前提"跟随上游、定期同步"已失效。fork 的实际形态是"以 release-9129 为基线的自治维护"——不再有 rebase 冲突面（坏消息的正面），但 PG 18/19 追平、Neon 后续修复全部要自己背（坏消息）。按"维护一个自有存储引擎"做人力预算，而不是按"跟随上游"。

### 1.2 竞争坐标修正：行级 MLS 不是全行业空白

- **达梦 DM8 安全版已有行级强制访问控制**：标签形"等级：范围：组"、每行携带标记列、SYSSSO 管理、ENABLE_MAC 初始化（eco.dameng.com 强制访问控制手册，2026-09-02 检索）；且达梦 MPP 不支持 MAC——这是可打的差异点；
- **PG 系信创阵营（openGauss/金仓/Vastbase）确实没有密级标签 MLS**：openGauss 6.0.5/7.0-RC3 只有策略式 RLS + 资源标签（审计用），但其**全密态数据库已是成熟能力**（客户端 CMK/CEK、SM4_SM3、密态等值查询）、7.0 支持 TLCP + 第三方 KMS TDE + 防篡改账本 + 库内向量 DataVec（docs.opengauss.org，2026-09-02 检索）；
- **密评证据自动化是全行业真空白**：检索未发现任何厂商提供"GB/T 39786 测评项 → 运行时证据链自动生成"工具，各家止步于产品认证证书 + 人工测评。

**含义**：JTDB 的差异化定位成立且应更聚焦——对 PG 系是增量卖点，对达梦是替换兼容问题（Level=等级、Categories=范围/组，映射成本低，docs/05 §3 需补达梦语义兼容小节）；"密评证据包"从 P0 功能升级为**产品第一卖点**；全密态等值查询是 openGauss 已设的基线，JTDB 的全密态路线图不能低于此。

### 1.3 PG 版本时间线确认自研路线

- PG 18 已发布（2025-09-25）：异步 I/O（部分场景 3x）、uuidv7、OAuth、checksum 默认开启（postgresql.org）；
- PG 19 开发中，**内核 TDE 无可确认的 commitfest 进展**（commitfest.postgresql.org 检索，2026-09-02）；
- 社区现实路径是发行版自研：Percona pg_tde 已 GA（1.0.0 2025-06-30，2.2.1 2026-07，KMS 集成 + 在线轮转）。

**含义**：JTDB 自研内核加密（ADR-007）的判断正确，且不必等待 PG 内核；但注意 fork 基点 release-9129（2025-07-25）早于 PG 18 发布，**fork 快照对 PG 18 的支持状态是建仓时必须核实的第一项**。

## 2. ADR 逐条复核

| ADR | 复核结论 | 说明 |
|---|---|---|
| 001 直接使用并修改 Neon 源码 | **需修订** | 增加"上游失活条款"：上游冻结视为常态，release-9129 为自治基线；同步机制表述作废。方向级修订待拍板（§5） |
| 002 Rust 为核心语言 | 维持 | Rust 存储从"跟随上游"变为"自治维护"，语言决策不受影响 |
| 003 三平面=信任边界 | 维持 | 不受外部事实影响 |
| 004 单机多进程 | 维持 | profile 化边界已补充 |
| 005 Compute 最终边界 | 维持 | SE-PostgreSQL 行级方案 15 年未落地、PG RLS 无性能改进（PG18 release notes 无条目），内核执行的判断被反向印证 |
| 006 复用 Neon 存储体系 | **需修订** | 与 001 联动：复用对象是"冻结快照"，标注维护责任归属 |
| 007 全生命周期加密 | 维持并加强 | PG19 TDE 无进展、pg_tde 只覆盖表数据，WAL/备份全链路加密仍是自研差异化 |
| 008 扩展受控开放 | 维持 | 无变化 |
| 009 开发体验 | 维持 | 无变化 |
| 010 TiDB 不作基座 | 维持 | 无变化 |
| 011 行级标记 | 维持并加强 | 达梦语义兼容（等级：范围：组 → Level/Categories 映射）补入 docs/05 |
| 012 超管围栏 | 维持 | 金仓持商密认证 + EAL4+（kingbase.com.cn），三权分立是市场已有心智，不是过度设计 |
| 013 KMS 协议 | 维持 | pg_tde 的 KMS 集成（HashiCorp/Thales/Fortanix/OpenBao）可作为 jt-kms 对接参照 |
| 014 分支密钥 scope | 维持 | 与 001 修订联动（快照版 timeline/branch 仍是卖点） |

## 3. 设计级验证结论（外部事实 vs 我们的设计）

| 设计项 | 外部事实 | 结论 |
|---|---|---|
| docs/04 chunked AEAD + GCM | 存储加密主流是 AES-XTS（IEEE 1619，无认证）；AEAD 是 1619.1-2018 定义的认证变体；"块号绑定 nonce"是通行做法，未发现业界反例 | **方向正确，补三条纪律**：(key,nonce) 永不重复的形式论证；crash 后重写 chunk 的 nonce 派生规则（已有"重写=新对象"覆盖）；对标 1619.1-2018 命名以便审计对标 |
| 国密栈 | Tongsuo（铜锁）活跃恢复发版（8.5.0-pre2，2026-08），持商密产品认证证书，用户含支付宝/OceanBase；RustCrypto 官方 sm2/sm3/sm4 crate 活跃但 sm4 为 hazmat、sm4-gcm crate 停滞 | **选型落地**：tongsuo-backend = 合规主力（有商密认证，直接利好密评）；pure-rust-backend = RustCrypto sm2/sm3/sm4 + 自组 GCM，定位测试/非合规场景。docs/12 §3.3 据此细化 |
| Cedar | v4.12.0 活跃（2026-07），cedar-spec 用 Lean 全量形式化 + 差分随机测试，同类唯一 | **选型站得住**；对外材料引用形式化证据而非装机量（AWS 之外生产案例未核实） |
| 形式化工具 | TLA+ 仍是工业默认；Quint v0.32 活跃（可执行模型 + Apalache 后端）；Ivy 已归档（2021） | **TLA+ 主 + Quint 双轨**；现有 KmsKeyEpochRotation.tla 继续有效，Ivy 不采用 |
| TEE/可信 | 海光 CSV 远程证明生态未成熟（openEuler secGear 标记 future）；openEuler 内核已有 CSV guest 驱动 | jt-attest 第一梯队 = TCM/TPCM + 软件度量；CSV/TEE 降级为实验特性，文档已有此倾向，保持 |
| 向量生态 | pgvector v0.8.6（2026-07）、VectorChord、ParadeDB 均活跃，赛道极度拥挤 | "PG 兼容+向量"引流叙事弱化；差异化改为**行级标签 × 向量检索过滤**（敏感向量数据的标签级访问控制，无人做的组合） |
| 替代基座 | OrioleDB 活跃但 beta（beta15/16 专注稳定性，2026-07）；Aurora DSQL 闭源不可 fork；Supabase 栈非内核安全 | 均不构成对 ADR-001 的替代；作为 §5 决策门的备选项记录 |

## 4. 对信心的诚实评估

**该有信心的（有外部证据支撑）**：

1. **真空白存在**：密评证据自动化全行业无人做；PG 系信创阵营无内核级行级 MLS——这两个是采购决策的真刚需，不是自嗨功能；
2. **设计经得起对标**：chunked AEAD 方向被 IEEE 1619 认证变体与业界实践印证；Cedar 是唯一带形式化证明的候选；TLA+ 模型已实际跑通；
3. **合规路径清晰**：Tongsuo 商密认证 + GM/T 0028 二级 + GB/T 39786 映射，密评材料链是完整的；
4. **核心安全语义不依赖任何活得短的开源项目**：MLS/审计/加密/KMS 全部自研，Neon 只贡献存储执行层。

**真实的风险（不粉饰）**：

1. **工程量性质变了**：从"跟随上游的 fork"变成"自治维护一个云原生存储引擎"（Pageserver/Safekeeper 约十万行 Rust），这是 5-10 人年级的长期承诺；
2. **达梦是直接对手**：安全版行级 MAC + 商密认证 + 上市公司的销售网络；JTDB 必须靠"PG 生态兼容 + 密评自动化 + 价格"打，而不是靠"也有 MAC"；
3. **人力/时间**：规划的阶段 0-5 隐含一支能同时做 C 内核、Rust 存储、安全、信创适配的团队，任何一项缺人都会把时间线拉长一倍。

## 5. 决策建议：ADR-001 修订方案与决策门（待拍板）

三个可选路线：

| 选项 | 内容 | 优势 | 代价 |
|---|---|---|---|
| A（推荐） | 确认 fork release-9129 为自治基线；**第一批交付"传统本地存储 + 全部安全能力"**，Neon 存储栈（timeline/branch/PITR）作为第二阶段平台能力 | 安全差异化最快上市；Neon 栈风险被决策门隔离；符合"密评自动化优先"的定位 | 第一批没有 branch/PITR 卖点 |
| B | 放弃 Neon，原生 PG 17/18 + pg_tde 参照 + 自研全链路加密 | 工程量最小 | 丢掉 Rust 存储/timeline/branch 全部先进性叙事；pg_tde 许可证与模型需尽调 |
| C | 维持原计划，Neon 栈进第一批 | 叙事完整 | 承受 §4 风险 1 的全部重量 |

**决策门（阶段 0 新增，4-6 周可行性验证）**，全部通过则 Neon 栈进第一批，任一失败则走 A 的分期：

1. release-9129 在 x86-64 + 鲲鹏 aarch64 信创环境完成编译并跑通 Neon 回归；
2. 核实其对 PG 18 的支持状态，或明确 PG 版本策略（17 起步）；
3. 最小安全补丁 PoC（安全上下文 + 一个 MAC 执行点）落在 Compute 上，基准对照符合 §5 SLO 的数量级。

## 6. 人工复核清单（调研环境受限，需人工补核）

1. 密评监管 2025-2026 新要求（oscca.gov.cn 与中国密码协会通报）；
2. 金仓 KES V9 密级标识/四权分立官方文档（docs.kingbase.com.cn 渲染异常未取证）；
3. pg_tde 的开源许可证与 per-page IV/nonce 设计细节（docs.percona.com 多次超时）；
4. Neon compute 仓库（PG 分支）对 PG 18 的支持边界与 release-9129 的匹配；
5. TCM 2.0/TPCM 服务器落地的 2025-2026 权威材料（搜索引擎结果受污染）。

## 7. 审计产生的文档修订清单（2026-09-03 已执行）

| 文档 | 修订 |
|---|---|
| ADR-001/006 | 上游失活条款（§5 选项 A 或 C，取决于拍板） |
| docs/04 | 补 §4.5"与 IEEE 1619.1-2018 对标"与 (key,nonce) 唯一性论证小节 |
| docs/05 | 补达梦 MAC 语义兼容小节（等级：范围：组 → Level/Categories） |
| docs/12 | §3.3 合规模式细化：Tongsuo 商密认证为合规主路径的事实依据 |
| docs/13 | jt-attest 梯队声明：CSV/TEE 降级为实验特性（secGear 现状） |
| 规划 §4 | 向量功能说明改为"行级标签 × 向量过滤"差异化定位 |

## 8. 路线拍板（2026-09-03）

决策方确认：**JTDB 自行维护 Neon fork**（排除 B 放弃路线）。据此已执行：

1. ADR-001 增补**上游失活条款**：基线固化为 release-9129（2025-07-25），"跟随上游"机制作废，按"自有存储引擎长期维护"核定人力预算；
2. ADR-006 增补边界：复用对象为冻结快照，维护责任完全归属 JTDB；
3. 实现方案 §1.3 同步机制作废，改用于自治基线溯源；规划文档 §8 记录拍板（决策 #7）、§9.2 修订为固化基线规则；
4. "第一批交付是否包含 Neon 存储栈"由 §5 决策门（4-6 周可行性验证：release-9129 双平台编译 + PG 18 支持边界核实 + MAC 补丁 PoC 基准）结果确定——**该门仅决定交付分期，不影响自治维护承诺**。

## 9. 决策门执行记录

| 任务 | 内容 | 结果 |
|---|---|---|
| 1 | release-9129 在本机（aarch64）编译跑通 | **部分通过（2026-09-03）**：Neon workspace `cargo check` 绿线——覆盖 pageserver、proxy、compute_tools、storage_controller、postgres_ffi 等 24 个 crate；safekeeper/walproposer 暂排除（需 `make walproposer-lib` 在容器内构建 C 库 libwalproposer.a，下一步）。过程中解决两个平台问题：①postgres_ffi 需要 pg_install/{v14..v17} 头文件 → 用 Debian bookworm 容器按 vendor/revisions.json 精确版本（17.5/16.9/15.13/14.18）构建（scripts/build-pg.sh，产物在缓存卷，删除 Linux bin 以触发头文件 fallback）；②macOS bindgen 与 PG port.h 的 strlcat/strlcpy 声明冲突 → pg_config.h 的 HAVE_DECL_STRLCAT/STRLCOPY 置 1（已固化进 build-pg.sh）。日志：缓存卷 logs/cargo-check-neon-9129-3.log |
| 2 | PG 18 支持边界核实 | 初核（2026-09-03）：release-9129 vendor 矩阵无 PG 18。**同日决策方要求 v1 必须支持最新大版本 → ADR-015**：路径 = neon postgres fork 的 `REL_18_STABLE_neon`（PG 18.2，公开活跃）作 vendor + neon 仓库侧 JTDB 自研回合（公开仓库无 v18，私有 fork 已证明可行）。第一层接线当日完成并通过 workspace check（见 ADR-015 执行记录）；pgxn/neon C 扩展 PG18 兼容为最大待办 |
| 3 | MAC 补丁 PoC 基准 | 未开始（依赖任务 1） |
| — | 双平台 CI（x86-64 + aarch64 信创） | 未开始；本机 aarch64 macOS 先行，x86-64 信创环境待硬件到位 |
