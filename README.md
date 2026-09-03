# JTDB 文档索引

| 项 | 值 |
|---|---|
| 项目 | 金湯 JTDB（暂定）——面向信创和中小企业的 PostgreSQL 兼容安全数据库平台 |
| 基座 | fork Neon（PostgreSQL Compute + Rust 存储体系），自研安全/国密/控制/审计/开发体验层 |
| 文档状态 | 讨论稿阶段；正式编号文件待建仓后迁入 docs/ |
| 本文件职责 | 文档总览、阅读顺序、目录映射、术语表 |

## 1. 文档总览与阅读顺序

新读者建议按下列编号顺序阅读；每份文档的元数据表都标注了自己的承接关系。

| # | 文件 | 定位 | 版本 | 状态 |
|---|---|---|---|---|
| 1 | JTDB-架构决策记录.md | ADR-001~014，全部已确认决策 | — | 决策入册 |
| 2 | 信创安全数据库-三平面零信任架构.md | 总体目标架构 | v0.4 | 待技术评审 |
| 3 | 信创安全数据库-实现方案.md | 技术实现总纲（组件/接口/内核/存储） | v0.3 | 待技术评审 |
| 4 | JTDB-架构评审意见与改进规划.md | 评审结论、SLO 基线、实施路线、决策记录 | v1.0 | 阶段 0 依据 |
| 5 | JTDB-密评合规与随机数设计.md | docs/12：GB/T 39786 映射、GM/T 0028 二级、随机数 | v0.1 | 待密码专项评审 |
| 6 | JTDB-身份与节点引导设计.md | docs/13：CA 层次、enrollment、离线部署、三权引导 | v0.1 | 待技术评审 |
| 7 | JTDB-连接与会话治理设计.md | docs/14：内建连接池、主体亲和、会话复位 | v0.1 | 待技术评审 |
| 8 | JTDB-加密对象与存储加密设计.md | docs/04：chunked AEAD 对象格式（字节级） | v0.1 | 待技术评审 |
| 9 | JTDB-安全上下文与MLS设计.md | docs/05：行级标记、pg_jt_label、谓词下推 | v0.1 | 待技术评审 |
| 10 | JTDB-核心接口字段规格.md | KMS/Audit 接口字段级定义（docs/15） | v0.1 | 待技术评审 |
| 11 | JTDB-正式开发前外部技术审计.md | 外部技术尽调：Neon 停滞、竞品坐标、设计对标、决策门 | v1.0 | 供路线拍板 |
| 12 | verification/KmsKeyEpochRotation.tla | ADR-013 轮换协议 TLA+ 模型 | — | TLC 已验证 |

## 2. 仓库布局（2026-09-03 建仓，按实现方案 §1.2）

```text
├── docs/                      # 编号文档树（见上表；旧文件名引用均对应此树）
│   ├── 00-架构评审意见与改进规划 / 00-正式开发前外部技术审计
│   ├── 01-总体架构 / 02-技术实现方案
│   ├── 04-加密对象 / 05-MLS / 12-密评 / 13-身份引导 / 14-连接治理 / 15-接口规格
│   └── adr/JTDB-架构决策记录.md（ADR-001~014）
├── upstream/neon/             # Neon 子模块，锁定 release-9129（见 upstream/NEON_COMMIT）
├── postgres/                  # JTDB Compute 源码与补丁（jtdb-patches）
├── pageserver/ safekeeper/ proxy/
├── libs/                      # jt-crypto-api / jt-crypto-sm / jt-encrypted-object / jt-key-epoch
│                              # jt-storage-protocol / jt-audit-proto / jt-postgres-ffi / jt-common
├── services/                  # jt-gateway / jt-controller / jt-pdp / jt-kms / jt-attest / jt-audit-*
├── cli/jt-cli/  sdk/  extensions/
├── deployment/                # single-node / primary-standby / separated-planes / cluster
├── tests/  compliance/  packaging/
├── scripts/env.sh             # 构建环境（产物重定向缓存卷）
└── verification/              # TLA+ 协议模型
```

待起草编号：03-Compute 内核改造、07-审计平面、08-国密与可信验证、09-开发体验与扩展生态、10-部署升级备份恢复、11-测试兼容性供应链（清单见 docs/02 §11）。文档间引用如出现旧文件名（如《信创安全数据库-实现方案》），均指本树中对应编号文件。

## 2.1 构建环境（主盘空间受限）

本机主盘仅余个位数 GB，**所有构建产物必须落在缓存卷**。任何 cargo/rustup 调用前先：

```bash
source scripts/env.sh
```

该脚本将 `RUSTUP_HOME`、`CARGO_HOME`、`CCACHE_DIR`、`CARGO_TARGET_DIR` 全部重定向到 `/Volumes/fushilu/.caches/jtdb/`。禁止在本仓库内运行会产生大体积 `target/` 的构建；Neon 子模块构建使用 `JTDB_NEON_TARGET_DIR`。

## 3. 术语表

| 术语 | 含义 |
|---|---|
| 三平面 | 数据/控制/审计平面的职责与信任边界，不等于三台机器（ADR-003） |
| Compute | PostgreSQL/Neon 计算节点，最终安全执行边界（ADR-005） |
| Pageserver / Safekeeper | Neon 的页面服务与 WAL 持久化组件（Rust） |
| Timeline / Layer | Neon 存储的时间线与不可变分层文件 |
| PITR / Branch | 按时间点恢复 / 基于 copy-on-write 的数据库分支 |
| key epoch | 密钥代际；轮换单位，旧 epoch 按保留策略销毁实现加密擦除 |
| RK / KEK / DEK | 根密钥 / 密钥加密密钥 / 数据加密密钥（信封层次） |
| TLCP | 国密传输层密码协议，GB/T 38636-2020 |
| SM2 / SM3 / SM4 | 国密签名 / 摘要 / 分组密码算法 |
| TCM / TPCM | 可信密码模块 / 可信平台控制模块（国密可信硬件） |
| TEE / CSV | 可信执行环境 / 海光安全虚拟化 |
| MLS / MAC | 多级安全 / 强制访问控制（ADR-011：对象级+行级） |
| BLP | Bell-LaPadula 模型：不下读、不上写、类别支配 |
| RLS | PostgreSQL 行级安全，JTDB 中仅作纵深防御 |
| AAD / AEAD | 附加认证数据 / 认证加密（SM4-GCM，模式待密码专项核对） |
| BranchKeyGrant | ADR-014：分支对父层密钥的受限只读授权 |
| enrollment | 节点首次入网流程（docs/13） |
| attestation | 可信证明：度量 → TCM/TEE 证据 → KMS 密钥释放 |
| WORM / TSA | 一次写入多次读取存储 / 可信时间戳权威 |
| SBOM | 软件物料清单（供应链治理，ADR-008） |
| 三权分立 | jt_sysadmin / jt_secadmin / jt_auditor 角色隔离（ADR-012） |
| 主体亲和 | docs/14：连接复用限定相同 subject_id + 标签档位 |

## 4. 验证资产

```bash
cd verification
java -cp tla2tools.jar tlc2.TLC -deadlock KmsKeyEpochRotation.tla
# 预期：Model checking completed. No error has been found.
```

当前覆盖：轮换状态机、journal 先行持久化、崩溃/恢复、先 Cutover 后写入。
未覆盖（待扩展）：DEK 租约续期、attestation 绑定、BranchKeyGrant、多 timeline 并发。

## 5. 关键决策速查

| 决策 | 编号 | 一句话 |
|---|---|---|
| Neon 源码基座 | ADR-001 | 直接 fork 并修改（2026-09-03 上游失活条款：release-9129 自治基线） |
| Rust 为核心语言 | ADR-002 | C 仅保留内核边界与 FFI |
| 三平面=信任边界 | ADR-003 | 不强制三台机器 |
| Compute 最终边界 | ADR-005 | 网关不是安全边界 |
| 全生命周期加密 | ADR-007 | WAL/Layer/快照/备份全覆盖 |
| MLS 对象级+行级 | ADR-011 | 元组隐藏列 +4B/行 |
| 超管围栏 | ADR-012 | 三权分立替代 superuser |
| KMS 协议 | ADR-013 | 租约/轮换状态机/防回滚/可信时间 |
| 分支密钥 scope | ADR-014 | (cluster, timeline, epoch, lsn_range) |

完整列表见《JTDB-架构决策记录》。
