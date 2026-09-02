# JTDB 身份与节点引导设计

| 项 | 值 |
|---|---|
| 项目代号 | 金湯 JTDB（暂定） |
| 承接文档 | 《三平面零信任架构》v0.4、《实现方案》v0.3、《架构评审意见与改进规划》v1.0 |
| 对应文档树 | docs/13（规划文档 §7.2） |
| 文档版本 | v0.1 起草稿 |
| 日期 | 2026-09-02 |
| 状态 | 阶段 0 专项，待技术评审 |
| 已确认决策 | 超级用户围栏与三权分立（ADR-012）；KMS 租约与可信时间（ADR-013） |

## 1. 目标与范围

本文解决规划文档 P1-2：身份引导（bootstrap）流程缺失问题。覆盖三类身份问题：

1. **组件身份**：节点/服务如何获得可信身份并保持轮换；
2. **人的身份**：三权分立角色的凭据生命周期（ADR-012 落地）；
3. **首次入网**：解决"节点要 KMS 密钥才能起、KMS 租约又要节点身份"的鸡生蛋问题。

不含：TLCP 证书编码细节（实现方案 §5.4）、KMS 内部密钥层次（ADR-013）、MLS 主体标签语义（ADR-011）。

## 2. 身份模型

### 2.1 组件身份

```text
组件 ID：jtdb://<cluster_id>/<component>/<node_id>
    例：jtdb://c-8f3a/pageserver/node-01
```

- 证书：SM2 双证书（签名 + 加密，TLCP 要求），由 Component CA 签发；
- 短期自动轮换；私钥存储于 TCM/TEE 可用时的受保护存储，否则加密文件 + OS 权限隔离；
- 组件 ID 与安全上下文衔接：组件身份 → jt-attest 度量绑定 → KMS 租约（ADR-013）。

### 2.2 人的身份

```text
jt_sysadmin / jt_secadmin / jt_auditor   三权角色（ADR-012）
业务主体                                  由网关认证后映射（实现方案 §5.2）
```

认证方式：SM3 口令（加盐 + KDF）、SM2 证书、UKey/SKF（可选）。人的身份经网关转化为短期安全上下文材料，由 Compute 内核验证绑定（实现方案 §3.1）。

## 3. 信任锚与 CA 层次

```text
Cluster Root CA（离线保管，10 年）
├── Component CA（1 年）—— 签发组件/节点证书
└── User CA（1 年）      —— 签发人证书，或交叉信任企业既有 PKI
```

- `jtdb init` 首次初始化时生成集群根；
- Root CA 私钥**离线保管**：加密介质单独存放，或 TCM/HSM 保护 + 分片托管（按部署形态选择）；
- 信创场景常见企业已有 CA：支持对接（信任桥接方式见 §10 待验证问题）。

## 4. 节点 Enrollment 流程（核心）

```text
0. 管理员在 jt-controller 预登记节点：node_id + 一次性 enrollment token（10 分钟有效）
1. 节点首次启动：生成 SM2 密钥对 + CSR（携带本机度量摘要）
2. jt-attest 校验 TCM/TEE 证据，绑定 CSR 公钥 ↔ 度量值 ↔ node_id
3. Component CA 校验 token + attest 结论，签发节点证书（90 天）
4. 节点以证书换取 bootstrap 凭据：初始策略快照 + KMS 首个租约（ADR-013）
5. 常态运行：证书到期前经 mTLS 再认证自动轮换；密钥对不变可只换证书
```

**防中间人三重校验**：enrollment token 带外传递 + 管理员侧确认 + attestation 度量绑定。三者缺一不可，单独持有 token 无法伪造节点。

### 4.1 KMS 引导顺序（鸡生蛋解法）

```text
RK 初始化（集群初始化时一次）：TCM SRK / 安装时生成 + 分片托管
    ↓
节点 enrollment → 身份证书 → attestation 通过
    ↓
jt-kms 发放首个 DEK 租约（scope 限定本节点用途，ADR-013/014）
```

RK 初始化早于一切组件证书；Root/Component CA 私钥在 RK 保护下或加密托管。初始化顺序固化进 `jtdb init`，禁止跳步。

### 4.2 重装与重镜像

| 场景 | 处理 |
|---|---|
| 节点重装，node_id 不变 | 重新 enrollment（旧证书自动撤销） |
| node_id 变更 | 视为新节点，旧身份立即撤销，存储 ownership 迁移走控制面流程 |
| 密钥对疑似泄露 | 撤销 + 换密钥对 + jt-attest 复查后重新入网 |

## 5. 证书与撤销

| 证书/凭据 | 有效期 | 轮换方式 | 撤销机制 |
|---|---|---|---|
| Cluster Root CA | 10 年 | 不在线轮换（重签树为灾难预案） | 物理保管，不可在线撤销 |
| Component/User CA | 1 年 | 到期重签 | CRL + OCSP |
| 节点/组件证书 | 90 天 | mTLS 再认证自动轮换 | CRL/OCSP，撤销传播 ≤5 分钟 |
| Enrollment token | 10 分钟 | 一次性 | 即用即废 |
| 人证书 | 1 年 | 自动/重新认证 | CRL/OCSP |

- 撤销触发：attestation 失败、节点下线、疑似泄露、管理员操作（双人复核）；
- CRL 由 jt-identity 签发并向各组件推送缓存；离线部署采用定期 CRL；
- 撤销传播时限（≤5 分钟）写入 SLO 验收（规划文档 §5）。

## 6. 三权分离引导（ADR-012 落地）

```text
jtdb init --bootstrap-admins
  → 生成三份密封凭据信封（分别用三位责任人的公钥/口令加密）
  → 输出到三个独立介质，任何单一信封无法恢复其他角色
  → 首次登录强制改密
```

- 口令策略：SM3 + 盐 + KDF（KDF 参数随密码专项冻结，docs/12 §4.5）；
- 角色丢失恢复：需其余角色 + Root CA 离线介质配合，全程审计；
- 三权角色一旦启用，`jtdb init` 的默认引导凭据立即失效。

## 7. jt-identity 组件职责

```text
CA 托管代理       Component/User CA 私钥操作（TCM/HSM 内完成签名）
Enrollment 服务   token 校验、CSR 校验、与 jt-attest 协同签发
CRL/OCSP 服务     撤销名单签发与分发
轮换协调          组件证书到期提醒与再认证
```

- 部署形态：单机 profile 下可与 jt-controller 合并进程（ADR-004 边界补充），但 CA 私钥仍须 TCM/HSM 或加密文件 + 分片托管；
- jt-identity 不持有业务数据密钥（与 jt-controller 一致，实现方案 §6.1）。

## 8. 失效与应急

| 场景 | 行为 |
|---|---|
| 节点证书泄露 | 立即撤销 → 传播 ≤5min → 节点换密钥重新 enrollment → 全程审计 |
| Component CA 泄露 | 撤销该 CA → 全部子证书重签（预案演练项） |
| Cluster Root CA 泄露（灾难级） | 全树重签 + 集群凭据轮换，预案在阶段 5 演练 |
| jt-identity/controller 不可用 | 已发证书继续有效（CRL 用最后缓存版本），新 enrollment 阻塞，数据平面不受影响 |
| 时间源异常 | 与 ADR-013 一致：拒绝签发新证书/新租约，存量按最坏情况收紧 |

## 9. 测试标准

- enrollment 攻击面：无 token / 过期 token / 重复 token / 度量不匹配 / 冒名 node_id，全部拒绝并审计；
- 撤销传播时限 ≤5 分钟（含离线 CRL 场景的上限豁免说明）；
- 证书自动轮换业务无中断（轮换窗口压测）；
- Root CA 离线保管与启用演练、CRL 断网传播演练；
- 三权凭据信封：单信封不可恢复他角色、首次改密强制、信封介质丢失恢复流程。

## 10. 待验证问题

1. 与企业既有 PKI/信创 CA 的信任桥接方式（交叉签名 vs 直签 vs 手工信任链）；
2. TEE/CSV/TCM 度量报告格式与 jt-attest 接口的冻结（依赖信创硬件适配进展）；
3. 离线环境下 CRL 推送周期与"撤销传播 ≤5 分钟"SLO 的矛盾取舍；
4. enrollment token 的带外传递形态（管理控制台出示 vs 安装包内置 vs 现场扫码）；
5. 节点私钥在无 TCM/TEE 平台上的保护强度声明（避免过度承诺）。
