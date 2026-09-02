# JTDB 核心接口字段规格

| 项 | 值 |
|---|---|
| 项目代号 | 金湯 JTDB（暂定） |
| 承接文档 | 《实现方案》v0.3 §2.3/§6.3/§7、《架构决策记录》ADR-013/014、《架构评审意见与改进规划》v1.0 |
| 对应文档树 | docs/ 增补（阶段 0 产出） |
| 文档版本 | v0.1 起草稿 |
| 日期 | 2026-09-02 |
| 状态 | 阶段 0 专项；冻结范围 = KMS + Audit 两组接口 |

## 1. 目标与范围

解决评审确认的 P0-4 空洞：实现方案 §2.3 的接口停留在自然语言。本文把**安全关键**的两组接口（jt-kms、jt-audit）降到字段级，作为协议冻结的基础。Controller/Storage 协议在阶段 1 补充为同规格附录。

载体约定：gRPC/protobuf 映射，字段编号即 proto tag；本文表格中的"#"列直接用作字段号。

## 2. 通用信封（所有接口共用）

```proto
message CommonHeader {
  string   request_id      = 1;  // 幂等键，UUIDv7
  string   source_id       = 2;  // 组件身份 jtdb://cluster/component/node
  uint64   policy_version  = 3;
  uint64   key_epoch       = 4;
  bytes    nonce           = 5;  // 16B 随机（docs/12 §4）
  int64    timestamp_us    = 6;  // UTC，可信时间（ADR-013）
  int64    deadline_us     = 7;  // 超时，过期拒绝
  bytes    signature       = 8;  // SM2(请求体 || header 除本字段)
  uint32   protocol_ver    = 9;  // 当前 = 1
}
```

校验顺序：deadline → 签名 → nonce 防重放（滑动窗口）→ source_id 与 mTLS 身份一致 → policy/epoch 匹配。任一失败返回统一错误码（§5）。

## 3. jt-kms 接口

### 3.1 KeyRequest（获取/续租 DEK 租约）

| # | 字段 | 类型 | 必选 | 说明 |
|---|---|---|---|---|
| 1 | scope | KeyScope | 是 | 见 3.2 |
| 2 | purpose | enum | 是 | WAL / LAYER / SNAPSHOT / BACKUP / AUDIT |
| 3 | attestation_digest | bytes(32) | 是 | 最新证明摘要（SM3），KMS 校验新鲜度 |
| 4 | lease_requested_sec | uint32 | 否 | 缺省 900（ADR-013） |
| 5 | grant_ref | string | 否 | 续租时携带原 grant_id |

响应：`grant_id`、`wrapped_dek`（docs/04 §6 格式）、`lease_expires_us`、`epoch`。

### 3.2 KeyScope（ADR-014 作用域）

| # | 字段 | 类型 | 必选 | 说明 |
|---|---|---|---|---|
| 1 | cluster_id | string | 是 | |
| 2 | timeline_id | bytes(16) | 是 | |
| 3 | epoch | uint64 | 是 | |
| 4 | mode | enum | 是 | WRITE / READ |
| 5 | lsn_start / lsn_end | uint64 | READ 时必选 | LSN 范围（含下不含上） |
| 6 | label_digest | bytes(32) | 否 | scope digest 输入（docs/04 §6） |

### 3.3 BranchKeyGrant（分支授权，ADR-014）

| # | 字段 | 类型 | 必选 | 说明 |
|---|---|---|---|---|
| 1 | branch_timeline | bytes(16) | 是 | 新分支 timeline |
| 2 | parent_timeline | bytes(16) | 是 | |
| 3 | up_to_lsn | uint64 | 是 | 分支点 |
| 4 | max_epoch | uint64 | 是 | 允许 unwrap 的父层 epoch 上限 |
| 5 | expires_at_us | int64 | 是 | 授权有效期 |

语义：KMS 收到 branch_timeline 的 KeyRequest(READ, parent 范围) 时，仅当存在覆盖该范围的 BranchKeyGrant 才发 wrapped_dek；父 timeline 轮换出 max_epoch 之后的层，分支天然拿不到。

### 3.4 RotateNotify / Revoke

RotateNotify（KMS → 组件）：`new_epoch`、`drain_deadline_us`、`rekey_scope`。组件收到后进入 ADR-013 状态机对应阶段。
Revoke（KMS → 组件）：`grant_id`、`reason`（COMPROMISE / ATTEST_FAIL / ADMIN）。组件立即停用并刷新上下文（docs/14 §4）。

## 4. jt-audit 接口

### 4.1 AuditEvent（实现方案 §7.2 E0~E3 分级）

| # | 字段 | 类型 | 必选 | 说明 |
|---|---|---|---|---|
| 1 | event_id | bytes(16) | 是 | UUIDv7 |
| 2 | severity | enum | 是 | E0/E1/E2/E3（实现方案 §7.2 表） |
| 3 | source_id | string | 是 | 产生组件 |
| 4 | subject_id | string | 否 | 主体（系统事件可空） |
| 5 | session_id / request_id | string | 否 | 关联链路 |
| 6 | policy_version / key_epoch | uint64 | 否 | |
| 7 | timeline_id / lsn | bytes(16) / uint64 | 否 | 存储侧事件 |
| 8 | action_code | uint32 | 是 | 动作枚举（附录 A 维护） |
| 9 | result | enum | 是 | OK / DENIED / ERROR / ABORTED |
| 10 | detail_digest | bytes(32) | 是 | 摘要的 SM3（不传业务明文，实现方案 §3.3） |
| 11 | event_time_us | int64 | 是 | |
| 12 | journal_seq | uint64 | 是 | 本地 journal 序号（防乱序/断链检测） |
| 13 | prev_hash | bytes(32) | 是 | SM3(event(n) ‖ h(n-1))，实现方案 §7.3 |

### 4.2 IngestBatch / Ack

```proto
message IngestBatch { CommonHeader header=1; repeated AuditEvent events=2; uint64 first_seq=3; uint64 last_seq=4; }
message IngestAck    { CommonHeader header=1; uint64 acked_seq=2; bytes  store_checkpoint=3; }
```

语义：按 `journal_seq` 连续性接收，断链整批拒收（触发源端重传与 E2 审计）；`acked_seq` 之前的事件源端才可淘汰本地 journal（实现方案 §7.2）；E3 事件另走 write-ahead journal 路径，不依赖本接口的可用性。

### 4.3 Checkpoint（锚点）

`segment_id`、`first_seq/last_seq/count`、`head_hash`、`tsa_token`；由 jt-audit-store 定期生成并 SM2 签名（实现方案 §7.3）。

## 5. 错误码（通用）

| 码 | 名称 | 场景 |
|---|---|---|
| 1 | DEADLINE_EXPIRED | header 超时 |
| 2 | BAD_SIGNATURE | 签名/身份不符 |
| 3 | REPLAYED | nonce 重复 |
| 4 | POLICY_STALE | policy_version 低于当前 |
| 5 | EPOCH_MISMATCH | key_epoch 不匹配 |
| 6 | ATTEST_REQUIRED | 证明缺失/过期 |
| 7 | SCOPE_DENIED | 越出 KeyScope / 无 BranchKeyGrant |
| 8 | LEASE_EXPIRED | 租约过期（触发 ADR-013 降级矩阵） |
| 9 | SEQUENCE_BREAK | journal_seq 断链 |
| 10 | UNAVAILABLE | 依赖不可用（调用方按失效矩阵降级） |

## 6. 版本化与演进

- `protocol_ver` 向后兼容一版；字段只增不改语义；
- 枚举（purpose/mode/severity/action_code）集中登记，新增走评审；
- 本规格冻结后，proto 文件入库 `libs/jt-storage-protocol/`（实现方案 §1.2），以 IDL 为唯一事实源，本文为评审视图。

## 7. 待验证问题

1. action_code 枚举全集（对齐等保测评事件清单）在阶段 2 冻结；
2. gRPC over TLCP 的成熟度（Tongsuo 后端）vs 自定义帧 + TLCP 的取舍；
3. IngestBatch 批量上限与 E1 批量 fsync 节奏的参数化；
4. Checkpoint 的 TSA 离线模式（无外网时本地 TSA 组件，docs/13 §9）。
