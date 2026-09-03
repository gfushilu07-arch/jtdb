# JTDB 连接与会话治理设计

| 项 | 值 |
|---|---|
| 项目代号 | 金湯 JTDB（暂定） |
| 承接文档 | 《三平面零信任架构》v0.4、《实现方案》v0.3、《架构评审意见与改进规划》v1.0 |
| 对应文档树 | docs/14（规划文档 §7.2） |
| 文档版本 | v0.1 起草稿 |
| 日期 | 2026-09-02 |
| 状态 | 阶段 0 起草，接入平面工作域落地 |
| 承接项 | 规划文档 §3"内建连接池"、"单机 profile 化"（网关侧） |

## 1. 目标与范围

解决两个问题：

1. **中小企业不装 pgbouncer**：jt-gateway 内建连接池，池化能力是产品的一部分而非外挂；
2. **池化与安全上下文的冲突**：连接复用不得导致会话状态、权限、安全上下文跨主体泄漏——这是池化在安全数据库里的第一设计约束。

范围：jt-gateway 的连接与池化管理、会话状态复位、安全上下文随池化的传递与失效、连接治理（限额/队列/取消/速率）。

不含：TLCP 握手细节（实现方案 §5.4）、SQL 防火墙规则语义（实现方案 §5.3）、Compute 内核上下文结构（实现方案 §3.1）、KMS 租约（ADR-013）。

## 2. 总体模型

```text
客户端 ──TLCP── jt-gateway [认证 / 防火墙 / 池化] ──内部认证── jtdb-compute
```

两种池化模式：

| 模式 | 行为 | 适用 |
|---|---|---|
| 会话级（默认） | 客户端会话独占后端连接直至断开 | 中小企业默认；无状态泄漏面 |
| 事务级多路复用（opt-in） | 事务结束后后端连接归还池，按规则复用 | 少数应用账号承载大量连接的场景 |

### 2.1 主体亲和（subject affinity）——安全设计核心

事务级模式下，**后端连接只允许复用给相同 subject_id（及安全标签档位）的客户端会话**。

- 安全收益：即使复位逻辑存在缺陷，跨主体的权限、标签、GUC、临时对象泄漏在物理上不可能——复位从"唯一防线"降级为"第二道防线"；
- 代价：多主体场景复用率下降。中小企业典型形态是应用以少数服务账号连接，主体亲和恰好是效率与安全的合理平衡点；
- 普通用户禁止 `SET SESSION AUTHORIZATION` / `SET ROLE` 越出映射范围（与 ADR-012 围栏一致），保证亲和键不被会话内篡改。

## 3. 会话状态复位（DISCARD ALL 语义）

连接归还池之前必须复位。**复位走协议级/内核级路径（Compute 内部复位例程），禁止通过网关转发一段 `DISCARD ALL` SQL 文本实现**——文本可被客户端注入干扰，也无法覆盖内核态状态。

复位清单：

```text
GUC：                SET / SET LOCAL 全部恢复默认
prepared statements：具名 statement 全部 DEALLOCATE
cursors：            CLOSE ALL；WITH HOLD cursor 归还时强制关闭并审计
temp tables：        会话内创建的临时表删除（可配置为 pin）
advisory locks：     session 级全部释放
LISTEN/NOTIFY：      UNLISTEN *
异步缓冲：           清空未消费的协议消息
```

### 3.1 Pin 条件（存在以下状态则连接保持绑定，不归还）

- 持有 session 级 advisory lock；
- LISTEN 生效；
- WITH HOLD cursor 打开；
- 创建了 temp table（可配置：复位删除 vs pin）；
- SET 了非默认 GUC 且未复位（可配置）。

设计原则：**宁可 pin 降低池化率，不可复位出错**。pin 决策与原因记录进指标（§6）。

## 4. 安全上下文随池化的传递与失效

- 认证发生在网关，Compute 内核验证并绑定上下文（实现方案 §3.1/§5.2）。事务级模式下，上下文材料**按事务随连接传递**（绑定到事务，而非物理连接）；
- 主体亲和保证同一物理连接不出现不同 subject_id；上下文材料含 nonce 且单次有效，池与连接上不留存可独立通过认证的凭据；
- **policy_version / key_epoch 失效传播**：池中空闲连接收到策略撤销或 epoch 轮换通知后标记 stale，归还时强制重建（重新走上下文绑定），必要时直接关闭；活跃连接按租约与撤销语义处理（ADR-013 失效矩阵）；
- 复位与重建事件全部进审计（事件含原因：policy 撤销 / epoch 轮换 / pin 违例 / 常规归还）。

## 5. 连接治理

```text
限额：    per-cluster / per-database / per-subject / per-source-IP 四级上限 + 队列上限
超限：    排队（公平调度 + 排队超时）或快速失败，按配置
速率：    实现方案 §5.3 会话速率限制在此生效
生命周期：客户端空闲超时 / 后端空闲超时 / 最大连接时长 / TLCP 会话重议价
取消：    pg cancel（PID + secret key）由网关映射；禁止取消他人会话的查询；
          主体亲和下取消目标必须属于本客户端会话的连接映射
协议：    COPY 双向流、extended protocol pipeline 在事务边界作为复用切换点；
          pipeline 中间不得归还连接（以 Sync 划界）
```

## 6. 可观测性

```text
池指标：  in_pool / active / pinned（按 pin 原因分桶）/ waiting / queue_time_p99
安全指标：复位次数、stale 淘汰数、策略/epoch 触发的连接重建数
关联：    pool_connection_id 进入 request_id 诊断链路（架构文档 §6.5）
CLI：     jtdb pool status（人类可读 + JSON，实现方案 §8.1）
```

## 7. 与 Neon proxy 的关系

复用 Neon proxy 的连接管理与路由基础（实现方案 §1.2 `proxy/` 目录），在其上增量实现：主体亲和、内核级状态复位、安全上下文传递、TLCP 接入。上游同步时，连接管理层的补丁冲突面收敛在此目录（规划文档 §3"上游锁定与补丁治理"）。

## 8. 测试标准

泄漏矩阵（事务级模式必须全绿）：

| 用例 | 通过标准 |
|---|---|
| GUC 泄漏 | A 会话 SET 后归还，同主体 B 会话复用读到默认值 |
| prepared statement 污染 | B 会话不可见 A 的具名 statement |
| temp table 冲突 | 归还后同名 temp table 不可见/已删除 |
| advisory lock | 无泄漏、无自锁；持锁连接被 pin 不归还 |
| LISTEN 泄漏 | B 收不到 A 的订阅通知 |
| WITH HOLD cursor | 归还时强制关闭并有审计事件 |
| 跨主体隔离 | 不同 subject_id 永不复用同一后端连接（物理验证） |
| cancel 越权 | 无法取消他人会话的查询 |
| 失效传播 | 策略撤销 / epoch 轮换后池内连接重建时效符合 SLO |

性能：开启事务级池化后，网关透传 P99 增幅仍 ≤1ms（规划文档 §5 SLO）。

## 9. 待验证问题

1. 主体亲和粒度（subject_id vs subject+标签档位）对复用率的量化影响，需基准数据支撑默认值；
2. temp table 复位删除 vs pin 的默认取舍（性能 vs 兼容性）；
3. Neon proxy 可直接复用的子系统范围与需重写的边界；
4. TLCP session resumption 与池化叠加的实际收益；
5. extended protocol pipeline 高并发下以 Sync 划界的复用切换是否引入可观测延迟。
