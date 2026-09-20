//! JTDB 策略决策点（jt-pdp，docs/02 §6.2）。
//!
//! 设计要点（docs/02 §6.2）：
//! * **Cedar 风格策略**：主体（principal）/ 动作（action）/ 资源（resource）/
//!   上下文（context）四元组 + permit/forbid 规则；
//! * **JTDB MLS 集成**：Level/Categories 支配关系与标签传播参与决策；
//! * **Policy Compiler**：把策略编译为可下发的快照（Compute 安全策略 /
//!   Gateway 粗粒度规则 / 管理策略三类）；
//! * **Policy Lease**：策略快照带版本 + 有效期；**PDP 不在每条 SQL 的关键
//!   路径上远程同步决策**——Compute 使用有租约的快照本地决策，关键变更
//!   通过撤销（revocation）+ 租约失效生效。
//!
//! 本模块是纯逻辑层（可测试）；HTTP 服务面与 Cedar 完整语法解析为后续。

pub mod policy;
pub mod snapshot;

pub use policy::{
    Decision, Effect, JtLabel, PolicyError, PolicyRequest, PolicySet, PolicyVersion,
};
pub use snapshot::{PolicyLease, PolicySnapshot, SnapshotError, SnapshotManager};
