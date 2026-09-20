//! JTDB 控制平面（jt-controller，docs/02 §6.1）。
//!
//! 职责（docs/02 §6.1）：组件注册、心跳、Compute/Pageserver/Safekeeper
//! 生命周期、Timeline/Branch、**generation**、**配置租约**、备份策略和
//! 安全管理员操作。**不直接持有明文数据密钥**。
//!
//! 接口（docs/02 §2.3）：`Controller ↔ Pageserver/Safekeeper/Compute:
//! register / health / lifecycle / generation / config lease`。
//!
//! generation 语义（Neon 借鉴 + docs/13 §4）：组件注册时获得单调递增的
//! generation；generation 变化 = 前一代失权（防脑裂：旧 generation 的
//! 组件不得再服务）。配置租约：组件持有带 TTL 的配置快照，到期续租，
//! 否则降级。
//!
//! 安全不变量：
//! 1. generation 单调——**含跨 controller 重启**。围栏令牌 write-ahead
//!    落盘（[`fence`]），重启后高水位保留。
//! 2. 下线即吊销——Offline 节点不得靠心跳复活。
//! 3. 控制平面不持有密钥材料——配置租约拒绝密钥类键。

pub mod api;
pub mod fence;
pub mod registry;

pub use fence::{FenceError, FenceRecord, FenceScope, GenerationJournal, JournalState};
pub use registry::{
    ComponentKind, ComponentRecord, ComponentState, ConfigLease, Controller, ControllerError,
    Generation, NodeId, TimelineRecord,
};
