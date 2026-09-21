//! JTDB 密钥轮换与 DEK 供给（jt-key-epoch，ADR-013）。
//!
//! 职责：为组件提供按 (timeline, epoch) 作用域的 DEK 供给接口
//! （[`KeyProvider`]），隔离"密钥从哪来"（KMS 租约/开发模式）与
//! "密钥怎么用"（jt-encrypted-object）。
//!
//! 模块：
//! * [`provider`] —— DEK 供给抽象 + [`DevKeyProvider`]（开发模式，SM3 派生）；
//! * [`rotation`] —— journal 化轮换状态机（Sealed→Prepare→Cutover→Drain→
//!   Rekey→Retire）+ 防回滚计数器（ADR-013 结论第 3/4 条）；
//! * [`lease`] —— KMS 租约与失效矩阵（ADR-013 结论第 1/2/5 条：15 分钟租约、
//!   续租携带新鲜 attestation 摘要、过期拒绝新会话+存量转只读、时间源异常
//!   拒绝签发、审计中断 fail-closed）。
//!
//! * [`kms_provider`] —— **生产 DEK 供给**：租约驱动的缓存 + 后台续租，
//!   `get_dek` 只读缓存（同步、无网络），过期 fail-closed、Retire 转
//!   [`KeyError::UnknownScope`]（加密擦除，ADR-013）。
//!
//! 尚未实现（需真实 KMS 网络与 attestation 硬件）：TCM/TEE attestation
//! 采集（证明摘要由装配层注入 `HttpKmsClient`）、防回滚计数器的 KMS 侧
//! 持久化（本模块提供本地份与校验逻辑）。

pub mod kms_provider;
pub mod lease;
pub mod provider;
pub mod rotation;

pub use lease::{
    Admission, DegradePolicy, ExistingSession, Lease, LeaseError, LeaseManager, LeaseState,
    MonotonicTimeSource, TimeError, TimeSource, DEFAULT_LEASE_DURATION,
};
pub use provider::{DevKeyProvider, DekScope, KeyError, KeyProvider};
pub use rotation::{
    JournalEntry, RotationCoordinator, RotationError, RotationJournal, RotationProgress,
    RotationState,
};
