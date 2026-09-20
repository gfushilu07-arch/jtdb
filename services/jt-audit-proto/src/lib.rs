//! JTDB 审计事件协议（jt-audit-proto，docs/02 §7）。
//!
//! 职责：定义审计事件格式、分级语义、hash 链完整性、本地 journal
//! 与交付确认协议。供所有组件（Compute/Gateway/KMS/PDP/Safekeeper）
//! 统一引用，确保审计事件跨组件一致。
//!
//! 事件分级（docs/02 §7.2）：
//! * E3 关键 — 审计先于生效（write-ahead audit），中断阻断（fail-closed）
//! * E2 高价值 — 事务提交时同步写，中断阻断对应操作
//! * E1 常规 — 批量 fsync 后异步上送，中断排队
//! * E0 可丢弃 — 异步，可降级丢弃
//!
//! 防篡改：h(n) = SM3(event(n) || h(n-1))。
//! 交付确认：E3/E2 需收到 delivery ack 后才从本地 journal 淘汰。

pub mod event;
pub mod journal;
pub mod ack;

pub use ack::{DeliveryAck, DeliveryStatus};
pub use event::{AuditAction, AuditEvent, AuditLevel, AuditOutcome};
pub use journal::{JournalError, JournalEntry, JournalStats, WriteAheadAuditJournal};

#[cfg(test)]
mod tests;
