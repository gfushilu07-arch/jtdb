//! JTDB TSA 时间戳锚定服务（jt-tsa，docs/02 §7.3、docs/12 §2）。
//!
//! 职责：为审计 checkpoint 提供**可信时间锚定**——用 SM2 签名把
//! "某段审计在某个时刻已存在"这一事实绑定，使事后篡改/重建在时间维度
//! 可检出（配合 WORM/远程见证）。
//!
//! 锚定对象：jt-audit-store 的 `Checkpoint`（含 segment_id/first_seq/
//! last_seq/count/head_hash）。TSA 对 checkpoint 的**规范编码**加时间戳后
//! 签名，产出 TimestampToken。
//!
//! 锚定周期与租约周期对齐（docs/00 §（4）：TSA 锚定周期与租约周期对齐）。
//! 可信时间来源：`TimeSource`（生产 = NTS/认证 NTP + RTC 跳变检测，
//! 复用 jt-key-epoch 的 MonotonicTimeSource 语义）。

pub mod token;

pub use token::{TimestampError, TimestampToken, Tsa};

/// 默认锚定周期（秒）——与 jt-kms 租约默认 15 分钟对齐（docs/00 §（4））。
pub const DEFAULT_ANCHOR_PERIOD_SECS: u64 = 900;
