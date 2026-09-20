//! 交付确认协议（jt-audit-ingest → 组件）。

use crate::event::AuditLevel;
use serde::{Deserialize, Serialize};

/// 交付确认。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAck {
    /// 确认的 journal seq。
    pub seq: u64,
    /// 交付状态。
    pub status: DeliveryStatus,
    /// jt-audit-ingest 接收时间戳。
    pub ack_ts_ms: u64,
    /// 摘要（jt-audit-ingest 侧计算的 hash，供端到端校验）。
    pub digest: String,
}

/// 交付状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// 已接收（写入 jt-audit-store）。
    Received,
    /// 已锚定（TSA/WORM 见证完成）。
    Anchored,
    /// 已持久化（WORM 落盘完成）。
    Persisted,
    /// 交付失败（需要重试）。
    Failed(String),
}

/// 批量交付确认。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDeliveryAck {
    pub acks: Vec<DeliveryAck>,
    /// 批次 ID。
    pub batch_id: String,
}
