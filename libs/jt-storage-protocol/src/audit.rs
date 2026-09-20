//! jt-audit 接口（docs/15 §4）：AuditEvent / IngestBatch / IngestAck /
//! Checkpoint。
//!
//! 与 `services/jt-audit-proto` 的关系：该 crate 是**实现侧**（本地 journal
//! 与 ack 状态机），本模块是**线上协议侧**（字段号、规范编码、批量连续性
//! 校验）。两者字段语义一致，本模块补的是跨进程/跨语言的字节级约定。

use crate::encode::{encode_bytes, encode_fixed, encode_opt_str, encode_opt_u64, Canonical, Digest, TimelineId};
use crate::error::{ErrorCode, ProtoError};

/// 审计等级（docs/15 §4.1 tag 2；与实现侧 AuditLevel 数值一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AuditSeverity {
    E0 = 0,
    E1 = 1,
    E2 = 2,
    E3 = 3,
}

impl AuditSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::E0 => "E0",
            Self::E1 => "E1",
            Self::E2 => "E2",
            Self::E3 => "E3",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::E0,
            1 => Self::E1,
            2 => Self::E2,
            3 => Self::E3,
            _ => return None,
        })
    }
}

/// 审计结果（docs/15 §4.1 tag 9）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuditResult {
    Ok = 1,
    Denied = 2,
    Error = 3,
    Aborted = 4,
}

impl AuditResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Denied => "DENIED",
            Self::Error => "ERROR",
            Self::Aborted => "ABORTED",
        }
    }
}

/// 审计事件（docs/15 §4.1）。字段号即 proto tag。
///
/// **不传业务明文**：`detail_digest` 是摘要（docs/02 §3.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// tag 1：UUIDv7（16B）。
    pub event_id: [u8; 16],
    /// tag 2。
    pub severity: AuditSeverity,
    /// tag 3：产生组件。
    pub source_id: String,
    /// tag 4：主体（系统事件可空）。
    pub subject_id: Option<String>,
    /// tag 5。
    pub session_id: Option<String>,
    /// tag 5。
    pub request_id: Option<String>,
    /// tag 6。
    pub policy_version: Option<u64>,
    /// tag 6。
    pub key_epoch: Option<u64>,
    /// tag 7。
    pub timeline_id: Option<TimelineId>,
    /// tag 7。
    pub lsn: Option<u64>,
    /// tag 8：动作枚举（附录 A 维护）。
    pub action_code: u32,
    /// tag 9。
    pub result: AuditResult,
    /// tag 10：detail 的 SM3。
    pub detail_digest: Digest,
    /// tag 11：事件时刻（微秒）。
    pub event_time_us: i64,
    /// tag 12：本地 journal 序号（防乱序/断链检测）。
    pub journal_seq: u64,
    /// tag 13：SM3(event(n) ‖ h(n-1))。
    pub prev_hash: Digest,
}

impl AuditEvent {
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.source_id.is_empty() {
            return Err(ProtoError::BadField {
                field: "source_id",
                detail: "must not be empty".into(),
            });
        }
        if self.event_id == [0u8; 16] {
            return Err(ProtoError::BadField {
                field: "event_id",
                detail: "must not be all-zero".into(),
            });
        }
        if self.journal_seq == 0 {
            return Err(ProtoError::BadField {
                field: "journal_seq",
                detail: "sequence starts at 1".into(),
            });
        }
        // 存储侧事件必须成对给出 timeline 与 lsn（只给一个无法定位）
        if self.timeline_id.is_some() != self.lsn.is_some() {
            return Err(ProtoError::BadField {
                field: "timeline_id/lsn",
                detail: "storage-side events must carry both or neither".into(),
            });
        }
        Ok(())
    }

    pub fn to_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_fixed(&mut out, &self.event_id);
        (self.severity as u8).encode(&mut out);
        crate::encode::encode_str(&mut out, &self.source_id);
        encode_opt_str(&mut out, &self.subject_id);
        encode_opt_str(&mut out, &self.session_id);
        encode_opt_str(&mut out, &self.request_id);
        encode_opt_u64(&mut out, &self.policy_version);
        encode_opt_u64(&mut out, &self.key_epoch);
        match &self.timeline_id {
            Some(t) => {
                out.push(1);
                t.encode(&mut out);
            }
            None => out.push(0),
        }
        encode_opt_u64(&mut out, &self.lsn);
        self.action_code.encode(&mut out);
        (self.result as u8).encode(&mut out);
        self.detail_digest.encode(&mut out);
        self.event_time_us.encode(&mut out);
        self.journal_seq.encode(&mut out);
        self.prev_hash.encode(&mut out);
        out
    }
}

/// IngestBatch（docs/15 §4.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestBatch {
    /// 事件序列。
    pub events: Vec<AuditEvent>,
    /// tag 3。
    pub first_seq: u64,
    /// tag 4。
    pub last_seq: u64,
}

impl IngestBatch {
    /// 批量连续性校验（docs/15 §4.2：**断链整批拒收**，触发源端重传与
    /// E2 审计）。
    ///
    /// 三重要求：`first_seq`/`last_seq` 与实际内容一致、事件序号连续无洞、
    /// 无重复。任一不满足返回 [`ErrorCode::SequenceBreak`]。
    pub fn validate_sequence(&self) -> Result<(), ErrorCode> {
        if self.events.is_empty() {
            return Err(ErrorCode::SequenceBreak);
        }
        let expected_count = self
            .last_seq
            .checked_sub(self.first_seq)
            .and_then(|d| d.checked_add(1));
        match expected_count {
            Some(n) if n == self.events.len() as u64 => {}
            _ => return Err(ErrorCode::SequenceBreak),
        }
        for (i, ev) in self.events.iter().enumerate() {
            let want = self.first_seq + i as u64;
            if ev.journal_seq != want {
                return Err(ErrorCode::SequenceBreak);
            }
        }
        Ok(())
    }

    /// 逐事件结构校验（在连续性之前或之后均可；失败返回首个错误）。
    pub fn validate_events(&self) -> Result<(), ProtoError> {
        for ev in &self.events {
            ev.validate()?;
        }
        Ok(())
    }

    pub fn to_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        (self.events.len() as u32).encode(&mut out);
        for ev in &self.events {
            let b = ev.to_canonical();
            encode_bytes(&mut out, &b);
        }
        self.first_seq.encode(&mut out);
        self.last_seq.encode(&mut out);
        out
    }
}

/// IngestAck（docs/15 §4.2）。
///
/// 语义：`acked_seq` 之前的事件源端才可淘汰本地 journal。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestAck {
    pub acked_seq: u64,
    /// tag 3：store checkpoint（可选）。
    pub store_checkpoint: Option<Vec<u8>>,
}

/// Checkpoint（docs/15 §4.3；锚点）。
///
/// 由 jt-audit-store 定期生成并 SM2 签名；`tsa_token` 为时间戳锚定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub segment_id: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: u64,
    pub head_hash: Digest,
    /// TSA 令牌（可选；无外网时用本地 TSA，docs/13 §9）。
    pub tsa_token: Option<Vec<u8>>,
}

impl Checkpoint {
    /// 待签规范编码：`segment_id ‖ first_seq ‖ last_seq ‖ count ‖ head_hash`
    /// （全大端，与 jt-audit-store 现有实现一致）。
    ///
    /// 签名覆盖段身份 + 边界 + 条数 + 头哈希，使**整段删除/重建可检出**——
    /// hash 链单靠自身无法防整链重建。
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        self.segment_id.encode(&mut msg);
        self.first_seq.encode(&mut msg);
        self.last_seq.encode(&mut msg);
        self.count.encode(&mut msg);
        self.head_hash.encode(&mut msg);
        msg
    }

    /// 结构合法性。
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.last_seq < self.first_seq {
            return Err(ProtoError::BadField {
                field: "first_seq/last_seq",
                detail: "last_seq must not precede first_seq".into(),
            });
        }
        let expected = self.last_seq - self.first_seq + 1;
        if self.count != expected {
            return Err(ProtoError::BadField {
                field: "count",
                detail: format!("count {expected} does not match sequence span"),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64) -> AuditEvent {
        AuditEvent {
            event_id: [seq as u8; 16],
            severity: AuditSeverity::E2,
            source_id: "jtdb://c/compute/n1".into(),
            subject_id: Some("alice".into()),
            session_id: None,
            request_id: None,
            policy_version: Some(7),
            key_epoch: Some(2),
            timeline_id: None,
            lsn: None,
            action_code: 100,
            result: AuditResult::Ok,
            detail_digest: Digest([0x11; 32]),
            event_time_us: 1_700_000_000_000_000,
            journal_seq: seq,
            prev_hash: Digest([0x22; 32]),
        }
    }

    #[test]
    fn event_shape_validation() {
        let mut e = ev(1);
        assert!(e.validate().is_ok());
        e.source_id = String::new();
        assert!(e.validate().is_err(), "source_id 必填");
        let mut e = ev(1);
        e.journal_seq = 0;
        assert!(e.validate().is_err(), "序号从 1 起");
        let mut e = ev(1);
        e.event_id = [0u8; 16];
        assert!(e.validate().is_err(), "全零 event_id 非法");
    }

    #[test]
    fn storage_event_requires_paired_timeline_and_lsn() {
        let mut e = ev(1);
        e.timeline_id = Some(TimelineId([3u8; 16]));
        assert!(e.validate().is_err(), "只给 timeline 不给 lsn 必须拒绝");
        e.lsn = Some(0x1000);
        assert!(e.validate().is_ok());
        // 反过来
        let mut e = ev(1);
        e.lsn = Some(0x1000);
        assert!(e.validate().is_err());
    }

    #[test]
    fn batch_sequence_contiguous_accepted() {
        let b = IngestBatch {
            events: vec![ev(10), ev(11), ev(12)],
            first_seq: 10,
            last_seq: 12,
        };
        assert!(b.validate_sequence().is_ok());
    }

    #[test]
    fn batch_with_hole_rejected() {
        // 断链整批拒收（docs/15 §4.2）
        let b = IngestBatch {
            events: vec![ev(10), ev(12)],
            first_seq: 10,
            last_seq: 12,
        };
        assert_eq!(
            b.validate_sequence().unwrap_err(),
            ErrorCode::SequenceBreak
        );
    }

    #[test]
    fn batch_bounds_mismatch_rejected() {
        let b = IngestBatch {
            events: vec![ev(10), ev(11)],
            first_seq: 10,
            last_seq: 99, // 与内容不符
        };
        assert_eq!(
            b.validate_sequence().unwrap_err(),
            ErrorCode::SequenceBreak
        );
    }

    #[test]
    fn empty_batch_rejected() {
        let b = IngestBatch {
            events: vec![],
            first_seq: 1,
            last_seq: 1,
        };
        assert_eq!(
            b.validate_sequence().unwrap_err(),
            ErrorCode::SequenceBreak
        );
    }

    #[test]
    fn duplicate_seq_rejected() {
        let b = IngestBatch {
            events: vec![ev(10), ev(10)],
            first_seq: 10,
            last_seq: 11,
        };
        assert_eq!(
            b.validate_sequence().unwrap_err(),
            ErrorCode::SequenceBreak
        );
    }

    #[test]
    fn single_event_batch_accepted() {
        let b = IngestBatch {
            events: vec![ev(5)],
            first_seq: 5,
            last_seq: 5,
        };
        assert!(b.validate_sequence().is_ok());
    }

    #[test]
    fn checkpoint_count_must_match_span() {
        let c = Checkpoint {
            segment_id: 1,
            first_seq: 1,
            last_seq: 10,
            count: 10,
            head_hash: Digest([0u8; 32]),
            tsa_token: None,
        };
        assert!(c.validate().is_ok());
        let bad = Checkpoint { count: 9, ..c.clone() };
        assert!(bad.validate().is_err(), "条数与序号跨度不符必须拒绝");
        let bad2 = Checkpoint {
            first_seq: 20,
            last_seq: 10,
            ..c
        };
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn checkpoint_signing_message_covers_segment_identity() {
        // 签名必须覆盖段身份与边界，否则整段重建无法检出。
        let base = Checkpoint {
            segment_id: 1,
            first_seq: 1,
            last_seq: 10,
            count: 10,
            head_hash: Digest([0xAA; 32]),
            tsa_token: None,
        };
        let msg = base.signing_message();
        assert_eq!(msg.len(), 8 * 4 + 32, "4 个 u64 + 32B 头哈希");
        for variant in [
            Checkpoint { segment_id: 2, ..base.clone() },
            Checkpoint { first_seq: 2, ..base.clone() },
            Checkpoint { last_seq: 11, ..base.clone() },
            Checkpoint { count: 11, ..base.clone() },
            Checkpoint { head_hash: Digest([0xBB; 32]), ..base.clone() },
        ] {
            assert_ne!(
                variant.signing_message(),
                msg,
                "任一字段变化都必须改变待签消息"
            );
        }
    }

    #[test]
    fn severity_and_result_values_frozen() {
        assert_eq!(AuditSeverity::E0 as u8, 0);
        assert_eq!(AuditSeverity::E3 as u8, 3);
        assert_eq!(AuditResult::Ok as u8, 1);
        assert_eq!(AuditResult::Denied as u8, 2);
        assert_eq!(AuditResult::Error as u8, 3);
        assert_eq!(AuditResult::Aborted as u8, 4);
    }

    #[test]
    fn canonical_encoding_distinguishes_none_from_empty_string() {
        // None（存在位 0）与 Some("")（存在位 1 + 长度 0）必须可区分，
        // 否则"未提供主体"与"主体为空串"会被签名混同。
        let mut a = ev(1);
        a.subject_id = None;
        let mut b = ev(1);
        b.subject_id = Some(String::new());
        assert_ne!(a.to_canonical(), b.to_canonical());
    }
}
