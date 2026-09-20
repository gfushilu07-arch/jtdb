//! 统一错误码（docs/15 §5）。
//!
//! 错误码是**协议的一部分**：调用方按码做降级决策（如 LEASE_EXPIRED 触发
//! ADR-013 失效矩阵、SEQUENCE_BREAK 触发源端重传）。数值冻结，只增不改。

/// 协议错误码（docs/15 §5 表格；数值即协议值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ErrorCode {
    /// header 超时。
    DeadlineExpired = 1,
    /// 签名/身份不符。
    BadSignature = 2,
    /// nonce 重复（重放）。
    Replayed = 3,
    /// policy_version 低于当前。
    PolicyStale = 4,
    /// key_epoch 不匹配。
    EpochMismatch = 5,
    /// 证明缺失/过期。
    AttestRequired = 6,
    /// 越出 KeyScope / 无 BranchKeyGrant。
    ScopeDenied = 7,
    /// 租约过期（触发 ADR-013 降级矩阵）。
    LeaseExpired = 8,
    /// journal_seq 断链。
    SequenceBreak = 9,
    /// 依赖不可用（调用方按失效矩阵降级）。
    Unavailable = 10,
}

impl ErrorCode {
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::DeadlineExpired,
            2 => Self::BadSignature,
            3 => Self::Replayed,
            4 => Self::PolicyStale,
            5 => Self::EpochMismatch,
            6 => Self::AttestRequired,
            7 => Self::ScopeDenied,
            8 => Self::LeaseExpired,
            9 => Self::SequenceBreak,
            10 => Self::Unavailable,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeadlineExpired => "DEADLINE_EXPIRED",
            Self::BadSignature => "BAD_SIGNATURE",
            Self::Replayed => "REPLAYED",
            Self::PolicyStale => "POLICY_STALE",
            Self::EpochMismatch => "EPOCH_MISMATCH",
            Self::AttestRequired => "ATTEST_REQUIRED",
            Self::ScopeDenied => "SCOPE_DENIED",
            Self::LeaseExpired => "LEASE_EXPIRED",
            Self::SequenceBreak => "SEQUENCE_BREAK",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

/// 协议层错误（本地编解码/校验失败；非错误码本身）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtoError {
    /// 字段非法（缺必选、长度错、取值越界）。
    #[error("bad field {field}: {detail}")]
    BadField {
        field: &'static str,
        detail: String,
    },
    /// 对端返回的错误码。
    #[error("remote error {}: {}", .0.as_str(), .1)]
    Remote(ErrorCode, String),
    /// 编码缓冲区耗尽/长度溢出。
    #[error("encode error: {0}")]
    Encode(&'static str),
}

impl ProtoError {
    /// 该错误对应的协议错误码（本地错误映射为 BAD_SIGNATURE 之外的
    /// 语义最近者；调用方通常直接使用 [`ProtoError::Remote`] 携带的码）。
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ProtoError::Remote(c, _) => Some(*c),
            ProtoError::BadField { .. } | ProtoError::Encode(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_roundtrip() {
        for v in 1..=10u32 {
            let c = ErrorCode::from_u32(v).expect("known code");
            assert_eq!(c.as_u32(), v);
        }
        assert_eq!(ErrorCode::from_u32(0), None);
        assert_eq!(ErrorCode::from_u32(11), None);
        assert_eq!(ErrorCode::from_u32(999), None);
    }

    #[test]
    fn code_values_are_frozen() {
        // 数值是协议的一部分：改动会破坏互操作。
        assert_eq!(ErrorCode::DeadlineExpired.as_u32(), 1);
        assert_eq!(ErrorCode::BadSignature.as_u32(), 2);
        assert_eq!(ErrorCode::Replayed.as_u32(), 3);
        assert_eq!(ErrorCode::PolicyStale.as_u32(), 4);
        assert_eq!(ErrorCode::EpochMismatch.as_u32(), 5);
        assert_eq!(ErrorCode::AttestRequired.as_u32(), 6);
        assert_eq!(ErrorCode::ScopeDenied.as_u32(), 7);
        assert_eq!(ErrorCode::LeaseExpired.as_u32(), 8);
        assert_eq!(ErrorCode::SequenceBreak.as_u32(), 9);
        assert_eq!(ErrorCode::Unavailable.as_u32(), 10);
    }
}
