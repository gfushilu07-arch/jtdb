//! jt-kms 接口（docs/15 §3）：KeyRequest / KeyScope / BranchKeyGrant /
//! RotateNotify / Revoke。

use crate::encode::{encode_opt_digest, encode_opt_str, encode_opt_u64, encode_str, Canonical, Digest, TimelineId};
use crate::error::ProtoError;

/// 密钥用途（docs/15 §3.1 tag 2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyPurpose {
    Wal = 1,
    Layer = 2,
    Snapshot = 3,
    Backup = 4,
    Audit = 5,
}

impl KeyPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wal => "WAL",
            Self::Layer => "LAYER",
            Self::Snapshot => "SNAPSHOT",
            Self::Backup => "BACKUP",
            Self::Audit => "AUDIT",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Wal,
            2 => Self::Layer,
            3 => Self::Snapshot,
            4 => Self::Backup,
            5 => Self::Audit,
            _ => return None,
        })
    }
}

/// 密钥作用域模式（docs/15 §3.2 tag 4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyMode {
    Write = 1,
    Read = 2,
}

impl KeyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Write => "WRITE",
            Self::Read => "READ",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Write,
            2 => Self::Read,
            _ => return None,
        })
    }
}

/// 密钥作用域（docs/15 §3.2；ADR-014）。
///
/// **安全语义**：`mode` 与 `lsn` 范围共同界定"这把密钥允许解哪些层"。
/// WRITE 不得携带 LSN 范围（写作用域是整条 timeline 的当前代）；
/// READ 必须携带范围，否则等于无界读取权限——[`Self::validate`] 强制。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyScope {
    /// tag 1：集群标识。
    pub cluster_id: String,
    /// tag 2：timeline。
    pub timeline_id: TimelineId,
    /// tag 3：epoch。
    pub epoch: u64,
    /// tag 4：模式。
    pub mode: KeyMode,
    /// tag 5：LSN 范围起点（含）；READ 时必选。
    pub lsn_start: Option<u64>,
    /// tag 5：LSN 范围终点（不含）；READ 时必选。
    pub lsn_end: Option<u64>,
    /// tag 6：scope digest 输入（docs/04 §6）。
    pub label_digest: Option<Digest>,
}

impl KeyScope {
    /// 结构合法性（docs/15 §3.2 必选约束）。
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.cluster_id.is_empty() {
            return Err(ProtoError::BadField {
                field: "cluster_id",
                detail: "must not be empty".into(),
            });
        }
        match self.mode {
            KeyMode::Read => {
                let (s, e) = match (self.lsn_start, self.lsn_end) {
                    (Some(s), Some(e)) => (s, e),
                    _ => {
                        return Err(ProtoError::BadField {
                            field: "lsn_start/lsn_end",
                            detail: "READ scope requires an LSN range".into(),
                        })
                    }
                };
                if s >= e {
                    return Err(ProtoError::BadField {
                        field: "lsn_start/lsn_end",
                        detail: format!("range must be non-empty (got {s:#x}..{e:#x})"),
                    });
                }
            }
            KeyMode::Write => {
                if self.lsn_start.is_some() || self.lsn_end.is_some() {
                    return Err(ProtoError::BadField {
                        field: "lsn_start/lsn_end",
                        detail: "WRITE scope must not carry an LSN range".into(),
                    });
                }
            }
        }
        Ok(())
    }

    /// 该作用域是否覆盖给定 LSN 范围（授权判定的核心）。
    ///
    /// 用于 BranchKeyGrant 检查：分支请求父 timeline 的 READ 范围，仅当
    /// 存在覆盖该范围的授权才发放密钥。
    pub fn covers(&self, start: u64, end: u64) -> bool {
        match (self.lsn_start, self.lsn_end) {
            (Some(s), Some(e)) => s <= start && end <= e,
            // 无范围的 WRITE 作用域不构成"覆盖某段历史"的授权
            _ => false,
        }
    }

    pub fn to_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_str(&mut out, &self.cluster_id);
        self.timeline_id.encode(&mut out);
        self.epoch.encode(&mut out);
        (self.mode as u8).encode(&mut out);
        encode_opt_u64(&mut out, &self.lsn_start);
        encode_opt_u64(&mut out, &self.lsn_end);
        encode_opt_digest(&mut out, &self.label_digest);
        out
    }
}

/// KeyRequest（docs/15 §3.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequest {
    /// tag 1。
    pub scope: KeyScope,
    /// tag 2。
    pub purpose: KeyPurpose,
    /// tag 3：最新证明摘要（SM3，32B）——KMS 校验新鲜度。
    pub attestation_digest: Digest,
    /// tag 4：请求租约时长（秒）；缺省 900（ADR-013）。
    pub lease_requested_sec: Option<u32>,
    /// tag 5：续租时携带原 grant_id。
    pub grant_ref: Option<String>,
}

/// ADR-013 默认租约时长（秒）。
pub const DEFAULT_LEASE_SEC: u32 = 900;

impl KeyRequest {
    /// 生效的租约时长（缺省 900，上限 900——docs/15 §3.1 与 ADR-013 一致：
    /// 请求方不得自行延长租约，否则租约新鲜度承诺失效）。
    pub fn effective_lease_sec(&self) -> Result<u32, ProtoError> {
        match self.lease_requested_sec {
            None => Ok(DEFAULT_LEASE_SEC),
            Some(0) => Err(ProtoError::BadField {
                field: "lease_requested_sec",
                detail: "must not be 0".into(),
            }),
            Some(v) if v > DEFAULT_LEASE_SEC => Err(ProtoError::BadField {
                field: "lease_requested_sec",
                detail: format!("must not exceed {DEFAULT_LEASE_SEC} (ADR-013)"),
            }),
            Some(v) => Ok(v),
        }
    }

    pub fn validate(&self) -> Result<(), ProtoError> {
        self.scope.validate()?;
        self.effective_lease_sec()?;
        if let Some(g) = &self.grant_ref {
            if g.is_empty() {
                return Err(ProtoError::BadField {
                    field: "grant_ref",
                    detail: "must not be empty when present".into(),
                });
            }
        }
        Ok(())
    }

    pub fn to_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.scope.to_canonical());
        (self.purpose as u8).encode(&mut out);
        self.attestation_digest.encode(&mut out);
        encode_opt_u64(&mut out, &self.lease_requested_sec.map(u64::from));
        encode_opt_str(&mut out, &self.grant_ref);
        out
    }
}

/// BranchKeyGrant（docs/15 §3.3；ADR-014）。
///
/// **语义**：KMS 收到 branch_timeline 的 `KeyRequest(READ, parent 范围)` 时，
/// 仅当存在覆盖该范围的 grant 才发 wrapped_dek；父 timeline 轮换出
/// `max_epoch` 之后的层，分支天然拿不到。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchKeyGrant {
    /// tag 1：新分支 timeline。
    pub branch_timeline: TimelineId,
    /// tag 2：父 timeline。
    pub parent_timeline: TimelineId,
    /// tag 3：分支点。
    pub up_to_lsn: u64,
    /// tag 4：允许 unwrap 的父层 epoch 上限。
    pub max_epoch: u64,
    /// tag 5：授权有效期（微秒）。
    pub expires_at_us: i64,
}

impl BranchKeyGrant {
    /// 该授权是否允许在 `now_us` 时刻、为 `requested_scope` 发放密钥。
    ///
    /// 三条必须同时满足（docs/15 §3.3 语义）：
    /// 1. 请求 scope 的 timeline 必须是本授权的分支 timeline——否则任何
    ///    父 timeline 的授权都能被拿去读别人的层；
    /// 2. 请求 epoch 不得超过 `max_epoch`——这是轮换切断分支读取的机制；
    /// 3. 请求的 LSN 范围必须落在 `up_to_lsn` 之内——分支点之后的数据
    ///    不属于分支。
    pub fn authorizes(
        &self,
        requested_scope: &KeyScope,
        now_us: i64,
    ) -> Result<(), ProtoError> {
        if now_us > self.expires_at_us {
            return Err(ProtoError::Remote(
                crate::ErrorCode::LeaseExpired,
                "branch grant expired".into(),
            ));
        }
        if requested_scope.timeline_id != self.branch_timeline {
            return Err(ProtoError::Remote(
                crate::ErrorCode::ScopeDenied,
                "scope timeline is not the granted branch".into(),
            ));
        }
        if requested_scope.epoch > self.max_epoch {
            return Err(ProtoError::Remote(
                crate::ErrorCode::ScopeDenied,
                format!(
                    "requested epoch {} exceeds granted max_epoch {}",
                    requested_scope.epoch, self.max_epoch
                ),
            ));
        }
        let e = match (requested_scope.lsn_start, requested_scope.lsn_end) {
            (Some(_s), Some(e)) => e,
            _ => {
                return Err(ProtoError::Remote(
                    crate::ErrorCode::ScopeDenied,
                    "branch read requires an explicit LSN range".into(),
                ))
            }
        };
        if e > self.up_to_lsn {
            return Err(ProtoError::Remote(
                crate::ErrorCode::ScopeDenied,
                format!(
                    "requested LSN range end {e:#x} exceeds branch point {:#x}",
                    self.up_to_lsn
                ),
            ));
        }
        Ok(())
    }
}

/// RotateNotify（KMS → 组件；docs/15 §3.4）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateNotify {
    /// 新 epoch。
    pub new_epoch: u64,
    /// 排水截止时刻（微秒）。
    pub drain_deadline_us: i64,
    /// 重加密范围描述。
    pub rekey_scope: String,
}

/// 撤销原因（docs/15 §3.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RevokeReason {
    Compromise = 1,
    AttestFail = 2,
    Admin = 3,
}

impl RevokeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compromise => "COMPROMISE",
            Self::AttestFail => "ATTEST_FAIL",
            Self::Admin => "ADMIN",
        }
    }
}

/// Revoke（KMS → 组件；docs/15 §3.4）。
///
/// 组件收到后必须立即停用并刷新上下文（docs/14 §4）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoke {
    pub grant_id: String,
    pub reason: RevokeReason,
}

impl Revoke {
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.grant_id.is_empty() {
            return Err(ProtoError::BadField {
                field: "grant_id",
                detail: "must not be empty".into(),
            });
        }
        Ok(())
    }
}

/// KeyRequest 的响应（docs/15 §3.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyGrant {
    pub grant_id: String,
    /// wrapped_dek（docs/04 §6 格式）。
    pub wrapped_dek: Vec<u8>,
    /// 租约到期时刻（微秒）。
    pub lease_expires_us: i64,
    pub epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_read(start: u64, end: u64) -> KeyScope {
        KeyScope {
            cluster_id: "cluster-a".into(),
            timeline_id: TimelineId([1u8; 16]),
            epoch: 3,
            mode: KeyMode::Read,
            lsn_start: Some(start),
            lsn_end: Some(end),
            label_digest: None,
        }
    }

    #[test]
    fn read_scope_requires_lsn_range() {
        let mut s = scope_read(0, 0x1000);
        s.lsn_start = None;
        assert!(s.validate().is_err(), "READ 无范围 = 无界读取，必须拒绝");
        s.lsn_start = Some(0x1000);
        s.lsn_end = Some(0x1000);
        assert!(s.validate().is_err(), "空范围必须拒绝");
        s.lsn_end = Some(0x1000 - 1);
        assert!(s.validate().is_err(), "逆序范围必须拒绝");
    }

    #[test]
    fn write_scope_must_not_carry_range() {
        let s = KeyScope {
            cluster_id: "c".into(),
            timeline_id: TimelineId([1u8; 16]),
            epoch: 1,
            mode: KeyMode::Write,
            lsn_start: Some(0),
            lsn_end: Some(100),
            label_digest: None,
        };
        assert!(s.validate().is_err(), "WRITE 携带 LSN 范围必须拒绝");
    }

    #[test]
    fn covers_is_inclusive_of_bounds() {
        let s = scope_read(0x1000, 0x2000);
        assert!(s.covers(0x1000, 0x2000), "边界相等算覆盖");
        assert!(s.covers(0x1800, 0x1900));
        assert!(!s.covers(0x0FFF, 0x2000), "起点越界");
        assert!(!s.covers(0x1000, 0x2001), "终点越界");
    }

    #[test]
    fn write_scope_covers_nothing() {
        let s = KeyScope {
            cluster_id: "c".into(),
            timeline_id: TimelineId([1u8; 16]),
            epoch: 1,
            mode: KeyMode::Write,
            lsn_start: None,
            lsn_end: None,
            label_digest: None,
        };
        assert!(!s.covers(0, 100), "无范围的 WRITE 不构成历史读取授权");
    }

    #[test]
    fn lease_duration_capped_at_default() {
        let mk = |v: Option<u32>| KeyRequest {
            scope: scope_read(0, 0x100),
            purpose: KeyPurpose::Layer,
            attestation_digest: Digest([0u8; 32]),
            lease_requested_sec: v,
            grant_ref: None,
        };
        assert_eq!(mk(None).effective_lease_sec().unwrap(), DEFAULT_LEASE_SEC);
        assert_eq!(mk(Some(60)).effective_lease_sec().unwrap(), 60);
        assert!(
            mk(Some(DEFAULT_LEASE_SEC + 1)).effective_lease_sec().is_err(),
            "请求方不得自行延长租约（新鲜度承诺会失效）"
        );
        assert!(mk(Some(0)).effective_lease_sec().is_err());
    }

    #[test]
    fn branch_grant_happy_path() {
        let g = BranchKeyGrant {
            branch_timeline: TimelineId([2u8; 16]),
            parent_timeline: TimelineId([1u8; 16]),
            up_to_lsn: 0x5000,
            max_epoch: 4,
            expires_at_us: 2_000_000,
        };
        let mut s = scope_read(0x1000, 0x4000);
        s.timeline_id = TimelineId([2u8; 16]);
        s.epoch = 3;
        assert!(g.authorizes(&s, 1_000_000).is_ok());
    }

    #[test]
    fn branch_grant_rejects_wrong_timeline() {
        let g = BranchKeyGrant {
            branch_timeline: TimelineId([2u8; 16]),
            parent_timeline: TimelineId([1u8; 16]),
            up_to_lsn: 0x5000,
            max_epoch: 4,
            expires_at_us: 2_000_000,
        };
        // 用父 timeline 的 scope 请求 → 拒绝（否则任何分支授权可读别人）
        let s = scope_read(0x1000, 0x4000);
        let err = g.authorizes(&s, 1_000_000).unwrap_err();
        assert_eq!(err.code(), Some(crate::ErrorCode::ScopeDenied));
    }

    #[test]
    fn branch_grant_rejects_epoch_above_max() {
        // 轮换切断分支读取的机制：父 timeline 轮换出 max_epoch 后的层
        let g = BranchKeyGrant {
            branch_timeline: TimelineId([2u8; 16]),
            parent_timeline: TimelineId([1u8; 16]),
            up_to_lsn: 0x5000,
            max_epoch: 4,
            expires_at_us: 2_000_000,
        };
        let mut s = scope_read(0x1000, 0x4000);
        s.timeline_id = TimelineId([2u8; 16]);
        s.epoch = 5;
        assert_eq!(
            g.authorizes(&s, 1_000_000).unwrap_err().code(),
            Some(crate::ErrorCode::ScopeDenied)
        );
    }

    #[test]
    fn branch_grant_rejects_lsn_beyond_branch_point() {
        let g = BranchKeyGrant {
            branch_timeline: TimelineId([2u8; 16]),
            parent_timeline: TimelineId([1u8; 16]),
            up_to_lsn: 0x5000,
            max_epoch: 4,
            expires_at_us: 2_000_000,
        };
        let mut s = scope_read(0x1000, 0x6000); // 越过分支点
        s.timeline_id = TimelineId([2u8; 16]);
        assert_eq!(
            g.authorizes(&s, 1_000_000).unwrap_err().code(),
            Some(crate::ErrorCode::ScopeDenied)
        );
    }

    #[test]
    fn branch_grant_expires() {
        let g = BranchKeyGrant {
            branch_timeline: TimelineId([2u8; 16]),
            parent_timeline: TimelineId([1u8; 16]),
            up_to_lsn: 0x5000,
            max_epoch: 4,
            expires_at_us: 2_000_000,
        };
        let mut s = scope_read(0x1000, 0x4000);
        s.timeline_id = TimelineId([2u8; 16]);
        assert_eq!(
            g.authorizes(&s, 3_000_000).unwrap_err().code(),
            Some(crate::ErrorCode::LeaseExpired)
        );
    }

    #[test]
    fn branch_grant_requires_explicit_range() {
        let g = BranchKeyGrant {
            branch_timeline: TimelineId([2u8; 16]),
            parent_timeline: TimelineId([1u8; 16]),
            up_to_lsn: 0x5000,
            max_epoch: 4,
            expires_at_us: 2_000_000,
        };
        let s = KeyScope {
            cluster_id: "c".into(),
            timeline_id: TimelineId([2u8; 16]),
            epoch: 3,
            mode: KeyMode::Write, // 无范围
            lsn_start: None,
            lsn_end: None,
            label_digest: None,
        };
        assert_eq!(
            g.authorizes(&s, 1_000_000).unwrap_err().code(),
            Some(crate::ErrorCode::ScopeDenied)
        );
    }

    #[test]
    fn revoke_requires_grant_id() {
        assert!(Revoke {
            grant_id: String::new(),
            reason: RevokeReason::Compromise
        }
        .validate()
        .is_err());
        assert!(Revoke {
            grant_id: "g-1".into(),
            reason: RevokeReason::Admin
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn purpose_and_mode_values_frozen() {
        assert_eq!(KeyPurpose::Wal as u8, 1);
        assert_eq!(KeyPurpose::Layer as u8, 2);
        assert_eq!(KeyPurpose::Snapshot as u8, 3);
        assert_eq!(KeyPurpose::Backup as u8, 4);
        assert_eq!(KeyPurpose::Audit as u8, 5);
        assert_eq!(KeyMode::Write as u8, 1);
        assert_eq!(KeyMode::Read as u8, 2);
        assert_eq!(RevokeReason::Compromise as u8, 1);
        assert_eq!(RevokeReason::AttestFail as u8, 2);
        assert_eq!(RevokeReason::Admin as u8, 3);
    }
}
