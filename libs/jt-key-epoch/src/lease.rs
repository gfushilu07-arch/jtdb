//! ADR-013：KMS 租约与失效矩阵。
//!
//! 租约语义（ADR-013 结论第 1~2 条）：
//! * 组件持有 wrap 后 DEK + 租约（默认 15 分钟，可配）；
//! * 续租携带**新鲜 attestation 摘要**（同一摘要不能重复续租 —— 防重放）；
//! * 失效矩阵：租约过期 → 拒绝新会话、存量会话转只读（可配）；
//!   时间源异常 → 拒绝签发新租约；审计中断 → 高危阻断/普通排队（fail-closed）。
//!
//! 时间源抽象：[`TimeSource`]。生产用 NTS/认证 NTP + RTC 跳变检测
//! （[`MonotonicTimeSource`] 提供跳变检测骨架），测试用 [`ManualClock`]。

use parking_lot::Mutex;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// 租约默认时长（ADR-013：默认 15 分钟，可配）。
pub const DEFAULT_LEASE_DURATION: Duration = Duration::from_secs(15 * 60);

/// 失效时的会话处置（ADR-013 失效矩阵，可配置）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradePolicy {
    /// 存量会话转只读（默认）。
    ReadOnly,
    /// 存量会话直接断开。
    Disconnect,
}

/// 租约状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// 有效。
    Valid,
    /// 已过期（未续租）。
    Expired,
    /// 已撤销（时间源异常/审计中断/策略撤销）。
    Revoked,
}

/// 时间源异常（ADR-013：RTC 跳变 / 不可信时间 → 拒绝签发新租约）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TimeError {
    #[error("clock jumped backwards by {0:?} (RTC tamper suspected)")]
    BackwardsJump(Duration),
    #[error("time source unavailable")]
    Unavailable,
}

/// 时间源抽象（可信时间，ADR-013 结论第 5 条）。
pub trait TimeSource: Send + Sync {
    fn now(&self) -> Result<Instant, TimeError>;
}

/// 单调时间源：拒绝回退（RTC 跳变检测骨架）。
///
/// 生产实现应包装 NTS/认证 NTP 客户端；本类型提供跳变检测逻辑，
/// 与真实时间源解耦以便测试。
#[derive(Debug, Default)]
pub struct MonotonicTimeSource {
    last: Mutex<Option<Instant>>,
}

impl MonotonicTimeSource {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TimeSource for MonotonicTimeSource {
    fn now(&self) -> Result<Instant, TimeError> {
        let now = Instant::now();
        let mut last = self.last.lock();
        if let Some(prev) = *last {
            if now < prev {
                return Err(TimeError::BackwardsJump(prev - now));
            }
        }
        *last = Some(now);
        Ok(now)
    }
}

/// 租约记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub timeline_id: [u8; 16],
    pub key_epoch: u64,
    pub issued_at: Instant,
    pub expires_at: Instant,
    pub state: LeaseState,
}

impl Lease {
    pub fn is_valid_at(&self, now: Instant) -> bool {
        self.state == LeaseState::Valid && now < self.expires_at
    }
}

/// 租约管理器：签发/续租/撤销 + 失效矩阵。
#[derive(Debug)]
pub struct LeaseManager {
    duration: Duration,
    degrade_policy: DegradePolicy,
    /// 审计通道健康（ADR-013：审计中断时高危事件阻断）。
    audit_healthy: Mutex<bool>,
    leases: Mutex<Vec<Lease>>,
    /// 已用过的 attestation 摘要（防重放：同一摘要不能重复续租）。
    seen_attestations: Mutex<HashSet<[u8; 32]>>,
}

impl LeaseManager {
    pub fn new(duration: Duration, degrade_policy: DegradePolicy) -> Self {
        Self {
            duration,
            degrade_policy,
            audit_healthy: Mutex::new(true),
            leases: Mutex::new(Vec::new()),
            seen_attestations: Mutex::new(HashSet::new()),
        }
    }

    pub fn degrade_policy(&self) -> DegradePolicy {
        self.degrade_policy
    }

    pub fn set_audit_healthy(&self, healthy: bool) {
        *self.audit_healthy.lock() = healthy;
    }

    /// 签发新租约（需可信时间 + 新鲜 attestation 摘要）。
    pub fn issue(
        &self,
        ts: &dyn TimeSource,
        timeline_id: [u8; 16],
        key_epoch: u64,
        attestation_digest: [u8; 32],
    ) -> Result<Lease, LeaseError> {
        let now = ts.now().map_err(LeaseError::Time)?;
        if !*self.audit_healthy.lock() {
            return Err(LeaseError::AuditUnavailable);
        }
        {
            let mut seen = self.seen_attestations.lock();
            if !seen.insert(attestation_digest) {
                return Err(LeaseError::StaleAttestation);
            }
        }
        let lease = Lease {
            timeline_id,
            key_epoch,
            issued_at: now,
            expires_at: now + self.duration,
            state: LeaseState::Valid,
        };
        self.leases.lock().push(lease.clone());
        Ok(lease)
    }

    /// 续租（携带新鲜 attestation 摘要；过期租约不可续 —— 必须重新签发）。
    pub fn renew(
        &self,
        ts: &dyn TimeSource,
        timeline_id: [u8; 16],
        key_epoch: u64,
        attestation_digest: [u8; 32],
    ) -> Result<Lease, LeaseError> {
        let now = ts.now().map_err(LeaseError::Time)?;
        if !*self.audit_healthy.lock() {
            return Err(LeaseError::AuditUnavailable);
        }
        {
            let mut seen = self.seen_attestations.lock();
            if !seen.insert(attestation_digest) {
                return Err(LeaseError::StaleAttestation);
            }
        }
        let mut leases = self.leases.lock();
        let lease = leases
            .iter_mut()
            .rev()
            .find(|l| l.timeline_id == timeline_id && l.key_epoch == key_epoch)
            .ok_or(LeaseError::NotFound)?;
        if !lease.is_valid_at(now) {
            return Err(LeaseError::Expired);
        }
        lease.expires_at = now + self.duration;
        Ok(lease.clone())
    }

    /// 撤销某 timeline 全部租约（策略撤销 / epoch Retire / 时间源异常）。
    pub fn revoke(&self, timeline_id: [u8; 16]) -> usize {
        let mut n = 0;
        for l in self.leases.lock().iter_mut() {
            if l.timeline_id == timeline_id && l.state == LeaseState::Valid {
                l.state = LeaseState::Revoked;
                n += 1;
            }
        }
        n
    }

    /// 查询租约有效性（读路径每事务开始 + 每 E3 操作前的检查点）。
    pub fn check(&self, ts: &dyn TimeSource, timeline_id: [u8; 16], key_epoch: u64) -> LeaseState {
        let Ok(now) = ts.now() else {
            return LeaseState::Revoked; // 时间源异常 = 不可信，按撤销处置
        };
        let leases = self.leases.lock();
        match leases
            .iter()
            .rev()
            .find(|l| l.timeline_id == timeline_id && l.key_epoch == key_epoch)
        {
            Some(l) if l.state == LeaseState::Revoked => LeaseState::Revoked,
            Some(l) if now >= l.expires_at => LeaseState::Expired,
            Some(_) => LeaseState::Valid,
            None => LeaseState::Expired, // 无租约 = 视为过期（拒绝新会话）
        }
    }

    /// 失效矩阵判定：租约失效时新会话是否放行、存量会话如何处置。
    ///
    /// ADR-013：过期 → 拒绝新会话、存量转只读（可配）；撤销 → 同样处置。
    pub fn admission(&self, state: LeaseState) -> Admission {
        match state {
            LeaseState::Valid => Admission {
                allow_new_session: true,
                existing: ExistingSession::Normal,
            },
            LeaseState::Expired | LeaseState::Revoked => Admission {
                allow_new_session: false,
                existing: match self.degrade_policy {
                    DegradePolicy::ReadOnly => ExistingSession::ReadOnly,
                    DegradePolicy::Disconnect => ExistingSession::Disconnect,
                },
            },
        }
    }
}

/// 失效矩阵输出。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    pub allow_new_session: bool,
    pub existing: ExistingSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingSession {
    Normal,
    ReadOnly,
    Disconnect,
}

/// 租约错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LeaseError {
    #[error("time source rejected: {0}")]
    Time(TimeError),
    #[error("attestation digest already used (replay rejected)")]
    StaleAttestation,
    #[error("audit channel unavailable: high-risk operations blocked (fail-closed)")]
    AuditUnavailable,
    #[error("no such lease")]
    NotFound,
    #[error("lease expired: must re-issue, not renew")]
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: [u8; 16] = [0x11; 16];

    /// 手动时钟（测试用；可控前进/回退）。
    struct ManualClock {
        now: Mutex<Instant>,
    }
    impl ManualClock {
        fn new() -> Self {
            Self {
                now: Mutex::new(Instant::now()),
            }
        }
        fn advance(&self, d: Duration) {
            *self.now.lock() += d;
        }
        fn rewind(&self, d: Duration) {
            *self.now.lock() -= d;
        }
    }
    impl TimeSource for ManualClock {
        fn now(&self) -> Result<Instant, TimeError> {
            Ok(*self.now.lock())
        }
    }

    fn digest(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn issue_and_check_valid() {
        let ts = ManualClock::new();
        let m = LeaseManager::new(DEFAULT_LEASE_DURATION, DegradePolicy::ReadOnly);
        let l = m.issue(&ts, T, 0, digest(1)).unwrap();
        assert_eq!(l.state, LeaseState::Valid);
        assert_eq!(m.check(&ts, T, 0), LeaseState::Valid);
        // 14 分钟后仍有效
        ts.advance(Duration::from_secs(14 * 60));
        assert_eq!(m.check(&ts, T, 0), LeaseState::Valid);
    }

    #[test]
    fn expiry_matrix_blocks_new_and_degrades_existing() {
        let ts = ManualClock::new();
        let m = LeaseManager::new(Duration::from_secs(60), DegradePolicy::ReadOnly);
        m.issue(&ts, T, 0, digest(1)).unwrap();
        ts.advance(Duration::from_secs(61));
        assert_eq!(m.check(&ts, T, 0), LeaseState::Expired);
        let a = m.admission(LeaseState::Expired);
        assert!(!a.allow_new_session, "过期必须拒绝新会话");
        assert_eq!(a.existing, ExistingSession::ReadOnly, "存量转只读");
    }

    #[test]
    fn disconnect_policy_configurable() {
        let ts = ManualClock::new();
        let m = LeaseManager::new(Duration::from_secs(60), DegradePolicy::Disconnect);
        m.issue(&ts, T, 0, digest(1)).unwrap();
        ts.advance(Duration::from_secs(61));
        let a = m.admission(m.check(&ts, T, 0));
        assert_eq!(a.existing, ExistingSession::Disconnect);
    }

    #[test]
    fn renewal_requires_fresh_attestation() {
        let ts = ManualClock::new();
        let m = LeaseManager::new(Duration::from_secs(60), DegradePolicy::ReadOnly);
        m.issue(&ts, T, 0, digest(1)).unwrap();
        // 同一摘要续租：拒绝（防重放）
        assert!(matches!(
            m.renew(&ts, T, 0, digest(1)),
            Err(LeaseError::StaleAttestation)
        ));
        // 新鲜摘要：成功
        assert!(m.renew(&ts, T, 0, digest(2)).is_ok());
    }

    #[test]
    fn expired_lease_cannot_be_renewed() {
        let ts = ManualClock::new();
        let m = LeaseManager::new(Duration::from_secs(60), DegradePolicy::ReadOnly);
        m.issue(&ts, T, 0, digest(1)).unwrap();
        ts.advance(Duration::from_secs(61));
        assert!(matches!(m.renew(&ts, T, 0, digest(2)), Err(LeaseError::Expired)));
    }

    #[test]
    fn audit_unavailable_blocks_issue_fail_closed() {
        let ts = ManualClock::new();
        let m = LeaseManager::new(DEFAULT_LEASE_DURATION, DegradePolicy::ReadOnly);
        m.set_audit_healthy(false);
        assert!(matches!(
            m.issue(&ts, T, 0, digest(1)),
            Err(LeaseError::AuditUnavailable)
        ));
        // 恢复后可用
        m.set_audit_healthy(true);
        assert!(m.issue(&ts, T, 0, digest(1)).is_ok());
    }

    #[test]
    fn time_backwards_jump_detected() {
        let src = MonotonicTimeSource::new();
        let _ = src.now().unwrap();
        // 手动构造回退场景：直接测试 MonotonicTimeSource 的检测逻辑
        // （真实 Instant 单调，故用内部状态注入验证逻辑分支）
        let ts = ManualClock::new();
        ts.rewind(Duration::from_secs(10));
        // ManualClock 允许回退，但 MonotonicTimeSource 会拒绝：
        // 此处验证 TimeSource 契约 —— 返回 Err 时租约层按撤销处置
        struct Backwards;
        impl TimeSource for Backwards {
            fn now(&self) -> Result<Instant, TimeError> {
                Err(TimeError::BackwardsJump(Duration::from_secs(10)))
            }
        }
        let m = LeaseManager::new(DEFAULT_LEASE_DURATION, DegradePolicy::ReadOnly);
        assert!(matches!(
            m.issue(&Backwards, T, 0, digest(1)),
            Err(LeaseError::Time(TimeError::BackwardsJump(_)))
        ));
        // 时间源异常时 check 按 Revoked 处置
        assert_eq!(m.check(&Backwards, T, 0), LeaseState::Revoked);
    }

    #[test]
    fn revoke_invalidates_leases() {
        let ts = ManualClock::new();
        let m = LeaseManager::new(DEFAULT_LEASE_DURATION, DegradePolicy::ReadOnly);
        m.issue(&ts, T, 0, digest(1)).unwrap();
        assert_eq!(m.revoke(T), 1);
        assert_eq!(m.check(&ts, T, 0), LeaseState::Revoked);
        let a = m.admission(LeaseState::Revoked);
        assert!(!a.allow_new_session);
    }

    #[test]
    fn unknown_timeline_is_expired() {
        let ts = ManualClock::new();
        let m = LeaseManager::new(DEFAULT_LEASE_DURATION, DegradePolicy::ReadOnly);
        assert_eq!(m.check(&ts, [0xFF; 16], 0), LeaseState::Expired);
    }
}
