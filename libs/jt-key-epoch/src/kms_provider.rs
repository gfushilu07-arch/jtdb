//! jt-kms 租约供给的 KeyProvider（生产实现，docs/02 §6.3、ADR-013）。
//!
//! # 为什么是"缓存 + 后台续租"而非"每次调用发 HTTP"
//!
//! [`crate::KeyProvider::get_dek`] 是**同步**接口（调用点在加密热路径
//! 上：每写一个 Layer / WAL 段取一次 DEK），而 KMS 是 HTTP 服务。若在
//! `get_dek` 内同步发 HTTP，会带来两个问题：
//!
//! 1. **热路径阻塞**：加密写入被网络往返拖慢（页写入路径不可接受）；
//! 2. **租约语义错位**：租约是"一段时间内有效"的授权，不是每次取密钥都要
//!    重新申请——按 ADR-013，组件持有租约、到期续租。
//!
//! 故本实现把 KMS 交互放在**后台任务**：`refresh` 拉取/续租并把 DEK 写入
//! 内存缓存；`get_dek` 只读缓存（同步、无网络）。
//!
//! # 失效语义（ADR-013，必须严格）
//!
//! | 状态 | `get_dek` 行为 |
//! |---|---|
//! | 租约有效 | 返回缓存的 DEK |
//! | 租约过期且续租未成功 | [`KeyError::FailClosed`]（**不得**返回旧 DEK） |
//! | epoch 已 Retire（KMS 报 unknown/revoked） | [`KeyError::UnknownScope`]（**加密擦除**语义） |
//! | 从未成功拉取过 | [`KeyError::FailClosed`] |
//!
//! **fail-closed 的理由**：租约过期意味着"授权不再有效"，此时继续用旧 DEK
//! 加密会让轮换/撤销失去意义（撤销后仍能写出可解密数据）。故过期即拒绝，
//! 由调用方走降级矩阵。
//!
//! # 审计
//!
//! 每次成功/失败的租约操作都会记录（`is_degraded` 供上层标记）；KMS 侧
//! 自身也记录 `lease.issue`/`lease.renew`（services/jt-kms/src/api.rs）。

use crate::{DekScope, KeyError, KeyProvider};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 租约状态（每 scope）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// 从未成功拉取。
    NeverFetched,
    /// 有效（含到期时刻，Unix 秒）。
    Valid { expires_at: u64 },
    /// 已过期（续租失败）。
    Expired { expired_at: u64 },
    /// 已被撤销 / epoch 已 Retire（加密擦除）。
    Revoked,
}

impl LeaseState {
    pub fn is_valid_at(&self, now: u64) -> bool {
        matches!(self, LeaseState::Valid { expires_at } if *expires_at > now)
    }
}

/// 缓存的 DEK 条目。
#[derive(Debug, Clone)]
struct CachedDek {
    dek: [u8; 16],
    state: LeaseState,
    /// 上次成功刷新时刻（Unix 秒）。
    fetched_at: u64,
}

/// KMS 客户端抽象。
///
/// 抽成 trait 使测试可注入假 KMS（无需起真实服务），生产用
/// [`HttpKmsClient`]。
pub trait KmsClient: Send + Sync {
    /// 申请或续租 DEK。
    ///
    /// 返回 `Ok(dek)` = 成功；`Err(KmsError::Revoked)` = epoch 已 Retire
    /// （调用方应转 [`KeyError::UnknownScope`]）；其余错误 = 暂时性失败。
    fn fetch_dek(&self, scope: &DekScope, lease_secs: u64) -> Result<[u8; 16], KmsError>;
}

/// KMS 交互错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KmsError {
    /// epoch 已 Retire / 租约被撤销（加密擦除语义）。
    #[error("epoch retired or lease revoked: {0}")]
    Revoked(String),
    /// 证明不新鲜（KMS 拒绝签发）。
    #[error("attestation stale")]
    StaleAttestation,
    /// 审计平面不可用（KMS fail-closed）。
    #[error("audit plane unavailable")]
    AuditUnavailable,
    /// 网络/服务暂时不可用。
    #[error("kms unavailable: {0}")]
    Unavailable(String),
}

/// 租约驱动的 DEK 供给（生产实现）。
pub struct KmsLeaseProvider {
    client: Arc<dyn KmsClient>,
    /// 默认租约时长（秒）——与 KMS 侧 `lease_secs` 一致。
    lease_secs: u64,
    /// DEK 缓存（scope → 条目）。
    cache: RwLock<HashMap<DekScope, CachedDek>>,
    /// 降级标记（软件熵源 / 刷新失败）。
    degraded: RwLock<bool>,
    /// 时间源（测试可注入）。
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl KmsLeaseProvider {
    pub fn new(client: Arc<dyn KmsClient>, lease_secs: u64) -> Self {
        Self::with_clock(client, lease_secs, Box::new(unix_now))
    }

    pub fn with_clock(
        client: Arc<dyn KmsClient>,
        lease_secs: u64,
        clock: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        KmsLeaseProvider {
            client,
            lease_secs,
            cache: RwLock::new(HashMap::new()),
            degraded: RwLock::new(false),
            clock,
        }
    }

    /// 刷新某 scope 的租约（后台任务调用；也可显式调用以预热）。
    ///
    /// 成功 → `Valid`；`Revoked` → `Revoked`（并**清除**缓存 DEK，实现加密
    /// 擦除）；其他错误 → `Expired`（保留旧 DEK 但标记不可用——保留是为了
    /// 让"撤销后仍能解密历史数据"的场景不被误伤，但 `get_dek` 不会返回它）。
    pub fn refresh(&self, scope: &DekScope) -> Result<(), KmsError> {
        let now = (self.clock)();
        match self.client.fetch_dek(scope, self.lease_secs) {
            Ok(dek) => {
                let mut c = self.cache.write();
                c.insert(
                    scope.clone(),
                    CachedDek {
                        dek,
                        state: LeaseState::Valid {
                            expires_at: now + self.lease_secs,
                        },
                        fetched_at: now,
                    },
                );
                *self.degraded.write() = false;
                Ok(())
            }
            Err(KmsError::Revoked(reason)) => {
                // 加密擦除：**清除** DEK（不留旧值）
                let mut c = self.cache.write();
                c.insert(
                    scope.clone(),
                    CachedDek {
                        dek: [0u8; 16],
                        state: LeaseState::Revoked,
                        fetched_at: now,
                    },
                );
                *self.degraded.write() = true;
                Err(KmsError::Revoked(reason))
            }
            Err(e) => {
                let mut c = self.cache.write();
                let entry = c.entry(scope.clone()).or_insert(CachedDek {
                    dek: [0u8; 16],
                    state: LeaseState::NeverFetched,
                    fetched_at: 0,
                });
                entry.state = LeaseState::Expired { expired_at: now };
                *self.degraded.write() = true;
                Err(e)
            }
        }
    }

    /// 当前租约状态（审计/指标用）。
    pub fn lease_state(&self, scope: &DekScope) -> LeaseState {
        self.cache
            .read()
            .get(scope)
            .map(|e| e.state)
            .unwrap_or(LeaseState::NeverFetched)
    }

    /// 已缓存的 scope 列表（后台续租遍历用）。
    pub fn known_scopes(&self) -> Vec<DekScope> {
        self.cache.read().keys().cloned().collect()
    }
}

impl KeyProvider for KmsLeaseProvider {
    fn get_dek(&self, scope: &DekScope) -> Result<[u8; 16], KeyError> {
        let now = (self.clock)();
        let c = self.cache.read();
        let entry = c.get(scope).ok_or(KeyError::FailClosed)?;
        match entry.state {
            LeaseState::Valid { expires_at } if expires_at > now => Ok(entry.dek),
            // 已撤销：加密擦除语义（ADR-013）
            LeaseState::Revoked => Err(KeyError::UnknownScope),
            // 过期 / 从未拉取：fail-closed（**不得**返回旧 DEK）
            LeaseState::Expired { .. } | LeaseState::NeverFetched | LeaseState::Valid { .. } => {
                Err(KeyError::FailClosed)
            }
        }
    }

    fn is_degraded(&self) -> bool {
        *self.degraded.read()
    }
}

/// HTTP KMS 客户端（生产）。
///
/// 端点（services/jt-kms/src/api.rs）：
/// * `POST /v1/lease/issue` —— 申请租约并取回 DEK
/// * `POST /v1/lease/renew` —— 续租
///
/// **同步实现**：`KmsClient::fetch_dek` 是同步 trait（由后台任务调用），
/// 故此处用阻塞 HTTP。若后续要在 async 运行时内调用，应改用
/// `tokio::task::spawn_blocking` 包装，或把 trait 改为 async。
pub struct HttpKmsClient {
    endpoint: String,
    node_id: String,
    /// 最新证明摘要（SM3 hex）——KMS 校验新鲜度。
    attestation_digest: RwLock<String>,
}

impl HttpKmsClient {
    pub fn new(endpoint: impl Into<String>, node_id: impl Into<String>, att_hex: impl Into<String>) -> Self {
        HttpKmsClient {
            endpoint: endpoint.into(),
            node_id: node_id.into(),
            attestation_digest: RwLock::new(att_hex.into()),
        }
    }

    /// 更新证明摘要（attest 刷新后调用）。
    pub fn update_attestation(&self, att_hex: impl Into<String>) {
        *self.attestation_digest.write() = att_hex.into();
    }

    fn post_json(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value, KmsError> {
        let url = format!("{}{}", self.endpoint.trim_end_matches('/'), path);
        let resp = ureq::post(&url)
            .set("content-type", "application/json")
            .send_json(body)
            .map_err(|e| KmsError::Unavailable(format!("{path}: {e}")))?;
        resp.into_json::<serde_json::Value>()
            .map_err(|e| KmsError::Unavailable(format!("{path}: bad json: {e}")))
    }
}

impl KmsClient for HttpKmsClient {
    fn fetch_dek(&self, scope: &DekScope, lease_secs: u64) -> Result<[u8; 16], KmsError> {
        let att = self.attestation_digest.read().clone();
        let body = serde_json::json!({
            "timeline_id": hex::encode(scope.timeline_id),
            "key_epoch": scope.key_epoch,
            "node_id": self.node_id,
            "attestation_digest": att,
        });
        let v = self.post_json("/v1/lease/issue", body)?;

        // 错误映射：KMS 侧 KmsApiError 的语义 → 本层 KmsError
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            let lower = err.to_lowercase();
            if lower.contains("retired") || lower.contains("revoked") || lower.contains("unknown") {
                return Err(KmsError::Revoked(err.to_string()));
            }
            if lower.contains("attest") {
                return Err(KmsError::StaleAttestation);
            }
            if lower.contains("audit") {
                return Err(KmsError::AuditUnavailable);
            }
            return Err(KmsError::Unavailable(err.to_string()));
        }

        let dek_hex = v
            .get("dek_hex")
            .and_then(|d| d.as_str())
            .ok_or_else(|| KmsError::Unavailable("response missing dek_hex".into()))?;
        let bytes = hex::decode(dek_hex)
            .map_err(|e| KmsError::Unavailable(format!("dek_hex not hex: {e}")))?;
        let dek: [u8; 16] = bytes
            .try_into()
            .map_err(|_| KmsError::Unavailable("dek must be 16 bytes".into()))?;
        let _ = lease_secs; // 租约时长由 KMS 侧决定（ADR-013 上限 900s）
        Ok(dek)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 后台续租：在租约过半时刷新，避免临界过期。
///
/// 返回建议的休眠时长（秒）——调用方（tokio 任务）按此节奏循环。
pub fn renew_interval_secs(lease_secs: u64) -> Duration {
    Duration::from_secs((lease_secs / 2).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// 假 KMS：可编程返回。
    struct FakeKms {
        mode: AtomicU64, // 0=ok, 1=revoked, 2=unavailable, 3=stale-att
        calls: AtomicUsize,
        dek: [u8; 16],
    }

    impl FakeKms {
        fn new() -> Self {
            FakeKms {
                mode: AtomicU64::new(0),
                calls: AtomicUsize::new(0),
                dek: [0xAB; 16],
            }
        }
        fn set_mode(&self, m: u64) {
            self.mode.store(m, Ordering::SeqCst);
        }
    }

    impl KmsClient for FakeKms {
        fn fetch_dek(&self, _scope: &DekScope, _secs: u64) -> Result<[u8; 16], KmsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.mode.load(Ordering::SeqCst) {
                0 => Ok(self.dek),
                1 => Err(KmsError::Revoked("epoch retired".into())),
                2 => Err(KmsError::Unavailable("conn refused".into())),
                _ => Err(KmsError::StaleAttestation),
            }
        }
    }

    fn scope() -> DekScope {
        DekScope {
            timeline_id: [0x11; 16],
            key_epoch: 1,
        }
    }

    fn provider(kms: Arc<FakeKms>, now: Arc<AtomicU64>, lease: u64) -> KmsLeaseProvider {
        let clock = move || now.load(Ordering::SeqCst);
        KmsLeaseProvider::with_clock(kms, lease, Box::new(clock))
    }

    #[test]
    fn valid_lease_returns_dek() {
        let kms = Arc::new(FakeKms::new());
        let now = Arc::new(AtomicU64::new(1000));
        let p = provider(kms, now, 900);
        assert_eq!(p.get_dek(&scope()), Err(KeyError::FailClosed), "未拉取前 fail-closed");
        p.refresh(&scope()).unwrap();
        assert_eq!(p.get_dek(&scope()).unwrap(), [0xAB; 16]);
        assert!(!p.is_degraded());
    }

    #[test]
    fn expired_lease_fails_closed_not_stale_dek() {
        // 租约过期后**不得**返回旧 DEK（否则撤销/轮换失去意义）
        let kms = Arc::new(FakeKms::new());
        let now = Arc::new(AtomicU64::new(1000));
        let p = provider(kms, now.clone(), 100);
        p.refresh(&scope()).unwrap();
        assert!(p.get_dek(&scope()).is_ok());

        now.store(1200, Ordering::SeqCst); // 超过 expires_at
        assert_eq!(
            p.get_dek(&scope()),
            Err(KeyError::FailClosed),
            "过期租约须 fail-closed"
        );
    }

    #[test]
    fn revoked_epoch_yields_unknown_scope_and_erases_dek() {
        // ADR-013：Retire 后必须 UnknownScope（加密擦除语义）
        let kms = Arc::new(FakeKms::new());
        let now = Arc::new(AtomicU64::new(1000));
        let p = provider(kms.clone(), now, 900);
        p.refresh(&scope()).unwrap();
        assert!(p.get_dek(&scope()).is_ok());

        kms.set_mode(1); // revoked
        assert!(matches!(p.refresh(&scope()), Err(KmsError::Revoked(_))));
        assert_eq!(p.get_dek(&scope()), Err(KeyError::UnknownScope));
        assert!(p.is_degraded(), "撤销后须标记降级");
    }

    #[test]
    fn refresh_failure_marks_degraded_and_expires() {
        let kms = Arc::new(FakeKms::new());
        let now = Arc::new(AtomicU64::new(1000));
        let p = provider(kms.clone(), now, 900);
        p.refresh(&scope()).unwrap();

        kms.set_mode(2); // unavailable
        assert!(matches!(p.refresh(&scope()), Err(KmsError::Unavailable(_))));
        assert!(p.is_degraded(), "刷新失败须标记降级");
        assert_eq!(p.get_dek(&scope()), Err(KeyError::FailClosed), "失败后 fail-closed");
    }

    #[test]
    fn stale_attestation_is_distinguished() {
        let kms = Arc::new(FakeKms::new());
        let now = Arc::new(AtomicU64::new(1000));
        let p = provider(kms.clone(), now, 900);
        kms.set_mode(3);
        assert!(matches!(
            p.refresh(&scope()),
            Err(KmsError::StaleAttestation)
        ));
    }

    #[test]
    fn refresh_success_clears_degraded() {
        let kms = Arc::new(FakeKms::new());
        let now = Arc::new(AtomicU64::new(1000));
        let p = provider(kms.clone(), now, 900);
        kms.set_mode(2);
        let _ = p.refresh(&scope());
        assert!(p.is_degraded());
        kms.set_mode(0);
        p.refresh(&scope()).unwrap();
        assert!(!p.is_degraded(), "恢复后须清除降级标记");
    }

    #[test]
    fn multiple_scopes_isolated() {
        let kms = Arc::new(FakeKms::new());
        let now = Arc::new(AtomicU64::new(1000));
        let p = provider(kms, now, 900);
        let s1 = scope();
        let s2 = DekScope {
            timeline_id: [0x22; 16],
            key_epoch: 1,
        };
        p.refresh(&s1).unwrap();
        assert!(p.get_dek(&s1).is_ok());
        assert_eq!(p.get_dek(&s2), Err(KeyError::FailClosed), "未拉取的 scope 独立");
        p.refresh(&s2).unwrap();
        assert!(p.get_dek(&s2).is_ok());
        assert_eq!(p.known_scopes().len(), 2);
    }

    #[test]
    fn lease_state_reports_transitions() {
        let kms = Arc::new(FakeKms::new());
        let now = Arc::new(AtomicU64::new(1000));
        let p = provider(kms.clone(), now.clone(), 100);
        assert_eq!(p.lease_state(&scope()), LeaseState::NeverFetched);
        p.refresh(&scope()).unwrap();
        assert!(matches!(p.lease_state(&scope()), LeaseState::Valid { .. }));
        now.store(1200, Ordering::SeqCst);
        assert!(!p.lease_state(&scope()).is_valid_at(1200));
    }

    #[test]
    fn renew_interval_is_half_lease() {
        assert_eq!(renew_interval_secs(900), Duration::from_secs(450));
        assert_eq!(renew_interval_secs(1), Duration::from_secs(1), "下限 1 秒");
        assert_eq!(renew_interval_secs(0), Duration::from_secs(1), "零租约退化到 1 秒");
    }

    #[test]
    fn concurrent_get_dek_is_consistent() {
        let kms = Arc::new(FakeKms::new());
        let now = Arc::new(AtomicU64::new(1000));
        let p = Arc::new(provider(kms, now, 900));
        p.refresh(&scope()).unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let p = p.clone();
            handles.push(std::thread::spawn(move || p.get_dek(&scope()).unwrap()));
        }
        for h in handles {
            assert_eq!(h.join().unwrap(), [0xAB; 16]);
        }
    }
}
