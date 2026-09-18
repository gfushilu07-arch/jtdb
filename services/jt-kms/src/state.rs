//! jt-kms 服务端状态：租约、防回滚计数器、轮换协调 + 持久化。
//!
//! 持久化布局（data_dir）：
//! * `master.key`      — RK（0600）
//! * `counters.json`   — 防回滚计数器 + 已见 attestation 摘要（原子写）
//! * `rotation.journal`— 轮换 journal（逐行 JSON，重放恢复）
//!
//! ADR-013：防回滚计数器"持久化于 KMS + 本地 TCM NV/安全文件双份"——
//! 本文件即 KMS 份；组件侧份由 pageserver 的 rollback_guard 承载。

use crate::keys::{self, KEK_LEN, RK_LEN};
use jt_key_epoch::{LeaseError, LeaseState, RotationCoordinator, RotationError, RotationState};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 服务端租约记录（Unix 时间戳口径，可持久化）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLease {
    pub timeline_id: String,
    pub key_epoch: u64,
    pub node_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

/// KMS 全局状态。
pub struct KmsState {
    pub cluster: String,
    pub component_scope: String,
    pub lease_duration: Duration,
    rk: [u8; RK_LEN],
    /// 服务端租约表（timeline → lease）。
    leases: Mutex<HashMap<String, ServerLease>>,
    /// 防回滚计数器（timeline → epoch → max_generation）。
    counters: Mutex<HashMap<String, HashMap<u64, u64>>>,
    /// 已见 attestation 摘要（hex；防重放，持久化）。
    seen_att: Mutex<Vec<String>>,
    /// 轮换协调器。
    pub rotation: RotationCoordinator,
    data_dir: PathBuf,
    /// 审计健康（fail-closed 演示位；生产接 jt-audit-ingest 心跳）。
    audit_healthy: Mutex<bool>,
}

/// 状态持久化错误。
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] crate::keys::KmsCryptoError),
}

#[derive(Serialize, Deserialize, Default)]
struct CountersFile {
    counters: HashMap<String, HashMap<u64, u64>>,
    seen_att: Vec<String>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

impl KmsState {
    pub fn load_or_init(
        data_dir: &Path,
        cluster: &str,
        component_scope: &str,
        lease_duration: Duration,
    ) -> Result<Self, StateError> {
        std::fs::create_dir_all(data_dir)?;
        let rk = keys::load_or_create_rk(&data_dir.join("master.key"))?;

        let mut counters = HashMap::new();
        let mut seen_att = Vec::new();
        let counters_path = data_dir.join("counters.json");
        if let Ok(bytes) = std::fs::read(&counters_path) {
            let f: CountersFile = serde_json::from_slice(&bytes)?;
            counters = f.counters;
            seen_att = f.seen_att;
        }

        let rotation = RotationCoordinator::new();
        let journal_path = data_dir.join("rotation.journal");
        if journal_path.exists() {
            // 重放 journal 到协调器（崩溃恢复；幂等）
            for line in std::fs::read_to_string(&journal_path)?.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(e) = serde_json::from_str::<JournalLine>(line) {
                    rotation.journal().append(jt_key_epoch::JournalEntry {
                        timeline_id: hex::decode(&e.timeline_id)
                            .ok()
                            .and_then(|v| <[u8; 16]>::try_from(v).ok())
                            .unwrap_or([0; 16]),
                        from_epoch: e.from_epoch,
                        to_epoch: e.to_epoch,
                        state: RotationState::parse(&e.state).unwrap_or(RotationState::Sealed),
                        rollback_counter: e.rollback_counter,
                    });
                }
            }
            rotation.recover_from_journal();
        }

        Ok(Self {
            cluster: cluster.to_string(),
            component_scope: component_scope.to_string(),
            lease_duration,
            rk,
            leases: Mutex::new(HashMap::new()),
            counters: Mutex::new(counters),
            seen_att: Mutex::new(seen_att),
            rotation,
            data_dir: data_dir.to_path_buf(),
            audit_healthy: Mutex::new(true),
        })
    }

    fn kek(&self) -> [u8; KEK_LEN] {
        keys::derive_kek(&self.rk, &self.cluster, &self.component_scope)
    }

    /// attestation 摘要登记：首次出现 = 新鲜；重复 = 过期（防重放）。
    ///
    /// 注意：必须在返回前释放 seen_att 锁（persist_counters 需再取同一锁，
    /// parking_lot 不可重入）。
    pub fn check_attestation_fresh(&self, digest_hex: &str) -> bool {
        let fresh = {
            let mut seen = self.seen_att.lock();
            if seen.iter().any(|s| s == digest_hex) {
                return false;
            }
            seen.push(digest_hex.to_string());
            // 上限保护：超限丢弃最旧的一半（生产换布隆/LSM；语义保留近期防重放）
            if seen.len() > 65536 {
                let keep_at = seen.len() / 2;
                let drained: Vec<String> = seen.drain(..keep_at).collect();
                debug_assert!(!drained.is_empty());
            }
            true
        };
        self.persist_counters().ok();
        fresh
    }

    /// 签发租约（KMS 侧；携带该 scope 的 DEK hex）。
    pub fn issue_lease(
        &self,
        timeline_hex: &str,
        key_epoch: u64,
        node_id: &str,
        att_hex: &str,
    ) -> Result<ServerLeaseWithDek, KmsApiError> {
        if !*self.audit_healthy.lock() {
            return Err(KmsApiError::AuditUnavailable);
        }
        if !self.check_attestation_fresh(att_hex) {
            return Err(KmsApiError::StaleAttestation);
        }
        let tl = parse_timeline(timeline_hex)?;
        let now = unix_now();
        let lease = ServerLease {
            timeline_id: timeline_hex.to_string(),
            key_epoch,
            node_id: node_id.to_string(),
            issued_at: now,
            expires_at: now + self.lease_duration.as_secs(),
            revoked: false,
        };
        self.leases
            .lock()
            .insert(timeline_hex.to_string(), lease.clone());
        let dek = keys::derive_dek_dev(&tl, key_epoch);
        Ok(ServerLeaseWithDek {
            lease,
            dek_hex: hex::encode(dek),
        })
    }

    /// 续租（要求现有租约未过期未撤销 + 新鲜 attestation）。
    pub fn renew_lease(
        &self,
        timeline_hex: &str,
        key_epoch: u64,
        att_hex: &str,
    ) -> Result<ServerLease, KmsApiError> {
        if !*self.audit_healthy.lock() {
            return Err(KmsApiError::AuditUnavailable);
        }
        if !self.check_attestation_fresh(att_hex) {
            return Err(KmsApiError::StaleAttestation);
        }
        let mut leases = self.leases.lock();
        let lease = leases
            .get_mut(timeline_hex)
            .filter(|l| l.key_epoch == key_epoch)
            .ok_or(KmsApiError::NotFound)?;
        if lease.revoked {
            return Err(KmsApiError::Revoked);
        }
        if unix_now() >= lease.expires_at {
            return Err(KmsApiError::Expired);
        }
        lease.expires_at = unix_now() + self.lease_duration.as_secs();
        Ok(lease.clone())
    }

    /// 撤销某 timeline 租约。
    pub fn revoke_lease(&self, timeline_hex: &str) -> bool {
        self.leases
            .lock()
            .get_mut(timeline_hex)
            .map(|l| {
                l.revoked = true;
            })
            .is_some()
    }

    /// 租约有效性检查。
    pub fn lease_state(&self, timeline_hex: &str, key_epoch: u64) -> LeaseState {
        match self.leases.lock().get(timeline_hex) {
            Some(l) if l.revoked => LeaseState::Revoked,
            Some(l) if unix_now() >= l.expires_at => LeaseState::Expired,
            Some(_) => LeaseState::Valid,
            None => LeaseState::Expired,
        }
    }

    /// KEK 信封封装（组件提交 DEK 材料，KMS 用 KEK 包；DEK 明文不出 KMS 亦可
    /// 由 KMS 生成——两种模式都走此接口）。
    pub fn wrap(
        &self,
        timeline_hex: &str,
        key_epoch: u64,
        lsn_range: &str,
        dek_hex: Option<&str>,
    ) -> Result<WrappedDek, KmsApiError> {
        let tl = parse_timeline(timeline_hex)?;
        let sd = keys::scope_digest(&self.cluster, &tl, key_epoch, lsn_range);
        let dek = match dek_hex {
            Some(h) => {
                let bytes = hex::decode(h).map_err(|_| KmsApiError::BadRequest)?;
                <[u8; KEK_LEN]>::try_from(bytes).map_err(|_| KmsApiError::BadRequest)?
            }
            None => keys::generate_dek(),
        };
        let kek = self.kek();
        let blob = keys::wrap_dek(&kek, &dek, &sd);
        Ok(WrappedDek {
            dek_hex: hex::encode(dek),
            wrapped_hex: hex::encode(&blob),
            scope_digest_hex: hex::encode(sd),
        })
    }

    /// 信封解封（需有效租约；scope 不匹配/篡改拒绝）。
    pub fn unwrap(
        &self,
        timeline_hex: &str,
        key_epoch: u64,
        lsn_range: &str,
        wrapped_hex: &str,
    ) -> Result<String, KmsApiError> {
        if self.lease_state(timeline_hex, key_epoch) != LeaseState::Valid {
            return Err(KmsApiError::NoValidLease);
        }
        let tl = parse_timeline(timeline_hex)?;
        let sd = keys::scope_digest(&self.cluster, &tl, key_epoch, lsn_range);
        let blob = hex::decode(wrapped_hex).map_err(|_| KmsApiError::BadRequest)?;
        let kek = self.kek();
        let dek = keys::unwrap_dek(&kek, &blob, &sd).map_err(KmsApiError::Crypto)?;
        Ok(hex::encode(dek))
    }

    /// 防回滚：记录 generation（回退拒绝）。
    pub fn counter_record(
        &self,
        timeline_hex: &str,
        key_epoch: u64,
        generation: u64,
    ) -> Result<u64, KmsApiError> {
        // 防回滚：generation 不得低于已记录最大值（对 KMS 自身 counters 表校验；
        // 语义与 jt_key_epoch::RotationCoordinator::check_generation 一致）
        let recorded = {
            let mut c = self.counters.lock();
            let e = c
                .entry(timeline_hex.to_string())
                .or_default()
                .entry(key_epoch)
                .or_insert(0);
            if generation < *e {
                return Err(KmsApiError::Rollback(format!(
                    "generation regression: seen={generation} recorded={e}"
                )));
            }
            if generation > *e {
                *e = generation;
            }
            *e
        };
        self.persist_counters().map_err(KmsApiError::State)?;
        Ok(recorded)
    }

    pub fn counter_get(&self, timeline_hex: &str, key_epoch: u64) -> u64 {
        self.counters
            .lock()
            .get(timeline_hex)
            .and_then(|m| m.get(&key_epoch))
            .copied()
            .unwrap_or(0)
    }

    /// 轮换推进（journal 持久化后改内存态）。
    pub fn rotation_begin(
        &self,
        timeline_hex: &str,
        from_epoch: u64,
    ) -> Result<(), KmsApiError> {
        let tl = parse_timeline(timeline_hex)?;
        self.rotation
            .begin(tl, from_epoch)
            .map_err(KmsApiError::Rotation)?;
        self.persist_journal().map_err(KmsApiError::State)?;
        Ok(())
    }

    pub fn rotation_advance(
        &self,
        timeline_hex: &str,
        to: &str,
    ) -> Result<String, KmsApiError> {
        let tl = parse_timeline(timeline_hex)?;
        let to_state =
            RotationState::parse(to).ok_or_else(|| KmsApiError::BadRequest)?;
        let now = self
            .rotation
            .advance(tl, to_state)
            .map_err(KmsApiError::Rotation)?;
        self.persist_journal().map_err(KmsApiError::State)?;
        Ok(now.as_str().to_string())
    }

    pub fn rotation_status(&self, timeline_hex: &str) -> Option<(u64, u64, String, u64)> {
        self.rotation
            .progress(parse_timeline(timeline_hex).ok()?)
            .map(|p| (p.from_epoch, p.to_epoch, p.state.as_str().to_string(), p.rekeyed_objects))
    }

    /// 审计健康位（演示 fail-closed；生产接 jt-audit-ingest 心跳）。
    pub fn set_audit_healthy(&self, healthy: bool) {
        *self.audit_healthy.lock() = healthy;
    }

    fn persist_counters(&self) -> Result<(), StateError> {
        let f = CountersFile {
            counters: self.counters.lock().clone(),
            seen_att: self.seen_att.lock().clone(),
        };
        atomic_write(
            &self.data_dir.join("counters.json"),
            &serde_json::to_vec_pretty(&f)?,
        )
    }

    fn persist_journal(&self) -> Result<(), StateError> {
        let mut out = String::new();
        for e in self.rotation.journal().snapshot() {
            let line = JournalLine {
                timeline_id: hex::encode(e.timeline_id),
                from_epoch: e.from_epoch,
                to_epoch: e.to_epoch,
                state: e.state.as_str().to_string(),
                rollback_counter: e.rollback_counter,
            };
            out.push_str(&serde_json::to_string(&line)?);
            out.push('\n');
        }
        atomic_write(&self.data_dir.join("rotation.journal"), out.as_bytes())
    }
}

/// journal 行（文件格式）。
#[derive(Serialize, Deserialize)]
struct JournalLine {
    timeline_id: String,
    from_epoch: u64,
    to_epoch: u64,
    state: String,
    rollback_counter: u64,
}

/// API 响应：租约 + DEK。
#[derive(Serialize)]
pub struct ServerLeaseWithDek {
    pub lease: ServerLease,
    pub dek_hex: String,
}

/// API 响应：信封。
#[derive(Serialize)]
pub struct WrappedDek {
    pub dek_hex: String,
    pub wrapped_hex: String,
    pub scope_digest_hex: String,
}

/// API 错误。
#[derive(Debug, thiserror::Error)]
pub enum KmsApiError {
    #[error("bad request")]
    BadRequest,
    #[error("not found")]
    NotFound,
    #[error("lease revoked")]
    Revoked,
    #[error("lease expired")]
    Expired,
    #[error("no valid lease for this timeline/epoch")]
    NoValidLease,
    #[error("stale attestation (replay rejected)")]
    StaleAttestation,
    #[error("audit channel unavailable: fail-closed")]
    AuditUnavailable,
    #[error("rollback detected: {0}")]
    Rollback(String),
    #[error("rotation: {0}")]
    Rotation(#[from] RotationError),
    #[error("lease: {0}")]
    Lease(#[from] LeaseError),
    #[error("crypto: {0}")]
    Crypto(#[from] keys::KmsCryptoError),
    #[error("state: {0}")]
    State(StateError),
    #[error("bad timeline id (expect 32 hex chars)")]
    BadTimeline,
}

fn parse_timeline(hexstr: &str) -> Result<[u8; 16], KmsApiError> {
    let bytes = hex::decode(hexstr).map_err(|_| KmsApiError::BadTimeline)?;
    <[u8; 16]>::try_from(bytes).map_err(|_| KmsApiError::BadTimeline)
}
