//! 策略快照与租约（docs/02 §6.2 Policy Lease）。
//!
//! 核心设计：**PDP 不在每条 SQL 的关键路径上远程同步决策**。Compute 持有
//! 经过签名验证的策略快照 + 租约，本地决策；关键变更通过**撤销**（把
//! 快照标记失效）和租约到期生效。

use crate::policy::{PolicySet, PolicyVersion};
use jt_crypto_api::{SignatureKey, SignatureVerifier};
use jt_crypto_sm::{Sm2Signer, Sm2Verifier, Sm3Digest};
use jt_crypto_api::Digest256 as _;
use serde::{Deserialize, Serialize};

/// 快照错误。
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot signature invalid")]
    InvalidSignature,
    #[error("snapshot revoked")]
    Revoked,
    #[error("snapshot lease expired (issued={issued}, ttl={ttl}, now={now})")]
    Expired { issued: u64, ttl: u64, now: u64 },
    #[error("snapshot digest mismatch")]
    DigestMismatch,
    #[error("signing failed")]
    SignFailed,
    #[error("snapshot signer is not the trusted PDP (possible forged policy)")]
    UntrustedSigner,
}

/// 策略快照（签名 + 版本 + 内容）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    /// 快照版本（单调递增）。
    pub version: PolicyVersion,
    /// 策略集。
    pub policy: PolicySet,
    /// 内容摘要（SM3 of canonical policy json）。
    pub digest: String,
    /// 签发时刻（Unix 秒）。
    pub issued_at: u64,
    /// 租约 TTL（秒）。
    pub ttl_secs: u64,
    /// PDP 签名（覆盖 version + digest + issued_at + ttl）。
    pub signature: String,
    /// PDP 公钥（hex）。
    pub signer_pk: String,
}

impl PolicySnapshot {
    /// 待签规范编码。
    fn signing_message(version: u64, digest: &str, issued_at: u64, ttl_secs: u64) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&version.to_be_bytes());
        m.extend_from_slice(digest.as_bytes());
        m.push(b'|');
        m.extend_from_slice(&issued_at.to_be_bytes());
        m.extend_from_slice(&ttl_secs.to_be_bytes());
        m
    }

    /// 内容摘要（策略集 canonical json 的 SM3）。
    pub fn compute_digest(policy: &PolicySet) -> Result<String, SnapshotError> {
        let json = serde_json::to_string(policy).map_err(|_| SnapshotError::DigestMismatch)?;
        let dg = Sm3Digest;
        Ok(hex::encode(dg.digest(json.as_bytes())))
    }

    /// 校验：**签名者信任锚** + 签名 + 摘要 + 租约有效性 + 未撤销。
    ///
    /// `expected_signer_pk` = 受信任 PDP 的公钥（hex）。这是关键安全检查：
    /// 只验签名有效性是不够的——攻击者可自签一个策略快照；必须确认签名者
    /// 就是本集群信任的 PDP。
    pub fn verify(
        &self,
        expected_signer_pk: &str,
        revoked: &[PolicyVersion],
        now_secs: u64,
    ) -> Result<(), SnapshotError> {
        // 0. 信任锚检查（签名者必须是受信任的 PDP）
        if self.signer_pk != expected_signer_pk {
            return Err(SnapshotError::UntrustedSigner);
        }
        // 1. 撤销检查
        if revoked.contains(&self.version) {
            return Err(SnapshotError::Revoked);
        }
        // 2. 租约检查
        if self.ttl_secs > 0 && now_secs > self.issued_at + self.ttl_secs {
            return Err(SnapshotError::Expired {
                issued: self.issued_at,
                ttl: self.ttl_secs,
                now: now_secs,
            });
        }
        // 3. 摘要检查（策略内容未被篡改）
        let computed = Self::compute_digest(&self.policy)?;
        if computed != self.digest {
            return Err(SnapshotError::DigestMismatch);
        }
        // 4. 签名检查
        let pk = hex::decode(&self.signer_pk).map_err(|_| SnapshotError::InvalidSignature)?;
        let verifier =
            Sm2Verifier::from_pk_bytes(&pk).map_err(|_| SnapshotError::InvalidSignature)?;
        let sig = hex::decode(&self.signature).map_err(|_| SnapshotError::InvalidSignature)?;
        let msg = Self::signing_message(
            self.version.0,
            &self.digest,
            self.issued_at,
            self.ttl_secs,
        );
        if !verifier.verify(&msg, &sig) {
            return Err(SnapshotError::InvalidSignature);
        }
        Ok(())
    }
}

/// 策略租约（Compute 侧持有的快照 + 续租状态）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyLease {
    pub snapshot: PolicySnapshot,
    /// 最近一次续租时刻。
    pub last_renewed_at: u64,
}

/// 快照管理器（PDP 侧：签发 + 撤销；Compute 侧：持有 + 校验）。
pub struct SnapshotManager {
    signer: Sm2Signer,
    pk_hex: String,
    ttl_secs: u64,
    /// 当前版本（签发时自增）。
    version: parking_lot::Mutex<u64>,
    /// 已撤销版本（撤销列表）。
    revoked: parking_lot::Mutex<Vec<PolicyVersion>>,
}

impl SnapshotManager {
    /// 从 PDP 私钥构造。`ttl_secs` = 快照租约 TTL（docs/00 §（4）：
    /// 与 KMS 租约周期对齐建议 900s）。
    pub fn from_sk(sk: &[u8], ttl_secs: u64) -> Result<Self, SnapshotError> {
        let signer = Sm2Signer::from_sk_bytes(sk).map_err(|_| SnapshotError::SignFailed)?;
        let pk_hex = hex::encode(signer.public_key_bytes());
        Ok(Self {
            signer,
            pk_hex,
            ttl_secs,
            version: parking_lot::Mutex::new(0),
            revoked: parking_lot::Mutex::new(Vec::new()),
        })
    }

    /// 签发新快照（版本自增）。
    pub fn issue(
        &self,
        policy: PolicySet,
        now_secs: u64,
    ) -> Result<PolicySnapshot, SnapshotError> {
        let version = {
            let mut v = self.version.lock();
            *v += 1;
            PolicyVersion(*v)
        };
        let mut policy = policy;
        policy.version = version;
        let digest = PolicySnapshot::compute_digest(&policy)?;
        let msg = PolicySnapshot::signing_message(version.0, &digest, now_secs, self.ttl_secs);
        let sig = self.signer.sign(&msg);
        if sig.is_empty() {
            return Err(SnapshotError::SignFailed);
        }
        Ok(PolicySnapshot {
            version,
            policy,
            digest,
            issued_at: now_secs,
            ttl_secs: self.ttl_secs,
            signature: hex::encode(&sig),
            signer_pk: self.pk_hex.clone(),
        })
    }

    /// 撤销指定版本（关键变更即时生效路径）。
    pub fn revoke(&self, version: PolicyVersion) {
        self.revoked.lock().push(version);
    }

    /// 当前撤销列表（下发给 Compute）。
    pub fn revoked(&self) -> Vec<PolicyVersion> {
        self.revoked.lock().clone()
    }

    /// 校验快照（使用本管理器的撤销列表 + 本 PDP 公钥作为信任锚）。
    pub fn verify(&self, snapshot: &PolicySnapshot, now_secs: u64) -> Result<(), SnapshotError> {
        let revoked = self.revoked();
        snapshot.verify(&self.pk_hex, &revoked, now_secs)
    }

    /// 本 PDP 公钥（hex；下发给 Compute 作信任锚）。
    pub fn public_key_hex(&self) -> &str {
        &self.pk_hex
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Effect, PolicyRule};

    const PDP_SK: [u8; 32] = [0x55; 32];

    fn policy() -> PolicySet {
        PolicySet::new(0).with_rule(PolicyRule {
            id: "allow-read".into(),
            effect: Effect::Permit,
            principal: "*".into(),
            action: "read".into(),
            resource: "*".into(),
            require_dominates: true,
            allow_trusted_downgrade: false,
        })
    }

    #[test]
    fn issue_and_verify() {
        let mgr = SnapshotManager::from_sk(&PDP_SK, 900).unwrap();
        let snap = mgr.issue(policy(), 1000).unwrap();
        assert_eq!(snap.version.0, 1);
        assert_eq!(snap.ttl_secs, 900);
        assert!(mgr.verify(&snap, 1500).is_ok());
    }

    #[test]
    fn expired_lease_rejected() {
        let mgr = SnapshotManager::from_sk(&PDP_SK, 900).unwrap();
        let snap = mgr.issue(policy(), 1000).unwrap();
        assert!(matches!(
            mgr.verify(&snap, 2000),
            Err(SnapshotError::Expired { .. })
        ));
    }

    #[test]
    fn revoked_snapshot_rejected() {
        let mgr = SnapshotManager::from_sk(&PDP_SK, 900).unwrap();
        let snap = mgr.issue(policy(), 1000).unwrap();
        mgr.revoke(snap.version);
        assert!(matches!(
            mgr.verify(&snap, 1100),
            Err(SnapshotError::Revoked)
        ));
    }

    #[test]
    fn tampered_policy_detected_by_digest() {
        let mgr = SnapshotManager::from_sk(&PDP_SK, 900).unwrap();
        let mut snap = mgr.issue(policy(), 1000).unwrap();
        // 篡改策略内容（加一条 permit 全部）
        snap.policy.rules.push(PolicyRule {
            id: "backdoor".into(),
            effect: Effect::Permit,
            principal: "*".into(),
            action: "*".into(),
            resource: "*".into(),
            require_dominates: false,
            allow_trusted_downgrade: false,
        });
        assert!(matches!(
            mgr.verify(&snap, 1100),
            Err(SnapshotError::DigestMismatch)
        ));
    }

    #[test]
    fn tampered_ttl_detected_by_signature() {
        let mgr = SnapshotManager::from_sk(&PDP_SK, 900).unwrap();
        let mut snap = mgr.issue(policy(), 1000).unwrap();
        snap.ttl_secs = 999_999; // 延长租约
        assert!(matches!(
            mgr.verify(&snap, 1100),
            Err(SnapshotError::InvalidSignature)
        ));
    }

    #[test]
    fn wrong_pdp_signer_rejected() {
        // 攻击者自签一个策略快照（签名本身有效，但签名者不是受信任 PDP）
        let attacker = SnapshotManager::from_sk(&[0x66; 32], 900).unwrap();
        let forged = attacker.issue(policy(), 1000).unwrap();
        // 受害者用自己的 PDP 公钥作信任锚验证 → 必须拒绝
        let victim_pdp = SnapshotManager::from_sk(&PDP_SK, 900).unwrap();
        assert!(matches!(
            victim_pdp.verify(&forged, 1100),
            Err(SnapshotError::UntrustedSigner)
        ));
    }

    #[test]
    fn trusted_signer_accepted_via_anchor() {
        // 正例：信任锚匹配时通过（验证信任锚不误伤正常路径）
        let pdp = SnapshotManager::from_sk(&PDP_SK, 900).unwrap();
        let snap = pdp.issue(policy(), 1000).unwrap();
        let anchor = pdp.public_key_hex().to_string();
        assert!(snap.verify(&anchor, &[], 1100).is_ok());
    }

    #[test]
    fn version_monotonic_across_issues() {
        let mgr = SnapshotManager::from_sk(&PDP_SK, 900).unwrap();
        let s1 = mgr.issue(policy(), 1000).unwrap();
        let s2 = mgr.issue(policy(), 1001).unwrap();
        let s3 = mgr.issue(policy(), 1002).unwrap();
        assert_eq!((s1.version.0, s2.version.0, s3.version.0), (1, 2, 3));
    }

    #[test]
    fn local_decision_via_snapshot_without_remote_call() {
        // docs/02 §6.2 核心：Compute 用快照本地决策，不远程同步
        let mgr = SnapshotManager::from_sk(&PDP_SK, 900).unwrap();
        let snap = mgr.issue(policy(), 1000).unwrap();
        mgr.verify(&snap, 1100).unwrap(); // 一次性校验（租约获取）

        // 之后本地决策多次（无远程调用）
        use crate::policy::{Decision, JtLabel, PolicyRequest, RequestContext};
        for _ in 0..100 {
            let r = PolicyRequest {
                principal: "alice".into(),
                principal_roles: vec![],
                action: "read".into(),
                resource: "table:t1".into(),
                subject_label: JtLabel::new(30, 0),
                resource_label: Some(JtLabel::new(20, 0)),
                context: RequestContext {
                    policy_version: snap.version.0,
                    node_id: "ps-1".into(),
                    now_secs: 1100,
                    trusted: false,
                },
            };
            assert!(matches!(snap.policy.evaluate(&r), Ok(Decision::Allow)));
        }
    }
}
