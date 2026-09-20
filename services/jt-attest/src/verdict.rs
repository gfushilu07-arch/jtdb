//! 证明结论与密钥释放门槛（docs/02 §6.4）。

use crate::evidence::{AttestationEvidence, AttestationTier};
use jt_crypto_api::{Digest256 as _, SignatureVerifier};
use jt_crypto_sm::{Sm2Verifier, Sm3Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 证明错误。
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("insufficient capabilities: {0} (tier1 requires TCM + rollback counter)")]
    InsufficientCapabilities(String),
    #[error("PCR measurement mismatch: pcr[{index}] expected {expected}, got {got}")]
    PcrMismatch {
        index: u8,
        expected: String,
        got: String,
    },
    #[error("software measurement mismatch for '{object}': expected {expected}, got {got}")]
    SoftwareMismatch {
        object: String,
        expected: String,
        got: String,
    },
    #[error("build identity invalid: {0}")]
    BuildIdentityInvalid(String),
    #[error("rollback detected: evidence counter {seen} < recorded {recorded}")]
    RollbackDetected { seen: u64, recorded: u64 },
    #[error("evidence digest mismatch")]
    DigestMismatch,
}

/// 证明结论（参与 KMS 密钥释放）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationVerdict {
    pub node_id: String,
    /// 结论：通过 / 拒绝（含理由）。
    pub passed: bool,
    pub reason: String,
    /// 生效梯队（平台能力缺失时降级）。
    pub effective_tier: AttestationTier,
    /// 证据摘要（绑定到 KMS 租约，docs/02 §6.3 续租携带新鲜 attestation 摘要）。
    pub evidence_digest: String,
    /// 结论签发时刻。
    pub verified_at: u64,
}

/// 密钥释放门槛（docs/02 §6.4："证明结果参与 KMS 密钥释放，而不仅写日志"）。
///
/// KMS 在发放租约前调用 `KeyReleaseGate::check()`——只有通过的结论才能
/// 换取 DEK。
pub struct KeyReleaseGate;

impl KeyReleaseGate {
    /// 判定是否允许释放密钥。
    ///
    /// 规则：结论必须 `passed == true`，且证据摘要非空（绑定有效）。
    pub fn check(verdict: &AttestationVerdict) -> Result<(), AttestationError> {
        if !verdict.passed {
            return Err(AttestationError::BuildIdentityInvalid(format!(
                "attestation denied: {}",
                verdict.reason
            )));
        }
        if verdict.evidence_digest.is_empty() {
            return Err(AttestationError::DigestMismatch);
        }
        Ok(())
    }
}

/// 证明器（jt-attest 侧：校验证据 + 产出结论）。
///
/// 参考值（expected PCR / 度量 / 构建身份公钥）由管理员在集群初始化时
/// 登记（docs/13 §4 预登记）。
pub struct Attestor {
    /// 期望 PCR 值（index → digest hex）。
    expected_pcrs: HashMap<u8, String>,
    /// 期望软件度量（object → digest hex）。
    expected_measurements: HashMap<String, String>,
    /// 受信任的构建签名者公钥（hex）。
    trusted_build_signers: Vec<String>,
    /// 防回滚计数器记录（node_id → 已见最大值）。
    rollback_counters: parking_lot::Mutex<HashMap<String, u64>>,
    /// 是否强制要求第一梯队能力（生产承诺）。
    require_tier1: bool,
}

impl Attestor {
    pub fn new(require_tier1: bool) -> Self {
        Self {
            expected_pcrs: HashMap::new(),
            expected_measurements: HashMap::new(),
            trusted_build_signers: Vec::new(),
            rollback_counters: parking_lot::Mutex::new(HashMap::new()),
            require_tier1,
        }
    }

    pub fn with_pcr(mut self, index: u8, digest_hex: &str) -> Self {
        self.expected_pcrs.insert(index, digest_hex.to_string());
        self
    }

    pub fn with_measurement(mut self, object: &str, digest_hex: &str) -> Self {
        self.expected_measurements
            .insert(object.to_string(), digest_hex.to_string());
        self
    }

    pub fn with_build_signer(mut self, pk_hex: &str) -> Self {
        self.trusted_build_signers.push(pk_hex.to_string());
        self
    }

    /// 校验证据并产出结论。
    ///
    /// 校验链（docs/13 §4）：
    /// 1. 能力梯队（require_tier1 时必须满足 TCM + 防回滚计数器）
    /// 2. PCR 度量（有 TCM 时逐条比对期望值）
    /// 3. 软件度量（降级路径）
    /// 4. 构建身份签名（签名者必须是受信任构建者）
    /// 5. 防回滚计数器（不得回退）
    pub fn verify(
        &self,
        evidence: &AttestationEvidence,
        now_secs: u64,
    ) -> Result<AttestationVerdict, AttestationError> {
        let evidence_digest = evidence
            .digest()
            .map_err(|_| AttestationError::DigestMismatch)?;

        let deny = |e: AttestationError| AttestationVerdict {
            node_id: evidence.node_id.clone(),
            passed: false,
            reason: e.to_string(),
            effective_tier: evidence.capabilities.effective_tier(),
            evidence_digest: evidence_digest.clone(),
            verified_at: now_secs,
        };

        // 1. 能力梯队
        if self.require_tier1 && !evidence.capabilities.meets_tier1() {
            return Ok(deny(AttestationError::InsufficientCapabilities(format!(
                "tcm={}, rollback_counter={}",
                evidence.capabilities.tcm_available,
                evidence.capabilities.rollback_counter_available
            ))));
        }

        // 2. PCR 度量比对（仅比对已登记的期望值；未登记 = 不校验）
        for (idx, expected) in &self.expected_pcrs {
            match evidence.pcrs.iter().find(|p| p.index == *idx) {
                Some(got) if &got.digest == expected => {}
                Some(got) => {
                    return Ok(deny(AttestationError::PcrMismatch {
                        index: *idx,
                        expected: expected.clone(),
                        got: got.digest.clone(),
                    }))
                }
                None => {
                    return Ok(deny(AttestationError::PcrMismatch {
                        index: *idx,
                        expected: expected.clone(),
                        got: "<missing>".to_string(),
                    }))
                }
            }
        }

        // 3. 软件度量比对
        for (obj, expected) in &self.expected_measurements {
            match evidence
                .software_measurements
                .iter()
                .find(|m| &m.object == obj)
            {
                Some(got) if &got.digest == expected => {}
                Some(got) => {
                    return Ok(deny(AttestationError::SoftwareMismatch {
                        object: obj.clone(),
                        expected: expected.clone(),
                        got: got.digest.clone(),
                    }))
                }
                None => {
                    return Ok(deny(AttestationError::SoftwareMismatch {
                        object: obj.clone(),
                        expected: expected.clone(),
                        got: "<missing>".to_string(),
                    }))
                }
            }
        }

        // 4. 构建身份签名（若提供则必须验证；有受信任签名者列表时必须提供）
        if let Some(bi) = &evidence.build_identity {
            if !self.trusted_build_signers.is_empty()
                && !self.trusted_build_signers.contains(&bi.signer_pk)
            {
                return Ok(deny(AttestationError::BuildIdentityInvalid(
                    "build signer not trusted".to_string(),
                )));
            }
            let pk = match hex::decode(&bi.signer_pk) {
                Ok(p) => p,
                Err(_) => {
                    return Ok(deny(AttestationError::BuildIdentityInvalid(
                        "bad signer pk hex".to_string(),
                    )))
                }
            };
            let verifier = match Sm2Verifier::from_pk_bytes(&pk) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(deny(AttestationError::BuildIdentityInvalid(
                        "bad signer pk".to_string(),
                    )))
                }
            };
            let sig = match hex::decode(&bi.signature) {
                Ok(s) => s,
                Err(_) => {
                    return Ok(deny(AttestationError::BuildIdentityInvalid(
                        "bad signature hex".to_string(),
                    )))
                }
            };
            // 签名消息 = build_id || artifact_digest
            let mut msg = Vec::new();
            msg.extend_from_slice(bi.build_id.as_bytes());
            msg.push(b'|');
            msg.extend_from_slice(bi.artifact_digest.as_bytes());
            if !verifier.verify(&msg, &sig) {
                return Ok(deny(AttestationError::BuildIdentityInvalid(
                    "signature invalid".to_string(),
                )));
            }
            // 构建产物摘要应与软件度量中的二进制度量一致（若有）
            if let Some(m) = evidence
                .software_measurements
                .iter()
                .find(|m| m.object.contains("binary"))
            {
                if m.digest != bi.artifact_digest {
                    return Ok(deny(AttestationError::BuildIdentityInvalid(
                        "artifact digest does not match measured binary".to_string(),
                    )));
                }
            }
        } else if !self.trusted_build_signers.is_empty() {
            return Ok(deny(AttestationError::BuildIdentityInvalid(
                "build identity required but absent".to_string(),
            )));
        }

        // 5. 防回滚计数器（单调；回退 = 重放旧镜像）
        {
            let mut counters = self.rollback_counters.lock();
            let recorded = counters.get(&evidence.node_id).copied().unwrap_or(0);
            if evidence.rollback_counter < recorded {
                return Ok(deny(AttestationError::RollbackDetected {
                    seen: evidence.rollback_counter,
                    recorded,
                }));
            }
            counters.insert(evidence.node_id.clone(), evidence.rollback_counter);
        }

        Ok(AttestationVerdict {
            node_id: evidence.node_id.clone(),
            passed: true,
            reason: "all checks passed".to_string(),
            effective_tier: evidence.capabilities.effective_tier(),
            evidence_digest,
            verified_at: now_secs,
        })
    }
}

/// 计算构建身份签名消息（CI 侧用；与 Attestor 校验口径一致）。
pub fn build_identity_message(build_id: &str, artifact_digest: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(build_id.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(artifact_digest.as_bytes());
    msg
}

/// 计算度量摘要（SM3；节点侧采集用）。
pub fn measure(data: &[u8]) -> String {
    let dg = Sm3Digest;
    hex::encode(dg.digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{BuildIdentity, Capabilities, PcrValue, SoftwareMeasurement};
    use jt_crypto_api::SignatureKey;
    use jt_crypto_sm::Sm2Signer;

    const BUILD_SK: [u8; 32] = [0x77; 32];

    fn caps_tier1() -> Capabilities {
        Capabilities {
            tcm_available: true,
            rollback_counter_available: true,
            build_identity_available: true,
            tee_remote_attestation: false,
        }
    }

    fn good_evidence() -> AttestationEvidence {
        AttestationEvidence {
            node_id: "ps-1".to_string(),
            capabilities: caps_tier1(),
            pcrs: vec![PcrValue {
                index: 0,
                digest: "aa".repeat(32),
            }],
            software_measurements: vec![SoftwareMeasurement {
                object: "pageserver-binary".to_string(),
                digest: "bb".repeat(32),
            }],
            build_identity: None,
            rollback_counter: 5,
            node_pk: "cc".repeat(32),
            collected_at: 1000,
        }
    }

    fn attestor() -> Attestor {
        Attestor::new(true)
            .with_pcr(0, &"aa".repeat(32))
            .with_measurement("pageserver-binary", &"bb".repeat(32))
    }

    #[test]
    fn happy_path_passes() {
        let a = attestor();
        let v = a.verify(&good_evidence(), 1000).unwrap();
        assert!(v.passed, "reason: {}", v.reason);
        assert_eq!(v.effective_tier, AttestationTier::Tier1);
        assert!(!v.evidence_digest.is_empty());
    }

    #[test]
    fn key_release_gate_allows_passed() {
        let a = attestor();
        let v = a.verify(&good_evidence(), 1000).unwrap();
        assert!(KeyReleaseGate::check(&v).is_ok());
    }

    #[test]
    fn key_release_gate_blocks_denied() {
        let a = Attestor::new(true); // 无期望值但 require_tier1
        let mut ev = good_evidence();
        ev.capabilities.tcm_available = false; // 能力不足
        let v = a.verify(&ev, 1000).unwrap();
        assert!(!v.passed);
        assert!(KeyReleaseGate::check(&v).is_err(), "证明失败必须阻断密钥释放");
    }

    #[test]
    fn pcr_mismatch_denied() {
        let a = attestor();
        let mut ev = good_evidence();
        ev.pcrs[0].digest = "dd".repeat(32); // 固件被改
        let v = a.verify(&ev, 1000).unwrap();
        assert!(!v.passed);
        assert!(v.reason.contains("PCR"), "reason: {}", v.reason);
    }

    #[test]
    fn missing_pcr_denied() {
        let a = attestor();
        let mut ev = good_evidence();
        ev.pcrs.clear();
        let v = a.verify(&ev, 1000).unwrap();
        assert!(!v.passed);
    }

    #[test]
    fn software_measurement_mismatch_denied() {
        let a = attestor();
        let mut ev = good_evidence();
        ev.software_measurements[0].digest = "ee".repeat(32); // 二进制被换
        let v = a.verify(&ev, 1000).unwrap();
        assert!(!v.passed);
    }

    #[test]
    fn build_identity_verified() {
        let signer = Sm2Signer::from_sk_bytes(&BUILD_SK).unwrap();
        let pk_hex = hex::encode(signer.public_key_bytes());
        let artifact = "bb".repeat(32);
        let msg = build_identity_message("git-abc123", &artifact);
        let sig = signer.sign(&msg);
        let bi = BuildIdentity {
            build_id: "git-abc123".to_string(),
            artifact_digest: artifact.clone(),
            signature: hex::encode(&sig),
            signer_pk: pk_hex.clone(),
        };
        let a = attestor().with_build_signer(&pk_hex);
        let mut ev = good_evidence();
        ev.build_identity = Some(bi.clone());
        let v = a.verify(&ev, 1000).unwrap();
        assert!(v.passed, "reason: {}", v.reason);

        // 伪造构建签名（另一把密钥）
        let attacker = Sm2Signer::from_sk_bytes(&[0x88; 32]).unwrap();
        let mut forged = bi.clone();
        forged.signer_pk = hex::encode(attacker.public_key_bytes());
        forged.signature = hex::encode(attacker.sign(&msg));
        let mut ev2 = good_evidence();
        ev2.build_identity = Some(forged);
        let v2 = a.verify(&ev2, 1000).unwrap();
        assert!(!v2.passed, "不受信任构建者必须拒绝");
    }

    #[test]
    fn build_identity_required_when_signers_registered() {
        let a = attestor().with_build_signer(&"11".repeat(64));
        // 未提供构建身份
        let v = a.verify(&good_evidence(), 1000).unwrap();
        assert!(!v.passed);
        assert!(v.reason.contains("required"), "reason: {}", v.reason);
    }

    #[test]
    fn rollback_counter_detected() {
        let a = attestor();
        let mut ev = good_evidence();
        ev.rollback_counter = 10;
        assert!(a.verify(&ev, 1000).unwrap().passed);
        // 重放旧镜像（计数器回退）
        ev.rollback_counter = 3;
        let v = a.verify(&ev, 1001).unwrap();
        assert!(!v.passed);
        assert!(v.reason.contains("rollback"), "reason: {}", v.reason);
    }

    #[test]
    fn tier1_required_denies_degraded_platform() {
        let a = Attestor::new(true);
        let mut ev = good_evidence();
        ev.capabilities.rollback_counter_available = false;
        let v = a.verify(&ev, 1000).unwrap();
        assert!(!v.passed, "生产承诺要求第一梯队能力");
    }

    #[test]
    fn tier2_platform_reports_experimental() {
        let a = Attestor::new(false); // 不强制 tier1
        let mut ev = good_evidence();
        ev.capabilities.tee_remote_attestation = true;
        let v = a.verify(&ev, 1000).unwrap();
        assert!(v.passed);
        assert_eq!(v.effective_tier, AttestationTier::Tier2Experimental);
    }

    #[test]
    fn evidence_digest_is_stable_and_binding() {
        let ev = good_evidence();
        let d1 = ev.digest().unwrap();
        let d2 = ev.digest().unwrap();
        assert_eq!(d1, d2, "同证据同摘要（可绑定到 KMS 租约）");
        let mut ev2 = good_evidence();
        ev2.rollback_counter = 6;
        assert_ne!(d1, ev2.digest().unwrap(), "证据变化摘要必须变");
    }
}
