//! 证明证据模型（docs/02 §6.4、docs/13 §2.3）。

use serde::{Deserialize, Serialize};

/// 证明能力梯队（docs/13 §2.3）。
///
/// **排序不代表优劣**（`Ord` 仅由 derive 提供，勿用于比较）：三档是**互斥
/// 的能力标签**，语义分别是"满足生产承诺"、"实验特性"、"无硬件根信任"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttestationTier {
    /// 第一梯队（生产承诺）：TCM/TPCM PCR + 软件度量 + 防回滚计数器。
    Tier1 = 1,
    /// 第二梯队（实验特性）：TEE 远程证明（iTrustee / CSV）。
    Tier2Experimental = 2,
    /// **无硬件根信任**：平台无 TCM/TPCM（或缺防回滚计数器）。
    ///
    /// 此时证据仅由软件度量构成——**不构成 docs/13 §2.3 的第一梯队能力，
    /// 不得进入 SLO 与密评材料**。该档位存在的意义正是"如实标注"：让开发
    /// 与降级环境能跑通链路，同时不冒充生产承诺。
    ///
    /// 开发/测试可用（KMS 侧需显式 `require_tier1 = off` 放行），生产禁用。
    SoftwareOnly = 3,
}

/// 节点平台能力（capability flag；docs/13 §2.3 "实验能力以 capability flag 呈现"）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// TCM/TPCM 可用（第一梯队）。
    pub tcm_available: bool,
    /// 防回滚计数器可用（第一梯队；TCM NV 或安全文件）。
    pub rollback_counter_available: bool,
    /// 构建身份签名可用（第一梯队）。
    pub build_identity_available: bool,
    /// TEE 远程证明可用（第二梯队；鲲鹏 iTrustee / 海光 CSV）。
    pub tee_remote_attestation: bool,
}

impl Capabilities {
    /// 是否满足第一梯队（生产承诺的最低要求）。
    pub fn meets_tier1(&self) -> bool {
        self.tcm_available && self.rollback_counter_available
    }

    /// 有效梯队（按平台实际能力如实报告）。
    ///
    /// 判定顺序：TEE → 第一梯队 → 软件-only。
    ///
    /// **曾经此处只判 TEE**（`if tee { Tier2 } else { Tier1 }`），于是
    /// `Capabilities::default()`（全 false，即纯软件模拟）会报 **Tier1** ——
    /// 而 Tier1 是"进 SLO 与密评材料"的生产承诺档。这是**自我夸大**：无 TCM
    /// 的平台声称满足生产承诺，且该字段会流入审计与密评材料。
    ///
    /// 注意 `meets_tier1()` 本身是对的（要求 TCM + 防回滚计数器），校验链在
    /// `require_tier1 = true` 时也会正确拒绝；缺陷仅在于**报告的档位**说谎。
    /// 故本函数必须调用 `meets_tier1()` 而非只判 TEE。
    pub fn effective_tier(&self) -> AttestationTier {
        if self.tee_remote_attestation {
            // TEE 可用：实验特性档（docs/13 §2.3 明确"不进生产承诺"）
            AttestationTier::Tier2Experimental
        } else if self.meets_tier1() {
            AttestationTier::Tier1
        } else {
            AttestationTier::SoftwareOnly
        }
    }

    /// 该证据是否可用于生产承诺（进 SLO 与密评材料）。
    ///
    /// 与 [`Self::effective_tier`] 配套：Tier1 才算；Tier2Experimental 与
    /// SoftwareOnly 均不进生产承诺。
    pub fn meets_production_commitment(&self) -> bool {
        self.effective_tier() == AttestationTier::Tier1
    }
}

/// TCM/TPCM PCR 值。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    /// PCR 索引（如 0=固件、1=配置、10=IMA 度量）。
    pub index: u8,
    /// 摘要（SM3，hex）。
    pub digest: String,
}

/// 软件度量（无 TCM 平台时的降级路径）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareMeasurement {
    /// 被度量对象标识（如 "pageserver-binary"）。
    pub object: String,
    /// 度量摘要（SM3，hex）。
    pub digest: String,
}

/// 构建身份签名（证明二进制来自可信构建）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildIdentity {
    /// 构建标识（如 git commit）。
    pub build_id: String,
    /// 构建产物摘要（SM3，hex）。
    pub artifact_digest: String,
    /// 构建签名（SM2，hex；由 CI 私钥签）。
    pub signature: String,
    /// 构建签名者公钥（hex）。
    pub signer_pk: String,
}

/// 证明证据（节点提交给 jt-attest）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// 节点标识（docs/13 §4 enrollment 绑定）。
    pub node_id: String,
    /// 平台能力。
    pub capabilities: Capabilities,
    /// TCM/TPCM PCR 值（第一梯队；空 = 无 TCM）。
    pub pcrs: Vec<PcrValue>,
    /// 软件度量（降级路径）。
    pub software_measurements: Vec<SoftwareMeasurement>,
    /// 构建身份。
    pub build_identity: Option<BuildIdentity>,
    /// 防回滚计数器当前值。
    pub rollback_counter: u64,
    /// 节点声明的密钥对公钥（enrollment：绑定 CSR 公钥 ↔ 度量 ↔ node_id）。
    pub node_pk: String,
    /// 证据采集时刻（Unix 秒）。
    pub collected_at: u64,
}

impl AttestationEvidence {
    /// 证据总摘要（SM3 of canonical 编码；用于绑定到 KMS 租约）。
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        use jt_crypto_api::Digest256 as _;
        let dg = jt_crypto_sm::Sm3Digest;
        let json = serde_json::to_string(self)?;
        Ok(hex::encode(dg.digest(json.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(tcm: bool, counter: bool, build: bool, tee: bool) -> Capabilities {
        Capabilities {
            tcm_available: tcm,
            rollback_counter_available: counter,
            build_identity_available: build,
            tee_remote_attestation: tee,
        }
    }

    #[test]
    fn no_hardware_root_reports_software_only_not_tier1() {
        // 回归保护：曾经 effective_tier 只判 TEE，导致"全 false"的平台报
        // Tier1（生产承诺档）—— 自我夸大，且该字段流入审计与密评材料。
        let c = Capabilities::default();
        assert_eq!(
            c.effective_tier(),
            AttestationTier::SoftwareOnly,
            "无 TCM/无防回滚计数器的平台不得报 Tier1"
        );
        assert!(!c.meets_tier1());
        assert!(!c.meets_production_commitment());
    }

    #[test]
    fn tcm_but_no_counter_is_software_only() {
        // 第一梯队要求 TCM **且** 防回滚计数器；只满足其一不算
        let c = caps(true, false, true, false);
        assert_eq!(c.effective_tier(), AttestationTier::SoftwareOnly);
        assert!(!c.meets_production_commitment());
    }

    #[test]
    fn full_tier1_capabilities_report_tier1() {
        let c = caps(true, true, true, false);
        assert_eq!(c.effective_tier(), AttestationTier::Tier1);
        assert!(c.meets_production_commitment());
    }

    #[test]
    fn tee_platform_reports_experimental_even_with_tcm() {
        // TEE 可用 → 实验特性档（docs/13 §2.3 明确不进生产承诺）
        let c = caps(true, true, true, true);
        assert_eq!(c.effective_tier(), AttestationTier::Tier2Experimental);
        assert!(
            !c.meets_production_commitment(),
            "TEE 档不进生产承诺"
        );
    }

    #[test]
    fn software_only_is_distinguishable_from_tier2() {
        // 两档必须可区分：软件-only 是"缺硬件根信任"，Tier2 是"有更强能力
        // 但生态未成熟"。混为一谈会让密评无法判断平台是否满足承诺。
        assert_ne!(
            AttestationTier::SoftwareOnly,
            AttestationTier::Tier2Experimental
        );
        let sw = caps(false, false, false, false).effective_tier();
        let t2 = caps(false, false, false, true).effective_tier();
        assert_ne!(sw, t2);
    }

    #[test]
    fn build_identity_alone_does_not_upgrade_tier() {
        // 构建身份是加分项但不是梯队判据（第一梯队判据是 TCM + 计数器）
        let c = caps(false, false, true, false);
        assert_eq!(c.effective_tier(), AttestationTier::SoftwareOnly);
    }
}
