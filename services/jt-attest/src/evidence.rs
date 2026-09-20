//! 证明证据模型（docs/02 §6.4、docs/13 §2.3）。

use serde::{Deserialize, Serialize};

/// 证明能力梯队（docs/13 §2.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttestationTier {
    /// 第一梯队（生产承诺）：TCM/TPCM PCR + 软件度量 + 防回滚计数器。
    Tier1 = 1,
    /// 第二梯队（实验特性）：TEE 远程证明（iTrustee / CSV）。
    Tier2Experimental = 2,
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

    /// 有效梯队（平台缺失高阶能力时降级）。
    pub fn effective_tier(&self) -> AttestationTier {
        if self.tee_remote_attestation {
            AttestationTier::Tier2Experimental
        } else {
            AttestationTier::Tier1
        }
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
