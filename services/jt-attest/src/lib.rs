//! JTDB 证明服务（jt-attest，docs/02 §6.4、docs/13 §2.3/§4）。
//!
//! 职责：采集节点度量证据（TCM/TPCM PCR、软件度量、TEE 远程证明、
//! 构建身份签名、防回滚计数器），产出**证明结论**；该结论**参与 KMS
//! 密钥释放**（docs/02 §6.4："证明结果参与 KMS 密钥释放，而不仅写日志"）。
//!
//! 能力梯队（docs/13 §2.3）：
//! * 第一梯队（生产承诺）：TCM/TPCM 度量与 PCR、软件度量、防回滚计数器；
//! * 第二梯队（实验）：鲲鹏 iTrustee、海光 CSV 远程证明——以 capability
//!   flag 呈现，平台缺失时按第一梯队语义**降级**（不承诺同等 TEE 强举证）。
//!
//! 本模块为纯逻辑层（证据模型 + 校验 + 结论 + 密钥释放门槛）；真实
//! TCM/TEE 设备交互（ioctl / secGear）为后续。

pub mod evidence;
pub mod verdict;

pub use evidence::{
    AttestationEvidence, AttestationTier, BuildIdentity, Capabilities, PcrValue, SoftwareMeasurement,
};
pub use verdict::{AttestationError, AttestationVerdict, Attestor, KeyReleaseGate};
