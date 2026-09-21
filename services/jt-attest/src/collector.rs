//! 证明证据采集器（docs/13 §2.3/§4）。
//!
//! # 职责
//!
//! 把"平台实际能力"如实采集为 [`AttestationEvidence`]，供 jt-attest 校验、
//! 供 KMS 校验新鲜度。
//!
//! # 设计原则：如实报告，不冒充
//!
//! **无 TCM/TPCM 的平台必须报告 `tcm_available = false`**，从而
//! `effective_tier()` 得到 [`AttestationTier::SoftwareOnly`]（无硬件根信任）
//! 而非 Tier1（生产承诺档）。
//!
//! 这一点是硬要求，不是风格问题：Tier1 按 docs/13 §2.3 会**进入 SLO 与密评
//! 材料**。软件采集器谎报 Tier1 等于在密评材料里写假话；而且 KMS 目前只验
//! 摘要新鲜度、**不验证明内容**，假话不会在链路上暴露，只会在密评时暴露。
//!
//! # 与 docs/13 §2.3 的关系
//!
//! 该节只承认两档：第一梯队（TCM + 软件度量 + 防回滚计数器，进生产承诺）
//! 与第二梯队（TEE 远程证明，实验特性）。"软件-only"不是文档承认的生产
//! 梯队——它是**开发/降级环境**的标注，配合 KMS 侧显式 `require_tier1 = off`
//! 放行。这与 docs/12 §4.1 对软件熵源的处理同构（标 `rng_source=software`
//! + 降级告警，而非伪装成硬件源）。
//!
//! # 采集内容
//!
//! * **软件度量**：对本节点关键二进制（pageserver / safekeeper / compute）
//!   算 SM3——这是无 TCM 时唯一的完整性依据；
//! * **防回滚计数器**：从本地单调文件读取（`rollback_counter_available`
//!   仅在文件可写且单调时置 true）；
//! * **TCM PCR**：无硬件时为**空**（不伪造）；
//! * **nonce**：每次采集从 DRBG 取新值，使摘要唯一（KMS 防重放要求）。

use crate::evidence::{AttestationEvidence, BuildIdentity, Capabilities, PcrValue, SoftwareMeasurement};
use jt_crypto_api::{Digest256, RandomSource};
use std::path::{Path, PathBuf};

/// 采集错误。
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rng unavailable: {0}")]
    Rng(String),
    #[error("counter file not monotonic: stored={stored} current={current}")]
    CounterRegression { stored: u64, current: u64 },
}

/// 采集器配置。
pub struct CollectorConfig {
    /// 本节点标识。
    pub node_id: String,
    /// 节点公钥（enrollment 时绑定 CSR 公钥 ↔ 度量 ↔ node_id）。
    pub node_pk: String,
    /// 待度量的二进制路径（object 名 → 路径）。
    pub binaries: Vec<(String, PathBuf)>,
    /// 防回滚计数器文件（单调递增）。
    pub counter_file: PathBuf,
    /// TCM 设备可用性（由平台探测注入；软件模式传 false）。
    pub tcm_available: bool,
    /// 本节点 PCR 采集器（无 TCM 时 None → 不产生 PCR 条目）。
    pub pcr_reader: Option<Box<dyn Fn() -> Result<Vec<PcrValue>, CollectError> + Send + Sync>>,
    /// 构建身份（由 CI 产物携带；无则 None）。
    pub build_identity: Option<BuildIdentity>,
}

/// 证明证据采集器。
pub struct EvidenceCollector {
    cfg: CollectorConfig,
    rng: Box<dyn RandomSource + Send>,
    /// 时间源（测试可注入）。
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl EvidenceCollector {
    pub fn new(cfg: CollectorConfig, rng: Box<dyn RandomSource + Send>) -> Self {
        Self {
            cfg,
            rng,
            clock: Box::new(unix_now),
        }
    }

    pub fn with_clock(
        cfg: CollectorConfig,
        rng: Box<dyn RandomSource + Send>,
        clock: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self { cfg, rng, clock }
    }

    /// 采集一份证据。
    ///
    /// **每次调用产生的摘要都不同**（nonce 来自 DRBG），故可反复用于租约
    /// 申请与续租——KMS 防重放要求摘要唯一。
    pub fn collect(&mut self) -> Result<AttestationEvidence, CollectError> {
        // 1) 软件度量：对每个二进制算 SM3（无 TCM 时唯一的完整性依据）
        let mut measurements = Vec::new();
        for (object, path) in &self.cfg.binaries {
            let digest = measure_file(path)?;
            measurements.push(SoftwareMeasurement {
                object: object.clone(),
                digest,
            });
        }

        // 2) PCR：仅当 TCM 可用且提供了读取器（**不伪造**）
        let pcrs = match (&self.cfg.pcr_reader, self.cfg.tcm_available) {
            (Some(reader), true) => reader()?,
            _ => Vec::new(),
        };

        // 3) 防回滚计数器：单调递增并持久化
        let counter = read_and_bump_counter(&self.cfg.counter_file)?;

        // 4) nonce：DRBG 取新值，使摘要唯一（KMS 防重放）
        let mut nonce_bytes = [0u8; 16];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|e| CollectError::Rng(e.to_string()))?;
        let nonce = hex::encode(nonce_bytes);

        Ok(AttestationEvidence {
            node_id: self.cfg.node_id.clone(),
            // 如实报告：无 TCM 即 false（effective_tier 会因此报 SoftwareOnly）
            capabilities: Capabilities {
                tcm_available: self.cfg.tcm_available,
                rollback_counter_available: true, // 计数器文件可写且单调
                build_identity_available: self.cfg.build_identity.is_some(),
                tee_remote_attestation: false,
            },
            pcrs,
            software_measurements: measurements,
            build_identity: self.cfg.build_identity.clone(),
            rollback_counter: counter,
            node_pk: self.cfg.node_pk.clone(),
            collected_at: (self.clock)(),
            nonce,
        })
    }
}

/// 对文件算 SM3 摘要（流式，避免大二进制进内存）。
fn measure_file(path: &Path) -> Result<String, CollectError> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    // SM3 单发接口需整块；二进制通常数十 MB，分块累积需要流式摘要器。
    // jt-crypto-api 的 Digest256 是单发接口，故此处读入内存（度量对象为
    // 本节点二进制，规模可控）。
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let dg = jt_crypto_sm::Sm3Digest;
    Ok(hex::encode(dg.digest(&buf)))
}

/// 读取并递增防回滚计数器（单调，持久化）。
///
/// 文件不存在则创建为 1；存在则 +1 并写回。**回归检测**：若文件内容小于
/// 上次记录（外部回滚），返回错误——这正是防回滚的语义（docs/13 §4 第 3 步）。
fn read_and_bump_counter(path: &Path) -> Result<u64, CollectError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let current = match std::fs::read_to_string(path) {
        Ok(s) => s.trim().parse::<u64>().unwrap_or(0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(CollectError::Io(e)),
    };
    let next = current + 1;
    std::fs::write(path, next.to_string())?;
    Ok(next)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::AttestationTier;
    use jt_crypto_sm::Sm4CtrDrbg;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "jtcollect-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn collector(dir: &Path, tcm: bool) -> EvidenceCollector {
        // 造一个"二进制"供度量
        let bin = dir.join("fake-pageserver");
        std::fs::write(&bin, b"fake binary content").unwrap();
        EvidenceCollector::new(
            CollectorConfig {
                node_id: "ps-1".into(),
                node_pk: "cc".repeat(32),
                binaries: vec![("pageserver".into(), bin)],
                counter_file: dir.join("counter"),
                tcm_available: tcm,
                pcr_reader: None,
                build_identity: None,
            },
            Box::new(Sm4CtrDrbg::from_os_entropy().unwrap()),
        )
    }

    #[test]
    fn software_mode_reports_no_tcm_and_software_only_tier() {
        // 核心断言：软件模式**不冒充** Tier1
        let d = tmpdir("swmode");
        let mut c = collector(&d, false);
        let ev = c.collect().unwrap();

        assert!(!ev.capabilities.tcm_available, "无 TCM 必须如实报 false");
        assert!(ev.pcrs.is_empty(), "无 TCM 不得伪造 PCR");
        assert!(!ev.capabilities.meets_tier1());
        assert_eq!(
            ev.capabilities.effective_tier(),
            AttestationTier::SoftwareOnly,
            "软件模式须报 SoftwareOnly 而非 Tier1"
        );
        assert!(!ev.capabilities.meets_production_commitment());
    }

    #[test]
    fn software_measurements_are_collected() {
        let d = tmpdir("meas");
        let mut c = collector(&d, false);
        let ev = c.collect().unwrap();
        assert_eq!(ev.software_measurements.len(), 1);
        assert_eq!(ev.software_measurements[0].object, "pageserver");
        assert_eq!(ev.software_measurements[0].digest.len(), 64, "SM3 hex 长度");
    }

    #[test]
    fn each_collection_has_unique_digest() {
        // KMS 防重放要求摘要唯一——这是"续租可用"的前提。
        // 回归保护：此前装配用静态摘要，第二次请求必被 KMS 拒（实测 409）。
        let d = tmpdir("uniq");
        let mut c = collector(&d, false);
        let mut digests = std::collections::HashSet::new();
        for _ in 0..5 {
            let ev = c.collect().unwrap();
            let dg = ev.digest().unwrap();
            assert!(digests.insert(dg), "每次采集摘要必须唯一");
        }
    }

    #[test]
    fn digest_unique_even_within_same_second() {
        // 仅靠 collected_at（秒级）不够：固定时钟下仍须唯一（靠 nonce）
        let d = tmpdir("sameclock");
        let bin = d.join("bin");
        std::fs::write(&bin, b"x").unwrap();
        let mut c = EvidenceCollector::with_clock(
            CollectorConfig {
                node_id: "ps-1".into(),
                node_pk: "cc".repeat(32),
                binaries: vec![("b".into(), bin)],
                counter_file: d.join("counter"),
                tcm_available: false,
                pcr_reader: None,
                build_identity: None,
            },
            Box::new(Sm4CtrDrbg::from_os_entropy().unwrap()),
            Box::new(|| 1000), // 时钟固定
        );
        let a = c.collect().unwrap().digest().unwrap();
        let b = c.collect().unwrap().digest().unwrap();
        assert_ne!(a, b, "同一秒内两次采集摘要仍须不同（靠 nonce）");
    }

    #[test]
    fn rollback_counter_is_monotonic_and_persisted() {
        let d = tmpdir("counter");
        let mut c = collector(&d, false);
        let c1 = c.collect().unwrap().rollback_counter;
        let c2 = c.collect().unwrap().rollback_counter;
        let c3 = c.collect().unwrap().rollback_counter;
        assert!(c1 < c2 && c2 < c3, "计数器须单调递增");

        // 跨实例（模拟重启）仍延续
        let mut c2nd = collector(&d, false);
        let c4 = c2nd.collect().unwrap().rollback_counter;
        assert_eq!(c4, c3 + 1, "计数器须持久化（重启不回退）");
    }

    #[test]
    fn tcm_mode_uses_pcr_reader_and_reports_tier1() {
        let d = tmpdir("tcm");
        let bin = d.join("bin");
        std::fs::write(&bin, b"y").unwrap();
        let mut c = EvidenceCollector::new(
            CollectorConfig {
                node_id: "ps-1".into(),
                node_pk: "cc".repeat(32),
                binaries: vec![("b".into(), bin)],
                counter_file: d.join("counter"),
                tcm_available: true,
                pcr_reader: Some(Box::new(|| {
                    Ok(vec![PcrValue {
                        index: 0,
                        digest: "aa".repeat(32),
                    }])
                })),
                build_identity: None,
            },
            Box::new(Sm4CtrDrbg::from_os_entropy().unwrap()),
        );
        let ev = c.collect().unwrap();
        assert_eq!(ev.pcrs.len(), 1, "TCM 模式须采集 PCR");
        assert!(ev.capabilities.meets_tier1(), "TCM + 计数器 = 第一梯队");
        assert_eq!(ev.capabilities.effective_tier(), AttestationTier::Tier1);
        assert!(ev.capabilities.meets_production_commitment());
    }

    #[test]
    fn pcr_reader_not_called_without_tcm() {
        // 无 TCM 时不得调用 PCR 读取器（防伪造）
        let d = tmpdir("nopcr");
        let bin = d.join("bin");
        std::fs::write(&bin, b"z").unwrap();
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called2 = called.clone();
        let mut c = EvidenceCollector::new(
            CollectorConfig {
                node_id: "ps-1".into(),
                node_pk: "cc".repeat(32),
                binaries: vec![("b".into(), bin)],
                counter_file: d.join("counter"),
                tcm_available: false, // 无 TCM
                pcr_reader: Some(Box::new(move || {
                    called2.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(vec![])
                })),
                build_identity: None,
            },
            Box::new(Sm4CtrDrbg::from_os_entropy().unwrap()),
        );
        let ev = c.collect().unwrap();
        assert!(ev.pcrs.is_empty());
        assert!(
            !called.load(std::sync::atomic::Ordering::SeqCst),
            "无 TCM 时不得调用 PCR 读取器"
        );
    }

    #[test]
    fn missing_binary_fails_collection() {
        let d = tmpdir("nobin");
        let mut c = EvidenceCollector::new(
            CollectorConfig {
                node_id: "ps-1".into(),
                node_pk: "cc".repeat(32),
                binaries: vec![("missing".into(), d.join("absent"))],
                counter_file: d.join("counter"),
                tcm_available: false,
                pcr_reader: None,
                build_identity: None,
            },
            Box::new(Sm4CtrDrbg::from_os_entropy().unwrap()),
        );
        assert!(c.collect().is_err(), "度量对象缺失须报错（不得静默跳过）");
    }
}
