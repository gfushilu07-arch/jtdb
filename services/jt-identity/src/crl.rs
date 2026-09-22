//! CRL 签发与撤销传播（docs/13 §5、§8）。
//!
//! # 撤销传播 ≤5 分钟（SLO）
//!
//! docs/13 §5 把"撤销传播 ≤5 分钟"写入 SLO 验收。达成它需要两件事：
//!
//! 1. **CRL 可被快速重签**：CRL 是 CA 私钥签名的列表，重签成本低；
//! 2. **组件能拉到新 CRL**：本模块提供 `crl_der()`；组件侧定时拉取（或
//!    由 jt-controller 推送）后热加载。
//!
//! 本模块只负责"签发"，不负责"推送"——推送属控制平面（docs/13 §7 的
//! 轮换协调职责）。**这一分工是有意的**：把推送放进 CA 会让 CA 承担
//! 网络职责，违背 ADR-003 的平面职责边界。
//!
//! # 离线部署的 CRL 过期策略
//!
//! docs/13 §9.3 要求部署档案在"严格模式"（CRL 过期后拒绝新会话）与
//! "可用模式"（沿用最后 CRL + 告警，需 secadmin 与 auditor 双人签署）中
//! 二选一。本模块用 `CrlFreshness` 表达该选择，并由调用方（组件）执行；
//! **默认严格模式**（fail-closed）——可用模式必须显式开启。

use crate::ca::Ca;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::x509::{X509Crl, X509CrlBuilder, X509NameBuilder, X509RevokedBuilder};
use std::time::{SystemTime, UNIX_EPOCH};

/// CRL 有效期（docs/13 §9.3：在线默认短周期，便于快速传播撤销）。
pub const CRL_VALIDITY_HOURS: u32 = 24;

/// CRL 过期后的行为（docs/13 §9.3 的部署档案必选项）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlFreshness {
    /// 严格模式（默认）：CRL 过期后拒绝新 TLS 会话（fail-closed）。
    Strict,
    /// 可用模式：沿用最后 CRL + 持续告警。
    ///
    /// **必须由 secadmin 与 auditor 双人签署启用**（docs/13 §9.3）——
    /// 本类型只表达状态，双人签署的流程在控制平面侧落实。
    BestEffort,
}

impl Default for CrlFreshness {
    fn default() -> Self {
        // 默认严格：一个"默认放宽"的安全策略等于没有策略
        CrlFreshness::Strict
    }
}

/// 撤销条目（序列号 + 时间 + 原因）。
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    pub serial_hex: String,
    /// 撤销时间（Unix 秒）。
    pub revoked_at: u64,
    pub reason: String,
}

/// 用 CA 私钥签发 CRL。
///
/// `entries` 为空时也签发（**空 CRL 有意义**：它告诉组件"当前无撤销"，
/// 且刷新了 `thisUpdate`，使严格模式下的"CRL 过期"判定得以延续）。
pub fn sign_crl(ca: &Ca, entries: &[RevokedEntry]) -> Result<Vec<u8>, CrlError> {
    let mut nb = X509NameBuilder::new().map_err(CrlError::openssl)?;
    nb.append_entry_by_text("CN", &ca.subject).map_err(CrlError::openssl)?;
    let issuer = nb.build();

    let mut b = X509CrlBuilder::new().map_err(CrlError::openssl)?;
    b.set_issuer_name(&issuer).map_err(CrlError::openssl)?;
    let this_update = Asn1Time::days_from_now(0).map_err(CrlError::openssl)?;
    b.set_last_update(&this_update).map_err(CrlError::openssl)?;
    let next_update = Asn1Time::from_unix(
        now_secs() as i64 + (CRL_VALIDITY_HOURS as i64) * 3600,
    )
    .map_err(CrlError::openssl)?;
    b.set_next_update(&next_update).map_err(CrlError::openssl)?;

    for e in entries {
        // 序列号是 hex 字符串 → BigNum → ASN.1 INTEGER
        let bn = BigNum::from_hex_str(&e.serial_hex).map_err(CrlError::openssl)?;
        let serial = bn.to_asn1_integer().map_err(CrlError::openssl)?;
        let rev_time = Asn1Time::from_unix(e.revoked_at as i64).map_err(CrlError::openssl)?;

        let mut rb = X509RevokedBuilder::new().map_err(CrlError::openssl)?;
        rb.set_serial_number(&serial).map_err(CrlError::openssl)?;
        rb.set_revocation_date(&rev_time).map_err(CrlError::openssl)?;
        // 撤销原因码统一不设：人类可读原因由 jt-identity 的审计日志承载，
        // CRL 只承载"已撤销"这一事实（原因码取值语义在各实现间不一致，
        // 写错反而误导）
        b.add_revoked(rb.build()).map_err(CrlError::openssl)?;
    }

    /*
     * Authority Key Identifier：**OpenSSL 强制要求** CRL 带此扩展
     * （`X509_CRL_sign` 会以 "CRL must have an Authority Key Identifier
     * extension" 拒绝，实测踩到）。语义上也必要：它让验签方能确定
     * "这份 CRL 是哪个密钥签的"——同一 CA 轮换密钥后，旧 CRL 不会被
     * 误当作新密钥签发的。
     *
     * `keyid(true)` = always 包含 keyIdentifier（而非仅在必要时）。
     */
    let aki = ca.authority_key_id_extension().map_err(CrlError::Ca)?;
    b.append_extension(aki).map_err(CrlError::openssl)?;

    /*
     * CRL Number：**OpenSSL 强制要求**（否则 `X509_CRL_sign` 报
     * "CRL must have a Crl Number extension"，实测踩到）。
     *
     * 语义上也必要（RFC 5280 §5.2.3）：客户端据此判断"这份 CRL 是否比手上
     * 的新"——缺它则无法区分新旧 CRL，撤销可能被旧 CRL 覆盖回去。
     * 用单调递增的序号（基于签发时刻的秒数）。
     */
    let mut crl_num = BigNum::new().map_err(CrlError::openssl)?;
    crl_num
        .add_word(now_secs() as u32) // 单调递增（基于签发时刻）
        .map_err(CrlError::openssl)?;
    let crl_ext = openssl::x509::extension::CrlNumber::new(crl_num)
        .map_err(CrlError::openssl)?
        .build()
        .map_err(CrlError::openssl)?;
    b.append_extension(crl_ext).map_err(CrlError::openssl)?;

    let key = ca.private_key_for_crl().map_err(CrlError::Ca)?;
    b.sign(key, MessageDigest::sm3()).map_err(CrlError::openssl)?;
    let crl = b.build().map_err(CrlError::openssl)?;
    crl.to_der().map_err(CrlError::openssl)
}

/// 校验 CRL 是否由该 CA 签发（防止伪造 CRL 清空撤销列表）。
pub fn verify_crl(ca: &Ca, crl_der: &[u8]) -> Result<bool, CrlError> {
    let crl = X509Crl::from_der(crl_der).map_err(CrlError::openssl)?;
    let ca_cert = ca.cert_for_crl_check().map_err(CrlError::Ca)?;
    let pubkey = ca_cert.public_key().map_err(CrlError::openssl)?;
    crl.verify(&pubkey).map_err(CrlError::openssl)
}

/// 判断 CRL 是否已过期（严格模式据此拒绝新会话）。
pub fn is_expired(crl_der: &[u8]) -> Result<bool, CrlError> {
    let crl = X509Crl::from_der(crl_der).map_err(CrlError::openssl)?;
    let now = Asn1Time::days_from_now(0).map_err(CrlError::openssl)?;
    // nextUpdate < now ⇒ 过期
    Ok(crl.next_update().map(|n| n.compare(&now).map(|o| o == std::cmp::Ordering::Less).unwrap_or(true)).unwrap_or(true))
}

#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    #[error("openssl: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),
    #[error("ca: {0}")]
    Ca(#[from] crate::ca::CaError),
}

impl CrlError {
    fn openssl(e: openssl::error::ErrorStack) -> Self {
        CrlError::Openssl(e)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CaKind;

    fn ca() -> Ca {
        Ca::generate(CaKind::Component, "CRL Test CA").unwrap()
    }

    #[test]
    fn empty_crl_is_valid_and_verifiable() {
        // 空 CRL 有意义：刷新 thisUpdate，使严格模式的"过期"判定得以延续
        let c = ca();
        let der = sign_crl(&c, &[]).unwrap();
        assert!(verify_crl(&c, &der).unwrap());
        assert!(!is_expired(&der).unwrap());
    }

    #[test]
    fn crl_with_entries_verifies() {
        let c = ca();
        let der = sign_crl(
            &c,
            &[RevokedEntry {
                serial_hex: "0A1B2C".into(),
                revoked_at: now_secs(),
                reason: "key compromise".into(),
            }],
        )
        .unwrap();
        assert!(verify_crl(&c, &der).unwrap());
        let crl = X509Crl::from_der(&der).unwrap();
        // 条目必须真的进到 CRL 里（否则"撤销"只是本地状态，对端看不到）
        let n = crl.get_revoked().map(|s| s.into_iter().count()).unwrap_or(0);
        assert_eq!(n, 1);
    }

    #[test]
    fn crl_from_other_ca_is_rejected() {
        // 反证：伪造 CA 的 CRL 不得被接受（否则攻击者可用空 CRL 清空撤销列表）
        let c1 = ca();
        let c2 = ca();
        let der = sign_crl(&c2, &[]).unwrap();
        assert!(!verify_crl(&c1, &der).unwrap());
    }

    #[test]
    fn freshness_defaults_to_strict() {
        // 默认必须严格（fail-closed）：默认放宽的安全策略等于没有策略
        assert_eq!(CrlFreshness::default(), CrlFreshness::Strict);
    }
}
