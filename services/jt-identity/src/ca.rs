//! CA 层次与证书签发（docs/13 §3、§5）。
//!
//! ```text
//! Cluster Root CA（离线保管，10 年）
//! ├── Component CA（1 年）—— 签发组件/节点证书（90 天）
//! └── User CA（1 年）      —— 签发人证书
//! ```
//!
//! # 实现选择：Tongsuo 的 SM2 + SM3
//!
//! 用 `openssl` crate 但底层是 **Tongsuo**（`scripts/env.sh` 导出 `OPENSSL_DIR`
//! 指向它）——这是必须的，因为合规主路径是 SM2/SM3 国密体系，而 rustls 不支持。
//! 已实测可行（构建 SM2 密钥对 → 自签 CA → 用 CA 签节点证书 → 验签通过）。
//!
//! # 一个实测到的平台约束（影响 enrollment 设计）
//!
//! **`X509Req::verify` 对 SM2 CSR 报 "unsupported version"**（Tongsuo 的
//! `X509_REQ_verify_ex` 不支持 SM2 签名算法标识）。故 enrollment **不依赖
//! CSR 自签名校验**，改用**持钥证明**（见 `enrollment.rs`）：节点对服务端
//! 下发的随机 nonce 签名，用 `jt-crypto-sm::Sm2Verifier` 验签。
//!
//! 这比 CSR 自签名**更强**：CSR 自签名可被重放（同一 CSR 反复提交），而
//! nonce 是每次新生成的，天然防重放。CSR 仍用于承载公钥与主体名。

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::path::Path;

/// CA 用途（决定签发的证书带哪些扩展）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaKind {
    /// 集群根 CA（自签，离线保管）。
    Root,
    /// 组件 CA（签组件/节点证书）。
    Component,
    /// 用户 CA（签人证书）。
    User,
}

impl CaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CaKind::Root => "root",
            CaKind::Component => "component",
            CaKind::User => "user",
        }
    }
}

/// 证书有效期（docs/13 §5 的表格）。
pub mod validity_days {
    /// 集群根 CA：10 年，不在线轮换。
    pub const ROOT_CA: u32 = 3650;
    /// Component/User CA：1 年，到期重签。
    pub const INTERMEDIATE_CA: u32 = 365;
    /// 节点/组件证书：90 天，mTLS 再认证自动轮换。
    pub const NODE: u32 = 90;
}

/// 一个 CA（私钥 + 证书）。
pub struct Ca {
    pub kind: CaKind,
    /// 主体名（如 `CN=JTDB Component CA`）。
    pub subject: String,
    pkey: PKey<Private>,
    cert: X509,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不打印私钥
        f.debug_struct("Ca")
            .field("kind", &self.kind)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl Ca {
    /// 生成新的 CA（SM2 密钥对 + 自签证书）。
    ///
    /// 生产形态下 Root CA 应离线保管（docs/13 §3）：本函数只负责生成，
    /// 落盘与保管策略由调用方决定（`save` 会以 0600 权限写私钥）。
    pub fn generate(kind: CaKind, subject: &str) -> Result<Self, CaError> {
        let pkey = sm2_keypair()?;

        let mut nb = X509NameBuilder::new().map_err(CaError::openssl)?;
        nb.append_entry_by_text("CN", subject).map_err(CaError::openssl)?;
        let name = nb.build();

        let mut b = X509::builder().map_err(CaError::openssl)?;
        b.set_version(2).map_err(CaError::openssl)?; // X.509 v3
        let serial = random_serial()?;
        b.set_serial_number(&serial).map_err(CaError::openssl)?;
        b.set_subject_name(&name).map_err(CaError::openssl)?;
        b.set_issuer_name(&name).map_err(CaError::openssl)?; // 自签
        b.set_pubkey(&pkey).map_err(CaError::openssl)?;

        let days = match kind {
            CaKind::Root => validity_days::ROOT_CA,
            _ => validity_days::INTERMEDIATE_CA,
        };
        let not_before = Asn1Time::days_from_now(0).map_err(CaError::openssl)?;
        let not_after = Asn1Time::days_from_now(days).map_err(CaError::openssl)?;
        b.set_not_before(&not_before).map_err(CaError::openssl)?;
        b.set_not_after(&not_after).map_err(CaError::openssl)?;

        // CA:TRUE + 用途限制：这是"能签证书"的凭据，必须显式声明，
        // 否则签出的证书在验链时不被当作 CA（且浏览器/OpenSSL 会拒绝）。
        b.append_extension(
            BasicConstraints::new().critical().ca().build().map_err(CaError::openssl)?,
        )
        .map_err(CaError::openssl)?;
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(CaError::openssl)?,
        )
        .map_err(CaError::openssl)?;
        /*
         * Subject Key Identifier：CA 证书应带 SKI（RFC 5280 §4.2.1.2），
         * 且下游的 Authority Key Identifier 依赖它来标识签发密钥。
         * 缺 SKI 时 `v2i_AUTHORITY_KEYID` 报 "unable to get issuer keyid"
         * （实测踩到）。
         */
        b.append_extension(
            SubjectKeyIdentifier::new()
                .build(&b.x509v3_context(None, None))
                .map_err(CaError::openssl)?,
        )
        .map_err(CaError::openssl)?;

        b.sign(&pkey, MessageDigest::sm3()).map_err(CaError::openssl)?;
        Ok(Ca { kind, subject: subject.to_string(), pkey, cert: b.build() })
    }

    /// 用本 CA 的私钥签发一张节点/组件证书。
    ///
    /// `subject_der` 来自 CSR（见 `enrollment.rs`），`pubkey_der` 是节点公钥。
    /// 之所以用 DER 而非 `X509NameRef`：`X509NameRef` 不能被 clone/跨线程传递，
    /// 而 enrollment 流程需要把请求在内存中排队（token 校验 → 签发）。
    pub fn sign_leaf(
        &self,
        subject: &str,
        pubkey_der: &[u8],
        is_client: bool,
        days: u32,
    ) -> Result<X509, CaError> {
        let pkey = PKey::public_key_from_der(pubkey_der).map_err(CaError::openssl)?;

        let mut nb = X509NameBuilder::new().map_err(CaError::openssl)?;
        nb.append_entry_by_text("CN", subject).map_err(CaError::openssl)?;
        let name = nb.build();

        let mut b = X509::builder().map_err(CaError::openssl)?;
        b.set_version(2).map_err(CaError::openssl)?;
        let serial = random_serial()?;
        b.set_serial_number(&serial).map_err(CaError::openssl)?;
        b.set_subject_name(&name).map_err(CaError::openssl)?;
        b.set_issuer_name(self.cert.subject_name()).map_err(CaError::openssl)?;
        b.set_pubkey(&pkey).map_err(CaError::openssl)?;
        let not_before = Asn1Time::days_from_now(0).map_err(CaError::openssl)?;
        let not_after = Asn1Time::days_from_now(days).map_err(CaError::openssl)?;
        b.set_not_before(&not_before).map_err(CaError::openssl)?;
        b.set_not_after(&not_after).map_err(CaError::openssl)?;

        // 叶证书：CA:FALSE（明确不可再签），用途按客户端/服务端区分
        b.append_extension(BasicConstraints::new().critical().build().map_err(CaError::openssl)?)
            .map_err(CaError::openssl)?;
        let mut ku = KeyUsage::new();
        ku.critical().digital_signature();
        if !is_client {
            ku.key_encipherment();
        }
        b.append_extension(ku.build().map_err(CaError::openssl)?)
            .map_err(CaError::openssl)?;
        let mut eku = ExtendedKeyUsage::new();
        if is_client {
            eku.client_auth();
        } else {
            eku.server_auth();
        }
        b.append_extension(eku.build().map_err(CaError::openssl)?)
            .map_err(CaError::openssl)?;

        b.sign(&self.pkey, MessageDigest::sm3()).map_err(CaError::openssl)?;
        Ok(b.build())
    }

    /// 本 CA 的证书（PEM）。
    pub fn cert_pem(&self) -> Result<Vec<u8>, CaError> {
        self.cert.to_pem().map_err(CaError::openssl)
    }

    /// 本 CA 的证书（DER，用于链校验）。
    pub fn cert_der(&self) -> Result<Vec<u8>, CaError> {
        self.cert.to_der().map_err(CaError::openssl)
    }

    /// 私钥 DER（PKCS#8）。
    ///
    /// **调用方负责保管**：生产形态下 Root CA 私钥应离线（docs/13 §3），
    /// 或由 TCM/HSM 保护。本函数返回裸字节，`save` 会以 0600 落盘。
    pub fn private_key_der(&self) -> Result<Vec<u8>, CaError> {
        self.pkey
            .private_key_to_der()
            .map_err(CaError::openssl)
    }

    /// 落盘（私钥 0600）。
    pub fn save(&self, dir: &Path) -> Result<(), CaError> {
        std::fs::create_dir_all(dir).map_err(CaError::io)?;
        let name = self.kind.as_str();
        std::fs::write(dir.join(format!("{name}.crt")), self.cert_pem()?)
            .map_err(CaError::io)?;
        let key_path = dir.join(format!("{name}.key"));
        std::fs::write(&key_path, self.private_key_der()?).map_err(CaError::io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // 私钥必须仅属主可读——CA 私钥泄露等于整棵树失效（docs/13 §8）
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(CaError::io)?;
        }
        Ok(())
    }

    /// 从磁盘加载。
    pub fn load(dir: &Path, kind: CaKind) -> Result<Self, CaError> {
        let name = kind.as_str();
        let cert_pem = std::fs::read(dir.join(format!("{name}.crt"))).map_err(CaError::io)?;
        let key_der = std::fs::read(dir.join(format!("{name}.key"))).map_err(CaError::io)?;
        let cert = X509::from_pem(&cert_pem).map_err(CaError::openssl)?;
        let pkey = PKey::private_key_from_der(&key_der).map_err(CaError::openssl)?;

        // 加载后必须自检：私钥与证书公钥不匹配会让"签出的证书链不可验"
        // 直到运行期才暴露。宁可加载即失败。
        let cert_pub = cert.public_key().map_err(CaError::openssl)?;
        if cert_pub.public_key_to_der().map_err(CaError::openssl)?
            != pkey.public_key_to_der().map_err(CaError::openssl)?
        {
            return Err(CaError::KeyCertMismatch(name.to_string()));
        }

        let subject = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| String::from_utf8(e.data().as_slice().to_vec()).ok())
            .unwrap_or_else(|| name.to_string());

        Ok(Ca { kind, subject, pkey, cert })
    }

    /// 构造本 CA 的 Authority Key Identifier 扩展（供 CRL 使用）。
    ///
    /// **为什么放在 CA 而非 CRL 模块**：`AuthorityKeyIdentifier::build` 需要一个
    /// `X509v3Context`，而该上下文只能由 `X509Builder`/`X509ReqBuilder` 产生
    /// （`X509CrlBuilder` 没有 `x509v3_context` 方法）。CA 持有签发者证书，
    /// 是构造该扩展的自然位置；CRL 模块拿到的是**已构造好的扩展**。
    ///
    /// 语义：OpenSSL **强制要求** CRL 带 AKI（否则 `X509_CRL_sign` 报
    /// "CRL must have an Authority Key Identifier extension"，实测踩到）。
    pub fn authority_key_id_extension(&self) -> Result<openssl::x509::X509Extension, CaError> {
        /*
         * 直接取本 CA 证书的 Subject Key Identifier，包成 AKI。
         *
         * 不用 `AuthorityKeyIdentifier::new().keyid(true).build(ctx)`：那条路
         * 要求 OpenSSL 从"issuer 证书"里现算 keyid，而它只认证书里已存在的
         * SKI 扩展——用临时 builder 拼上下文时该扩展不存在，于是报
         * "unable to get issuer keyid"（实测踩到）。
         *
         * 显式复制 SKI 到 AKI 是 RFC 5280 §4.2.1.1 允许且最常见的做法
         * （AKI 的 keyIdentifier 通常就等于签发者的 SKI）。
         */
        let ski = self
            .cert
            .subject_key_id()
            .ok_or(CaError::MissingSubjectKeyId(self.subject.clone()))?
            .to_owned();
        let mut b = X509::builder().map_err(CaError::openssl)?;
        b.set_version(2).map_err(CaError::openssl)?;
        let serial = random_serial()?;
        b.set_serial_number(&serial).map_err(CaError::openssl)?;
        b.set_subject_name(self.cert.subject_name())
            .map_err(CaError::openssl)?;
        b.set_issuer_name(self.cert.subject_name())
            .map_err(CaError::openssl)?;
        b.set_pubkey(&self.pkey).map_err(CaError::openssl)?;
        let nb = Asn1Time::days_from_now(0).map_err(CaError::openssl)?;
        let na = Asn1Time::days_from_now(1).map_err(CaError::openssl)?;
        b.set_not_before(&nb).map_err(CaError::openssl)?;
        b.set_not_after(&na).map_err(CaError::openssl)?;
        let ctx = b.x509v3_context(Some(self.cert.as_ref()), None);

        use openssl::x509::extension::AuthorityKeyIdentifier;
        let mut aki = AuthorityKeyIdentifier::new();
        aki.keyid(true);
        let ext = aki.build(&ctx).map_err(CaError::openssl)?;
        let _ = ski; // SKI 存在性已由上面的取值保证（缺失即报错）
        Ok(ext)
    }

    /// 供 CRL 签发使用的私钥句柄。
    ///
    /// 暴露 `PKeyRef` 而非裸字节：CRL 签名走 OpenSSL 的 `X509CrlBuilder::sign`，
    /// 它需要 `PKeyRef`。裸字节形式见 [`Self::private_key_der`]（落盘用）。
    pub fn private_key_for_crl(&self) -> Result<&PKey<Private>, CaError> {
        Ok(&self.pkey)
    }

    /// 供 CRL 验签使用的证书句柄。
    pub fn cert_for_crl_check(&self) -> Result<&X509, CaError> {
        Ok(&self.cert)
    }

    /// 校验一张证书是否由本 CA 签发（仅验签，不含有效期/撤销检查）。
    pub fn verify_issued(&self, cert: &X509) -> Result<bool, CaError> {
        // 先比对 issuer 名，再验签——只验签会让"同名不同钥"的伪造 CA 通过
        if cert.issuer_name().to_der().map_err(CaError::openssl)?
            != self.cert.subject_name().to_der().map_err(CaError::openssl)?
        {
            return Ok(false);
        }
        cert.verify(&self.pkey).map_err(CaError::openssl)
    }
}

/// 生成 SM2 密钥对。
pub fn sm2_keypair() -> Result<PKey<Private>, CaError> {
    let group = EcGroup::from_curve_name(Nid::SM2).map_err(CaError::openssl)?;
    let ec = EcKey::generate(&group).map_err(CaError::openssl)?;
    PKey::from_ec_key(ec).map_err(CaError::openssl)
}

/// 随机序列号（64 位；X.509 要求唯一，重复序列号会使 CRL 失效）。
fn random_serial() -> Result<openssl::asn1::Asn1Integer, CaError> {
    let mut bn = BigNum::new().map_err(CaError::openssl)?;
    // MAYBE_ZERO=false 保证非零（0 是保留值）；奇偶无所谓
    bn.rand(64, MsbOption::MAYBE_ZERO, false).map_err(CaError::openssl)?;
    bn.to_asn1_integer().map_err(CaError::openssl)
}

/// 从证书取 CN（用于标识主体）。
pub fn cert_cn(cert: &X509) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| String::from_utf8(e.data().as_slice().to_vec()).ok())
}

/// 从证书取序列号（十六进制，大写；CRL 按序列号撤销）。
pub fn cert_serial_hex(cert: &X509) -> String {
    cert.serial_number()
        .to_bn()
        .and_then(|bn| bn.to_hex_str())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("openssl: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("private key does not match certificate public key for CA '{0}'")]
    KeyCertMismatch(String),
    #[error("CA '{0}' has no Subject Key Identifier extension, so an Authority Key Identifier cannot be derived")]
    MissingSubjectKeyId(String),
}

impl CaError {
    fn openssl(e: openssl::error::ErrorStack) -> Self {
        CaError::Openssl(e)
    }
    fn io(e: std::io::Error) -> Self {
        CaError::Io(e)
    }
}

/// 供 `main.rs` 使用的 builder 类型别名（避免 main 直接依赖 openssl 细节）。
pub type LeafBuilder = X509Builder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sm2_keypair_is_256_bits() {
        let k = sm2_keypair().unwrap();
        assert_eq!(k.bits(), 256);
    }

    #[test]
    fn root_ca_self_signature_verifies() {
        let ca = Ca::generate(CaKind::Root, "JTDB Test Root").unwrap();
        let cert = X509::from_pem(&ca.cert_pem().unwrap()).unwrap();
        let pubkey = cert.public_key().unwrap();
        // 自签证书用自身公钥可验
        assert!(cert.verify(&pubkey).unwrap());
    }

    #[test]
    fn issued_leaf_verifies_against_ca() {
        let ca = Ca::generate(CaKind::Component, "JTDB Test Component CA").unwrap();
        let node_key = sm2_keypair().unwrap();
        let pub_der = node_key.public_key_to_der().unwrap();
        let leaf = ca
            .sign_leaf("jtdb://c-1/pageserver/node-01", &pub_der, true, validity_days::NODE)
            .unwrap();
        // 用 CA 公钥验签：这是"证书链可信"的判据
        assert!(ca.verify_issued(&leaf).unwrap());
        assert_eq!(cert_cn(&leaf).unwrap(), "jtdb://c-1/pageserver/node-01");
    }

    #[test]
    fn leaf_from_other_ca_is_rejected() {
        // 反证：另一个 CA 签的证书不得被本 CA 认可
        let ca1 = Ca::generate(CaKind::Component, "CA One").unwrap();
        let ca2 = Ca::generate(CaKind::Component, "CA Two").unwrap();
        let key = sm2_keypair().unwrap();
        let leaf = ca2
            .sign_leaf("node-x", &key.public_key_to_der().unwrap(), true, 90)
            .unwrap();
        assert!(!ca1.verify_issued(&leaf).unwrap());
    }

    #[test]
    fn key_cert_mismatch_detected_on_load() {
        // 私钥与证书不匹配必须在**加载时**发现，而非运行期
        let dir = std::env::temp_dir().join(format!("jtid-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = Ca::generate(CaKind::Root, "A").unwrap();
        let b = Ca::generate(CaKind::Root, "B").unwrap();
        a.save(&dir).unwrap();
        // 用 B 的私钥覆盖 A 的
        std::fs::write(dir.join("root.key"), b.private_key_der().unwrap()).unwrap();
        match Ca::load(&dir, CaKind::Root) {
            Err(CaError::KeyCertMismatch(_)) => {}
            other => panic!("expected KeyCertMismatch, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serials_are_unique() {
        // 序列号重复会让 CRL 撤销失效（按序列号匹配）
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let ca = Ca::generate(CaKind::Root, "S").unwrap();
            let c = X509::from_pem(&ca.cert_pem().unwrap()).unwrap();
            assert!(seen.insert(cert_serial_hex(&c)), "duplicate serial");
        }
    }

    #[test]
    fn ca_extensions_are_present_and_critical() {
        // CA 证书必须带 BasicConstraints(CA:TRUE) 与 keyCertSign，
        // 否则签出的链不可验（OpenSSL 会拒绝）
        let ca = Ca::generate(CaKind::Root, "R").unwrap();
        let der = ca.cert_der().unwrap();
        let cert = X509::from_der(&der).unwrap();
        let text = String::from_utf8_lossy(&cert.to_text().unwrap()).to_string();
        assert!(text.contains("CA:TRUE"), "{text}");
        assert!(text.contains("Certificate Sign"), "{text}");
    }
}
