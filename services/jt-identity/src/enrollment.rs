//! 节点 Enrollment（docs/13 §4）——信任链的起点。
//!
//! # 为什么这是"鸡生蛋"的解法
//!
//! jt-attest 要验构建身份签名、jt-kms 要验 mTLS 客户端证书，但"证书由谁签、
//! 节点如何取得第一份凭据"此前没有答案。本模块给出答案：
//!
//! ```text
//! 0. 管理员预登记：node_id + 一次性 enrollment token（10 分钟有效）
//! 1. 节点生成 SM2 密钥对，提交 CSR（承载公钥与主体名）+ 度量摘要
//! 2. jt-identity 校验 token（一次性、未过期、node_id 匹配）
//! 3. jt-identity 校验**持钥证明**（节点对服务端 nonce 签名）
//! 4. jt-identity 校验度量摘要（与预登记值比对，防冒名节点）
//! 5. Component CA 签发节点证书（90 天）
//! ```
//!
//! # 关于 CSR 自签名：**不用它**（实测约束）
//!
//! docs/13 §4 原文写"Component CA 校验 token + attest 结论"。实测发现
//! **Tongsuo 的 `X509Req::verify` 对 SM2 CSR 报 "unsupported version"**
//! （`X509_REQ_verify_ex` 不支持 SM2 签名算法标识）。
//!
//! 故本实现改用**持钥证明**：服务端下发随机 nonce，节点用私钥签名，
//! 服务端用 `jt-crypto-sm::Sm2Verifier` 验签。这比 CSR 自签名**更强**：
//!
//! - CSR 自签名可被**重放**（同一 CSR 反复提交，签名始终有效）；
//! - nonce 每次新生成，**天然防重放**，且证明的是"此刻持有私钥"。
//!
//! CSR 仍用于承载公钥与主体名（`X509Req` 的解析是可行的，只有 verify 不行）。
//!
//! # 防中间人三重校验（docs/13 §4）
//!
//! `enrollment token（带外传递）+ 管理员侧确认 + 度量绑定`，三者缺一不可。
//! 单独持有 token 无法伪造节点——因为还要过持钥证明与度量比对。

use crate::ca::{self, Ca, CaError};
use jt_crypto_api::{SignatureVerifier as _, SignatureKey as _};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// token 有效期（docs/13 §5：10 分钟）。
pub const TOKEN_TTL: Duration = Duration::from_secs(600);

/// nonce 有效期（挑战窗口；比 token 短，因为它是即时的）。
pub const NONCE_TTL: Duration = Duration::from_secs(120);

/// 预登记的节点（管理员在 jt-controller/jt-identity 侧建立）。
#[derive(Debug, Clone)]
pub struct PreRegisteredNode {
    pub node_id: String,
    /// 预期度量摘要（hex）。空串 = 不校验度量（**仅开发用**，见 `register`）。
    pub expected_measurement: String,
}

/// 一次性 enrollment token。
#[derive(Debug, Clone)]
struct TokenEntry {
    node_id: String,
    expires_at: u64,
    /// 是否已被使用（一次性：用后即废，防重放）。
    used: bool,
}

/// 未完成的挑战（token 校验通过、等待持钥证明）。
#[derive(Debug, Clone)]
struct Challenge {
    node_id: String,
    nonce: Vec<u8>,
    expires_at: u64,
}

/// enrollment 请求（节点提交）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnrollRequest {
    pub node_id: String,
    pub token: String,
    /// CSR（PEM）：承载节点公钥与主体名。
    pub csr_pem: String,
    /// 度量摘要（hex，SM3）——节点自报，由服务端与预登记值比对。
    pub measurement: String,
    /// 持钥证明：对服务端 nonce 的 SM2 签名（hex）。
    pub proof_sig: String,
    /// 客户端证书用途（组件默认 true）。
    #[serde(default = "default_true")]
    pub is_client: bool,
}

fn default_true() -> bool {
    true
}

/// 签发的证书。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnrollResponse {
    pub node_id: String,
    /// 节点证书（PEM）。
    pub cert_pem: String,
    /// 签发者证书链（PEM；Component CA）。
    pub ca_pem: String,
    /// 序列号（hex，大写）——撤销时按它匹配。
    pub serial_hex: String,
    pub not_after_days: u32,
}

/// enrollment 服务状态。
pub struct EnrollmentService {
    component_ca: Ca,
    /// 预登记节点（node_id → 记录）。
    nodes: Mutex<HashMap<String, PreRegisteredNode>>,
    /// 未使用的 token（token → 记录）。
    tokens: Mutex<HashMap<String, TokenEntry>>,
    /// 进行中的挑战（node_id → 挑战）。
    challenges: Mutex<HashMap<String, Challenge>>,
    /// 已签发证书（序列号 → 元数据），供撤销与审计。
    issued: Mutex<HashMap<String, IssuedCert>>,
}

/// 已签发证书的元数据（撤销与审计用）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct IssuedCert {
    pub serial_hex: String,
    pub node_id: String,
    pub issued_at: u64,
    pub revoked: bool,
    pub revoked_at: Option<u64>,
    pub revoke_reason: Option<String>,
}

impl EnrollmentService {
    pub fn new(component_ca: Ca) -> Self {
        Self {
            component_ca,
            nodes: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
            issued: Mutex::new(HashMap::new()),
        }
    }

    /// 预登记节点并签发一次性 token（管理员操作，docs/13 §4 步骤 0）。
    ///
    /// `expected_measurement` 为空串时**不校验度量**——这是开发便利，
    /// 生产必须给值，否则"度量绑定"这道防线形同虚设（见 `enroll` 的注释）。
    pub fn register_node(
        &self,
        node_id: &str,
        expected_measurement: &str,
    ) -> Result<String, EnrollError> {
        if node_id.is_empty() {
            return Err(EnrollError::BadRequest("node_id must not be empty"));
        }
        self.nodes.lock().insert(
            node_id.to_string(),
            PreRegisteredNode {
                node_id: node_id.to_string(),
                expected_measurement: expected_measurement.to_string(),
            },
        );
        let token = random_hex(32);
        self.tokens.lock().insert(
            token.clone(),
            TokenEntry {
                node_id: node_id.to_string(),
                expires_at: now_secs() + TOKEN_TTL.as_secs(),
                used: false,
            },
        );
        Ok(token)
    }

    /// 步骤 A：节点请求挑战（提交 token）。
    ///
    /// 返回 nonce（hex）。**此时还不签发证书**——必须先证明持有私钥。
    pub fn begin(&self, node_id: &str, token: &str) -> Result<String, EnrollError> {
        let mut tokens = self.tokens.lock();
        let entry = tokens
            .get_mut(token)
            .ok_or(EnrollError::UnknownToken)?;

        // 一次性：已用过的 token 一律拒绝（防重放）
        if entry.used {
            return Err(EnrollError::TokenAlreadyUsed);
        }
        if entry.expires_at < now_secs() {
            return Err(EnrollError::TokenExpired);
        }
        // token 与 node_id 必须匹配：拿到别人的 token 也不能冒名
        if entry.node_id != node_id {
            return Err(EnrollError::TokenNodeMismatch {
                token_for: entry.node_id.clone(),
                claimed: node_id.to_string(),
            });
        }
        if !self.nodes.lock().contains_key(node_id) {
            return Err(EnrollError::NodeNotPreRegistered(node_id.to_string()));
        }

        let nonce = random_bytes(32);
        self.challenges.lock().insert(
            node_id.to_string(),
            Challenge {
                node_id: node_id.to_string(),
                nonce: nonce.clone(),
                expires_at: now_secs() + NONCE_TTL.as_secs(),
            },
        );
        // token 在此刻标记为已用：挑战一旦下发，token 不再可用于第二次 begin
        entry.used = true;
        Ok(hex::encode(nonce))
    }

    /// 步骤 B：提交 CSR + 度量 + 持钥证明，换取证书。
    pub fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse, EnrollError> {
        // 1) 节点必须已预登记
        let pre = self
            .nodes
            .lock()
            .get(&req.node_id)
            .cloned()
            .ok_or_else(|| EnrollError::NodeNotPreRegistered(req.node_id.clone()))?;

        // 2) 取回挑战（一次性：取出即删，同一 nonce 不能用于两次 enrollment）
        let ch = self
            .challenges
            .lock()
            .remove(&req.node_id)
            .ok_or(EnrollError::NoChallenge)?;
        if ch.expires_at < now_secs() {
            return Err(EnrollError::ChallengeExpired);
        }

        // 3) 解析 CSR，取公钥
        let csr = openssl::x509::X509Req::from_pem(req.csr_pem.as_bytes())
            .map_err(|e| EnrollError::BadCsr(format!("{e}")))?;
        let csr_pub = csr
            .public_key()
            .map_err(|e| EnrollError::BadCsr(format!("pubkey: {e}")))?;
        let pubkey_der = csr_pub
            .public_key_to_der()
            .map_err(|e| EnrollError::BadCsr(format!("pubkey der: {e}")))?;
        /*
         * 持钥证明的验证器要的是**未压缩点**（04||X||Y，65B），而
         * `public_key_to_der()` 给的是 SPKI 包装的 DER。两者不通用——
         * 直接把 SPKI 喂给 Sm2Verifier 会报 "must be 65 bytes uncompressed"
         * （实测踩到）。故显式取出 EC 点的未压缩编码。
         */
        let pubkey_point = ec_point_uncompressed(&csr_pub)?;

        // 4) **持钥证明**：验证节点对 nonce 的签名（见模块注释：不用 CSR 自签名）
        let sig = hex::decode(&req.proof_sig)
            .map_err(|e| EnrollError::BadProof(format!("sig not hex: {e}")))?;
        let verifier = jt_crypto_sm::Sm2Verifier::from_pk_bytes(&pubkey_point)
            .map_err(|e| EnrollError::BadProof(format!("pubkey not usable: {e}")))?;
        if !verifier.verify(&ch.nonce, &sig) {
            return Err(EnrollError::BadProof(
                "possession proof failed: signature does not verify over the server nonce".into(),
            ));
        }

        // 5) 度量绑定：节点自报的度量必须与预登记值一致
        //
        // **为什么不校验空值就放行**：那会让"度量绑定"这道防线消失——攻击者
        // 只要不报度量即可绕过。故只在**预登记值本身为空**时跳过（管理员显式
        // 选择不校验，属开发形态），并在此记录该事实供审计。
        if !pre.expected_measurement.is_empty()
            && pre.expected_measurement != req.measurement
        {
            return Err(EnrollError::MeasurementMismatch {
                expected: pre.expected_measurement.clone(),
                got: req.measurement.clone(),
            });
        }

        // 6) 签发（90 天，docs/13 §5）
        let subject = format!("jtdb://{}/{}", "cluster", req.node_id);
        let cert = self
            .component_ca
            .sign_leaf(
                &subject,
                &pubkey_der,
                req.is_client,
                ca::validity_days::NODE,
            )
            .map_err(EnrollError::Ca)?;

        let serial_hex = ca::cert_serial_hex(&cert);
        self.issued.lock().insert(
            serial_hex.clone(),
            IssuedCert {
                serial_hex: serial_hex.clone(),
                node_id: req.node_id.clone(),
                issued_at: now_secs(),
                revoked: false,
                revoked_at: None,
                revoke_reason: None,
            },
        );

        Ok(EnrollResponse {
            node_id: req.node_id.clone(),
            cert_pem: String::from_utf8_lossy(
                &cert.to_pem().map_err(|e| EnrollError::Ca(CaError::Openssl(e)))?,
            )
            .to_string(),
            ca_pem: String::from_utf8_lossy(
                &self
                    .component_ca
                    .cert_pem()
                    .map_err(EnrollError::Ca)?,
            )
            .to_string(),
            serial_hex,
            not_after_days: ca::validity_days::NODE,
        })
    }

    /// 撤销证书（docs/13 §5、§8）。返回是否确实发生状态变化。
    pub fn revoke(&self, serial_hex: &str, reason: &str) -> Result<(), EnrollError> {
        let mut issued = self.issued.lock();
        let e = issued
            .get_mut(serial_hex)
            .ok_or_else(|| EnrollError::UnknownSerial(serial_hex.to_string()))?;
        if e.revoked {
            // 幂等：重复撤销不报错，但不覆盖首次的时间与原因
            // （首次撤销的时间对"撤销传播 ≤5min"的 SLO 判定很重要）
            return Ok(());
        }
        e.revoked = true;
        e.revoked_at = Some(now_secs());
        e.revoke_reason = Some(reason.to_string());
        Ok(())
    }

    /// 已撤销序列号列表（CRL 内容）。
    pub fn revoked_serials(&self) -> Vec<String> {
        self.issued
            .lock()
            .values()
            .filter(|c| c.revoked)
            .map(|c| c.serial_hex.clone())
            .collect()
    }

    /// 全部已签发证书（审计用）。
    pub fn issued_certs(&self) -> Vec<IssuedCert> {
        self.issued.lock().values().cloned().collect()
    }

    /// 某序列号是否已撤销（供 mTLS 侧查询）。
    pub fn is_revoked(&self, serial_hex: &str) -> bool {
        self.issued
            .lock()
            .get(serial_hex)
            .map(|c| c.revoked)
            .unwrap_or(false)
    }

    /// 本服务持有的 Component CA（供 CRL 签发）。
    pub fn component_ca(&self) -> &Ca {
        &self.component_ca
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("unknown enrollment token")]
    UnknownToken,
    #[error("enrollment token already used (tokens are single-use)")]
    TokenAlreadyUsed,
    #[error("enrollment token expired")]
    TokenExpired,
    #[error("token was issued for node '{token_for}', but '{claimed}' was claimed")]
    TokenNodeMismatch { token_for: String, claimed: String },
    #[error("node '{0}' is not pre-registered")]
    NodeNotPreRegistered(String),
    #[error("no challenge in progress for this node (call begin first)")]
    NoChallenge,
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("bad CSR: {0}")]
    BadCsr(String),
    #[error("possession proof rejected: {0}")]
    BadProof(String),
    #[error("measurement mismatch: expected {expected}, got {got}")]
    MeasurementMismatch { expected: String, got: String },
    #[error("unknown certificate serial {0}")]
    UnknownSerial(String),
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error("ca: {0}")]
    Ca(#[from] CaError),
}

/// 供 HTTP 层映射状态码。
impl EnrollError {
    pub fn is_client_error(&self) -> bool {
        !matches!(self, EnrollError::Ca(_))
    }
}

/// 从 OpenSSL 公钥取出 EC 点的**未压缩编码**（04||X||Y，65 字节）。
///
/// 为什么需要它：`jt-crypto-sm::Sm2Verifier` 期望裸点，而 OpenSSL 的
/// `public_key_to_der()` 返回 SPKI 结构——两者不能混用。
fn ec_point_uncompressed(pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>) -> Result<Vec<u8>, EnrollError> {
    let ec = pkey
        .ec_key()
        .map_err(|e| EnrollError::BadCsr(format!("not an EC key: {e}")))?;
    let group = ec.group();
    let mut ctx = openssl::bn::BigNumContext::new()
        .map_err(|e| EnrollError::BadCsr(format!("{e}")))?;
    ec.public_key()
        .to_bytes(
            group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .map_err(|e| EnrollError::BadCsr(format!("point encode: {e}")))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

fn random_hex(n: usize) -> String {
    hex::encode(random_bytes(n))
}

/// 节点侧的便利函数：生成 SM2 密钥对 + CSR + 持钥证明。
///
/// 放在本模块而非单独的 client 模块，是为了让"服务端要验什么"与
/// "客户端要签什么"在**同一处**定义——两处分写会让协议漂移（本项目在
/// 标签读写两侧已因字符串不一致踩过坑）。
pub mod client {
    use super::*;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::x509::{X509NameBuilder, X509Req};

    /// 节点身份材料（私钥 + CSR + 签名器）。
    pub struct NodeIdentity {
        pub private_key_der: Vec<u8>,
        pub csr_pem: String,
        pub public_key_der: Vec<u8>,
        signer: jt_crypto_sm::Sm2Signer,
    }

    impl NodeIdentity {
        /// 生成新身份。
        pub fn generate(node_id: &str) -> Result<Self, EnrollError> {
            let pkey = ca::sm2_keypair().map_err(|e| EnrollError::Ca(e))?;
            let public_key_der = pkey
                .public_key_to_der()
                .map_err(|e| EnrollError::BadCsr(format!("{e}")))?;

            let mut nb = X509NameBuilder::new().map_err(|e| EnrollError::BadCsr(format!("{e}")))?;
            nb.append_entry_by_text("CN", node_id)
                .map_err(|e| EnrollError::BadCsr(format!("{e}")))?;
            let name = nb.build();

            let mut req = X509Req::builder().map_err(|e| EnrollError::BadCsr(format!("{e}")))?;
            req.set_subject_name(&name)
                .map_err(|e| EnrollError::BadCsr(format!("{e}")))?;
            req.set_pubkey(&pkey)
                .map_err(|e| EnrollError::BadCsr(format!("{e}")))?;
            req.sign(&pkey, MessageDigest::sm3())
                .map_err(|e| EnrollError::BadCsr(format!("{e}")))?;
            let csr_pem = String::from_utf8_lossy(
                &req.build()
                    .to_pem()
                    .map_err(|e| EnrollError::BadCsr(format!("{e}")))?,
            )
            .to_string();

            // 签名器用私钥标量（32B 大端）
            let sk = pkey
                .ec_key()
                .map(|ec| ec.private_key().to_vec())
                .map_err(|e| EnrollError::BadProof(format!("{e}")))?;
            let mut sk_pad = vec![0u8; 32usize.saturating_sub(sk.len())];
            sk_pad.extend_from_slice(&sk[..sk.len().min(32)]);
            let signer = jt_crypto_sm::Sm2Signer::from_sk_bytes(&sk_pad)
                .map_err(|e| EnrollError::BadProof(format!("{e}")))?;

            Ok(Self {
                private_key_der: pkey
                    .private_key_to_der()
                    .map_err(|e| EnrollError::BadProof(format!("{e}")))?,
                csr_pem,
                public_key_der,
                signer,
            })
        }

        /// 对服务端下发的 nonce 做持钥证明。
        pub fn prove(&self, nonce_hex: &str) -> Result<String, EnrollError> {
            let nonce =
                hex::decode(nonce_hex).map_err(|e| EnrollError::BadProof(format!("{e}")))?;
            Ok(hex::encode(self.signer.sign(&nonce)))
        }
    }

    /// 便于测试/工具：从私钥 DER 恢复签名器（用于验证 CSR 与私钥一致）。
    pub fn signer_from_der(der: &[u8]) -> Result<jt_crypto_sm::Sm2Signer, EnrollError> {
        use openssl::pkey::PKey;
        let pkey = PKey::private_key_from_der(der)
            .map_err(|e| EnrollError::BadProof(format!("{e}")))?;
        let sk = pkey
            .ec_key()
            .map(|ec| ec.private_key().to_vec())
            .map_err(|e| EnrollError::BadProof(format!("{e}")))?;
        let mut sk_pad = vec![0u8; 32usize.saturating_sub(sk.len())];
        sk_pad.extend_from_slice(&sk[..sk.len().min(32)]);
        jt_crypto_sm::Sm2Signer::from_sk_bytes(&sk_pad)
            .map_err(|e| EnrollError::BadProof(format!("{e}")))
    }

    /// SM2 曲线 NID（供调用方断言底层是国密曲线）。
    pub fn sm2_nid() -> Nid {
        Nid::SM2
    }
}

#[cfg(test)]
mod tests {
    use super::client::NodeIdentity;
    use super::*;
    use crate::ca::CaKind;

    /// 断言错误种类（EnrollError 不派生 PartialEq——CaError 无法派生，
    /// 且拿错误做相等比较本身不是好做法：错误里可能含细节）。
    macro_rules! assert_err {
        ($e:expr, $pat:pat) => {
            match $e {
                $pat => {}
                other => panic!("expected {}, got {other:?}", stringify!($pat)),
            }
        };
    }

    fn svc() -> EnrollmentService {
        EnrollmentService::new(Ca::generate(CaKind::Component, "Test Component CA").unwrap())
    }

    /// 完整的 happy path：register → begin → enroll → 证书可验。
    fn happy(svc: &EnrollmentService, node_id: &str, measurement: &str) -> EnrollResponse {
        let token = svc.register_node(node_id, measurement).unwrap();
        let ident = NodeIdentity::generate(node_id).unwrap();
        let nonce = svc.begin(node_id, &token).unwrap();
        let proof = ident.prove(&nonce).unwrap();
        svc.enroll(&EnrollRequest {
            node_id: node_id.into(),
            token,
            csr_pem: ident.csr_pem.clone(),
            measurement: measurement.into(),
            proof_sig: proof,
            is_client: true,
        })
        .unwrap()
    }

    #[test]
    fn happy_path_issues_verifiable_cert() {
        let s = svc();
        let r = happy(&s, "node-01", "abc123");
        assert_eq!(r.not_after_days, 90);
        let cert = openssl::x509::X509::from_pem(r.cert_pem.as_bytes()).unwrap();
        // 用 CA 公钥验签：这是"证书链可信"的判据
        assert!(s.component_ca().verify_issued(&cert).unwrap());
        assert_eq!(ca::cert_cn(&cert).unwrap(), "jtdb://cluster/node-01");
    }

    // ---- 攻击面（docs/13 §10）：每一项都必须被拒 ----

    #[test]
    fn unknown_token_rejected() {
        let s = svc();
        s.register_node("n1", "m").unwrap();
        assert_err!(s.begin("n1", "deadbeef").unwrap_err(), EnrollError::UnknownToken);
    }

    #[test]
    fn expired_token_rejected() {
        let s = svc();
        let token = s.register_node("n1", "m").unwrap();
        // 手工把过期时间推到过去（不 sleep 10 分钟）
        s.tokens.lock().get_mut(&token).unwrap().expires_at = now_secs() - 1;
        assert_err!(s.begin("n1", &token).unwrap_err(), EnrollError::TokenExpired);
    }

    #[test]
    fn token_is_single_use() {
        // 一次性：第二次 begin 必须失败（防重放）
        let s = svc();
        let token = s.register_node("n1", "m").unwrap();
        assert!(s.begin("n1", &token).is_ok());
        assert_err!(s.begin("n1", &token).unwrap_err(), EnrollError::TokenAlreadyUsed);
    }

    #[test]
    fn token_cannot_be_used_for_another_node() {
        // 拿到别人的 token 也不能冒名
        let s = svc();
        let token = s.register_node("node-A", "m").unwrap();
        s.register_node("node-B", "m").unwrap();
        assert_err!(
            s.begin("node-B", &token).unwrap_err(),
            EnrollError::TokenNodeMismatch { .. }
        );
    }

    #[test]
    fn unregistered_node_rejected() {
        let s = svc();
        // 有 token 但节点未预登记（理论上不会发生，因为 token 由 register 产生；
        // 此处直接构造以覆盖该分支）
        let token = random_hex(32);
        s.tokens.lock().insert(
            token.clone(),
            TokenEntry { node_id: "ghost".into(), expires_at: now_secs() + 100, used: false },
        );
        assert_err!(
            s.begin("ghost", &token).unwrap_err(),
            EnrollError::NodeNotPreRegistered(_)
        );
    }

    #[test]
    fn wrong_possession_proof_rejected() {
        // 核心防线：不能证明持有私钥则不发证书
        let s = svc();
        let token = s.register_node("n1", "m").unwrap();
        let ident = NodeIdentity::generate("n1").unwrap();
        let other = NodeIdentity::generate("n1").unwrap();
        let nonce = s.begin("n1", &token).unwrap();
        // 用**另一个**密钥对签名（模拟冒名者）
        let bad_proof = other.prove(&nonce).unwrap();
        let e = s
            .enroll(&EnrollRequest {
                node_id: "n1".into(),
                token,
                csr_pem: ident.csr_pem.clone(),
                measurement: "m".into(),
                proof_sig: bad_proof,
                is_client: true,
            })
            .unwrap_err();
        assert!(matches!(e, EnrollError::BadProof(_)), "{e:?}");
    }

    #[test]
    fn proof_for_wrong_nonce_rejected() {
        // 防重放：对别的 nonce 的签名无效
        let s = svc();
        let token = s.register_node("n1", "m").unwrap();
        let ident = NodeIdentity::generate("n1").unwrap();
        let _nonce = s.begin("n1", &token).unwrap();
        let stale = ident.prove(&hex::encode([0xAAu8; 32])).unwrap();
        let e = s
            .enroll(&EnrollRequest {
                node_id: "n1".into(),
                token,
                csr_pem: ident.csr_pem.clone(),
                measurement: "m".into(),
                proof_sig: stale,
                is_client: true,
            })
            .unwrap_err();
        assert!(matches!(e, EnrollError::BadProof(_)), "{e:?}");
    }

    #[test]
    fn measurement_mismatch_rejected() {
        // 度量绑定：模拟"同 node_id 但是另一台机器"
        let s = svc();
        let token = s.register_node("n1", "expected-measurement").unwrap();
        let ident = NodeIdentity::generate("n1").unwrap();
        let nonce = s.begin("n1", &token).unwrap();
        let proof = ident.prove(&nonce).unwrap();
        let e = s
            .enroll(&EnrollRequest {
                node_id: "n1".into(),
                token,
                csr_pem: ident.csr_pem.clone(),
                measurement: "attacker-measurement".into(),
                proof_sig: proof,
                is_client: true,
            })
            .unwrap_err();
        assert!(matches!(e, EnrollError::MeasurementMismatch { .. }), "{e:?}");
    }

    #[test]
    fn challenge_is_single_use() {
        // 同一 nonce 不能用于两次 enrollment
        let s = svc();
        let token = s.register_node("n1", "m").unwrap();
        let ident = NodeIdentity::generate("n1").unwrap();
        let nonce = s.begin("n1", &token).unwrap();
        let proof = ident.prove(&nonce).unwrap();
        let req = EnrollRequest {
            node_id: "n1".into(),
            token: token.clone(),
            csr_pem: ident.csr_pem.clone(),
            measurement: "m".into(),
            proof_sig: proof.clone(),
            is_client: true,
        };
        assert!(s.enroll(&req).is_ok());
        // 第二次：挑战已消费
        assert_err!(s.enroll(&req).unwrap_err(), EnrollError::NoChallenge);
    }

    #[test]
    fn enroll_without_begin_rejected() {
        let s = svc();
        let token = s.register_node("n1", "m").unwrap();
        let ident = NodeIdentity::generate("n1").unwrap();
        let e = s
            .enroll(&EnrollRequest {
                node_id: "n1".into(),
                token,
                csr_pem: ident.csr_pem.clone(),
                measurement: "m".into(),
                proof_sig: hex::encode([0u8; 64]),
                is_client: true,
            })
            .unwrap_err();
        assert_err!(e, EnrollError::NoChallenge);
    }

    #[test]
    fn empty_measurement_skips_check_but_nonempty_is_enforced() {
        // 预登记值为空 = 管理员显式选择不校验（开发形态）；
        // 非空则必须匹配——否则"度量绑定"这道防线会因"不报度量"而被绕过
        let s = svc();
        let r = happy(&s, "dev-node", "");
        assert!(!r.serial_hex.is_empty());
    }

    // ---- 撤销 ----

    #[test]
    fn revoke_marks_serial_and_is_idempotent() {
        let s = svc();
        let r = happy(&s, "n1", "m");
        assert!(!s.is_revoked(&r.serial_hex));
        s.revoke(&r.serial_hex, "leak").unwrap();
        assert!(s.is_revoked(&r.serial_hex));
        assert_eq!(s.revoked_serials(), vec![r.serial_hex.clone()]);
        // 幂等且不覆盖首次时间（首次时间对 SLO 判定重要）
        let first = s.issued.lock().get(&r.serial_hex).unwrap().revoked_at;
        s.revoke(&r.serial_hex, "other-reason").unwrap();
        assert_eq!(s.issued.lock().get(&r.serial_hex).unwrap().revoked_at, first);
    }

    #[test]
    fn revoke_unknown_serial_rejected() {
        let s = svc();
        assert!(matches!(
            s.revoke("DEADBEEF", "x").unwrap_err(),
            EnrollError::UnknownSerial(_)
        ));
    }

    #[test]
    fn distinct_nodes_get_distinct_serials() {
        let s = svc();
        let a = happy(&s, "n1", "m");
        let b = happy(&s, "n2", "m");
        assert_ne!(a.serial_hex, b.serial_hex);
        // 撤销 a 不得影响 b
        s.revoke(&a.serial_hex, "x").unwrap();
        assert!(s.is_revoked(&a.serial_hex));
        assert!(!s.is_revoked(&b.serial_hex));
    }
}
