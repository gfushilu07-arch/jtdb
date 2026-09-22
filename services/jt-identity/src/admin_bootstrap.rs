//! 三权分离引导（docs/13 §6、ADR-012）。
//!
//! ```text
//! jtdb init --bootstrap-admins
//!   → 生成三份密封凭据信封（分别用三位责任人的公钥/口令加密）
//!   → 输出到三个独立介质，任何单一信封无法恢复其他角色
//!   → 首次登录强制改密
//! ```
//!
//! # 为什么这里用口令派生密钥而不是直接发口令
//!
//! 本模块的"信封"用 **SM4-GCM** 加密：口令经 **SM3 迭代派生**（KDF）出密钥，
//! 再用该密钥加密该角色的初始凭据。好处：
//!
//! - 信封可在不安全介质上传递（内容已加密）；
//! - 三个信封各用**不同口令**，故单一信封（含其口令）无法解出其他角色；
//! - 首次登录强制改密，使初始口令的暴露窗口有限。
//!
//! # 遗留（与 docs/12 §8.3 一致）
//!
//! **KDF 结构尚未经密码专项评审冻结**（docs/12 §4.5 标注"KDF 结构专项冻结"）。
//! 本模块用的是"SM3 迭代 + 盐"的标准构造，参数（迭代次数）在评审后可能调整。
//! 该遗留已记录在 docs/16，不在此处假装完成。

use jt_crypto_api::{Aead as _, Digest256 as _, RandomSource as _};
use zeroize::Zeroizing;

/// 三个角色（ADR-012）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    /// 安全管理员：账户、标签、策略、扩展白名单；无审计查询与存储权限。
    SecAdmin,
    /// 系统管理员：实例/存储/备份/扩容；无标签与审计权限。
    SysAdmin,
    /// 审计员：审计查询/校验/导出，只读；配置变更需双人复核。
    Auditor,
}

impl AdminRole {
    pub fn as_str(self) -> &'static str {
        match self {
            AdminRole::SecAdmin => "jt_secadmin",
            AdminRole::SysAdmin => "jt_sysadmin",
            AdminRole::Auditor => "jt_auditor",
        }
    }
    pub fn all() -> [AdminRole; 3] {
        [AdminRole::SecAdmin, AdminRole::SysAdmin, AdminRole::Auditor]
    }
}

/// KDF 迭代次数。
///
/// 取值理由：SM3 迭代 200_000 次在当代硬件上约几十毫秒——对交互式登录可接受，
/// 对离线暴力破解则把单次尝试成本抬高数个数量级。**该参数属待评审项**
/// （docs/12 §4.5），评审后可能调整；调整会使旧信封不可解，故需在评审前
/// 完成引导（生产初始化本来就发生在评审之后）。
pub const KDF_ITERATIONS: u32 = 200_000;

/// 派生密钥（口令 → SM4 密钥）。
///
/// 构造：`key = SM3^N(salt ‖ password)`，即对 (盐‖口令) 迭代 N 次 SM3。
/// 这是标准的口令拉伸做法（与 PBKDF 同构，仅用国密原语）。
pub fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 16]> {
    let sm3 = jt_crypto_sm::Sm3Digest;
    let mut input = Vec::with_capacity(salt.len() + password.len());
    input.extend_from_slice(salt);
    input.extend_from_slice(password);

    let mut h = sm3.digest(&input);
    for _ in 1..iterations {
        let mut next = Vec::with_capacity(h.len() + salt.len());
        next.extend_from_slice(&h);
        next.extend_from_slice(salt);
        h = sm3.digest(&next);
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&h[..16]);
    Zeroizing::new(key)
}

/// 一份密封信封。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealedEnvelope {
    pub role: String,
    /// 盐（hex）。
    pub salt_hex: String,
    /// nonce（hex）。
    pub nonce_hex: String,
    /// 密文 + tag（hex）。
    pub ciphertext_hex: String,
    pub kdf_iterations: u32,
}

/// 信封内承载的凭据（解密后）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminCredential {
    pub role: String,
    /// 初始口令（首次登录强制改密，docs/13 §6）。
    pub initial_password: String,
    /// 是否已改密（引导后为 false；首次登录成功改密后置 true）。
    pub password_changed: bool,
    /// 生成时间（Unix 秒）。
    pub created_at: u64,
}

/// 生成三份密封信封。
///
/// 返回 `(信封, 口令)` 列表——**口令必须分别经独立介质交给责任人**
/// （docs/13 §6："输出到三个独立介质，任何单一信封无法恢复其他角色"）。
/// 本函数把两者一并返回，是为了让调用方（`jtdb init`）能立刻分发；
/// 若调用方把它们写在同一处，就破坏了该保证。
pub fn bootstrap_admins(
    cluster_id: &str,
) -> Result<Vec<(SealedEnvelope, Zeroizing<String>)>, BootstrapError> {
    let mut out = Vec::new();
    for role in AdminRole::all() {
        let password = Zeroizing::new(random_password());
        let cred = AdminCredential {
            role: role.as_str().to_string(),
            initial_password: password.to_string(),
            password_changed: false,
            created_at: now_secs(),
        };
        let env = seal(role, &cred, &password, cluster_id)?;
        out.push((env, password));
    }
    Ok(out)
}

/// 密封一份凭据。
///
/// `cluster_id` 参与 AAD：防止把 A 集群的信封拿到 B 集群使用
/// （与 docs/04 §4.2 对象 AAD 绑定 timeline 的思路一致）。
pub fn seal(
    role: AdminRole,
    cred: &AdminCredential,
    password: &str,
    cluster_id: &str,
) -> Result<SealedEnvelope, BootstrapError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    let mut rng = jt_crypto_sm::Sm4CtrDrbg::from_os_entropy()
        .map_err(|e| BootstrapError::Crypto(format!("{e}")))?;
    rng.fill(&mut salt).map_err(|e| BootstrapError::Crypto(format!("{e}")))?;
    rng.fill(&mut nonce).map_err(|e| BootstrapError::Crypto(format!("{e}")))?;

    let key = derive_key(password.as_bytes(), &salt, KDF_ITERATIONS);
    let plaintext = serde_json::to_vec(cred).map_err(|e| BootstrapError::Serde(e.to_string()))?;
    let aad = aad_for(role, cluster_id);

    let ct = jt_crypto_sm::Sm4Gcm
        .seal(&key[..], &nonce, &aad, &plaintext)
        .map_err(|e| BootstrapError::Crypto(format!("{e}")))?;

    Ok(SealedEnvelope {
        role: role.as_str().to_string(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(&ct),
        kdf_iterations: KDF_ITERATIONS,
    })
}

/// 解开信封（首次登录用）。
pub fn open(
    env: &SealedEnvelope,
    password: &str,
    cluster_id: &str,
) -> Result<AdminCredential, BootstrapError> {
    let role = AdminRole::all()
        .into_iter()
        .find(|r| r.as_str() == env.role)
        .ok_or_else(|| BootstrapError::UnknownRole(env.role.clone()))?;

    let salt = hex::decode(&env.salt_hex).map_err(|e| BootstrapError::Serde(e.to_string()))?;
    let nonce = hex::decode(&env.nonce_hex).map_err(|e| BootstrapError::Serde(e.to_string()))?;
    let ct = hex::decode(&env.ciphertext_hex)
        .map_err(|e| BootstrapError::Serde(e.to_string()))?;

    let key = derive_key(password.as_bytes(), &salt, env.kdf_iterations);
    let aad = aad_for(role, cluster_id);

    // 口令错误 ⇒ GCM 认证失败（这正是要的：无法区分"口令错"与"信封被改"，
    // 二者都不应给出可用的凭据）
    let pt = jt_crypto_sm::Sm4Gcm
        .open(&key[..], &nonce, &aad, &ct)
        .map_err(|_| BootstrapError::BadPasswordOrTampered)?;

    serde_json::from_slice(&pt).map_err(|e| BootstrapError::Serde(e.to_string()))
}

/// AAD：绑定角色与集群，使信封不可跨角色/跨集群搬移。
fn aad_for(role: AdminRole, cluster_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(role.as_str().len() + cluster_id.len() + 16);
    aad.extend_from_slice(b"jtdb-admin-envelope-v1");
    aad.extend_from_slice(role.as_str().as_bytes());
    aad.push(0);
    aad.extend_from_slice(cluster_id.as_bytes());
    aad
}

/// 生成随机初始口令（24 字符，含大小写数字；用 CSPRNG）。
fn random_password() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut buf = [0u8; 24];
    // 用 DRBG 而非 thread_rng：口令是密钥材料，须走项目统一的随机源
    if let Ok(mut rng) = jt_crypto_sm::Sm4CtrDrbg::from_os_entropy() {
        let _ = rng.fill(&mut buf);
    }
    buf.iter()
        .map(|b| CHARS[(*b as usize) % CHARS.len()] as char)
        .collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BootstrapError {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("serde: {0}")]
    Serde(String),
    #[error("unknown role '{0}'")]
    UnknownRole(String),
    #[error("wrong password, or envelope was tampered with")]
    BadPasswordOrTampered,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_produces_three_distinct_envelopes() {
        let envs = bootstrap_admins("c-test").unwrap();
        assert_eq!(envs.len(), 3);
        let roles: Vec<_> = envs.iter().map(|(e, _)| e.role.clone()).collect();
        assert!(roles.contains(&"jt_secadmin".to_string()));
        assert!(roles.contains(&"jt_sysadmin".to_string()));
        assert!(roles.contains(&"jt_auditor".to_string()));
        // 三份密文必须互不相同（不同口令 + 不同盐 + 不同 nonce）
        let cts: std::collections::HashSet<_> =
            envs.iter().map(|(e, _)| e.ciphertext_hex.clone()).collect();
        assert_eq!(cts.len(), 3);
    }

    #[test]
    fn envelope_roundtrips_with_correct_password() {
        let envs = bootstrap_admins("c-1").unwrap();
        for (env, pw) in &envs {
            let cred = open(env, pw, "c-1").unwrap();
            assert_eq!(&cred.role, &env.role);
            assert!(!cred.password_changed, "初始凭据必须标记为未改密");
        }
    }

    #[test]
    fn wrong_password_rejected() {
        let envs = bootstrap_admins("c-1").unwrap();
        let (env, _) = &envs[0];
        assert_eq!(
            open(env, "not-the-password", "c-1").unwrap_err(),
            BootstrapError::BadPasswordOrTampered
        );
    }

    #[test]
    fn one_envelope_cannot_open_another_role() {
        // 核心保证（docs/13 §6）：任何单一信封无法恢复其他角色
        let envs = bootstrap_admins("c-1").unwrap();
        let (sec_env, sec_pw) = &envs[0]; // secadmin 信封 + 其口令
        let (sys_env, _) = &envs[1];
        // 用 secadmin 的口令去开 sysadmin 的信封：必须失败
        assert_eq!(
            open(sys_env, sec_pw, "c-1").unwrap_err(),
            BootstrapError::BadPasswordOrTampered
        );
        // 且能正确打开自己的
        assert!(open(sec_env, sec_pw, "c-1").is_ok());
    }

    #[test]
    fn envelope_is_bound_to_cluster() {
        // AAD 绑定集群：把 A 集群的信封拿到 B 集群必须失败
        let envs = bootstrap_admins("cluster-A").unwrap();
        let (env, pw) = &envs[0];
        assert!(open(env, pw, "cluster-A").is_ok());
        assert_eq!(
            open(env, pw, "cluster-B").unwrap_err(),
            BootstrapError::BadPasswordOrTampered
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let envs = bootstrap_admins("c-1").unwrap();
        let (env, pw) = &envs[0];
        let mut tampered = env.clone();
        // 翻转密文最后一个字节（tag 区）——AEAD 必须检出
        let mut ct = hex::decode(&tampered.ciphertext_hex).unwrap();
        let n = ct.len();
        ct[n - 1] ^= 0x01;
        tampered.ciphertext_hex = hex::encode(&ct);
        assert_eq!(
            open(&tampered, pw, "c-1").unwrap_err(),
            BootstrapError::BadPasswordOrTampered
        );
    }

    #[test]
    fn kdf_is_deterministic_and_salt_sensitive() {
        let k1 = derive_key(b"pw", b"salt-a", 1000);
        let k2 = derive_key(b"pw", b"salt-a", 1000);
        let k3 = derive_key(b"pw", b"salt-b", 1000);
        let k4 = derive_key(b"pw2", b"salt-a", 1000);
        assert_eq!(k1[..], k2[..]);
        assert_ne!(k1[..], k3[..], "salt must affect the key");
        assert_ne!(k1[..], k4[..], "password must affect the key");
    }

    #[test]
    fn random_passwords_are_distinct_and_long_enough() {
        let a = random_password();
        let b = random_password();
        assert_ne!(a, b);
        assert_eq!(a.len(), 24);
    }
}
