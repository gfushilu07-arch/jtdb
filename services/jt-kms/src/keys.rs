//! jt-kms 密钥层级与信封（docs/02 §6.3、docs/04 §6、docs/12）。
//!
//! 层级：RK（根密钥，生产=TCM/HSM；开发=主密钥文件）→ KEK（集群/组件
//! 作用域）→ DEK（timeline+epoch 作用域）。
//!
//! 信封（docs/04 §6）：`wrapped_dek = SM4_wrap(kek, dek || dek_scope_digest)`
//! 实现为 SM4-GCM（AEAD 信封，认证性强于裸 KW）：
//! `nonce(12B) || SM4GCM.seal(kek, nonce, aad=scope_digest, plain=dek)`。
//!
//! DEK 派生（开发模式）：与 pageserver 侧 `DevKeyProvider` 同一派生式
//! （SM3("jtdev-dek:" || timeline || epoch)[..16]），保证 KMS 与组件对
//! DEK 值零迁移一致；生产切 DRBG 随机 DEK + 信封分发，接口不变。

use jt_crypto_sm::{Sm3Digest, Sm4Gcm};
use jt_crypto_api::{Aead as _, Digest256 as _};
use rand::RngCore;

/// 根密钥长度（字节）。
pub const RK_LEN: usize = 32;
/// KEK/DEK 长度（SM4）。
pub const KEK_LEN: usize = 16;

/// 加载或生成根密钥（首次运行自动生成，0600 落盘；生产由 TCM/HSM 承载）。
pub fn load_or_create_rk(path: &std::path::Path) -> Result<[u8; RK_LEN], KmsCryptoError> {
    if let Ok(bytes) = std::fs::read(path) {
        let arr: [u8; RK_LEN] = bytes
            .try_into()
            .map_err(|_| KmsCryptoError::MasterKeyCorrupt)?;
        return Ok(arr);
    }
    let mut rk = [0u8; RK_LEN];
    rand::thread_rng().fill_bytes(&mut rk);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, rk)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(rk)
}

/// KEK 派生：SM3(RK || "jt-kek:" || cluster || ":" || component_scope)[..16]。
pub fn derive_kek(rk: &[u8; RK_LEN], cluster: &str, component_scope: &str) -> [u8; KEK_LEN] {
    let dg = Sm3Digest;
    let mut msg = Vec::with_capacity(RK_LEN + 8 + cluster.len() + component_scope.len());
    msg.extend_from_slice(rk);
    msg.extend_from_slice(b"jt-kek:");
    msg.extend_from_slice(cluster.as_bytes());
    msg.extend_from_slice(b":");
    msg.extend_from_slice(component_scope.as_bytes());
    let d = dg.digest(&msg);
    let mut kek = [0u8; KEK_LEN];
    kek.copy_from_slice(&d[..KEK_LEN]);
    kek
}

/// DEK 派生（开发模式；与 DevKeyProvider 同式，零迁移一致）。
pub fn derive_dek_dev(timeline_id: &[u8; 16], key_epoch: u64) -> [u8; KEK_LEN] {
    let dg = Sm3Digest;
    let mut msg = Vec::with_capacity(10 + 16 + 8);
    msg.extend_from_slice(b"jtdev-dek:");
    msg.extend_from_slice(timeline_id);
    msg.extend_from_slice(&key_epoch.to_le_bytes());
    let d = dg.digest(&msg);
    let mut dek = [0u8; KEK_LEN];
    dek.copy_from_slice(&d[..KEK_LEN]);
    dek
}

/// scope digest：SM3(cluster || timeline || epoch || lsn_range)（docs/04 §6）。
pub fn scope_digest(
    cluster: &str,
    timeline_id: &[u8; 16],
    key_epoch: u64,
    lsn_range: &str,
) -> [u8; 32] {
    let dg = Sm3Digest;
    let mut msg = Vec::new();
    msg.extend_from_slice(cluster.as_bytes());
    msg.extend_from_slice(timeline_id);
    msg.extend_from_slice(&key_epoch.to_le_bytes());
    msg.extend_from_slice(lsn_range.as_bytes());
    dg.digest(&msg)
}

/// 信封封装：`nonce(12) || SM4GCM(kek, nonce, aad=scope_digest, plain=dek)`。
pub fn wrap_dek(kek: &[u8; KEK_LEN], dek: &[u8; KEK_LEN], scope_digest: &[u8; 32]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = Sm4Gcm
        .seal(kek, &nonce, scope_digest, dek)
        .expect("SM4-GCM seal infallible for valid key");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// 信封解封（AAD 不匹配 = 搬移/篡改检出）。
pub fn unwrap_dek(
    kek: &[u8; KEK_LEN],
    blob: &[u8],
    scope_digest: &[u8; 32],
) -> Result<[u8; KEK_LEN], KmsCryptoError> {
    if blob.len() < 12 + KEK_LEN + 16 {
        return Err(KmsCryptoError::EnvelopeTooShort);
    }
    let (nonce, ct) = blob.split_at(12);
    let plain = Sm4Gcm
        .open(kek, nonce, scope_digest, ct)
        .map_err(|_| KmsCryptoError::EnvelopeAuthFailed)?;
    let mut dek = [0u8; KEK_LEN];
    dek.copy_from_slice(&plain[..KEK_LEN]);
    Ok(dek)
}

/// 生成新 DEK（生产=DRBG 随机；当前用 OS RNG，接口不变）。
pub fn generate_dek() -> [u8; KEK_LEN] {
    let mut dek = [0u8; KEK_LEN];
    rand::thread_rng().fill_bytes(&mut dek);
    dek
}

/// KMS 密码层错误。
#[derive(Debug, thiserror::Error)]
pub enum KmsCryptoError {
    #[error("master key file corrupt (expected {RK_LEN} bytes)")]
    MasterKeyCorrupt,
    #[error("envelope blob too short")]
    EnvelopeTooShort,
    #[error("envelope authentication failed (scope mismatch or tamper)")]
    EnvelopeAuthFailed,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const TL: [u8; 16] = [0x77; 16];

    #[test]
    fn envelope_roundtrip() {
        let rk = [0x42u8; RK_LEN];
        let kek = derive_kek(&rk, "cluster-a", "pageserver");
        let dek = derive_dek_dev(&TL, 7);
        let sd = scope_digest("cluster-a", &TL, 7, "[0x0,0x10)");
        let blob = wrap_dek(&kek, &dek, &sd);
        assert_eq!(blob.len(), 12 + 16 + 16);
        let unwrapped = unwrap_dek(&kek, &blob, &sd).unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn envelope_scope_mismatch_rejected() {
        let rk = [0x42u8; RK_LEN];
        let kek = derive_kek(&rk, "cluster-a", "pageserver");
        let dek = derive_dek_dev(&TL, 7);
        let sd = scope_digest("cluster-a", &TL, 7, "[0x0,0x10)");
        let blob = wrap_dek(&kek, &dek, &sd);
        // 搬到另一 scope：拒绝（docs/04 §10 wrapped_dek 搬移检出）
        let sd2 = scope_digest("cluster-a", &TL, 8, "[0x0,0x10)");
        assert!(matches!(
            unwrap_dek(&kek, &blob, &sd2),
            Err(KmsCryptoError::EnvelopeAuthFailed)
        ));
        // 换 KEK（另一集群）：拒绝
        let kek_b = derive_kek(&rk, "cluster-b", "pageserver");
        assert!(unwrap_dek(&kek_b, &blob, &sd).is_err());
    }

    #[test]
    fn kek_scope_isolation() {
        let rk = [0x42u8; RK_LEN];
        assert_ne!(
            derive_kek(&rk, "cluster-a", "pageserver"),
            derive_kek(&rk, "cluster-a", "safekeeper")
        );
        assert_ne!(
            derive_kek(&rk, "cluster-a", "pageserver"),
            derive_kek(&rk, "cluster-b", "pageserver")
        );
    }

    #[test]
    fn dev_dek_matches_pageserver_dev_provider() {
        // KMS 侧派生必须与 pageserver 的 DevKeyProvider 完全一致（零迁移）
        let kms_dek = derive_dek_dev(&TL, 3);
        let mut p = jt_key_epoch::DevKeyProvider::new();
        p.insert_override(jt_key_epoch::DekScope { timeline_id: TL, key_epoch: 3 }, kms_dek);
        let ps_dek = jt_key_epoch::KeyProvider::get_dek(
            &jt_key_epoch::DevKeyProvider::new(),
            &jt_key_epoch::DekScope { timeline_id: TL, key_epoch: 3 },
        )
        .unwrap();
        assert_eq!(kms_dek, ps_dek);
    }

    #[test]
    fn rk_persist_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "jtkms-rk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("master.key");
        let rk1 = load_or_create_rk(&path).unwrap();
        let rk2 = load_or_create_rk(&path).unwrap();
        assert_eq!(rk1, rk2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "master key must be 0600");
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
