//! JTDB Tongsuo 密码后端（合规主路径，docs/12 §3.3）。
//!
//! 密评范围内的密码运算（SM4-GCM 对象加密、SM3 摘要、SM2 trailer 签名）
//! 经铜锁 Tongsuo（国家密码管理局商用密码认证产品）承担。实现 jt-crypto-api
//! 的 trait，与 pure-rust-backend（jt-crypto-sm）可互换。
//!
//! 链接：Tongsuo 安装树由 `JTDB_TONGSUO_DIR` 环境变量或默认缓存路径提供。

use jt_crypto_api::{Aead, CryptoError, Digest256};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::pkey::{PKey, Id};
use openssl::sign::Signer as OsslSigner;
use openssl::sign::Verifier as OsslVerifier;
use zeroize::Zeroizing;

pub const SM4_KEY_LEN: usize = 16;
pub const GCM_NONCE_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;

fn map_err(e: impl std::fmt::Display) -> CryptoError {
    CryptoError::Backend(Box::leak(format!("tongsuo: {e}").into_boxed_str()))
}

/// SM4-GCM AEAD（EVP_sm4_gcm）。
#[derive(Debug, Default, Clone, Copy)]
pub struct TongsuoSm4Gcm;

impl Aead for TongsuoSm4Gcm {
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if key.len() != SM4_KEY_LEN {
            return Err(CryptoError::InvalidInput("SM4 key must be 16 bytes"));
        }
        if nonce.len() != GCM_NONCE_LEN {
            return Err(CryptoError::InvalidInput("GCM nonce must be 12 bytes"));
        }
        let cipher = Cipher::fetch(None, "SM4-GCM", None).map_err(map_err)?;
        let mut ctx = CipherCtx::new().map_err(map_err)?;
        ctx.encrypt_init(Some(&cipher), Some(key), Some(nonce)).map_err(map_err)?;
        if !aad.is_empty() {
            ctx.cipher_update(aad, None).map_err(map_err)?;
        }
        let mut out = vec![0u8; plaintext.len() + GCM_TAG_LEN];
        let mut n = ctx.cipher_update(plaintext, Some(&mut out)).map_err(map_err)?;
        let mut fin = [0u8; 16];
        n += ctx.cipher_final(&mut fin).map_err(map_err)?;
        out.truncate(n);
        let mut tag = vec![0u8; GCM_TAG_LEN];
        ctx.tag(&mut tag).map_err(map_err)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if ciphertext_with_tag.len() < GCM_TAG_LEN {
            return Err(CryptoError::InvalidInput("ciphertext shorter than tag"));
        }
        let cipher = Cipher::fetch(None, "SM4-GCM", None).map_err(map_err)?;
        let mut ctx = CipherCtx::new().map_err(map_err)?;
        ctx.decrypt_init(Some(&cipher), Some(key), Some(nonce)).map_err(map_err)?;
        if !aad.is_empty() {
            ctx.cipher_update(aad, None).map_err(map_err)?;
        }
        let split = ciphertext_with_tag.len() - GCM_TAG_LEN;
        let (ct, tag) = ciphertext_with_tag.split_at(split);
        let mut pt = Zeroizing::new(vec![0u8; ct.len() + GCM_TAG_LEN]);
        let mut n = ctx.cipher_update(ct, Some(&mut pt)).map_err(map_err)?;
        ctx.set_tag(tag).map_err(map_err)?;
        ctx.cipher_final(&mut pt[n..]).map_err(map_err)?;
        pt.truncate(n);
        Ok(pt)
    }

    fn nonce_len(&self) -> usize {
        GCM_NONCE_LEN
    }

    fn key_len(&self) -> usize {
        SM4_KEY_LEN
    }
}

/// SM3 摘要（EVP_sm3）。
#[derive(Debug, Default, Clone, Copy)]
pub struct TongsuoSm3;

impl Digest256 for TongsuoSm3 {
    fn digest(&self, data: &[u8]) -> [u8; 32] {
        use openssl::hash::{hash, MessageDigest};
        let d = hash(MessageDigest::sm3(), data).expect("tongsuo sm3");
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }
}

/// SM2 签名者（EVP_sm2；私钥为 32B 大端）。
pub struct TongsuoSm2Signer {
    pkey: PKey<openssl::pkey::Private>,
    pk_bytes: Vec<u8>,
}

fn sm2_group() -> openssl::ec::EcGroup {
    openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SM2).expect("sm2 group")
}

impl TongsuoSm2Signer {
    pub fn from_sk_bytes(sk_bytes: &[u8]) -> Result<Self, CryptoError> {
        let group = sm2_group();
        let sk = openssl::bn::BigNum::from_slice(sk_bytes).map_err(map_err)?;
        // 公钥 = G * sk（EC_POINT_mul）
        let mut point = openssl::ec::EcPoint::new(&group).map_err(map_err)?;
        let mut ctx = openssl::bn::BigNumContext::new().map_err(map_err)?;
        point
            .mul_generator(&group, &sk, &mut ctx)
            .map_err(map_err)?;
        let ec = openssl::ec::EcKey::from_private_components(&group, &sk, &point)
            .map_err(map_err)?;
        ec.check_key().map_err(map_err)?;
        let mut pt_bytes = vec![0u8; 65];
        point
            .to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map(|b| pt_bytes.copy_from_slice(&b))
            .map_err(map_err)?;
        Ok(TongsuoSm2Signer {
            pkey: PKey::from_ec_key(ec).map_err(map_err)?,
            pk_bytes: pt_bytes,
        })
    }
}

impl jt_crypto_api::SignatureKey for TongsuoSm2Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        // 注意：SM2 签名的 userid（Z 值）参数 openssl 0.10 未暴露，Tongsuo 默认
        // userid=1234567812345678 与 libsm 一致——直接 SM3 摘要签名。
        let mut ctx = match OsslSigner::new(openssl::hash::MessageDigest::sm3(), &self.pkey) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        ctx.update(msg).and_then(|_| ctx.sign_to_vec()).unwrap_or_default()
    }

    fn public_key(&self) -> Vec<u8> {
        self.pk_bytes.clone()
    }
}

/// SM2 验证者（公钥 04||X||Y）。
pub struct TongsuoSm2Verifier {
    pkey: PKey<openssl::pkey::Public>,
}

impl TongsuoSm2Verifier {
    pub fn from_pk_bytes(pk: &[u8]) -> Result<Self, CryptoError> {
        if pk.len() != 65 || pk[0] != 0x04 {
            return Err(CryptoError::InvalidInput(
                "SM2 public key must be 65 bytes uncompressed (04||X||Y)",
            ));
        }
        let group = sm2_group();
        let mut ctx = openssl::bn::BigNumContext::new().map_err(map_err)?;
        let point =
            openssl::ec::EcPoint::from_bytes(&group, pk, &mut ctx).map_err(map_err)?;
        let ec = openssl::ec::EcKey::from_public_key(&group, &point).map_err(map_err)?;
        Ok(TongsuoSm2Verifier {
            pkey: PKey::from_ec_key(ec).map_err(map_err)?,
        })
    }
}

impl jt_crypto_api::SignatureVerifier for TongsuoSm2Verifier {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        let mut ctx = match OsslVerifier::new(openssl::hash::MessageDigest::sm3(), &self.pkey) {
            Ok(c) => c,
            Err(_) => return false,
        };
        ctx.update(msg).is_ok() && ctx.verify(signature).unwrap_or(false)
    }
}

/// 聚合后端（与 jt-crypto-sm::pure_rust_backend 同构）。
pub fn tongsuo_backend() -> Result<jt_crypto_api::CryptoBackend, CryptoError> {
    let aead = TongsuoSm4Gcm;
    // KAT：RFC 8998 向量（与 jt-crypto-sm 共用同一份标准）
    kat_rfc8998(&aead)?;
    Ok(jt_crypto_api::CryptoBackend {
        kind: jt_crypto_api::BackendKind::Tongsuo,
        aead: Box::new(aead),
        digest: Box::new(TongsuoSm3),
    })
}

fn kat_rfc8998(aead: &dyn Aead) -> Result<(), CryptoError> {
    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let iv: [u8; 12] = [0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd];
    let aad: [u8; 20] = [
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
        0xef, 0xab, 0xad, 0xda, 0xd2,
    ];
    let mut pt = Vec::new();
    for pair in [[0xAAu8, 0xBBu8], [0xCCu8, 0xDDu8], [0xEEu8, 0xFFu8], [0xEEu8, 0xAAu8]] {
        pt.extend_from_slice(&[pair[0]; 8]);
        pt.extend_from_slice(&[pair[1]; 8]);
    }
    let ct = aead.seal(&key, &iv, &aad, &pt)?;
    const EXPECTED_TAG: [u8; 16] = [
        0x83, 0xde, 0x35, 0x41, 0xe4, 0xc2, 0xb5, 0x81, 0x77, 0xe0, 0x65, 0xa9, 0xbf, 0x7b, 0x62,
        0xec,
    ];
    if ct.len() != pt.len() + 16 || ct[64..] != EXPECTED_TAG[..] {
        return Err(CryptoError::SelfTestFailed("RFC8998 tag mismatch"));
    }
    if aead.open(&key, &iv, &aad, &ct)?.as_slice() != pt {
        return Err(CryptoError::SelfTestFailed("RFC8998 roundtrip mismatch"));
    }
    Ok(())
}
