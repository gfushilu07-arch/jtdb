//! SM2 签名（libsm 适配；GB/T 32907 数字签名部分 / GM/T 0003）。
//!
//! 用途：对象 trailer 签名（docs/04 §3.4）——绑定"谁写的 + 内容是什么"，
//! 验签材料来自组件证书链（docs/13）。开发模式可无签名（flags.bit3=0）。

use jt_crypto_api::{CryptoError, SignatureKey, SignatureVerifier};
use libsm::sm2::ecc::{EccCtx, Point};
use libsm::sm2::signature::SigCtx;
use num_bigint::BigUint;
use zeroize::Zeroize as _;
use zeroize::Zeroizing;

/// 签名者（持私钥）。私钥在 Drop 时零化。
pub struct Sm2Signer {
    ctx: SigCtx,
    curve: EccCtx,
    sk: BigUint,
    pk_point: Point,
    pk_bytes: Vec<u8>, // 非压缩点 04||X||Y
}

impl std::fmt::Debug for Sm2Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sm2Signer").finish_non_exhaustive()
    }
}

impl Sm2Signer {
    /// 生成新密钥对（开发模式；生产由组件证书/密码卡提供，docs/13）。
    pub fn generate() -> Result<Self, CryptoError> {
        let ctx = SigCtx::new();
        let curve = EccCtx::new();
        let (pk, sk) = ctx
            .new_keypair()
            .map_err(|_| CryptoError::Backend("sm2 keygen"))?;
        let pk_bytes = curve
            .point_to_bytes(&pk, false)
            .map_err(|_| CryptoError::Backend("sm2 pk serialize"))?;
        Ok(Sm2Signer {
            ctx,
            curve,
            sk,
            pk_point: pk,
            pk_bytes,
        })
    }

    /// 从私钥字节恢复（KMS/证书链路径）。
    pub fn from_sk_bytes(sk_bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut sk_buf = Zeroizing::new(sk_bytes.to_vec());
        let sk = BigUint::from_bytes_be(&sk_buf);
        let ctx = SigCtx::new();
        let curve = EccCtx::new();
        let pk_point = ctx
            .pk_from_sk(&sk)
            .map_err(|_| CryptoError::Backend("sm2 pk derive"))?;
        let pk_bytes = curve
            .point_to_bytes(&pk_point, false)
            .map_err(|_| CryptoError::Backend("sm2 pk serialize"))?;
        sk_buf.zeroize();
        Ok(Sm2Signer {
            ctx,
            curve,
            sk,
            pk_point,
            pk_bytes,
        })
    }

    /// 公钥字节（非压缩点 04||X||Y，65B）。
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.pk_bytes
    }
}

impl SignatureKey for Sm2Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig = match self.ctx.sign(msg, &self.sk, &self.pk_point) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        // r||s 各 32B（大端定长）
        let mut out = Vec::with_capacity(64);
        let r = sig.get_r().to_bytes_be();
        let s = sig.get_s().to_bytes_be();
        out.extend(std::iter::repeat(0u8).take(32 - r.len()));
        out.extend_from_slice(&r);
        out.extend(std::iter::repeat(0u8).take(32 - s.len()));
        out.extend_from_slice(&s);
        out
    }

    fn public_key(&self) -> Vec<u8> {
        self.pk_bytes.clone()
    }
}

/// 验证者（仅公钥）。
pub struct Sm2Verifier {
    ctx: SigCtx,
    curve: EccCtx,
    pk: Vec<u8>,
}

impl Sm2Verifier {
    pub fn from_pk_bytes(pk: &[u8]) -> Result<Self, CryptoError> {
        if pk.len() != 65 || pk[0] != 0x04 {
            return Err(CryptoError::InvalidInput(
                "SM2 public key must be 65 bytes uncompressed (04||X||Y)",
            ));
        }
        Ok(Sm2Verifier {
            ctx: SigCtx::new(),
            curve: EccCtx::new(),
            pk: pk.to_vec(),
        })
    }
}

impl SignatureVerifier for Sm2Verifier {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let sig = libsm::sm2::signature::Signature::new(&signature[..32], &signature[32..]);
        match self.curve.bytes_to_point(&self.pk) {
            Ok(point) => self.ctx.verify(msg, &point, &sig).unwrap_or(false),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jt_crypto_api::SignatureVerifier as _;

    #[test]
    fn sign_verify_roundtrip() {
        let signer = Sm2Signer::generate().expect("keygen");
        let msg = b"jt trailer: header_digest || metadata_digest || last_chunk_tag";
        let sig = signer.sign(msg);
        assert_eq!(sig.len(), 64);
        let verifier = Sm2Verifier::from_pk_bytes(&signer.public_key_bytes()).expect("verifier");
        assert!(verifier.verify(msg, &sig));
        assert!(!verifier.verify(b"tampered", &sig));
    }

    #[test]
    fn different_keys_fail_verification() {
        let a = Sm2Signer::generate().expect("keygen a");
        let b = Sm2Signer::generate().expect("keygen b");
        let sig = a.sign(b"msg");
        let vb = Sm2Verifier::from_pk_bytes(&b.public_key_bytes()).expect("verifier b");
        assert!(!vb.verify(b"msg", &sig));
    }

    #[test]
    fn verifier_rejects_short_signature() {
        let signer = Sm2Signer::generate().expect("keygen");
        let v = Sm2Verifier::from_pk_bytes(&signer.public_key_bytes()).expect("verifier");
        assert!(!v.verify(b"msg", &[0u8; 32]));
    }
}
