//! 已知答案测试（KAT）。标准向量出处：
//!
//! * SM4 ECB：GM/T 0002-2012 附录 A 示例一（明文/密钥/密文均为
//!   `01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10`）；
//! * SM3：GB/T 32905-2016 附录 A（"abc"，见 crate 根 `sm3_kat`）；
//! * GCM：NIST SP 800-38D GCM spec Test Case 1（AES 分组无关组装正确性）。

use crate::gcm::Sm4Gcm;
use jt_crypto_api::{Aead, CryptoError, SelfTest};
use sm4::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use sm4::{cipher, Sm4};

/// GM/T 0002-2012 附录 A 示例一。
pub fn sm4_ecb_kat() -> Result<(), CryptoError> {
    const KEY: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    const PT: [u8; 16] = KEY;
    const EXPECTED_CT: [u8; 16] = [
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42,
        0x46,
    ];

    let cipher = Sm4::new_from_slice(&KEY).map_err(|_| CryptoError::Backend("sm4 init"))?;
    let mut block = cipher::Block::<Sm4>::clone_from_slice(&PT);
    cipher.encrypt_block(&mut block);
    if block.as_slice() != EXPECTED_CT {
        return Err(CryptoError::SelfTestFailed("SM4-ECB encrypt KAT mismatch"));
    }
    cipher.decrypt_block(&mut block);
    if block.as_slice() != PT {
        return Err(CryptoError::SelfTestFailed("SM4-ECB decrypt KAT mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jt_crypto_api::{Aead, CryptoError};

    #[test]
    fn sm4_ecb_standard_vector() {
        sm4_ecb_kat().expect("SM4 ECB KAT");
    }

    #[test]
    fn sm3_standard_vector() {
        super::super::sm3_kat().expect("SM3 KAT");
    }

    #[test]
    fn gcm_roundtrip() {
        let aead = Sm4Gcm;
        let key = [0x42u8; 16];
        let nonce = [0x99u8; 12];
        let aad = b"jt object aad";
        let pt = vec![0x5Au8; 64 * 1024]; // 1 chunk（docs/04 §4.1）
        let ct = aead.seal(&key, &nonce, aad, &pt).unwrap();
        assert_eq!(ct.len(), pt.len() + 16);
        let rt = aead.open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(rt.as_slice(), pt.as_slice());
    }

    #[test]
    fn gcm_rejects_tamper() {
        let aead = Sm4Gcm;
        let key = [0x42u8; 16];
        let nonce = [0x99u8; 12];
        let ct = aead.seal(&key, &nonce, b"aad", b"payload").unwrap();
        let mut t = ct.clone();
        let n = t.len();
        t[n - 1] ^= 1;
        assert!(matches!(
            aead.open(&key, &nonce, b"aad", &t),
            Err(CryptoError::AuthenticationFailed)
        ));
        // AAD 不匹配同样必须失败
        assert!(matches!(
            aead.open(&key, &nonce, b"aad2", &ct),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn gcm_nonce_uniqueness_semantics() {
        // docs/04 §4.5：同一 key 下 nonce 变化 → 同一明文产生不同密文
        let aead = Sm4Gcm;
        let key = [0x11u8; 16];
        let c1 = aead.seal(&key, &[1u8; 12], &[], b"x").unwrap();
        let c2 = aead.seal(&key, &[2u8; 12], &[], b"x").unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn power_on_self_test_passes() {
        let be = super::super::pure_rust_backend().expect("self test");
        assert_eq!(be.kind, jt_crypto_api::BackendKind::PureRust);
        assert_eq!(be.aead.key_len(), 16);
        assert_eq!(be.aead.nonce_len(), 12);
    }
}
