//! JTDB 纯 Rust 密码后端（jt-crypto-sm，pure-rust-backend）。
//!
//! 定位（docs/12 §3.3）：**测试、开发与未来认证储备**，不承担密评承诺；
//! 合规主路径为 tongsuo-backend（另行实现）。本 crate 提供：
//!
//! * [`Sm4Gcm`] —— SM4-GCM AEAD（ghash 组装，RFC 8452/NIST SP 800-38D 算法）；
//! * [`Sm3Digest`] —— SM3 摘要（RustCrypto `sm3`）；
//! * 标准 KAT 自检（GM/T 0002-2012 SM4 示例、GB/T 32905-2016 SM3 示例）。
//!
//! SM2 签名（trailer 签名，docs/04 §3.4）后续补充。

pub mod api { pub use jt_crypto_api::*; }

pub mod gcm;
pub mod kat;

use jt_crypto_api::{Aead, BackendKind, CryptoBackend, CryptoError, Digest256, SelfTest};
use zeroize::Zeroizing;

pub use gcm::Sm4Gcm;
pub use sm3_digest::Sm3Digest;

pub mod sm3_digest {
    use super::Digest256;

    /// SM3 摘要实现（RustCrypto `sm3`，GB/T 32905-2016）。
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Sm3Digest;

    impl Digest256 for Sm3Digest {
        fn digest(&self, data: &[u8]) -> [u8; 32] {
            use sm3::digest::Digest as _;
            let mut h = sm3::Sm3::new();
            h.update(data);
            h.finalize().into()
        }
    }
}

/// 组装默认 pure-rust 后端。组件装配时调用；返回前先跑上电自检。
pub fn pure_rust_backend() -> Result<CryptoBackend, CryptoError> {
    let backend = CryptoBackend {
        kind: BackendKind::PureRust,
        aead: Box::new(Sm4Gcm),
        digest: Box::new(Sm3Digest),
    };
    // SelfTest 的一致实现见 Sm4Gcm；此处复用聚合自检。
    <Sm4Gcm as SelfTest>::self_test(&Sm4Gcm)?;
    Ok(backend)
}

/// SM3 标准 KAT（GB/T 32905-2016 附录 A 示例一："abc"）。
pub fn sm3_kat() -> Result<(), CryptoError> {
    const EXPECTED: [u8; 32] = [
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4,
        0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b,
        0xa8, 0xe0,
    ];
    let d = Sm3Digest::digest(&Sm3Digest, b"abc");
    if d != EXPECTED {
        return Err(CryptoError::SelfTestFailed("SM3 KAT mismatch"));
    }
    Ok(())
}

impl SelfTest for Sm4Gcm {
    fn self_test(&self) -> Result<(), CryptoError> {
        kat::sm4_ecb_kat()?;
        sm3_kat()?;
        // RFC 8998 附录 A.1 SM4-GCM 官方向量（GB/T 36624 对标口径）
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let iv: [u8; 12] = [0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd];
        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let mut pt: Vec<u8> = Vec::new();
        // RFC 8998 明文布局：每行 32 hex = 16 字节（8A+8B / 8C+8D / 8E+8F / 8E+8A）
        for pair in [[0xAAu8, 0xBBu8], [0xCCu8, 0xDDu8], [0xEEu8, 0xFFu8], [0xEEu8, 0xAAu8]] {
            pt.extend_from_slice(&[pair[0]; 8]);
            pt.extend_from_slice(&[pair[1]; 8]);
        }
        let ct = self.seal(&key, &iv, &aad, &pt)?;
        const EXPECTED_CT: [u8; 64] = [
            0x17, 0xf3, 0x99, 0xf0, 0x8c, 0x67, 0xd5, 0xee, 0x19, 0xd0, 0xdc, 0x99, 0x69, 0xc4,
            0xbb, 0x7d, 0x5f, 0xd4, 0x6f, 0xd3, 0x75, 0x64, 0x89, 0x06, 0x91, 0x57, 0xb2, 0x82,
            0xbb, 0x20, 0x07, 0x35, 0xd8, 0x27, 0x10, 0xca, 0x5c, 0x22, 0xf0, 0xcc, 0xfa, 0x7c,
            0xbf, 0x93, 0xd4, 0x96, 0xac, 0x15, 0xa5, 0x68, 0x34, 0xcb, 0xcf, 0x98, 0xc3, 0x97,
            0xb4, 0x02, 0x4a, 0x26, 0x91, 0x23, 0x3b, 0x8d,
        ];
        const EXPECTED_TAG: [u8; 16] = [
            0x83, 0xde, 0x35, 0x41, 0xe4, 0xc2, 0xb5, 0x81, 0x77, 0xe0, 0x65, 0xa9, 0xbf, 0x7b,
            0x62, 0xec,
        ];
        if ct.len() != 80 || ct[..64] != EXPECTED_CT[..] {
            return Err(CryptoError::SelfTestFailed("RFC8998 ciphertext mismatch"));
        }
        if ct[64..] != EXPECTED_TAG[..] {
            return Err(CryptoError::SelfTestFailed("RFC8998 tag mismatch"));
        }
        Ok(())
    }
}

/// 便捷封装：随机 key 生成占位（OS CSPRNG）。DRBG 结构化实现（docs/12 §4.3）
/// 由 jt-key-epoch/KMS 层另行提供。
pub fn random_key() -> Zeroizing<[u8; 16]> {
    let mut k = Zeroizing::new([0u8; 16]);
    getrandom_fill(k.as_mut());
    k
}

fn getrandom_fill(buf: &mut [u8]) {
    // 独立小实现避免引入 getrandom 版本漂移；OS CSPRNG 受控回退路径（docs/12 §4.1）
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").expect("CSPRNG unavailable");
        f.read_exact(buf).expect("CSPRNG read failed");
    }
    #[cfg(target_os = "macos")]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").expect("CSPRNG unavailable");
        f.read_exact(buf).expect("CSPRNG read failed");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    compile_error!("unsupported platform for CSPRNG fallback");
}
