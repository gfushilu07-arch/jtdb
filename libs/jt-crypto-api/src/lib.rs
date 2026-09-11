//! JTDB 密码能力抽象层（jt-crypto-api）。
//!
//! 定位（docs/12 §3）：Pageserver/Safekeeper/Compute 通过本 crate 使用密码
//! 能力，自身不实现密码原语。双后端策略：
//!
//! * `tongsuo-backend` —— 合规主路径（密评范围内运算经 Tongsuo 承担）；
//! * `pure-rust-backend`（jt-crypto-sm）—— 测试、开发与未来认证储备。
//!
//! 上层代码只依赖本 crate 的 trait 与类型，后端在组件装配时选定。
//! 全部 trait 的实现必须通过 [`self_test`] 的已知答案测试（KAT）后方可
//! 投入服务（docs/12 §4.2 上电自检）。

use zeroize::Zeroizing;

/// 密码操作错误。实现方不得泄露密钥材料细节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// 输入长度不符合算法要求（密钥/nonce/AAD 布局等）。
    InvalidInput(&'static str),
    /// AEAD tag 校验失败（密文被篡改、密钥/nonce/AAD 不匹配）。
    AuthenticationFailed,
    /// 后端内部错误（底层库返回失败）。
    Backend(&'static str),
    /// 自检（KAT）失败——组件必须 fail-closed 拒绝服务（docs/12 §4.2）。
    SelfTestFailed(&'static str),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidInput(s) => write!(f, "invalid crypto input: {s}"),
            CryptoError::AuthenticationFailed => write!(f, "AEAD authentication failed"),
            CryptoError::Backend(s) => write!(f, "crypto backend error: {s}"),
            CryptoError::SelfTestFailed(s) => write!(f, "crypto self-test failed: {s}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// AEAD 加解密抽象（SM4-GCM 或等价认证式构造，docs/04 §4.2）。
///
/// 同一 key 下 nonce 严禁重用（调用方保证：对象格式由 base_nonce XOR
/// chunk_index 派生，docs/04 §4.5 唯一性论证）。
pub trait Aead {
    /// 加密：返回 `ciphertext || tag`（tag 16 字节，追加在尾部）。
    ///
    /// `aad` 参与认证但不加密（docs/04 §4.3 AAD 布局）。
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// 解密：输入 `ciphertext || tag`，tag 校验失败返回
    /// [`CryptoError::AuthenticationFailed`]。
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    /// 该 AEAD 构造的 nonce 字节长度（GCM = 12）。
    fn nonce_len(&self) -> usize;

    /// 该 AEAD 构造的 key 字节长度（SM4 = 16）。
    fn key_len(&self) -> usize;
}

/// 摘要抽象（SM3，256-bit 输出）。用于 header_digest、metadata_digest、
/// dek_scope_digest（docs/04 §3.1/§3.2/§6）。
pub trait Digest256 {
    /// 单发摘要。流式场景（大对象）由实现方另行提供扩展 trait。
    fn digest(&self, data: &[u8]) -> [u8; 32];
}

/// 上电自检：实现方必须用标准 KAT 依次验证原语正确性
/// （SM4 加解密回环、SM3 摘要 KAT、AEAD tag 回环——docs/12 §4.2），
/// 任何失败返回 [`CryptoError::SelfTestFailed`]，组件拒绝服务。
pub trait SelfTest {
    fn self_test(&self) -> Result<(), CryptoError>;
}

/// 签名抽象（SM2，docs/04 §3.4 对象 trailer 签名）。
/// 签名者持有私钥；验证者仅持公钥（组件证书链提供，docs/13）。
pub trait SignatureKey {
    /// 对消息签名，返回原始签名字节（SM2: r||s 各 32B）。
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    /// 签名者公钥字节（SM2 非压缩点：04||X||Y，65B）。
    fn public_key(&self) -> Vec<u8>;
}

/// 验证者抽象。
pub trait SignatureVerifier {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> bool;
}

/// 后端标识（装配与审计日志用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// 纯 Rust 实现（jt-crypto-sm）：测试、开发与未来认证储备。
    PureRust,
    /// Tongsuo 适配（密评主路径）。
    Tongsuo,
}

/// 密码后端聚合句柄：组件持有一个，向上提供全部能力。
pub struct CryptoBackend {
    pub kind: BackendKind,
    pub aead: Box<dyn Aead + Send + Sync>,
    pub digest: Box<dyn Digest256 + Send + Sync>,
}

impl CryptoBackend {
    /// 跑全部上电自检；失败即返回错误，调用方必须 fail-closed。
    pub fn power_on_self_test(&self) -> Result<(), CryptoError> {
        self.aead_self_test()?;
        Ok(())
    }

    /// AEAD 加解密回环 + 标准向量校验（由 SelfTest trait 实现方提供，
    /// 此处做通用最小回环：加密→解密一致 + 错误 key 解密必失败）。
    fn aead_self_test(&self) -> Result<(), CryptoError> {
        let key = [0xA5u8; 16];
        // GCM nonce 恒 12B；这里按实现方声明长度构造（后端自检一致性）
        let nonce = vec![0x07u8; self.aead.nonce_len()];
        let aad = b"jt-crypto-api self test";
        let pt = b"The quick brown fox jumps over the lazy dog";
        let ct = self.aead.seal(&key, &nonce, aad, pt)?;
        if ct.len() != pt.len() + 16 {
            return Err(CryptoError::SelfTestFailed("AEAD tag length mismatch"));
        }
        let rt = self.aead.open(&key, &nonce, aad, &ct)?;
        if rt.as_slice() != pt {
            return Err(CryptoError::SelfTestFailed("AEAD roundtrip mismatch"));
        }
        let bad_key = [0x5Au8; 16];
        if self.aead.open(&bad_key, &nonce, aad, &ct).is_ok() {
            return Err(CryptoError::SelfTestFailed("AEAD accepted wrong key"));
        }
        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        if self.aead.open(&key, &nonce, aad, &tampered).is_ok() {
            return Err(CryptoError::SelfTestFailed("AEAD accepted tampered tag"));
        }
        Ok(())
    }
}
