//! 对象层错误（与 jt-crypto-api 的 CryptoError 分层）。

#[derive(Debug, thiserror::Error)]
pub enum ObjectError {
    #[error("crypto: {0}")]
    Crypto(#[from] jt_crypto_api::CryptoError),

    #[error("object truncated or too short")]
    Truncated,

    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),

    #[error("object is not sealed (crash remnant?)")]
    NotSealed,

    #[error("chunk {0} out of range")]
    ChunkOutOfRange(u64),

    #[error("payload length mismatch: header says {header}, actual {actual}")]
    PayloadLenMismatch { header: u64, actual: u64 },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(&'static str),
}
