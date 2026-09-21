//! JTDB 加密对象（JtEncryptedObject v1，docs/04 冻结布局）。
//!
//! 职责：对象磁盘格式的精确编解码与读写协议。加密原语通过 jt-crypto-api
//! 注入（边界加密原则，docs/04 §2 原则 1——Timeline/Layer 内部逻辑不感知
//! 密文）。

pub mod error;
pub mod header;
pub mod live_wal;
pub mod object;
pub mod stream;
pub mod tlv;
pub mod wal;

pub use error::ObjectError;
pub use header::{Header, ObjectType, HEADER_SIZE};
pub use object::{chunk_aad, chunk_nonce, ObjectReader, Writer, DEFAULT_CHUNK_SIZE, TAG_LEN};
pub use live_wal::{
    live_chunk_aad, read_live_header, read_live_plain_at, LiveWalLayout, LiveWalMeta,
    LiveWalWriter, TagEntry, FLAG_LIVE_WAL, LIVE_CHUNK_SIZE, TAG_ENTRY_SIZE,
};
pub use stream::{decrypt_range, encrypt_stream, StreamMeta};
pub use wal::{
    seal_wal_segment, unseal_wal_segment, WalSegStats, WalSegWriter, TLV_REAL_CHUNK_COUNT,
    TLV_REAL_PAYLOAD_LEN,
};
