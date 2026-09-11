//! 对象 Header（docs/04 §3.1，v1 布局）。
//!
//! 格式裁决（ADR-015 2026-09-11 回写文档）：文档字段表 base_nonce 终点 98
//! 与"头长 96+32=128"自相矛盾（重叠 2B）。按无重叠原则执行
//! **HEADER_SIZE = 130**（主字段 0..98 + header_digest 98..130），
//! header_digest = SM3(offset 0..98)。文档 04 §3.1 已同步回改。

use crate::error::ObjectError;

pub const MAGIC: [u8; 8] = *b"JTENCOBJ";
pub const FORMAT_VERSION: u16 = 1;
/// 实际头部总长（主字段 98B + header_digest 32B）。
pub const HEADER_SIZE: usize = 130;
pub const DIGEST_OFFSET: usize = 98;

/// 对象类型（docs/04 §3.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectType {
    WalSeg = 1,
    Layer = 2,
    Snapshot = 3,
    Backup = 4,
    AuditJournal = 5,
}

impl ObjectType {
    pub fn from_u8(v: u8) -> Result<Self, ObjectError> {
        Ok(match v {
            1 => ObjectType::WalSeg,
            2 => ObjectType::Layer,
            3 => ObjectType::Snapshot,
            4 => ObjectType::Backup,
            5 => ObjectType::AuditJournal,
            _ => return Err(ObjectError::InvalidHeader("unknown object_type")),
        })
    }
}

/// flags 位定义（docs/04 §3.1）。
pub mod flags {
    pub const CHUNKED: u8 = 0b0000_0001;
    pub const METADATA_SIGNED: u8 = 0b0000_0010;
    pub const SEALED: u8 = 0b0000_0100;
    /// JTDB 追加位（docs/04 §9 允许 v1 定义者扩展）：对象尾部携带 SM2 trailer 签名
    /// （布局：u16 sig_len || signature，见 object.rs trailer 裁决）。
    pub const TRAILER_SIGNED: u8 = 0b0000_1000;
}

/// 解码后的 Header 字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub object_type: ObjectType,
    pub flags: u8,
    pub timeline_id: [u8; 16],
    pub object_id: [u8; 16],
    pub key_epoch: u64,
    pub generation: u64,
    pub chunk_size: u32,
    pub chunk_count: u64,
    pub payload_len: u64,
    pub base_nonce: [u8; 12],
    pub header_digest: [u8; 32],
}

impl Header {
    /// 序列化（130 字节）。header_digest 由 [`Self::compute_digest`] 先行计算。
    pub fn encode(&self) -> Result<[u8; HEADER_SIZE], ObjectError> {
        let mut b = [0u8; HEADER_SIZE];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        b[10] = self.object_type as u8;
        b[11] = self.flags;
        b[12..14].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        // metadata_len 由 Writer 写头时回填（此处 0 占位不破坏 digest 语义——
        // metadata_len 不进 digest 覆盖范围以外字段；docs/04 定义 digest 覆盖
        // offset 0..98，包含 metadata_len，因此 encode 前必须已知。调用方用
        // encode_with_metadata_len。）
        b[14..18].copy_from_slice(&0u32.to_le_bytes());
        b[18..34].copy_from_slice(&self.timeline_id);
        b[34..50].copy_from_slice(&self.object_id);
        b[50..58].copy_from_slice(&self.key_epoch.to_le_bytes());
        b[58..66].copy_from_slice(&self.generation.to_le_bytes());
        b[66..70].copy_from_slice(&self.chunk_size.to_le_bytes());
        b[70..78].copy_from_slice(&self.chunk_count.to_le_bytes());
        b[78..86].copy_from_slice(&self.payload_len.to_le_bytes());
        b[86..98].copy_from_slice(&self.base_nonce);
        b[DIGEST_OFFSET..HEADER_SIZE].copy_from_slice(&self.header_digest);
        Ok(b)
    }

    /// 带回填 metadata_len 的编码（digest 覆盖 0..98 含 metadata_len）。
    pub fn encode_with_metadata_len(
        &self,
        metadata_len: u32,
        digest: &[u8; 32],
    ) -> Result<[u8; HEADER_SIZE], ObjectError> {
        let mut b = [0u8; HEADER_SIZE];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        b[10] = self.object_type as u8;
        b[11] = self.flags;
        b[12..14].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        b[14..18].copy_from_slice(&metadata_len.to_le_bytes());
        b[18..34].copy_from_slice(&self.timeline_id);
        b[34..50].copy_from_slice(&self.object_id);
        b[50..58].copy_from_slice(&self.key_epoch.to_le_bytes());
        b[58..66].copy_from_slice(&self.generation.to_le_bytes());
        b[66..70].copy_from_slice(&self.chunk_size.to_le_bytes());
        b[70..78].copy_from_slice(&self.chunk_count.to_le_bytes());
        b[78..86].copy_from_slice(&self.payload_len.to_le_bytes());
        b[86..98].copy_from_slice(&self.base_nonce);
        b[DIGEST_OFFSET..HEADER_SIZE].copy_from_slice(digest);
        Ok(b)
    }

    /// 解码并验证 magic/version/长度与 header_digest 自校验。
    pub fn decode(buf: &[u8], digest_fn: &dyn jt_crypto_api::Digest256) -> Result<Self, ObjectError> {
        if buf.len() < HEADER_SIZE {
            return Err(ObjectError::Truncated);
        }
        if buf[0..8] != MAGIC {
            return Err(ObjectError::InvalidHeader("bad magic"));
        }
        let ver = u16::from_le_bytes(buf[8..10].try_into().unwrap());
        if ver != FORMAT_VERSION {
            return Err(ObjectError::InvalidHeader("unsupported format_version"));
        }
        // header_digest 自校验：SM3(0..98) == 98..130
        let expect = digest_fn.digest(&buf[0..DIGEST_OFFSET]);
        let stored: [u8; 32] = buf[DIGEST_OFFSET..HEADER_SIZE].try_into().unwrap();
        if expect != stored {
            return Err(ObjectError::InvalidHeader("header_digest mismatch"));
        }

        let object_type = ObjectType::from_u8(buf[10])?;
        let header_size = u16::from_le_bytes(buf[12..14].try_into().unwrap());
        if header_size as usize != HEADER_SIZE {
            return Err(ObjectError::InvalidHeader("unexpected header_size"));
        }
        Ok(Header {
            object_type,
            flags: buf[11],
            timeline_id: buf[18..34].try_into().unwrap(),
            object_id: buf[34..50].try_into().unwrap(),
            key_epoch: u64::from_le_bytes(buf[50..58].try_into().unwrap()),
            generation: u64::from_le_bytes(buf[58..66].try_into().unwrap()),
            chunk_size: u32::from_le_bytes(buf[66..70].try_into().unwrap()),
            chunk_count: u64::from_le_bytes(buf[70..78].try_into().unwrap()),
            payload_len: u64::from_le_bytes(buf[78..86].try_into().unwrap()),
            base_nonce: buf[86..98].try_into().unwrap(),
            header_digest: stored,
        })
    }
}
