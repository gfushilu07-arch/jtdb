//! Metadata TLV 编解码（docs/04 §3.2）。
//!
//! entry := type(u16) || len(u32) || value；未知 type 必须跳过（前向兼容）。

use crate::error::ObjectError;

pub mod tlv_type {
    pub const KEK_REF: u16 = 0x0001;
    pub const WRAPPED_DEK: u16 = 0x0002;
    pub const LSN_RANGE: u16 = 0x0003;
    pub const CREATED_AT: u16 = 0x0004;
    pub const NODE_ID: u16 = 0x0005;
    pub const LINEAGE_ID: u16 = 0x0006;
    pub const RETENTION_HINT: u16 = 0x0007;
}

/// 单条 TLV。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub tlv_type: u16,
    pub value: Vec<u8>,
}

impl Entry {
    pub fn new(tlv_type: u16, value: Vec<u8>) -> Self {
        Entry { tlv_type, value }
    }
}

/// 编码一组 TLV 为 metadata 区。
pub fn encode(entries: &[Entry]) -> Result<Vec<u8>, ObjectError> {
    let mut out = Vec::new();
    for e in entries {
        if e.value.len() > u32::MAX as usize {
            return Err(ObjectError::Other("TLV value too large"));
        }
        out.extend_from_slice(&e.tlv_type.to_le_bytes());
        out.extend_from_slice(&(e.value.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.value);
    }
    Ok(out)
}

/// 解码 metadata 区；未知 type 保留（前向兼容，消费方自行忽略）。
pub fn decode(buf: &[u8]) -> Result<Vec<Entry>, ObjectError> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        if pos + 6 > buf.len() {
            return Err(ObjectError::InvalidHeader("TLV header truncated"));
        }
        let tlv_type = u16::from_le_bytes(buf[pos..pos + 2].try_into().unwrap());
        let len = u32::from_le_bytes(buf[pos + 2..pos + 6].try_into().unwrap()) as usize;
        pos += 6;
        if pos + len > buf.len() {
            return Err(ObjectError::InvalidHeader("TLV value truncated"));
        }
        entries.push(Entry {
            tlv_type,
            value: buf[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    Ok(entries)
}
