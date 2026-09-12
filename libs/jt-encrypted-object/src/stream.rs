//! 流式加密映射与随机解密（EncryptedVirtualFile 的核心逻辑，docs/04 完整实现 A 步）。
//!
//! 物理布局（pageserver Layer 文件包装，ADR-015 定稿）：
//!   [blk0 summary：明文透传，ENC_START=8192 之前]
//!   [加密流区间：明文与密文 1:1 同偏移（AEAD 密文等长）]
//!   [tag 表：chunk_count × 16B（文件尾，finish 时落盘）]
//!
//! 明文流偏移 p（≥ ENC_START）→ chunk c = (p-ENC_START)/CS，
//! 密文物理偏移 = p（1:1），chunk 密文 = 明文 chunk ⊕ keystream（GCM），
//! tag[c] 单独存表。Layer 的 index 记录的 blob offset（明文语义）无需换算。

use crate::error::ObjectError;
use jt_crypto_api::Aead;

/// 流元数据（与 header 字段对齐，docs/04 §3.1）。
#[derive(Debug, Clone)]
pub struct StreamMeta {
    pub enc_start: u64,
    pub chunk_size: u64,
    pub base_nonce: [u8; 12],
}

impl StreamMeta {
    pub fn new(enc_start: u64, chunk_size: u64, base_nonce: [u8; 12]) -> Self {
        StreamMeta { enc_start, chunk_size, base_nonce }
    }

    pub fn chunk_nonce(&self, chunk_index: u64) -> [u8; 12] {
        let mut n = self.base_nonce;
        let idx = chunk_index.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= idx[i];
        }
        n
    }
}

/// 顺序流加密：明文流（≥ ENC_START 部分）按 chunk_size 切块 AEAD 加密，
/// 输出与明文等长的密文（写入原位置）与 tag 表。
///
/// `plaintext` 为**加密区完整明文**（不含 ENC_START 之前的明文区）。
/// 返回 (ciphertext（与 plaintext 等长）， tags（每 chunk 16B）)。
/// 单 chunk AEAD 加密（流式包装器用：写边逐 chunk seal，不整流缓冲）。
///
/// `chunk_plain` 长度必须 ≤ chunk_size（尾 chunk 允许短）；返回 (密文（与明文等长）， tag 16B)。
pub fn seal_chunk(
    aead: &dyn Aead,
    meta: &StreamMeta,
    header_digest: &[u8; 32],
    object_type_tag: u8,
    key_epoch: u64,
    generation: u64,
    dek: &[u8],
    chunk_index: u64,
    chunk_plain: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), ObjectError> {
    let ci = chunk_index;
    let offset = meta.enc_start + ci * meta.chunk_size;
    let nonce = meta.chunk_nonce(ci);
    let mut aad = Vec::with_capacity(32 + 1 + 8 + 8 + 4 + 8 + 4);
    aad.extend_from_slice(header_digest);
    aad.push(object_type_tag);
    aad.extend_from_slice(&key_epoch.to_le_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    aad.extend_from_slice(&ci.to_le_bytes());
    aad.extend_from_slice(&offset.to_le_bytes());
    aad.extend_from_slice(&(chunk_plain.len() as u32).to_le_bytes());
    let c = aead.seal(dek, &nonce, &aad, chunk_plain)?;
    debug_assert_eq!(c.len(), chunk_plain.len() + 16);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&c[chunk_plain.len()..]);
    Ok((c[..chunk_plain.len()].to_vec(), tag))
}

pub fn encrypt_stream(
    aead: &dyn Aead,
    meta: &StreamMeta,
    header_digest: &[u8; 32],
    object_type_tag: u8,
    key_epoch: u64,
    generation: u64,
    dek: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<Vec<u8>>), ObjectError> {
    let cs = meta.chunk_size as usize;
    let mut ct = Vec::with_capacity(plaintext.len());
    let mut tags = Vec::new();
    for (i, chunk) in plaintext.chunks(cs).enumerate() {
        let ci = i as u64;
        let offset = meta.enc_start + ci * meta.chunk_size;
        let nonce = meta.chunk_nonce(ci);
        let mut aad = Vec::with_capacity(32 + 1 + 8 + 8 + 4 + 8 + 4);
        aad.extend_from_slice(header_digest);
        aad.push(object_type_tag);
        aad.extend_from_slice(&key_epoch.to_le_bytes());
        aad.extend_from_slice(&generation.to_le_bytes());
        aad.extend_from_slice(&ci.to_le_bytes());
        aad.extend_from_slice(&offset.to_le_bytes());
        aad.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        let c = aead.seal(dek, &nonce, &aad, chunk)?;
        debug_assert_eq!(c.len(), chunk.len() + 16);
        tags.push(c[chunk.len()..].to_vec());
        ct.extend_from_slice(&c[..chunk.len()]);
    }
    Ok((ct, tags))
}

/// 随机范围解密：从密文（加密区完整密文 + tags）读取明文 [offset, offset+len)。
/// offset 为**流内偏移**（0 = 加密区起点；pageserver 调用方负责减去 ENC_START）。
///
/// v1 无 chunk 缓存（每 chunk 即时解密，Tongsuo 硬件加速 SM4；
/// LRU 缓存为 pageserver 胶水层的后续优化）。
pub fn decrypt_range(
    aead: &dyn Aead,
    meta: &StreamMeta,
    header_digest: &[u8; 32],
    object_type_tag: u8,
    key_epoch: u64,
    generation: u64,
    dek: &[u8],
    ciphertext: &[u8],
    tags: &[Vec<u8>],
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, ObjectError> {
    let cs = meta.chunk_size as usize;
    let rel = offset;
    if rel as usize + len > ciphertext.len() {
        return Err(ObjectError::Truncated);
    }
    let mut out = Vec::with_capacity(len);
    let mut done = 0usize;
    while done < len {
        let pos = rel as usize + done;
        let ci = pos / cs;
        let in_off = pos % cs;
        let take = (cs - in_off).min(len - done).min(ciphertext.len() - pos);
        // chunk 明文 = 密文块 ⊕ keystream；用 AEAD open 拿全 chunk 明文（tag 验证）
        let nonce = meta.chunk_nonce(ci as u64);
        // 必须解**整个 chunk**（AAD 的 chunk_len 与加密时一致；in_off 后从明文切片）
        let chunk_start = pos - in_off;
        let chunk_ct_len = (cs as usize).min(ciphertext.len() - chunk_start);
        let mut aad = Vec::with_capacity(32 + 1 + 8 + 8 + 4 + 8 + 4);
        aad.extend_from_slice(header_digest);
        aad.push(object_type_tag);
        aad.extend_from_slice(&key_epoch.to_le_bytes());
        aad.extend_from_slice(&(generation).to_le_bytes());
        aad.extend_from_slice(&(ci as u64).to_le_bytes());
        aad.extend_from_slice(&(meta.enc_start + ci as u64 * cs as u64).to_le_bytes());
        aad.extend_from_slice(&(chunk_ct_len as u32).to_le_bytes());
        let chunk_ct = &ciphertext[chunk_start..chunk_start + chunk_ct_len];
        let tag = tags.get(ci).ok_or(ObjectError::Truncated)?;
        let mut buf = chunk_ct.to_vec();
        buf.extend_from_slice(tag);
        let plain = aead.open(dek, &nonce, &aad, &buf)?;
        out.extend_from_slice(&plain[in_off..in_off + take]);
        done += take;
    }
    Ok(out)
}
