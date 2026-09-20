//! JtEncryptedObject v1 写/读协议（docs/04 §3/§4/§7）。
//!
//! 写（发布原子性 §7）：
//!   payload chunks → metadata → sealed header → trailer(可选 SM2) → fsync → rename
//! 读（页读取 §4.4）：
//!   随机页 = 定位 chunk → 读整 chunk 密文 → AEAD open → 取页；O(1)。
//!
//! trailer 布局（docs/04 §3.4 工程裁决，已回写文档）：
//!   文件末尾 `SM2 signature(64B) || u16 sig_len`（长度置尾）；header.flags bit3 = TRAILER_SIGNED。
//!   签名消息 = header_digest(32) || metadata_digest(32) || last_chunk_tag(16)。

use crate::error::ObjectError;
use crate::header::{flags, Header, ObjectType, HEADER_SIZE};
use crate::tlv::{self, Entry};
use jt_crypto_api::{Aead, Digest256, SignatureKey, SignatureVerifier};
use std::io::{Read, Seek, SeekFrom, Write};

/// 默认 chunk 大小（docs/04 §4.1：64 KiB = 8 × 8 KiB 页）。
pub const DEFAULT_CHUNK_SIZE: u32 = 65536;
pub const TAG_LEN: usize = 16;

/// chunk nonce 派生（docs/04 §4.2）：nonce(c) = base_nonce XOR u96(c)。
/// u96(c) 按 RFC 8446 record-nonce 惯例写入 12B 尾部（big-endian）。
pub fn chunk_nonce(base_nonce: &[u8; 12], chunk_index: u64) -> [u8; 12] {
    let mut n = *base_nonce;
    let idx = chunk_index.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= idx[i];
    }
    n
}

/// chunk AAD（docs/04 §4.3 字节级布局）。
pub fn chunk_aad(
    header_digest: &[u8; 32],
    object_type: ObjectType,
    key_epoch: u64,
    generation: u64,
    chunk_index: u64,
    chunk_offset: u64,
    chunk_len: usize,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 1 + 8 + 8 + 4 + 8 + 4);
    aad.extend_from_slice(header_digest);
    aad.push(object_type as u8);
    aad.extend_from_slice(&key_epoch.to_le_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.extend_from_slice(&chunk_offset.to_le_bytes());
    aad.extend_from_slice(&(chunk_len as u32).to_le_bytes());
    aad
}

/// 写对象到 `path`（临时名 `.part` → sealed → 原子 rename）。
/// 无 trailer 签名的便捷入口（开发模式，docs/04 §3.4）。
#[allow(clippy::too_many_arguments)]
pub struct Writer<'a> {
    pub backend: &'a dyn Aead,
    pub digest: &'a dyn Digest256,
}

impl<'a> Writer<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn write_object(
        &self,
        path: &std::path::Path,
        object_type: ObjectType,
        timeline_id: [u8; 16],
        object_id: [u8; 16],
        key_epoch: u64,
        generation: u64,
        base_nonce: [u8; 12],
        dek: &[u8],
        payload: &[u8],
        entries: &[Entry],
    ) -> Result<(), ObjectError> {
        self.write_object_signed(
            path, object_type, timeline_id, object_id, key_epoch, generation, base_nonce, dek,
            payload, entries, None,
        )
    }

    /// 带可选 trailer 签名的写入口（docs/04 §3.4）。
    /// 签名消息 = header_digest || metadata_digest || last_chunk_tag；
    /// trailer 布局：u16 sig_len || signature(64B)，置于文件末尾；置位
    /// flags.TRAAILER_SIGNED 位（header.rs TRAILER_SIGNED）。
    #[allow(clippy::too_many_arguments)]
    pub fn write_object_signed(
        &self,
        path: &std::path::Path,
        object_type: ObjectType,
        timeline_id: [u8; 16],
        object_id: [u8; 16],
        key_epoch: u64,
        generation: u64,
        base_nonce: [u8; 12],
        dek: &[u8],
        payload: &[u8],
        entries: &[Entry],
        signer: Option<&dyn SignatureKey>,
    ) -> Result<(), ObjectError> {
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let chunked = payload.len() as u64 > chunk_size as u64 || payload.is_empty();
        let chunk_size_u = if chunked { chunk_size as u64 } else { payload.len() as u64 };
        let chunk_count = if payload.is_empty() {
            0
        } else {
            ((payload.len() as u64) + chunk_size_u - 1) / chunk_size_u
        };

        let metadata = tlv::encode(entries)?;
        let metadata_len = metadata.len() as u32;

        let trailer_signed = signer.is_some();
        let hdr_flags = flags::CHUNKED
            | flags::SEALED
            | if trailer_signed { flags::TRAILER_SIGNED } else { 0 };

        let header = Header {
            object_type,
            flags: hdr_flags,
            timeline_id,
            object_id,
            key_epoch,
            generation,
            chunk_size: if chunked { chunk_size } else { 0 },
            chunk_count,
            payload_len: payload.len() as u64,
            base_nonce,
            header_digest: [0u8; 32],
        };

        // digest 先行：header 全字段在加密前已知（AAD 依赖 header_digest）
        let mut hb = [0u8; crate::header::DIGEST_OFFSET];
        hb[0..8].copy_from_slice(&crate::header::MAGIC);
        hb[8..10].copy_from_slice(&crate::header::FORMAT_VERSION.to_le_bytes());
        hb[10] = header.object_type as u8;
        hb[11] = header.flags;
        hb[12..14].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        hb[14..18].copy_from_slice(&metadata_len.to_le_bytes());
        hb[18..34].copy_from_slice(&header.timeline_id);
        hb[34..50].copy_from_slice(&header.object_id);
        hb[50..58].copy_from_slice(&header.key_epoch.to_le_bytes());
        hb[58..66].copy_from_slice(&header.generation.to_le_bytes());
        hb[66..70].copy_from_slice(&header.chunk_size.to_le_bytes());
        hb[70..78].copy_from_slice(&header.chunk_count.to_le_bytes());
        hb[78..86].copy_from_slice(&header.payload_len.to_le_bytes());
        hb[86..98].copy_from_slice(&header.base_nonce);
        let header_digest = self.digest.digest(&hb);

        // 单遍加密：AAD 用真实 digest
        let mut body2 = Vec::with_capacity(payload.len() + chunk_count as usize * TAG_LEN);
        for (i, chunk) in payload.chunks(chunk_size_u as usize).enumerate() {
            let ci = i as u64;
            let offset = ci * chunk_size_u;
            let aad = chunk_aad(
                &header_digest,
                object_type,
                key_epoch,
                generation,
                ci,
                offset,
                chunk.len(),
            );
            let nonce = chunk_nonce(&base_nonce, ci);
            let ct = self.backend.seal(dek, &nonce, &aad, chunk)?;
            body2.extend_from_slice(&ct);
        }

        // 发布：.part 写入 → sealed header → body → trailer(可选) → fsync → rename
        let part = path.with_extension("part");
        {
            let mut f = std::fs::File::create(&part)?;
            let encoded = header.encode_with_metadata_len(metadata_len, &header_digest)?;
            f.write_all(&encoded)?;
            f.write_all(&metadata)?;
            f.write_all(&body2)?;
            if let Some(signer) = signer {
                let metadata_digest = self.digest.digest(&metadata);
                let tag_start = body2.len() - TAG_LEN;
                let last_chunk_tag = &body2[tag_start..];
                let mut msg = Vec::with_capacity(80);
                msg.extend_from_slice(&header_digest);
                msg.extend_from_slice(&metadata_digest);
                msg.extend_from_slice(last_chunk_tag);
                let sig = signer.sign(&msg);
                if sig.len() != 64 {
                    return Err(ObjectError::Other("SM2 signature length != 64"));
                }
                // 布局裁决：signature(64B) || u16 sig_len（长度置尾，读取端先读末 2B）
                f.write_all(&sig)?;
                f.write_all(&(sig.len() as u16).to_le_bytes())?;
            }
            f.sync_all()?;
        }
        std::fs::rename(&part, path)?;
        Ok(())
    }
}

/// 已发布对象的读取句柄（内存持有 header/metadata；页读取走文件 seek）。
pub struct ObjectReader {
    pub header: Header,
    pub metadata: Vec<Entry>,
    pub metadata_digest: [u8; 32],
    file: std::fs::File,
    body_offset: u64, // header + metadata 之后
}

impl ObjectReader {
    pub fn open(
        path: &std::path::Path,
        backend: &dyn Aead,
        digest: &dyn Digest256,
        dek: &[u8],
    ) -> Result<Self, ObjectError> {
        let mut f = std::fs::File::open(path)?;
        let mut head = vec![0u8; HEADER_SIZE];
        f.read_exact(&mut head)?;
        let mut header = Header::decode(&head, digest)?;
        if header.flags & flags::SEALED == 0 {
            return Err(ObjectError::NotSealed);
        }
        let metadata_len = u32::from_le_bytes(head[14..18].try_into().unwrap()) as usize;
        let mut meta = vec![0u8; metadata_len];
        f.read_exact(&mut meta)?;
        let metadata = tlv::decode(&meta)?;
        let metadata_digest = digest.digest(&meta);
        let body_offset = (HEADER_SIZE + metadata_len) as u64;

        /*
         * 追加式对象（WAL 段）：header 记的是**容量上界**（见 crate::wal
         * 裁决 1），真实长度在 metadata。段可能未写满即封段，故必须以
         * metadata 的真实值覆盖 header 的容量值——否则读取端会按容量去读
         * 尾 chunk，撞 UnexpectedEof（实现期实测缺陷）。
         *
         * 仅在真实值存在且 ≤ 容量时采信（防御损坏的 metadata 把长度放大
         * 到越界）。
         */
        for e in &metadata {
            if e.tlv_type == crate::wal::TLV_REAL_PAYLOAD_LEN && e.value.len() == 8 {
                let real = u64::from_le_bytes(e.value[..8].try_into().unwrap());
                if real <= header.payload_len {
                    header.payload_len = real;
                }
            } else if e.tlv_type == crate::wal::TLV_REAL_CHUNK_COUNT && e.value.len() == 8 {
                let real = u64::from_le_bytes(e.value[..8].try_into().unwrap());
                if real <= header.chunk_count {
                    header.chunk_count = real;
                }
            }
        }

        let _ = (backend, dek);
        Ok(ObjectReader {
            header,
            metadata,
            metadata_digest,
            file: f,
            body_offset,
        })
    }

    /// 读一个 chunk 的密文（含 tag）。
    fn read_chunk_ct(&mut self, chunk_index: u64) -> Result<Vec<u8>, ObjectError> {
        let cs = self.header.chunk_size as u64;
        if self.header.chunk_size == 0 || cs == 0 {
            // 单发模式：整个 body 是一个 chunk
            let payload_len = self.header.payload_len;
            let len = payload_len + TAG_LEN as u64;
            self.file.seek(SeekFrom::Start(self.body_offset))?;
            let mut buf = vec![0u8; len as usize];
            self.file.read_exact(&mut buf)?;
            return Ok(buf);
        }
        if chunk_index >= self.header.chunk_count {
            return Err(ObjectError::ChunkOutOfRange(chunk_index));
        }
        let payload_len = self.header.payload_len;
        let full = self.header.chunk_count - 1;
        let plain_in_chunk = if chunk_index < full {
            cs
        } else {
            payload_len - full * cs
        };
        // 密文布局：每 chunk 占 plain + 16B tag
        let offset = self.body_offset + chunk_index * (cs + TAG_LEN as u64);
        let len = plain_in_chunk + TAG_LEN as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len as usize];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// 读 trailer（若 TRAILER_SIGNED）：返回签名消息与签名字节，供验签。
    /// docs/04 §11.4：验签可全量或抽样（首次+审计触发），由调用方决定。
    pub fn read_trailer_parts(&mut self) -> Result<(Vec<u8>, Vec<u8>), ObjectError> {
        if self.header.flags & flags::TRAILER_SIGNED == 0 {
            return Err(ObjectError::Other("object has no trailer signature"));
        }
        let flen = self.file.seek(SeekFrom::End(0))?;
        if flen < 2 + 64 {
            return Err(ObjectError::Truncated);
        }
        self.file.seek(SeekFrom::Start(flen - 2))?;
        let mut lb = [0u8; 2];
        self.file.read_exact(&mut lb)?;
        let sig_len = u16::from_le_bytes(lb) as usize;
        if flen < 2 + sig_len as u64 {
            return Err(ObjectError::Truncated);
        }
        let trailer_start = flen - 2 - sig_len as u64;
        self.file.seek(SeekFrom::Start(trailer_start))?;
        let mut sig = vec![0u8; sig_len];
        self.file.read_exact(&mut sig)?;
        // last_chunk_tag = trailer 前的 16 字节
        self.file.seek(SeekFrom::Start(trailer_start - TAG_LEN as u64))?;
        let mut last_tag = [0u8; 16];
        self.file.read_exact(&mut last_tag)?;
        let mut msg = Vec::with_capacity(80);
        msg.extend_from_slice(&self.header.header_digest);
        msg.extend_from_slice(&self.metadata_digest);
        msg.extend_from_slice(&last_tag);
        Ok((msg, sig))
    }

    /// 可选验签（docs/04 §11.4 抽样策略：首次加载 + 审计触发时调用）。
    pub fn verify_trailer(&mut self, verifier: &dyn SignatureVerifier) -> Result<bool, ObjectError> {
        let (msg, sig) = self.read_trailer_parts()?;
        Ok(verifier.verify(&msg, &sig))
    }

    /// 读一页（docs/04 §4.4）：offset 为明文内字节偏移；跨 chunk 自动续读。
    /// 对象真实明文长度。
    ///
    /// 对追加式对象（WAL 段）为 metadata 里的真实值；对一次写成的对象
    /// 即 header 的 payload_len（两者一致）。
    pub fn payload_len(&self) -> u64 {
        self.header.payload_len
    }

    /// 对象真实 chunk 数（同 [`Self::payload_len`] 的口径）。
    pub fn chunk_count(&self) -> u64 {
        self.header.chunk_count
    }

    pub fn read_range(
        &mut self,
        backend: &dyn Aead,
        dek: &[u8],
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, ObjectError> {
        if offset + len as u64 > self.header.payload_len {
            return Err(ObjectError::PayloadLenMismatch {
                header: self.header.payload_len,
                actual: offset + len as u64,
            });
        }
        let mut out = vec![0u8; len];
        let mut done = 0usize;
        while done < len {
            let pos = offset + done as u64;
            let (ci, in_chunk_off) = if self.header.chunk_size == 0 {
                (0u64, pos)
            } else {
                (
                    pos / self.header.chunk_size as u64,
                    pos % self.header.chunk_size as u64,
                )
            };
            let ct = self.read_chunk_ct(ci)?;
            let nonce = chunk_nonce(&self.header.base_nonce, ci);
            let aad = chunk_aad(
                &self.header.header_digest,
                self.header.object_type,
                self.header.key_epoch,
                self.header.generation,
                ci,
                ci * self.header.chunk_size as u64,
                ct.len() - TAG_LEN,
            );
            let plain = backend.open(dek, &nonce, &aad, &ct)?;
            let take =
                ((plain.len() as u64) - in_chunk_off).min((len - done) as u64) as usize;
            out[done..done + take]
                .copy_from_slice(&plain[in_chunk_off as usize..in_chunk_off as usize + take]);
            done += take;
        }
        Ok(out)
    }
}
