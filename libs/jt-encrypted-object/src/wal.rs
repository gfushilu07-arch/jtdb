//! WAL 段对象的**追加式**写入（docs/04 §5，object_type=WAL_SEG）。
//!
//! 与 Layer/Snapshot 的区别：Layer 是"整流已知后一次写成"，WAL 段是
//! **边收边写**——Safekeeper 持续追加 WAL 记录，无法等整段到齐。
//!
//! docs/04 §5 语义逐条对应本模块设计：
//!
//! 1. **明文在 64 KiB chunk 缓冲内累积，攒满一个 chunk 即加密追加**——
//!    [`WalSegWriter::append`] 只把数据放进缓冲，攒满才做一次 AEAD 落盘；
//!    调用方写多少、何时写，不改变 chunk 边界。
//! 2. **chunk 攒满前崩溃：未落盘明文丢弃，从对端重新拉取**——故**不**在
//!    chunk 未满时落盘半块明文；缓冲是纯内存状态（Neon Safekeeper 原生
//!    恢复路径，不新增协议）。
//! 3. **段写满后：sealed header + trailer 签名，`.part` → fsync → 原子
//!    rename**——[`WalSegWriter::finish`] 负责；**已发布对象不可追加**。
//! 4. **下一段 = 新对象（新 object_id）**——调用方创建新 writer。
//!
//! # 两个关键设计裁决
//!
//! ## 裁决 1：header 一次写定，真实长度记在 metadata
//!
//! 两个约束把设计夹在中间：
//!
//! * `header_digest = SM3(offset 0..98)` 且读取端**自校验**（[`crate::header::Header::decode`]）；
//! * chunk 的 AAD 含 `header_digest`（[`crate::stream::seal_chunk`]），而 digest
//!   覆盖 `chunk_count`/`payload_len`。
//!
//! 于是 `chunk_count`/`payload_len` **必须在加密第一个 chunk 之前确定**——
//! 事后回填会同时破坏摘要自校验与所有 chunk 的 AAD。解法：
//!
//! * **header 记"容量上界"**（create 时按调用方声明的 `capacity` 写定，
//!   全程不变）：`chunk_count = ceil(capacity/cs)`、`payload_len = capacity`；
//! * **真实长度记在 metadata**（[`TLV_REAL_PAYLOAD_LEN`] /
//!   [`TLV_REAL_CHUNK_COUNT`]，定宽 u64，finish 时**原地更新**——长度不变，
//!   故不破坏布局）；
//! * **读取端优先采信 metadata 的真实值**（见 [`crate::object::ObjectReader::open`]）。
//!
//! 为什么不能只靠 header 的容量值：段可能**未写满即封段**（如停机前最后
//! 一段）。若 header 的 `payload_len` 是容量而实际数据更少，读取端会按容量
//! 去读尾 chunk → `UnexpectedEof`（这是本模块实现期实测到的缺陷）。
//! 记真实长度使对象**自描述**，不依赖调用方另外记住 LSN 范围。
//!
//! ## 裁决 2：封段信号由原子 rename 承载
//!
//! `.part` 存在 = 未封段（恢复时忽略）；rename 到最终名 = 已封段。这与
//! spec"fsync(数据) → fsync(头) → 原子 rename"给出一致的崩溃语义，且
//! 无需改动 header（否则回到裁决 1 的矛盾）。

use crate::error::ObjectError;
use crate::header::{self, ObjectType, HEADER_SIZE};
use crate::object::{DEFAULT_CHUNK_SIZE, TAG_LEN};
use crate::stream::{seal_chunk, StreamMeta};
use crate::tlv::Entry;
use jt_crypto_api::{Aead, Digest256, SignatureKey};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// TLV 类型：**真实**明文长度（≤ header 的容量上界）。定宽 u64。
pub const TLV_REAL_PAYLOAD_LEN: u16 = 0x0010;
/// TLV 类型：**真实** chunk 数。定宽 u64。
pub const TLV_REAL_CHUNK_COUNT: u16 = 0x0011;

/// WAL 段追加写入器。
pub struct WalSegWriter<'a> {
    aead: &'a dyn Aead,
    digest: &'a dyn Digest256,
    timeline_id: [u8; 16],
    object_id: [u8; 16],
    key_epoch: u64,
    generation: u64,
    dek: Vec<u8>,
    path: PathBuf,
    part: File,
    /// 头摘要（create 时算定；AAD 与 header 字段都用它，全程不变）。
    header_digest: [u8; 32],
    metadata_len: u32,
    /// metadata 中两个真实值 entry 的**文件偏移**（finish 时原地更新用）。
    real_len_off: u64,
    real_cnt_off: u64,
    meta: StreamMeta,
    /// 未满一个 chunk 的待加密明文（纯内存，崩溃即丢）。
    buf: Vec<u8>,
    /// 容量上界（字节）。
    capacity: u64,
    chunk_index: u64,
    payload_len: u64,
    /// 最后一个已落盘 chunk 的 tag（trailer 签名消息需要；**内存持有**，
    /// 避免回读只写句柄——实现期实测 `File::create` 为只写，回读报
    /// `Bad file descriptor`）。
    last_tag: [u8; TAG_LEN],
    has_chunk: bool,
    signer: Option<&'a dyn SignatureKey>,
    finished: bool,
}

impl<'a> WalSegWriter<'a> {
    /// 创建 WAL 段写入器：写 header（含容量上界）+ metadata，随后可追加。
    ///
    /// `capacity` 为段容量上界（字节），由调用方按 WAL 段规格给出
    /// （如 16 MiB）。`append` 总量不得超过它。
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        aead: &'a dyn Aead,
        digest: &'a dyn Digest256,
        path: &Path,
        timeline_id: [u8; 16],
        object_id: [u8; 16],
        key_epoch: u64,
        generation: u64,
        base_nonce: [u8; 12],
        dek: &[u8],
        capacity: u64,
        entries: &[Entry],
        signer: Option<&'a dyn SignatureKey>,
    ) -> Result<Self, ObjectError> {
        if capacity == 0 {
            return Err(ObjectError::Other("WAL segment capacity must be > 0"));
        }
        let chunk_size = DEFAULT_CHUNK_SIZE as u64;
        let chunk_count = capacity.div_ceil(chunk_size);
        let meta = StreamMeta::new(0, chunk_size, base_nonce);

        // metadata = 调用方条目 + 两个真实值占位（定宽 u64，finish 原地更新）
        let mut all_entries = entries.to_vec();
        all_entries.push(Entry::new(TLV_REAL_PAYLOAD_LEN, 0u64.to_le_bytes().to_vec()));
        all_entries.push(Entry::new(TLV_REAL_CHUNK_COUNT, 0u64.to_le_bytes().to_vec()));
        let metadata = crate::tlv::encode(&all_entries)?;
        let metadata_len = metadata.len() as u32;

        // 定位两个真实值 entry 的 value 偏移（TLV 布局：type u16 || len u32 || value）
        let (real_len_off, real_cnt_off) = locate_real_value_offsets(&all_entries)?;

        // header 一次写定（容量上界），摘要此后不变。
        // TRAILER_SIGNED 位须在 create 时置位（header 不可事后回填）——
        // 是否带签名在创建时就由 signer 是否存在决定。
        let mut hdr_flags = header::flags::CHUNKED | header::flags::SEALED;
        if signer.is_some() {
            hdr_flags |= header::flags::TRAILER_SIGNED;
        }
        let mut header_bytes = build_header_bytes(
            timeline_id,
            object_id,
            key_epoch,
            generation,
            DEFAULT_CHUNK_SIZE,
            chunk_count,
            capacity,
            &base_nonce,
            hdr_flags,
            metadata_len,
        );
        let header_digest = digest.digest(&header_bytes[..header::DIGEST_OFFSET]);
        header_bytes[header::DIGEST_OFFSET..HEADER_SIZE].copy_from_slice(&header_digest);

        let part_path = part_path_of(path);
        let mut part = File::create(&part_path)?;
        part.write_all(&header_bytes)?;
        part.write_all(&metadata)?;

        Ok(WalSegWriter {
            aead,
            digest,
            timeline_id,
            object_id,
            key_epoch,
            generation,
            dek: dek.to_vec(),
            path: path.to_path_buf(),
            part,
            header_digest,
            metadata_len,
            real_len_off: HEADER_SIZE as u64 + real_len_off,
            real_cnt_off: HEADER_SIZE as u64 + real_cnt_off,
            meta,
            buf: Vec::with_capacity(DEFAULT_CHUNK_SIZE as usize),
            capacity,
            chunk_index: 0,
            payload_len: 0,
            last_tag: [0u8; TAG_LEN],
            has_chunk: false,
            signer,
            finished: false,
        })
    }

    /// 追加明文。攒满一个 chunk 即加密并落盘（docs/04 §5 第 1 条）。
    ///
    /// 超出容量上界返回错误——调用方应先 `finish()` 再开新段
    /// （docs/04 §5 第 4 条：下一段 = 新对象）。
    pub fn append(&mut self, data: &[u8]) -> Result<(), ObjectError> {
        if self.finished {
            return Err(ObjectError::Other("append after finish (segment is sealed)"));
        }
        if self.payload_len + self.buf.len() as u64 + data.len() as u64 > self.capacity {
            return Err(ObjectError::Other(
                "append exceeds WAL segment capacity; finish() and start a new segment",
            ));
        }
        let mut rest = data;
        while !rest.is_empty() {
            let space = DEFAULT_CHUNK_SIZE as usize - self.buf.len();
            let take = space.min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == DEFAULT_CHUNK_SIZE as usize {
                self.flush_chunk()?;
            }
        }
        Ok(())
    }

    /// 把当前缓冲作为（尾）chunk 加密落盘；缓冲为空时不动作。
    fn flush_chunk(&mut self) -> Result<(), ObjectError> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let (ct, tag) = seal_chunk(
            self.aead,
            &self.meta,
            &self.header_digest,
            ObjectType::WalSeg as u8,
            self.key_epoch,
            self.generation,
            &self.dek,
            self.chunk_index,
            &self.buf,
        )?;
        self.part.write_all(&ct)?;
        self.part.write_all(&tag)?;
        self.payload_len += self.buf.len() as u64;
        self.chunk_index += 1;
        self.last_tag = tag;
        self.has_chunk = true;
        self.buf.clear();
        Ok(())
    }

    /// 封段：冲刷尾 chunk、原地更新真实长度、写 trailer 签名、fsync、原子 rename。
    pub fn finish(mut self) -> Result<WalSegStats, ObjectError> {
        self.flush_chunk()?;

        // 1) 原地更新 metadata 的真实值（定宽，长度不变）
        self.part.seek(SeekFrom::Start(self.real_len_off))?;
        self.part.write_all(&self.payload_len.to_le_bytes())?;
        self.part.seek(SeekFrom::Start(self.real_cnt_off))?;
        self.part.write_all(&self.chunk_index.to_le_bytes())?;

        // 2) trailer 签名：SM2_sign(header_digest || metadata_digest || last_chunk_tag)
        //    metadata_digest 覆盖**更新后**的 metadata —— 故须在步骤 1 之后重算。
        //    这里从内存重建 metadata 字节（与文件内容一致：两个真实值已更新）。
        if let Some(signer) = self.signer {
            let metadata_bytes = self.rebuild_metadata_bytes()?;
            let metadata_digest = self.digest.digest(&metadata_bytes);
            let mut msg = Vec::with_capacity(80);
            msg.extend_from_slice(&self.header_digest);
            msg.extend_from_slice(&metadata_digest);
            msg.extend_from_slice(&self.last_tag);
            let sig = signer.sign(&msg);
            if sig.len() != 64 {
                return Err(ObjectError::Other("SM2 signature length != 64"));
            }
            self.part.seek(SeekFrom::End(0))?;
            // 布局与 object.rs 一致：signature(64B) || u16 sig_len（长度置尾）
            self.part.write_all(&sig)?;
            self.part.write_all(&(sig.len() as u16).to_le_bytes())?;
        }

        // 3) fsync → 原子 rename（封段信号）
        self.part.sync_all()?;
        let stats = WalSegStats {
            chunk_count: self.chunk_index,
            payload_len: self.payload_len,
            capacity: self.capacity,
        };
        self.finished = true;
        std::fs::rename(part_path_of(&self.path), &self.path)?;
        Ok(stats)
    }

    /// 重建 metadata 字节（含已更新的真实值）。仅用于计算签名摘要。
    fn rebuild_metadata_bytes(&self) -> Result<Vec<u8>, ObjectError> {
        // 结构：... || TLV_REAL_PAYLOAD_LEN(len=8) || value || TLV_REAL_CHUNK_COUNT(len=8) || value
        // 直接按偏移拼装，避免依赖 entry 顺序。
        let mut buf = vec![0u8; self.metadata_len as usize];
        // 从文件读回是不可行的（只写句柄），故按已知布局重建：
        // 调用方条目原样未知，但可由 create 时的字节序列复现——此处用
        // 读取路径同一逻辑：先取文件已写内容不可行，故改由字段拼装。
        //
        // 为保证与文件内容逐字节一致，这里从**文件**读取 metadata 区：
        // 句柄是只写的，故重新以读方式打开 .part。
        let part_path = part_path_of(&self.path);
        let mut f = File::open(&part_path)?;
        use std::io::Read;
        f.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        f.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// 封段统计。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalSegStats {
    /// 实际写入的 chunk 数。
    pub chunk_count: u64,
    /// 实际写入的明文字节数（≤ capacity）。
    pub payload_len: u64,
    /// 容量上界（create 时声明）。
    pub capacity: u64,
}

/// 定位两个真实值 entry 在 metadata 内的 value 偏移。
fn locate_real_value_offsets(entries: &[Entry]) -> Result<(u64, u64), ObjectError> {
    let mut off = 0u64;
    let mut real_len = None;
    let mut real_cnt = None;
    for e in entries {
        // type u16 || len u32 || value
        let value_off = off + 6;
        if e.tlv_type == TLV_REAL_PAYLOAD_LEN {
            real_len = Some(value_off);
        } else if e.tlv_type == TLV_REAL_CHUNK_COUNT {
            real_cnt = Some(value_off);
        }
        off = value_off + e.value.len() as u64;
    }
    match (real_len, real_cnt) {
        (Some(a), Some(b)) => Ok((a, b)),
        _ => Err(ObjectError::Other("real-value TLV entries missing")),
    }
}

fn part_path_of(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".part");
    PathBuf::from(s)
}

/// 构造 130B 头字节（主字段 0..98 + header_digest 98..130）。
///
/// 字段布局与 [`crate::object::Writer::write_object_signed`] **必须逐字段
/// 一致**——两处若漂移，WAL 段与 Layer 的头部解释将不同。
#[allow(clippy::too_many_arguments)]
fn build_header_bytes(
    timeline_id: [u8; 16],
    object_id: [u8; 16],
    key_epoch: u64,
    generation: u64,
    chunk_size: u32,
    chunk_count: u64,
    payload_len: u64,
    base_nonce: &[u8; 12],
    flags: u8,
    metadata_len: u32,
) -> [u8; HEADER_SIZE] {
    let mut out = [0u8; HEADER_SIZE];
    out[0..8].copy_from_slice(&header::MAGIC);
    out[8..10].copy_from_slice(&header::FORMAT_VERSION.to_le_bytes());
    out[10] = ObjectType::WalSeg as u8;
    out[11] = flags;
    out[12..14].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    out[14..18].copy_from_slice(&metadata_len.to_le_bytes());
    out[18..34].copy_from_slice(&timeline_id);
    out[34..50].copy_from_slice(&object_id);
    out[50..58].copy_from_slice(&key_epoch.to_le_bytes());
    out[58..66].copy_from_slice(&generation.to_le_bytes());
    out[66..70].copy_from_slice(&chunk_size.to_le_bytes());
    out[70..78].copy_from_slice(&chunk_count.to_le_bytes());
    out[78..86].copy_from_slice(&payload_len.to_le_bytes());
    out[86..98].copy_from_slice(base_nonce);
    out
}
