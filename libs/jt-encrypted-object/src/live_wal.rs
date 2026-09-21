//! WAL **活段**文件的加密布局（docs/04 §5.2，`flags.LIVE_WAL`）。
//!
//! 与 §5 的"对象"模型（[`crate::wal`]）不同：那是**已完成、不可变**的段
//! 封成对象（归档/卸载路径）；本模块处理 **Safekeeper 正在写的活段**——
//! 预分配、按任意偏移写、被对端按任意偏移并发读。两者不可混用，故用
//! `flags.LIVE_WAL` 区分（同一 `object_type=WalSeg`，布局不同）。
//!
//! # 文件布局（单一文件，预分配，总长固定）
//!
//! ```text
//! [0 .. S)                密文区：与明文 1:1 同偏移（S = seg_size，如 16 MiB）
//! [S .. S + T)            tag 区：每 chunk 一条，固定 32B
//! [S + T .. S + T + 130)  header（create 时写定，含 key_epoch/generation）
//! ```
//!
//! **为什么密文同偏移**：Safekeeper 的活段被对端按任意 `xlogoff` 读
//! （`WalReader::open_segment` seek 到 xlogoff），而 LSN↔偏移恒等是复制与
//! 恢复的基础。故密文不得前置头/就地追加 tag——tag 必须另置一区。
//!
//! # tag 条目（32B，按 `chunk_index` O(1) 定位：`S + c*32`）
//!
//! ```text
//! 0..4    plain_len  u32 LE   该 chunk 明文长度（0 = 未写；≤ chunk_size）
//! 4..16   nonce      [u8;12]  本次封装的 nonce（DRBG 随机）
//! 16..32  tag        [u8;16]  GCM tag
//! ```
//!
//! `plain_len == 0` 兼作"未写"哨兵：预分配的零填充 tag 区天然表示"该 chunk
//! 尚未写入"，无需额外位图。
//!
//! # 尾部半块的重新封装（本设计的关键裁决）
//!
//! 矛盾：flush_lsn 可落在 chunk 中间（WAL 记录不按页对齐，且对端必须能读到
//! 最新 flush 位置），但 GCM **禁止 (key, nonce) 重用**——若尾 chunk 用固定
//! nonce 反复封装不同长度，就是致命的 nonce 重用。
//!
//! 解法：**尾 chunk 每次 flush 用新 nonce 重新封装实际长度**，覆写密文区与
//! tag 条目。
//!
//! * 旧密文被覆写、旧 nonce 永久废弃 ⇒ **不存在 (key, nonce) 二次使用**；
//! * 整 chunk 一旦写满即固定（不再重新封装），保证已发布 chunk 不可变；
//! * 代价：每次 flush 至多重加密一个 chunk（≤ chunk_size）。SM4 吞吐下
//!   8 KiB 开销可忽略，且只影响尾块。
//!
//! **崩溃一致性**：先写密文、后写 tag 条目（tag 为提交点）。若崩在两者之间，
//! 读取端用旧 nonce 解新密文 → AEAD 认证失败 → **检出而非静默错误**
//! （fail-closed），随后走 Neon 原生对端重拉恢复。
//!
//! # AAD 绑定（docs/02 §4.4）
//!
//! ```text
//! timeline_id(16) || seg_no(8) || chunk_index(8) || chunk_plain_off(8)
//! || key_epoch(8) || generation(8) || plain_len(4)
//! ```
//!
//! 使"密文搬移到别的段/别的偏移/别的 epoch"均可检出。

use crate::error::ObjectError;
use crate::header::{self, ObjectType, HEADER_SIZE};
use jt_crypto_api::{Aead, Digest256, RandomSource};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// tag 条目大小（`plain_len(4) || nonce(12) || tag(16)`）。
pub const TAG_ENTRY_SIZE: usize = 32;

/// 活段默认 chunk 大小（8 KiB，与 PostgreSQL 页边界一致）。
pub const LIVE_CHUNK_SIZE: u32 = 8192;

/// 活段标记（`flags` 位，docs/04 §5.2）。与 [`crate::header::flags`] 其余位
/// 互斥使用：置位表示本文件是**活段布局**而非 §5 的对象布局。
pub const FLAG_LIVE_WAL: u8 = 0b0001_0000;

/// 活段布局参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveWalLayout {
    /// 段数据区大小（PostgreSQL 通常 16 MiB）。
    pub seg_size: u64,
    /// chunk 大小（默认 8 KiB）。
    pub chunk_size: u32,
}

impl LiveWalLayout {
    pub fn new(seg_size: u64, chunk_size: u32) -> Result<Self, ObjectError> {
        if seg_size == 0 || chunk_size == 0 {
            return Err(ObjectError::Other("live WAL layout: zero size"));
        }
        Ok(LiveWalLayout {
            seg_size,
            chunk_size,
        })
    }

    /// PostgreSQL 默认 16 MiB 段 + 8 KiB chunk。
    pub fn pg_default() -> Self {
        LiveWalLayout {
            seg_size: 16 * 1024 * 1024,
            chunk_size: LIVE_CHUNK_SIZE,
        }
    }

    pub fn chunk_count(&self) -> u64 {
        self.seg_size.div_ceil(self.chunk_size as u64)
    }

    /// tag 区起始偏移（= 段数据区末尾）。
    pub fn tag_area_off(&self) -> u64 {
        self.seg_size
    }

    pub fn tag_area_len(&self) -> u64 {
        self.chunk_count() * TAG_ENTRY_SIZE as u64
    }

    /// header 起始偏移。
    pub fn header_off(&self) -> u64 {
        self.tag_area_off() + self.tag_area_len()
    }

    /// 文件总长（预分配此长度后**不再变化**，满足 fdatasync 语义）。
    pub fn file_len(&self) -> u64 {
        self.header_off() + HEADER_SIZE as u64
    }

    /// 第 `c` 个 chunk 的 tag 条目偏移。
    pub fn tag_entry_off(&self, c: u64) -> u64 {
        self.tag_area_off() + c * TAG_ENTRY_SIZE as u64
    }

    /// 明文偏移 → chunk 索引。
    pub fn chunk_of(&self, offset: u64) -> u64 {
        offset / self.chunk_size as u64
    }
}

/// 单个 tag 条目。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagEntry {
    /// 明文长度（0 = 该 chunk 未写）。
    pub plain_len: u32,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
}

impl TagEntry {
    pub fn is_unwritten(&self) -> bool {
        self.plain_len == 0
    }

    pub fn encode(&self) -> [u8; TAG_ENTRY_SIZE] {
        let mut b = [0u8; TAG_ENTRY_SIZE];
        b[0..4].copy_from_slice(&self.plain_len.to_le_bytes());
        b[4..16].copy_from_slice(&self.nonce);
        b[16..32].copy_from_slice(&self.tag);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, ObjectError> {
        if b.len() < TAG_ENTRY_SIZE {
            return Err(ObjectError::Truncated);
        }
        Ok(TagEntry {
            plain_len: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            nonce: b[4..16].try_into().unwrap(),
            tag: b[16..32].try_into().unwrap(),
        })
    }
}

/// 活段的 AAD 构造（docs/02 §4.4 绑定字段）。
#[allow(clippy::too_many_arguments)]
pub fn live_chunk_aad(
    timeline_id: &[u8; 16],
    seg_no: u64,
    chunk_index: u64,
    chunk_plain_off: u64,
    key_epoch: u64,
    generation: u64,
    plain_len: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 8 * 5 + 4);
    aad.extend_from_slice(timeline_id);
    aad.extend_from_slice(&seg_no.to_le_bytes());
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.extend_from_slice(&chunk_plain_off.to_le_bytes());
    aad.extend_from_slice(&key_epoch.to_le_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    aad.extend_from_slice(&plain_len.to_le_bytes());
    aad
}

/// 活段头部元数据（读取端需要的绑定字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveWalMeta {
    pub timeline_id: [u8; 16],
    pub seg_no: u64,
    pub key_epoch: u64,
    pub generation: u64,
    pub chunk_size: u32,
    pub seg_size: u64,
}

// ============================================================================
// 写入端
// ============================================================================

/// 活段加密写入器。
///
/// 用法：`create` → 反复 `write_at`（顺序偏移）→ 每轮 `flush`（封尾块 + fsync）
/// → 段满时 `seal`（写 header + 原子 rename）。
pub struct LiveWalWriter<'a> {
    aead: &'a dyn Aead,
    digest: &'a dyn Digest256,
    /// RNG **由 writer 拥有**：它是唯一带可变状态的依赖，且需跨 await 存活
    /// （Safekeeper 集成场景）。`aead`/`digest` 是 unit struct，`&Sm4Gcm` 会
    /// 被 const-promote 为 `'static`，故仍借用即可。
    rng: Box<dyn RandomSource + Send>,
    layout: LiveWalLayout,
    meta: LiveWalMeta,
    dek: Vec<u8>,
    path: PathBuf,
    part: File,
    /// 已封装（durable）的明文长度 = 下一个 flush 后的可读上界。
    sealed_upto: u64,
    /// 已接受写入的明文总长度（= 下一个期望写入偏移）。
    written: u64,
    /// 当前尾 chunk 的起始绝对偏移（= chunk_of(written) * chunk_size）。
    chunk_base: u64,
    /// 当前尾 chunk 的**全部已写明文**（含已封装部分）。
    ///
    /// 必须保留全部内容而非只保留未封装部分：尾块每次 flush 都要用**新
    /// nonce 重新封装整个 chunk**（否则扩展后旧字节丢失，且无法保证
    /// "chunk 内非尾部分不变"）。该缓冲是纯内存状态，崩溃即丢——符合
    /// docs/04 §5"chunk 攒满前崩溃则未落盘明文丢弃、走对端重拉"。
    tail_buf: Vec<u8>,
    /// 已封装且已写 tag 的 chunk 数（用于 header/统计）。
    sealed_chunks: u64,
}

impl<'a> LiveWalWriter<'a> {
    /// 创建活段：预分配固定长度文件 + 写 header（一次写定，不再变更）。
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        aead: &'a dyn Aead,
        digest: &'a dyn Digest256,
        rng: Box<dyn RandomSource + Send>,
        path: &Path,
        layout: LiveWalLayout,
        timeline_id: [u8; 16],
        seg_no: u64,
        key_epoch: u64,
        generation: u64,
        dek: &[u8],
    ) -> Result<Self, ObjectError> {
        let meta = LiveWalMeta {
            timeline_id,
            seg_no,
            key_epoch,
            generation,
            chunk_size: layout.chunk_size,
            seg_size: layout.seg_size,
        };

        /*
         * 路径语义：`path` 即**实际写入路径**（调用方按 Safekeeper 约定给
         * `.partial` 名）。`seal()` 时去掉 `.partial` 后缀完成封段 rename——
         * 与 Neon 原生命名一致（`000000010000000000000001.partial` 是活段，
         * 去掉后缀是已完成段）。
         *
         * 注意不能"给传入路径再加 .partial"：调用方已按约定命名，重复加后缀
         * 会得到 `xxx.partial.partial`（实现期踩到）。
         */
        let mut f = File::create(path)?;
        // 预分配固定长度（fdatasync 语义要求文件大小不变）
        f.set_len(layout.file_len())?;

        // header 一次写定（chunk_count / seg_size 由布局决定，无需回填）
        let hdr = build_live_header(&layout, &meta, digest)?;
        f.seek(SeekFrom::Start(layout.header_off()))?;
        f.write_all(&hdr)?;
        f.sync_all()?;

        Ok(LiveWalWriter {
            aead,
            digest,
            rng,
            layout,
            meta,
            dek: dek.to_vec(),
            path: path.to_path_buf(),
            part: f,
            sealed_upto: 0,
            written: 0,
            chunk_base: 0,
            tail_buf: Vec::with_capacity(layout.chunk_size as usize),
            sealed_chunks: 0,
        })
    }

    /// 在明文偏移 `offset` 写入数据（必须顺序推进）。
    ///
    /// 语义：数据进入**尾块缓冲**；某 chunk 写满即封装落盘并冻结。
    /// 未满的尾块留在内存，`flush()` 时以当前长度封装。
    ///
    /// **不变量**：
    /// * `tail_buf` 始终等于当前尾 chunk 的**全部**内容（长度 = `written - chunk_base`）；
    /// * `written` = 已接受写入总长 = 下一次写入的期望偏移；
    /// * `sealed_upto` ≤ `written`，且 `flush()` 后二者相等。
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), ObjectError> {
        if offset != self.written {
            return Err(ObjectError::Other(
                "live WAL write must be sequential (offset != current write position)",
            ));
        }
        if offset + data.len() as u64 > self.layout.seg_size {
            return Err(ObjectError::Other("live WAL write beyond segment size"));
        }

        let cs = self.layout.chunk_size as usize;
        let mut rest = data;
        while !rest.is_empty() {
            let space = cs - self.tail_buf.len();
            let take = space.min(rest.len());
            self.tail_buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            self.written += take as u64;

            if self.tail_buf.len() == cs {
                // 整 chunk：封装一次，此后不可变（冻结）
                let chunk = std::mem::take(&mut self.tail_buf);
                let c = self.layout.chunk_of(self.chunk_base);
                self.seal_chunk_bytes(c, &chunk)?;
                self.sealed_upto = self.written;
                self.sealed_chunks += 1;
                self.chunk_base = self.written;
                self.tail_buf = Vec::with_capacity(cs);
            }
        }
        Ok(())
    }

    /// 封装并落盘一个 chunk（含 tag 条目），**先密文后 tag**。
    fn seal_chunk_bytes(&mut self, c: u64, plain: &[u8]) -> Result<(), ObjectError> {
        let off = c * self.layout.chunk_size as u64;
        let aad = live_chunk_aad(
            &self.meta.timeline_id,
            self.meta.seg_no,
            c,
            off,
            self.meta.key_epoch,
            self.meta.generation,
            plain.len() as u32,
        );

        // 每次封装都用新 nonce（尾块重复封装时旧 nonce 永久废弃 ⇒ 无重用）
        let mut nonce = [0u8; 12];
        self.rng
            .fill(&mut nonce)
            .map_err(|e| ObjectError::Other(leak_str(format!("DRBG for WAL nonce: {e}"))))?;

        let ct = self.aead.seal(&self.dek, &nonce, &aad, plain)?;
        debug_assert_eq!(ct.len(), plain.len() + 16);

        let entry = TagEntry {
            plain_len: plain.len() as u32,
            nonce,
            tag: ct[plain.len()..].try_into().unwrap(),
        };

        // 1) 密文（同偏移）
        self.part.seek(SeekFrom::Start(off))?;
        self.part.write_all(&ct[..plain.len()])?;
        // 2) tag 条目（提交点）
        self.part.seek(SeekFrom::Start(self.layout.tag_entry_off(c)))?;
        self.part.write_all(&entry.encode())?;

        Ok(())
    }

    /// 冲刷：以当前尾块长度封装（**新 nonce**）并 fsync。
    ///
    /// 调用方在向对端通告 `flush_lsn` **之前**必须调用本方法——否则通告的
    /// 位置可能尚未封装，对端读到的 tag 与密文不一致。
    ///
    /// **尾块每次 flush 都用新 nonce 重新封装整个 chunk**（含之前已封装的
    /// 部分）：旧密文被覆写、旧 nonce 永久废弃，故不存在 (key, nonce) 二次
    /// 使用。代价是每次 flush 至多重加密一个 chunk（≤ chunk_size）。
    pub fn flush(&mut self) -> Result<u64, ObjectError> {
        if !self.tail_buf.is_empty() {
            let c = self.layout.chunk_of(self.chunk_base);
            let chunk: Vec<u8> = self.tail_buf.clone();
            self.seal_chunk_bytes(c, &chunk)?;
            // 不变量：flush 后 sealed_upto == written（尾块全量已封装）
            self.sealed_upto = self.written;
        }
        self.part.sync_all()?;
        Ok(self.sealed_upto)
    }

    /// 当前已封装（可被对端读取）的明文长度。
    pub fn durable_len(&self) -> u64 {
        self.sealed_upto
    }

    /// 段写满：fsync + 去掉 `.partial` 后缀完成封段（封段信号，与 §5 裁决 2
    /// 的原子 rename 语义一致）。
    ///
    /// 若传入路径本就无 `.partial` 后缀（调用方自己管理命名），则本方法只做
    /// fsync 并返回长度，不做 rename。
    pub fn seal(mut self) -> Result<u64, ObjectError> {
        self.flush()?;
        self.part.sync_all()?;
        let n = self.sealed_upto;
        debug_assert_eq!(n, self.written, "seal 后 durable 上界须等于已写总长");
        if let Some(final_path) = sealed_path_of(&self.path) {
            std::fs::rename(&self.path, &final_path)?;
        }
        Ok(n)
    }
}

/// 把错误消息转成 `'static`（`ObjectError::Other` 需要）。
fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// 活段路径 → 已封段路径（去掉 `.partial` 后缀）；无后缀时返回 None。
fn sealed_path_of(path: &Path) -> Option<PathBuf> {
    let s = path.as_os_str().to_str()?;
    let base = s.strip_suffix(".partial")?;
    Some(PathBuf::from(base))
}

/// 构造活段 header（130B，与既有布局字段对齐，置 `LIVE_WAL` 位）。
fn build_live_header(
    layout: &LiveWalLayout,
    meta: &LiveWalMeta,
    digest: &dyn Digest256,
) -> Result<[u8; HEADER_SIZE], ObjectError> {
    let mut h = [0u8; HEADER_SIZE];
    h[0..8].copy_from_slice(&header::MAGIC);
    h[8..10].copy_from_slice(&header::FORMAT_VERSION.to_le_bytes());
    h[10] = ObjectType::WalSeg as u8;
    h[11] = header::flags::CHUNKED | FLAG_LIVE_WAL;
    h[12..14].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    h[14..18].copy_from_slice(&0u32.to_le_bytes()); // 活段无 metadata TLV 区
    h[18..34].copy_from_slice(&meta.timeline_id);
    // object_id 槽位（16B）承载段号：前 8B 段号，其余补零
    h[34..42].copy_from_slice(&meta.seg_no.to_le_bytes());
    h[50..58].copy_from_slice(&meta.key_epoch.to_le_bytes());
    h[58..66].copy_from_slice(&meta.generation.to_le_bytes());
    h[66..70].copy_from_slice(&layout.chunk_size.to_le_bytes());
    h[70..78].copy_from_slice(&layout.chunk_count().to_le_bytes());
    h[78..86].copy_from_slice(&layout.seg_size.to_le_bytes());
    // base_nonce 槽位置零：活段用**每 chunk 独立 nonce**（存 tag 条目），
    // 不用单一 base_nonce——因为尾块需重新封装，base_nonce 派生会重用。
    h[86..98].copy_from_slice(&[0u8; 12]);

    let d = digest.digest(&h[..header::DIGEST_OFFSET]);
    h[header::DIGEST_OFFSET..HEADER_SIZE].copy_from_slice(&d);
    Ok(h)
}

/// 读活段 header，校验 magic/version/`LIVE_WAL` 位/自校验。
pub fn read_live_header(
    path: &Path,
    digest: &dyn Digest256,
) -> Result<LiveWalMeta, ObjectError> {
    let mut f = File::open(path)?;
    let layout_probe = probe_layout(&mut f)?;
    let mut h = [0u8; HEADER_SIZE];
    f.seek(SeekFrom::Start(layout_probe.header_off))?;
    f.read_exact(&mut h)?;

    let hdr = header::Header::decode(&h, digest)?;
    if hdr.flags & FLAG_LIVE_WAL == 0 {
        return Err(ObjectError::InvalidHeader("not a live WAL segment"));
    }
    if hdr.object_type != ObjectType::WalSeg {
        return Err(ObjectError::InvalidHeader("live WAL: wrong object_type"));
    }
    Ok(LiveWalMeta {
        timeline_id: hdr.timeline_id,
        seg_no: u64::from_le_bytes(hdr.object_id[..8].try_into().unwrap()),
        key_epoch: hdr.key_epoch,
        generation: hdr.generation,
        chunk_size: hdr.chunk_size,
        seg_size: hdr.payload_len,
    })
}

/// 从文件大小反推布局（tag 区长度依赖 chunk_count，而 chunk_count 依赖
/// seg_size/chunk_size；header 在文件末尾固定 130B，故可由文件总长与
/// header 字段联合求解）。
fn probe_layout(f: &mut File) -> Result<ProbedLayout, ObjectError> {
    let total = f.metadata()?.len();
    if total < HEADER_SIZE as u64 {
        return Err(ObjectError::Truncated);
    }
    // 先读末尾 header 拿 chunk_size / seg_size
    let mut h = [0u8; HEADER_SIZE];
    f.seek(SeekFrom::Start(total - HEADER_SIZE as u64))?;
    f.read_exact(&mut h)?;
    let chunk_size = u32::from_le_bytes(h[66..70].try_into().unwrap());
    let seg_size = u64::from_le_bytes(h[78..86].try_into().unwrap());
    if chunk_size == 0 || seg_size == 0 {
        return Err(ObjectError::InvalidHeader("live WAL: zero chunk/seg size"));
    }
    let chunk_count = seg_size.div_ceil(chunk_size as u64);
    let header_off = seg_size + chunk_count * TAG_ENTRY_SIZE as u64;
    if header_off + HEADER_SIZE as u64 != total {
        return Err(ObjectError::InvalidHeader(
            "live WAL: file length does not match layout",
        ));
    }
    Ok(ProbedLayout { header_off })
}

struct ProbedLayout {
    header_off: u64,
}

// ============================================================================
// 读取端
// ============================================================================

/// 从活段按**明文偏移**读取（对端复制与 Pageserver 拉取用）。
///
/// 逐 chunk 解密：定位 chunk → 读 tag 条目 → 读密文 → AEAD open → 切片。
/// 支持读到**未写满的尾 chunk**（其 `plain_len` 由最近一次 flush 记录）。
pub fn read_live_plain_at(
    path: &Path,
    aead: &dyn Aead,
    digest: &dyn Digest256,
    dek: &[u8],
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, ObjectError> {
    let meta = read_live_header(path, digest)?;
    read_live_plain_at_with_meta(path, aead, dek, &meta, offset, len)
}

/// 已知 meta 时读取（避免每页重复读 header）。
pub fn read_live_plain_at_with_meta(
    path: &Path,
    aead: &dyn Aead,
    dek: &[u8],
    meta: &LiveWalMeta,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, ObjectError> {
    let cs = meta.chunk_size as u64;
    let layout = LiveWalLayout::new(meta.seg_size, meta.chunk_size)?;
    let end = offset + len as u64;
    if end > meta.seg_size {
        return Err(ObjectError::PayloadLenMismatch {
            header: meta.seg_size,
            actual: end,
        });
    }

    let mut f = File::open(path)?;
    let mut out = Vec::with_capacity(len);

    /*
     * 迭代条件必须看**已收集字节数**而非 chunk 覆盖范围：
     * 尾块的 `plain_len` 可能短于请求区间（尾块只记"当前已封装长度"），
     * 此时该 chunk 只能贡献部分字节，需继续到下一 chunk；反之已收满
     * `len` 就立即停止——否则会读到未写 chunk 而误报"read beyond durable
     * length"（实现期踩到：5×20=100 字节全在一个 chunk 内，却因循环条件
     * 用 chunk 覆盖范围而多迭代到 chunk 1）。
     */
    let mut c = offset / cs;
    while out.len() < len {
        let chunk_off = c * cs;
        if chunk_off >= meta.seg_size {
            return Err(ObjectError::Other(leak_str(
                "live WAL: read past end of segment".to_string(),
            )));
        }
        // 1) tag 条目
        let mut te = [0u8; TAG_ENTRY_SIZE];
        f.seek(SeekFrom::Start(layout.tag_entry_off(c)))?;
        f.read_exact(&mut te)?;
        let entry = TagEntry::decode(&te)?;
        if entry.is_unwritten() {
            return Err(ObjectError::Other(leak_str(format!(
                "live WAL: chunk {c} not written (read beyond durable length)"
            ))));
        }

        // 2) 密文
        let mut ct = vec![0u8; entry.plain_len as usize];
        f.seek(SeekFrom::Start(chunk_off))?;
        f.read_exact(&mut ct)?;
        ct.extend_from_slice(&entry.tag);

        // 3) AEAD open（AAD 含绑定字段，搬移即失败）
        let aad = live_chunk_aad(
            &meta.timeline_id,
            meta.seg_no,
            c,
            chunk_off,
            meta.key_epoch,
            meta.generation,
            entry.plain_len,
        );
        let plain = aead.open(dek, &entry.nonce, &aad, &ct)?;

        // 4) 切片：只取请求区间与该 chunk 实际长度的交集
        let s = offset.max(chunk_off);
        let e = end.min(chunk_off + entry.plain_len as u64);
        if s < e {
            out.extend_from_slice(&plain[(s - chunk_off) as usize..(e - chunk_off) as usize]);
        }
        c += 1;
    }
    Ok(out)
}
