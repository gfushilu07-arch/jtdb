//! 活段 WAL 加密测试（docs/04 §5.2 三项约束逐条验证）。

use jt_crypto_api::{Aead, Digest256, RandomSource, RngSource};
use jt_crypto_sm::{Sm3Digest, Sm4CtrDrbg, Sm4Gcm};
use jt_encrypted_object::live_wal::{
    read_live_header, read_live_plain_at, LiveWalLayout, LiveWalWriter, TagEntry, TAG_ENTRY_SIZE,
};
use jt_encrypted_object::ObjectError;

const TL: [u8; 16] = [0x11; 16];

fn dek() -> Vec<u8> {
    vec![0x44; 16]
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "jt-livewal-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// 小布局便于构造多 chunk（8 chunk × 256B）。
fn layout() -> LiveWalLayout {
    LiveWalLayout::new(256 * 8, 256).unwrap()
}

fn drbg() -> Sm4CtrDrbg {
    Sm4CtrDrbg::from_os_entropy().unwrap()
}

#[test]
fn write_then_read_roundtrip() {
    let d = tmpdir("rt");
    let path = d.join("000000010000000000000001.partial");
    let mut rng = drbg();
    let plain: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();

    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    w.write_at(0, &plain).unwrap();
    let durable = w.flush().unwrap();
    assert_eq!(durable, plain.len() as u64);

    let got = read_live_plain_at(&path, &Sm4Gcm, &Sm3Digest, &dek(), 0, plain.len()).unwrap();
    assert_eq!(got, plain, "活段读回须与写入一致");

    // 部分区间读（跨 chunk）
    let part = read_live_plain_at(&path, &Sm4Gcm, &Sm3Digest, &dek(), 200, 400).unwrap();
    assert_eq!(part, &plain[200..600], "跨 chunk 区间读须正确");
}

#[test]
fn ciphertext_is_same_offset_as_plaintext() {
    // 约束 (a)：密文与明文 1:1 同偏移 —— LSN↔偏移恒等的基础。
    let d = tmpdir("sameoff");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    // 写满恰好两个整 chunk
    let cs = layout().chunk_size as usize;
    let plain: Vec<u8> = (0..cs * 2).map(|i| (i % 253) as u8).collect();
    w.write_at(0, &plain).unwrap();
    w.flush().unwrap();

    // 直接读文件偏移 0..cs 的密文，用 tag 条目解密，须还原 plain[0..cs]
    let bytes = std::fs::read(&path).unwrap();
    let meta = read_live_header(&path, &Sm3Digest).unwrap();
    let te = TagEntry::decode(&bytes[layout().tag_entry_off(0) as usize..][..TAG_ENTRY_SIZE]).unwrap();
    let mut ct = bytes[0..cs].to_vec();
    ct.extend_from_slice(&te.tag);
    let aad = jt_encrypted_object::live_wal::live_chunk_aad(
        &meta.timeline_id, meta.seg_no, 0, 0, meta.key_epoch, meta.generation, cs as u32,
    );
    let got = Sm4Gcm.open(&dek(), &te.nonce, &aad, &ct).unwrap();
    assert_eq!(got.as_slice(), &plain[..cs], "chunk 0 密文位于文件偏移 0（同偏移）");

    // 数据区之后的 tag 区不得被密文占用（文件长度 = seg + tags + header）
    assert_eq!(bytes.len() as u64, layout().file_len());
}

#[test]
fn tail_reseal_uses_fresh_nonce_and_no_reuse() {
    // 约束 (b) 的核心：尾块反复扩展封装时，每次必须用新 nonce，
    // 否则就是致命的 (key, nonce) 重用。
    let d = tmpdir("reseal");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();

    let mut nonces = Vec::new();
    // 同一尾 chunk 逐步扩展 5 次，每次 flush
    for step in 1..=5u64 {
        w.write_at(w.durable_len(), &vec![step as u8; 20]).unwrap();
        w.flush().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let off = layout().tag_entry_off(0) as usize;
        let te = TagEntry::decode(&bytes[off..off + TAG_ENTRY_SIZE]).unwrap();
        nonces.push((te.plain_len, te.nonce));
    }

    // 长度递增
    for i in 1..nonces.len() {
        assert!(nonces[i].0 > nonces[i - 1].0, "尾块长度须递增");
    }
    // nonce 必须两两不同（这是本设计的关键不变量）
    for i in 0..nonces.len() {
        for j in (i + 1)..nonces.len() {
            assert_ne!(
                nonces[i].1, nonces[j].1,
                "尾块重新封装必须使用新 nonce（否则 GCM nonce 重用）"
            );
        }
    }
    // 最终内容正确
    let total = w.durable_len();
    let got = read_live_plain_at(&path, &Sm4Gcm, &Sm3Digest, &dek(), 0, total as usize).unwrap();
    let expect: Vec<u8> = (1..=5u8).flat_map(|b| vec![b; 20]).collect();
    assert_eq!(got, expect);
}

#[test]
fn full_chunks_are_immutable_after_seal() {
    // 约束：整 chunk 一旦写满即固定，后续扩展只影响尾块。
    let d = tmpdir("immutable");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    let cs = layout().chunk_size as usize;

    w.write_at(0, &vec![0xAAu8; cs]).unwrap();
    w.flush().unwrap();
    let before = std::fs::read(&path).unwrap();
    let te0_before = &before[layout().tag_entry_off(0) as usize..][..TAG_ENTRY_SIZE];

    // 继续写尾块并 flush —— chunk 0 的密文与 tag 条目都不得变化
    w.write_at(cs as u64, &vec![0xBBu8; 50]).unwrap();
    w.flush().unwrap();
    let after = std::fs::read(&path).unwrap();
    let te0_after = &after[layout().tag_entry_off(0) as usize..][..TAG_ENTRY_SIZE];

    assert_eq!(te0_before, te0_after, "已写满 chunk 的 tag 条目不可变");
    assert_eq!(
        &before[..cs],
        &after[..cs],
        "已写满 chunk 的密文不可变"
    );
}

#[test]
fn reading_beyond_durable_length_fails_closed() {
    // 未写的 chunk：plain_len=0 哨兵 → 读取必须报错（而非返回零填充）。
    let d = tmpdir("beyond");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    w.write_at(0, &vec![0x11u8; 100]).unwrap();
    w.flush().unwrap();

    // 读到未写区域（第二个 chunk）必须失败
    let r = read_live_plain_at(&path, &Sm4Gcm, &Sm3Digest, &dek(), 300, 10);
    assert!(r.is_err(), "读未写区域须 fail-closed（不得返回零填充）");

    // 读已写范围内但超出 durable 长度（尾块只到 100）
    let r2 = read_live_plain_at(&path, &Sm4Gcm, &Sm3Digest, &dek(), 50, 100);
    assert!(r2.is_err(), "读超出尾块已封装长度须失败");
}

#[test]
fn aad_binds_segment_identity() {
    // AAD 绑定 timeline/seg_no/chunk/offset/epoch/generation：
    // 把密文搬到别的段号必须认证失败（防跨段搬移）。
    let d = tmpdir("aad");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    w.write_at(0, &vec![0x22u8; 200]).unwrap();
    w.flush().unwrap();

    // 正常读成功
    assert!(read_live_plain_at(&path, &Sm4Gcm, &Sm3Digest, &dek(), 0, 200).is_ok());

    // 篡改 header 里的 seg_no（34..50 槽位）→ AAD 不匹配 → 读取失败
    let mut bytes = std::fs::read(&path).unwrap();
    let hoff = layout().header_off() as usize;
    bytes[hoff + 34] ^= 0x01;
    // 同时修 header_digest 使 header 自校验通过（模拟"攻击者改写绑定字段"）
    let hd = Sm3Digest.digest(&bytes[hoff..hoff + 98]);
    bytes[hoff + 98..hoff + 130].copy_from_slice(&hd);
    std::fs::write(&path, &bytes).unwrap();

    let r = read_live_plain_at(&path, &Sm4Gcm, &Sm3Digest, &dek(), 0, 200);
    assert!(
        r.is_err(),
        "绑定字段被改写后 AEAD 必须失败（header 自校验通过也不够）"
    );
}

#[test]
fn tampered_ciphertext_or_tag_fails_authentication() {
    let d = tmpdir("tamper");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    w.write_at(0, &vec![0x33u8; 300]).unwrap();
    w.flush().unwrap();

    // 篡改密文
    let mut b1 = std::fs::read(&path).unwrap();
    b1[10] ^= 0xFF;
    let p1 = d.join("t1.partial");
    std::fs::write(&p1, &b1).unwrap();
    assert!(
        read_live_plain_at(&p1, &Sm4Gcm, &Sm3Digest, &dek(), 0, 300).is_err(),
        "密文篡改须检出"
    );

    // 篡改 tag 条目
    let mut b2 = std::fs::read(&path).unwrap();
    let toff = layout().tag_entry_off(0) as usize + 16;
    b2[toff] ^= 0xFF;
    let p2 = d.join("t2.partial");
    std::fs::write(&p2, &b2).unwrap();
    assert!(
        read_live_plain_at(&p2, &Sm4Gcm, &Sm3Digest, &dek(), 0, 300).is_err(),
        "tag 篡改须检出"
    );
}

#[test]
fn wrong_key_fails() {
    let d = tmpdir("wrongkey");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    w.write_at(0, &vec![0x44u8; 128]).unwrap();
    w.flush().unwrap();

    assert!(
        read_live_plain_at(&path, &Sm4Gcm, &Sm3Digest, &vec![0xEE; 16], 0, 128).is_err(),
        "错误 DEK 不得解密"
    );
}

#[test]
fn seal_renames_partial_and_preserves_data() {
    let d = tmpdir("seal");
    let path = d.join("000000010000000000000001");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    let plain: Vec<u8> = (0..500).map(|i| (i % 97) as u8).collect();
    w.write_at(0, &plain).unwrap();
    let n = w.seal().unwrap();
    assert_eq!(n, 500);

    let partial = d.join("000000010000000000000001.partial");
    assert!(path.exists(), "seal 后最终名存在");
    assert!(!partial.exists(), "seal 后 .partial 消失");

    let got = read_live_plain_at(&path, &Sm4Gcm, &Sm3Digest, &dek(), 0, 500).unwrap();
    assert_eq!(got, plain, "封段后数据仍可读");
}

#[test]
fn non_sequential_write_is_rejected() {
    let d = tmpdir("seq");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    w.write_at(0, &vec![1u8; 10]).unwrap();
    // 跳到非连续偏移必须拒绝（活段是顺序追加语义）
    assert!(w.write_at(100, &vec![2u8; 10]).is_err(), "非顺序写须拒绝");
}

#[test]
fn file_length_is_fixed_at_creation() {
    // 约束：预分配固定长度（fdatasync 语义要求文件大小不变）。
    let d = tmpdir("fixedlen");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    let len0 = std::fs::metadata(&path).unwrap().len();
    assert_eq!(len0, layout().file_len());

    w.write_at(0, &vec![0x55u8; 1000]).unwrap();
    w.flush().unwrap();
    let len1 = std::fs::metadata(&path).unwrap().len();
    assert_eq!(len1, len0, "写入与 flush 不得改变文件长度");

    w.seal().unwrap();
    // seal 会去掉 .partial 后缀（Neon 命名约定），故检查最终名
    let sealed = d.join("seg");
    let len2 = std::fs::metadata(&sealed).unwrap().len();
    assert_eq!(len2, len0, "seal 也不得改变文件长度");
}

#[test]
fn crash_between_ciphertext_and_tag_is_detected() {
    // 崩溃窗口：先写密文、后写 tag（tag 为提交点）。若崩在两者之间，
    // 读取端用旧 nonce 解新密文 → AEAD 失败 → 检出（fail-closed）。
    let d = tmpdir("crashwin");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    w.write_at(0, &vec![0xAAu8; 200]).unwrap();
    w.flush().unwrap();

    // 模拟"密文已更新、tag 未更新"：改密文而保留旧 tag
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 0xFF;
    let p = d.join("crash.partial");
    std::fs::write(&p, &bytes).unwrap();

    assert!(
        read_live_plain_at(&p, &Sm4Gcm, &Sm3Digest, &dek(), 0, 200).is_err(),
        "密文/tag 不一致须被 AEAD 检出（不得静默返回错误数据）"
    );
}

#[test]
fn injected_rng_makes_nonces_reproducible_for_debugging() {
    // 可注入随机源：便于复现与调试（生产用进程级 DRBG）。
    struct CountingRng(u8);
    impl RandomSource for CountingRng {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), jt_crypto_api::CryptoError> {
            for b in dest.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
        fn source_kind(&self) -> RngSource {
            RngSource::OsCsprng
        }
    }

    let d = tmpdir("injrng");
    let path = d.join("seg.partial");
    let mut rng = CountingRng(0);
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    w.write_at(0, &vec![0x66u8; 300]).unwrap();
    w.flush().unwrap();

    let got = read_live_plain_at(&path, &Sm4Gcm, &Sm3Digest, &dek(), 0, 300).unwrap();
    assert_eq!(got, vec![0x66u8; 300]);
}

#[test]
fn empty_flush_is_noop() {
    let d = tmpdir("emptyflush");
    let path = d.join("seg.partial");
    let mut rng = drbg();
    let mut w = LiveWalWriter::create(
        &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
    )
    .unwrap();
    assert_eq!(w.flush().unwrap(), 0, "空 flush 不推进 durable 长度");
    assert_eq!(w.durable_len(), 0);
}

#[test]
fn not_a_live_segment_is_rejected() {
    // 对象布局（§5）的文件不得被活段读取端接受（两种布局互斥）。
    let d = tmpdir("wrongfmt");
    let path = d.join("obj.wal");
    let mut rng = drbg();
    // 用活段布局写，但把 LIVE_WAL 位清掉，模拟对象布局文件
    {
        let mut w = LiveWalWriter::create(
            &Sm4Gcm, &Sm3Digest, &mut rng, &path, layout(), TL, 1, 3, 1, &dek(),
        )
        .unwrap();
        w.write_at(0, &vec![0x77u8; 100]).unwrap();
        w.seal().unwrap();
    }
    let mut bytes = std::fs::read(&path).unwrap();
    let hoff = layout().header_off() as usize;
    bytes[hoff + 11] &= !jt_encrypted_object::FLAG_LIVE_WAL;
    let hd = Sm3Digest.digest(&bytes[hoff..hoff + 98]);
    bytes[hoff + 98..hoff + 130].copy_from_slice(&hd);
    std::fs::write(&path, &bytes).unwrap();

    let r = read_live_header(&path, &Sm3Digest);
    assert!(matches!(r, Err(ObjectError::InvalidHeader(_))), "非活段须拒绝");
}
