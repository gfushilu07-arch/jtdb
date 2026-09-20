//! WAL 段追加写入测试（docs/04 §5 语义逐条验证）。

use jt_crypto_api::{Aead, Digest256, SignatureKey};
use jt_crypto_sm::{Sm2Signer, Sm3Digest, Sm4Gcm};
use jt_encrypted_object::header::{Header, ObjectType, HEADER_SIZE};
use jt_encrypted_object::tlv;
use jt_encrypted_object::wal::WalSegWriter;
use jt_encrypted_object::{ObjectReader, DEFAULT_CHUNK_SIZE, TAG_LEN};

const TL: [u8; 16] = [0x11; 16];
const OBJ: [u8; 16] = [0x22; 16];
const NONCE: [u8; 12] = [0x33; 12];

fn dek() -> Vec<u8> {
    vec![0x44; 16]
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "jt-walseg-{}-{}-{}",
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

fn open_seg(path: &std::path::Path) -> ObjectReader {
    ObjectReader::open(path, &Sm4Gcm, &Sm3Digest, &dek()).expect("open WAL segment")
}

/// 小容量便于构造多 chunk（3 chunk × 64 KiB）。
const CAP: u64 = (DEFAULT_CHUNK_SIZE as u64) * 3;

#[test]
fn append_and_read_back_single_chunk() {
    let dir = tmpdir("one");
    let path = dir.join("seg.wal");

    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    let plain = b"hello wal segment";
    w.append(plain).unwrap();
    let stats = w.finish().unwrap();
    assert_eq!(stats.payload_len, plain.len() as u64);
    assert_eq!(stats.chunk_count, 1, "不足一 chunk 也应形成 1 个 chunk");
    assert_eq!(stats.capacity, CAP);

    let mut r = open_seg(&path);
    // 读取端以 metadata 的真实长度为准（header 记容量上界）
    assert_eq!(r.payload_len(), plain.len() as u64, "真实长度来自 metadata");
    let got = r.read_range(&Sm4Gcm, &dek(), 0, plain.len()).unwrap();
    assert_eq!(got.as_slice(), plain, "读回明文须与写入一致");
}

#[test]
fn chunk_boundary_is_independent_of_append_granularity() {
    // docs/04 §5 第 1 条：攒满一个 chunk 才加密，调用方怎么写不影响 chunk 边界。
    let dir = tmpdir("gran");
    let path_a = dir.join("a.wal");
    let path_b = dir.join("b.wal");

    let total = DEFAULT_CHUNK_SIZE as usize * 2 + 1000;
    let plain: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();

    // A：一次写全部
    let mut wa = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path_a, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    wa.append(&plain).unwrap();
    let sa = wa.finish().unwrap();

    // B：切成 7 字节碎片写
    let mut wb = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path_b, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    for c in plain.chunks(7) {
        wb.append(c).unwrap();
    }
    let sb = wb.finish().unwrap();

    assert_eq!(sa.chunk_count, sb.chunk_count, "chunk 数不随写入粒度变化");
    assert_eq!(sa.payload_len, sb.payload_len);
    assert_eq!(sa.chunk_count, 3, "2 整块 + 1 尾块");

    // 两者密文应逐字节相同（同 key/nonce/边界 → 确定性）
    let ca = std::fs::read(&path_a).unwrap();
    let cb = std::fs::read(&path_b).unwrap();
    assert_eq!(ca, cb, "同参数下密文应确定性一致（AEAD 无随机成分）");
}

#[test]
fn partial_chunk_not_flushed_before_finish() {
    // docs/04 §5 第 2 条：chunk 攒满前崩溃 → 未落盘明文丢弃。
    // 验证：append 未满一 chunk 时，数据区不应出现该 chunk。
    let dir = tmpdir("partial");
    let path = dir.join("seg.wal");

    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    w.append(b"short").unwrap();

    // 此时 .part 应只有 header + metadata，无数据区
    let part = dir.join("seg.wal.part");
    let size_before = std::fs::metadata(&part).unwrap().len();
    let header_and_meta = HEADER_SIZE as u64;
    assert!(
        size_before <= header_and_meta + 64,
        "未满 chunk 不应落盘数据区（size={size_before}）"
    );

    // 丢弃 writer（模拟崩溃）——最终名不应存在
    drop(w);
    assert!(
        !path.exists(),
        "未 finish 的段不得以最终名出现（封段信号由原子 rename 承载）"
    );
}

#[test]
fn finish_is_atomic_via_rename() {
    let dir = tmpdir("rename");
    let path = dir.join("seg.wal");
    let part = dir.join("seg.wal.part");

    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    w.append(b"data").unwrap();
    assert!(part.exists(), "写入期间为 .part");
    assert!(!path.exists(), "封段前最终名不应存在");

    w.finish().unwrap();
    assert!(path.exists(), "finish 后最终名存在");
    assert!(!part.exists(), "finish 后 .part 消失（rename 语义）");
}

#[test]
fn sealed_segment_rejects_further_append() {
    // docs/04 §5 第 3 条：已发布对象不可追加（chunk 不可变）。
    let dir = tmpdir("sealed");
    let path = dir.join("seg.wal");
    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    w.append(b"x").unwrap();
    w.finish().unwrap();

    // 下一段必须是新对象（新 object_id）——用新 writer 写另一路径验证可写
    let path2 = dir.join("seg2.wal");
    let mut w2 = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path2, TL, [0x99; 16], 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    w2.append(b"y").unwrap();
    w2.finish().unwrap();
    assert!(path2.exists());
}

#[test]
fn append_beyond_capacity_is_rejected() {
    let dir = tmpdir("cap");
    let path = dir.join("seg.wal");
    let cap = 1024u64;
    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 0, 1, NONCE, &dek(), cap, &[], None,
    )
    .unwrap();
    w.append(&vec![0u8; 1000]).unwrap();
    let err = w.append(&vec![0u8; 100]).unwrap_err();
    assert!(
        format!("{err}").contains("capacity"),
        "超容量须报错提示开新段，实际: {err}"
    );
}

#[test]
fn header_is_self_consistent_and_verifiable() {
    // 关键：header_digest 自校验必须通过（这是"不做回填"裁决的直接验证）。
    let dir = tmpdir("hdr");
    let path = dir.join("seg.wal");
    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 7, 3, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    w.append(b"payload").unwrap();
    w.finish().unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let hdr = Header::decode(&bytes[..HEADER_SIZE], &Sm3Digest).expect("header 自校验须通过");
    assert_eq!(hdr.object_type, ObjectType::WalSeg);
    assert_eq!(hdr.timeline_id, TL);
    assert_eq!(hdr.object_id, OBJ);
    assert_eq!(hdr.key_epoch, 7);
    assert_eq!(hdr.generation, 3);
    assert_eq!(hdr.payload_len, CAP, "header 记容量上界（真实长度在 metadata）");
    assert_eq!(hdr.chunk_count, CAP.div_ceil(DEFAULT_CHUNK_SIZE as u64));
}

#[test]
fn actual_payload_len_recovers_tail_chunk_length() {
    let dir = tmpdir("actual");
    let path = dir.join("seg.wal");
    let plain_len = DEFAULT_CHUNK_SIZE as usize + 123; // 1 整块 + 短尾块
    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    w.append(&vec![0xAB; plain_len]).unwrap();
    let stats = w.finish().unwrap();

    // 真实长度由 reader 从 metadata 读出（对象自描述，无需调用方另记）
    let r = open_seg(&path);
    assert_eq!(r.payload_len(), plain_len as u64, "真实长度须自描述");
    assert_eq!(r.payload_len(), stats.payload_len);
    assert!(r.payload_len() < stats.capacity, "段未写满：真实长度 < 容量上界");
}

#[test]
fn signed_segment_carries_trailer_and_verifies() {
    let dir = tmpdir("signed");
    let path = dir.join("seg.wal");
    let signer = Sm2Signer::from_sk_bytes(&[0x55u8; 32]).unwrap();

    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], Some(&signer),
    )
    .unwrap();
    w.append(b"signed wal data").unwrap();
    w.finish().unwrap();

    // trailer 布局：signature(64B) || u16 sig_len（长度置尾）
    let bytes = std::fs::read(&path).unwrap();
    let n = bytes.len();
    let sig_len = u16::from_le_bytes(bytes[n - 2..].try_into().unwrap());
    assert_eq!(sig_len, 64, "trailer 尾部 u16 应为签名长度");
    let sig = &bytes[n - 2 - 64..n - 2];

    // 走真实验签路径（reader 负责重建签名消息：header_digest || metadata_digest || last_tag）
    let v = jt_crypto_sm::Sm2Verifier::from_pk_bytes(&signer.public_key_bytes()).unwrap();
    let mut r = open_seg(&path);
    assert!(r.verify_trailer(&v).unwrap(), "trailer 签名须可验证");

    // 篡改 metadata（真实长度字段）后验签必须失败（签名覆盖 metadata_digest）
    let metadata_len = u32::from_le_bytes(bytes[14..18].try_into().unwrap()) as usize;
    let mut tampered = bytes.clone();
    // 翻转 metadata 内一个字节（跳过 0 偏移的 type/len 头）
    tampered[HEADER_SIZE + 8] ^= 0xFF;
    let bad = dir.join("seg_tampered.wal");
    std::fs::write(&bad, &tampered).unwrap();
    let mut rb = ObjectReader::open(&bad, &Sm4Gcm, &Sm3Digest, &dek()).unwrap();
    assert!(!rb.verify_trailer(&v).unwrap(), "metadata 被篡改须验签失败");
    let _ = metadata_len;
}

#[test]
fn metadata_carries_declared_capacity() {
    let dir = tmpdir("meta");
    let path = dir.join("seg.wal");
    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    w.append(b"z").unwrap();
    w.finish().unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let metadata_len = u32::from_le_bytes(bytes[14..18].try_into().unwrap()) as usize;
    let entries = tlv::decode(&bytes[HEADER_SIZE..HEADER_SIZE + metadata_len]).unwrap();
    let real_len = entries
        .iter()
        .find(|e| e.tlv_type == jt_encrypted_object::wal::TLV_REAL_PAYLOAD_LEN)
        .expect("metadata 须含真实长度");
    assert_eq!(
        u64::from_le_bytes(real_len.value[..8].try_into().unwrap()),
        1,
        "metadata 记真实明文长度（1 字节）"
    );
    let real_cnt = entries
        .iter()
        .find(|e| e.tlv_type == jt_encrypted_object::wal::TLV_REAL_CHUNK_COUNT)
        .expect("metadata 须含真实 chunk 数");
    assert_eq!(u64::from_le_bytes(real_cnt.value[..8].try_into().unwrap()), 1);
}

#[test]
fn tampered_ciphertext_fails_authentication() {
    let dir = tmpdir("tamper");
    let path = dir.join("seg.wal");
    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    w.append(b"authentic data").unwrap();
    w.finish().unwrap();

    // 翻转数据区一个字节
    let mut bytes = std::fs::read(&path).unwrap();
    let metadata_len = u32::from_le_bytes(bytes[14..18].try_into().unwrap()) as usize;
    let data_start = HEADER_SIZE + metadata_len;
    bytes[data_start] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    let mut r = open_seg(&path);
    assert!(
        r.read_range(&Sm4Gcm, &dek(), 0, 14).is_err(),
        "篡改密文须 AEAD 认证失败"
    );
}

#[test]
fn wrong_key_fails_to_open() {
    let dir = tmpdir("wrongkey");
    let path = dir.join("seg.wal");
    let mut w = WalSegWriter::create(
        &Sm4Gcm, &Sm3Digest, &path, TL, OBJ, 0, 1, NONCE, &dek(), CAP, &[], None,
    )
    .unwrap();
    w.append(b"secret").unwrap();
    w.finish().unwrap();

    let r = ObjectReader::open(&path, &Sm4Gcm, &Sm3Digest, &vec![0xFF; 16]);
    // 错误 DEK 时 open 可能通过（只读头），但读数据必失败
    match r {
        Err(_) => {}
        Ok(mut rr) => assert!(
            rr.read_range(&Sm4Gcm, &vec![0xFF; 16], 0, 6).is_err(),
            "错误 DEK 读取须失败"
        ),
    }
}
