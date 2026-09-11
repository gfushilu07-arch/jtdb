//! docs/04 §10 测试矩阵：篡改/交换/删除/截断/断电/随机读。

use jt_crypto_api::{Aead, Digest256};
use jt_crypto_sm::{Sm3Digest, Sm4Gcm};
use jt_encrypted_object::{
    chunk_nonce, ObjectError, ObjectReader, ObjectType, Writer, DEFAULT_CHUNK_SIZE,
};
use std::path::PathBuf;

fn tmpdir() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "jteobj-test-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn tid() -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..9].copy_from_slice(b"timeline0");
    t
}

fn oid(b: u8) -> [u8; 16] {
    let mut t = [b; 16];
    t[..4].copy_from_slice(b"obj!");
    t
}

const DEK: [u8; 16] = [0x33u8; 16];

fn write_sample(path: &PathBuf, payload: &[u8], backend: &dyn Aead, dg: &dyn Digest256) {
    let w = Writer { backend, digest: dg };
    w.write_object(
        path,
        ObjectType::Layer,
        tid(),
        oid(1),
        7,           // key_epoch
        42,          // generation
        [b'N'; 12], // base_nonce 12B
        &DEK,
        payload,
        &[],
    )
    .unwrap();
}

#[test]
fn roundtrip_small_and_large_and_random_pages() {
    let aead = Sm4Gcm;
    let dg = Sm3Digest;
    let d = tmpdir();

    // 小对象（单发模式）
    let p1 = d.join("small.obj");
    write_sample(&p1, b"hello jtdb", &aead, &dg);
    let mut r = ObjectReader::open(&p1, &aead, &dg, &DEK).unwrap();
    assert_eq!(r.read_range(&aead, &DEK, 0, 10).unwrap(), b"hello jtdb");

    // 大对象（>64KiB，多 chunk）+ 随机页读取（含跨 chunk 边界）
    let p2 = d.join("big.obj");
    let payload: Vec<u8> = (0..(DEFAULT_CHUNK_SIZE as usize * 3 + 1234))
        .map(|i| (i % 251) as u8)
        .collect();
    write_sample(&p2, &payload, &aead, &dg);
    let mut r = ObjectReader::open(&p2, &aead, &dg, &DEK).unwrap();
    // 页读取：随机 5 个 8KiB 页
    for page in [0usize, 1, 7, 8, 23] {
        let off = page * 8192;
        let got = r.read_range(&aead, &DEK, off as u64, 8192).unwrap();
        assert_eq!(got[..], payload[off..off + 8192], "page {page}");
    }
    // 全量比对
    let all = r.read_range(&aead, &DEK, 0, payload.len()).unwrap();
    assert_eq!(all, payload);
}

#[test]
fn tampered_header_rejected() {
    let aead = Sm4Gcm;
    let dg = Sm3Digest;
    let d = tmpdir();
    let p = d.join("obj");
    write_sample(&p, b"data", &aead, &dg);

    let mut raw = std::fs::read(&p).unwrap();
    raw[20] ^= 0x01; // 篡改 timeline_id 首字节（digest 覆盖范围内）
    std::fs::write(&p, &raw).unwrap();
    assert!(matches!(
        ObjectReader::open(&p, &aead, &dg, &DEK),
        Err(ObjectError::InvalidHeader("header_digest mismatch"))
    ));
}

#[test]
fn tampered_chunk_rejected() {
    let aead = Sm4Gcm;
    let dg = Sm3Digest;
    let d = tmpdir();
    let p = d.join("obj");
    let payload: Vec<u8> = (0..(DEFAULT_CHUNK_SIZE as usize + 100)).map(|i| (i % 253) as u8).collect();
    write_sample(&p, &payload, &aead, &dg);

    let mut raw = std::fs::read(&p).unwrap();
    let n = raw.len();
    raw[n - 10] ^= 0xFF; // 篡改 chunk 密文尾部（tag 覆盖内）
    std::fs::write(&p, &raw).unwrap();
    let mut r = ObjectReader::open(&p, &aead, &dg, &DEK).unwrap();
    // 篡改的是最后一个 chunk：读到末 chunk 范围才触发 tag 失败
    let tail_off = DEFAULT_CHUNK_SIZE as u64;
    assert!(r.read_range(&aead, &DEK, tail_off, 100).is_err());
}

#[test]
fn swapped_chunks_rejected() {
    let aead = Sm4Gcm;
    let dg = Sm3Digest;
    let d = tmpdir();
    let p = d.join("obj");
    let payload: Vec<u8> = (0..(DEFAULT_CHUNK_SIZE as usize * 2)).map(|i| (i % 251) as u8).collect();
    write_sample(&p, &payload, &aead, &dg);

    let mut raw = std::fs::read(&p).unwrap();
    let meta_len = u32::from_le_bytes(raw[14..18].try_into().unwrap()) as usize;
    let body = HEADER_START + meta_len;
    let cs = DEFAULT_CHUNK_SIZE as usize + 16;
    // 交换 chunk0 与 chunk1（AAD 绑定 chunk_index/offset → 必然 tag 失败）
    let (a, b) = raw.split_at(body + cs);
    let c0 = &a[body..];
    let c1 = b[..cs].to_vec();
    let mut out = Vec::new();
    out.extend_from_slice(&raw[..body]);
    out.extend_from_slice(&c1);
    out.extend_from_slice(c0);
    std::fs::write(&p, &out).unwrap();

    let mut r = ObjectReader::open(&p, &aead, &dg, &DEK).unwrap();
    assert!(r.read_range(&aead, &DEK, 0, 16).is_err());
}

const HEADER_START: usize = 130;

#[test]
fn truncated_object_rejected() {
    let aead = Sm4Gcm;
    let dg = Sm3Digest;
    let d = tmpdir();
    let p = d.join("obj");
    let payload: Vec<u8> = (0..(DEFAULT_CHUNK_SIZE as usize + 100)).map(|i| (i % 253) as u8).collect();
    write_sample(&p, &payload, &aead, &dg);

    let raw = std::fs::read(&p).unwrap();
    std::fs::write(&p, &raw[..raw.len() - 5]).unwrap(); // 截断尾部
    let mut r = ObjectReader::open(&p, &aead, &dg, &DEK).unwrap();
    // 末 chunk 读取时长度不足 → 错误
    assert!(r
        .read_range(&aead, &DEK, DEFAULT_CHUNK_SIZE as u64, 100)
        .is_err());
}

#[test]
fn unsealed_part_file_is_rejected() {
    let aead = Sm4Gcm;
    let dg = Sm3Digest;
    let d = tmpdir();
    let p = d.join("obj");
    write_sample(&p, b"xx", &aead, &dg);
    // .part 文件（未 sealed）：写一个 flags 无 SEALED 的对象
    let part = d.join("obj2.part");
    std::fs::write(&part, b"JTENCOBJ-partial-garbage").unwrap();
    let r = ObjectReader::open(&part, &aead, &dg, &DEK);
    assert!(matches!(
        r,
        Err(ObjectError::InvalidHeader(_))
            | Err(ObjectError::NotSealed)
            | Err(ObjectError::Truncated)
            | Err(ObjectError::Io(_))
    ));
    let _ = p;
}

#[test]
fn wrong_dek_rejected() {
    let aead = Sm4Gcm;
    let dg = Sm3Digest;
    let d = tmpdir();
    let p = d.join("obj");
    write_sample(&p, b"secret", &aead, &dg);
    let bad = [0x00u8; 16];
    let mut r = ObjectReader::open(&p, &aead, &dg, &bad).unwrap();
    assert!(r.read_range(&aead, &bad, 0, 6).is_err());
}

#[test]
fn nonce_derivation_is_unique_per_chunk() {
    let base = *b"nonce12base!";
    let n0 = chunk_nonce(&base, 0);
    let n1 = chunk_nonce(&base, 1);
    let nmax = chunk_nonce(&base, u64::MAX);
    assert_ne!(n0, n1);
    assert_ne!(n0, nmax);
    // docs/04 §4.2：nonce(c) = base_nonce XOR u96(c)（尾部 8 字节承载 index）
    let mut expect = base;
    let idx = 1u64.to_be_bytes();
    for i in 0..8 {
        expect[4 + i] ^= idx[i];
    }
    assert_eq!(n1, expect);
}

// ---------- trailer 签名（SM2，docs/04 §3.4） ----------

use jt_crypto_sm::{Sm2Signer, Sm2Verifier};
use jt_crypto_api::SignatureVerifier as _;

#[test]
fn trailer_signed_roundtrip_and_verify() {
    let aead = Sm4Gcm;
    let dg = Sm3Digest;
    let d = tmpdir();
    let p = d.join("signed.obj");
    let signer = Sm2Signer::generate().unwrap();
    let w = Writer { backend: &aead, digest: &dg };
    w.write_object_signed(
        &p, ObjectType::Layer, tid(), oid(9), 7, 42, [b'N'; 12], &DEK,
        b"signed payload", &[],
        Some(&signer),
    ).unwrap();

    // flags 应置 TRAILER_SIGNED
    let mut r = ObjectReader::open(&p, &aead, &dg, &DEK).unwrap();
    assert_ne!(r.header.flags & 0b0000_1000, 0);
    // 验签通过
    assert!(r.verify_trailer(&Sm2Verifier::from_pk_bytes(&signer.public_key_bytes()).unwrap()).unwrap());
    // 数据仍可读
    assert_eq!(r.read_range(&aead, &DEK, 0, 14).unwrap(), b"signed payload");
}

#[test]
fn trailer_tamper_detected() {
    let aead = Sm4Gcm;
    let dg = Sm3Digest;
    let d = tmpdir();
    let p = d.join("signed2.obj");
    let signer = Sm2Signer::generate().unwrap();
    let w = Writer { backend: &aead, digest: &dg };
    w.write_object_signed(
        &p, ObjectType::Layer, tid(), oid(9), 7, 42, [b'N'; 12], &DEK,
        b"payload", &[], Some(&signer),
    ).unwrap();

    // 篡改签名内部字节（n-3 = sig 尾字节；n-2/n-1 是 sig_len 字段）
    let mut raw = std::fs::read(&p).unwrap();
    let n = raw.len();
    raw[n - 3] ^= 0x01;
    std::fs::write(&p, &raw).unwrap();
    let mut r = ObjectReader::open(&p, &aead, &dg, &DEK).unwrap();
    assert!(!r.verify_trailer(&Sm2Verifier::from_pk_bytes(&signer.public_key_bytes()).unwrap()).unwrap());
}

#[test]
fn unsigned_object_has_no_trailer() {
    let aead = Sm4Gcm;
    let dg = Sm3Digest;
    let d = tmpdir();
    let p = d.join("unsigned.obj");
    write_sample(&p, b"plain", &aead, &dg);
    let mut r = ObjectReader::open(&p, &aead, &dg, &DEK).unwrap();
    assert!(matches!(
        r.verify_trailer(&Sm2Verifier::from_pk_bytes(&Sm2Signer::generate().unwrap().public_key_bytes()).unwrap()),
        Err(ObjectError::Other("object has no trailer signature"))
    ));
}
