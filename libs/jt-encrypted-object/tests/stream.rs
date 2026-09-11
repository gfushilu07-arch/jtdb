//! 流式加密映射与随机解密测试（EncryptedVirtualFile 核心逻辑）。

use jt_crypto_sm::{Sm3Digest, Sm4Gcm};
use jt_encrypted_object::stream::{decrypt_range, encrypt_stream, StreamMeta};

const DEK: [u8; 16] = [0x77u8; 16];
const ENC_START: u64 = 8192;
const CS: u64 = 65536;

fn meta() -> StreamMeta {
    StreamMeta::new(ENC_START, CS, *b"streambase!!")
}

fn hd() -> [u8; 32] {
    [0xEEu8; 32]
}

#[test]
fn full_roundtrip_multi_chunk() {
    let aead = Sm4Gcm;
    let m = meta();
    // 2.5 chunks
    let payload: Vec<u8> = (0..(CS as usize * 2 + 32768)).map(|i| (i % 251) as u8).collect();
    let (ct, tags) = encrypt_stream(
        &aead, &m, &hd(), 2, 7, 42, &DEK, &payload,
    ).unwrap();
    assert_eq!(ct.len(), payload.len());
    assert_eq!(tags.len(), 3);
    let back = decrypt_range(
        &aead, &m, &hd(), 2, 7, 42, &DEK, &ct, &tags, 0, payload.len(),
    ).unwrap();
    assert_eq!(back, payload);
}

#[test]
fn random_range_reads_cross_chunk() {
    let aead = Sm4Gcm;
    let m = meta();
    let payload: Vec<u8> = (0..(CS as usize * 3)).map(|i| (i % 241) as u8).collect();
    let (ct, tags) = encrypt_stream(&aead, &m, &hd(), 2, 7, 42, &DEK, &payload).unwrap();
    // 随机读（含 chunk 边界跨越、末 chunk）
    for &(off, len) in &[
        (0u64, 16usize),
        (8192, 8192),               // 页读
        (CS - 100, 200),            // 跨 chunk 边界
        (CS * 2 - 1, 2),            // 2 字节跨界
        (CS * 2, CS as usize),      // 整 chunk
        ((CS * 2 + 1) as u64, 100), // 末 chunk 内
    ] {
        let got = decrypt_range(&aead, &m, &hd(), 2, 7, 42, &DEK, &ct, &tags, off, len).unwrap();
        assert_eq!(got[..], payload[off as usize..off as usize + len], "off={off} len={len}");
    }
}

#[test]
fn tampered_ciphertext_rejected() {
    let aead = Sm4Gcm;
    let m = meta();
    let payload = vec![7u8; CS as usize];
    let (mut ct, tags) = encrypt_stream(&aead, &m, &hd(), 2, 7, 42, &DEK, &payload).unwrap();
    ct[100] ^= 1;
    assert!(decrypt_range(&aead, &m, &hd(), 2, 7, 42, &DEK, &ct, &tags, 0, 16).is_err());
}

#[test]
fn wrong_epoch_rejected() {
    let aead = Sm4Gcm;
    let m = meta();
    let payload = vec![7u8; 1000];
    let (ct, tags) = encrypt_stream(&aead, &m, &hd(), 2, 7, 42, &DEK, &payload).unwrap();
    // epoch 不同 → AAD 不同 → 认证失败（docs/04 §4.3 AAD 绑定 key_epoch）
    assert!(decrypt_range(&aead, &m, &hd(), 2, 8, 42, &DEK, &ct, &tags, 0, 16).is_err());
}

#[test]
fn truncation_detected() {
    let aead = Sm4Gcm;
    let m = meta();
    let payload: Vec<u8> = (0..(CS as usize * 2)).map(|i| (i % 251) as u8).collect();
    let (ct, tags) = encrypt_stream(&aead, &m, &hd(), 2, 7, 42, &DEK, &payload).unwrap();
    // 截断尾部 → 读取越界报错（docs/04 §10）
    assert!(decrypt_range(&aead, &m, &hd(), 2, 7, 42, &DEK, &ct[..ct.len() - 100], &tags, 0, payload.len()).is_err());
}
