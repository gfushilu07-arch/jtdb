//! KAT：RFC 8998（SM4-GCM）+ 交叉验证（与 pure-rust backend 输出一致）。

use jt_crypto_api::{Aead, Digest256};
use jt_crypto_sm::{Sm3Digest, Sm4Gcm};
use jt_crypto_tongsuo::{TongsuoSm3, TongsuoSm4Gcm};

#[test]
fn rfc8998_kat() {
    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let iv: [u8; 12] = [0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd];
    let aad: [u8; 20] = [
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
        0xef, 0xab, 0xad, 0xda, 0xd2,
    ];
    let mut pt = Vec::new();
    for pair in [[0xAAu8, 0xBBu8], [0xCCu8, 0xDDu8], [0xEEu8, 0xFFu8], [0xEEu8, 0xAAu8]] {
        pt.extend_from_slice(&[pair[0]; 8]);
        pt.extend_from_slice(&[pair[1]; 8]);
    }
    let aead = TongsuoSm4Gcm;
    let ct = aead.seal(&key, &iv, &aad, &pt).unwrap();
    assert_eq!(ct.len(), pt.len() + 16);
    const EXPECTED_TAG: [u8; 16] = [
        0x83, 0xde, 0x35, 0x41, 0xe4, 0xc2, 0xb5, 0x81, 0x77, 0xe0, 0x65, 0xa9, 0xbf, 0x7b, 0x62,
        0xec,
    ];
    assert_eq!(ct[pt.len()..], EXPECTED_TAG[..]);
    let rt = aead.open(&key, &iv, &aad, &ct).unwrap();
    assert_eq!(rt.as_slice(), pt.as_slice());
}

#[test]
fn sm3_kat() {
    let dg = TongsuoSm3;
    let expect: [u8; 32] = [
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4,
        0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b,
        0xa8, 0xe0,
    ];
    assert_eq!(dg.digest(b"abc"), expect);
}

#[test]
fn cross_backend_consistency() {
    // 双后端一致性：同 key/nonce/aad/plaintext 必须产生相同密文与 tag
    let key = [0x55u8; 16];
    let nonce = [0x66u8; 12];
    let aad = b"cross";
    let pt: Vec<u8> = (0..1000).map(|i| (i % 241) as u8).collect();
    let a = Sm4Gcm.seal(&key, &nonce, aad, &pt).unwrap();
    let b = TongsuoSm4Gcm.seal(&key, &nonce, aad, &pt).unwrap();
    assert_eq!(a, b);
    let da = Sm3Digest.digest(&pt);
    let db = TongsuoSm3.digest(&pt);
    assert_eq!(da, db);
    // 交叉解密
    let ra = Sm4Gcm.open(&key, &nonce, aad, &b).unwrap();
    let rb = TongsuoSm4Gcm.open(&key, &nonce, aad, &a).unwrap();
    assert_eq!(ra.as_slice(), pt.as_slice());
    assert_eq!(rb.as_slice(), pt.as_slice());
}
