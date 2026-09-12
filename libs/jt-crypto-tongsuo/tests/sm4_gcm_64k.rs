//! F 步归因基准（ADR-015（十四））：单独度量 SM4-GCM 64K chunk 的 seal/open，
//! 区分 pageserver 胶水（tokio fs 句柄 + Arc 分配）与纯密码成本。
//!
//! 跑法：cargo test -p jt-crypto-tongsuo --release --test sm4_gcm_64k -- --ignored --nocapture
use jt_crypto_api::Aead;
use jt_crypto_tongsuo::TongsuoSm4Gcm;

#[test]
#[ignore]
fn bench_sm4_gcm_64k() {
    let aead = TongsuoSm4Gcm;
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let aad = [1u8; 65];
    let plain = vec![0xA5u8; 65536];

    // 预热 + 计时：加密
    let t0 = std::time::Instant::now();
    let n = 500;
    for _ in 0..n {
        let ct = aead.seal(&key, &nonce, &aad, &plain).unwrap();
        assert_eq!(ct.len(), 65536 + 16);
    }
    let seal = t0.elapsed();
    println!(
        "SM4-GCM seal 64K: {:.1} us/op, {:.0} MiB/s",
        seal.as_secs_f64() * 1e6 / n as f64,
        64.0 * n as f64 / seal.as_secs_f64() / 1024.0
    );

    let mut ct = aead.seal(&key, &nonce, &aad, &plain).unwrap();
    let t0 = std::time::Instant::now();
    for _ in 0..n {
        ct = aead.seal(&key, &nonce, &aad, &plain).unwrap();
    }
    let _ = ct;
    let t0 = std::time::Instant::now();
    for _ in 0..n {
        let pt = aead.open(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(pt.len(), 65536);
    }
    let open = t0.elapsed();
    println!(
        "SM4-GCM open 64K: {:.1} us/op, {:.0} MiB/s",
        open.as_secs_f64() * 1e6 / n as f64,
        64.0 * n as f64 / open.as_secs_f64() / 1024.0
    );
}
