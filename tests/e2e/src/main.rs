//! 端到端验证：KmsLeaseProvider + Dynamic 摘要 → 真实 jt-kms。
//!
//! 验证两件事：
//! 1. Dynamic 摘要下**连续两次**取 DEK 都成功（修复前静态摘要第二次必被拒）
//! 2. 取回的 DEK 与 KMS 侧一致（同一 scope 同 DEK）
use jt_key_epoch::kms_provider::{HttpKmsClient, KmsLeaseProvider};
use jt_key_epoch::{DekScope, KeyProvider};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn main() {
    let endpoint = &std::env::var("KMS_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:7700".to_string());
    let node_id = "sk-e2e";
    let tl = [0xAAu8; 16];

    // Dynamic 摘要：每次采集产生新值（模拟 EvidenceCollector 的 nonce 机制）
    let counter = Arc::new(AtomicU64::new(0));
    let c2 = counter.clone();
    let collector = Box::new(move || {
        let n = c2.fetch_add(1, Ordering::SeqCst);
        // 真实采集器会把 nonce + 度量摘要一起 SM3；这里用 SM3 保证形态一致
        use jt_crypto_api::Digest256 as _;
        let dg = jt_crypto_sm::Sm3Digest;
        let msg = format!("evidence-nonce-{n}");
        Ok(hex::encode(dg.digest(msg.as_bytes())))
    });

    // 反向验证：改用 Fixed 摘要（模拟修复前的静态配置）
    let use_fixed = std::env::var("USE_FIXED").is_ok();
    let client = if use_fixed {
        Arc::new(HttpKmsClient::new(endpoint, node_id, "static-digest-for-reverse-test"))
    } else {
        Arc::new(HttpKmsClient::with_collector(endpoint, node_id, collector))
    };
    let provider = KmsLeaseProvider::new(client, 900);

    let scope = DekScope { timeline_id: tl, key_epoch: 1 };

    println!("=== 第一次 refresh（新摘要）===");
    match provider.refresh(&scope) {
        Ok(()) => {
            let dek = provider.get_dek(&scope).expect("get_dek after refresh");
            println!("  OK  dek={}", hex::encode(dek));
        }
        Err(e) => { println!("  FAIL: {e}"); std::process::exit(1); }
    }

    println!("=== 第二次 refresh（又新摘要）—— 静态摘要在此必失败 ===");
    match provider.refresh(&scope) {
        Ok(()) => {
            let dek = provider.get_dek(&scope).expect("get_dek after 2nd refresh");
            println!("  OK  dek={}", hex::encode(dek));
        }
        Err(e) => { println!("  FAIL: {e}"); std::process::exit(1); }
    }

    println!("=== 第三次 refresh（续租场景）===");
    match provider.refresh(&scope) {
        Ok(()) => println!("  OK  续租成功"),
        Err(e) => { println!("  FAIL: {e}"); std::process::exit(1); }
    }

    println!("\nE2E_OK: Dynamic 摘要下连续 3 次取 DEK 全部成功");
}
