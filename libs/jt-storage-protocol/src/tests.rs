//! jt-storage-protocol 集成测试：通用信封的校验顺序与防重放。

use crate::error::ErrorCode;
use crate::header::{validate, CommonHeader, ValidationContext, PROTOCOL_VER};
use crate::nonce::ReplayWindow;
use jt_crypto_api::SignatureKey;
use jt_crypto_sm::{Sm2Signer, Sm2Verifier};

fn signer() -> Sm2Signer {
    Sm2Signer::from_sk_bytes(&[0x11u8; 32]).expect("fixed sk")
}

fn header_for(s: &Sm2Signer, body: &[u8], now_us: i64) -> CommonHeader {
    let mut h = CommonHeader {
        request_id: "018f0a00-0000-7000-8000-000000000001".into(),
        source_id: "jtdb://cluster-a/pageserver/node-1".into(),
        policy_version: 7,
        key_epoch: 3,
        nonce: [0xAB; 16],
        timestamp_us: now_us,
        deadline_us: now_us + 5_000_000,
        signature: Vec::new(),
        protocol_ver: PROTOCOL_VER,
    };
    let msg = h.signing_message(body);
    h.signature = s.sign(&msg);
    h
}

fn ctx<'a>(now_us: i64, peer: &'a str) -> ValidationContext<'a> {
    ValidationContext {
        peer_identity: peer,
        current_policy_version: 7,
        current_key_epoch: 3,
        now_us,
        clock_skew_us: 1_000_000,
    }
}

fn verifier(s: &Sm2Signer) -> Sm2Verifier {
    Sm2Verifier::from_pk_bytes(&s.public_key()).expect("pk")
}

#[test]
fn valid_request_passes() {
    let s = signer();
    let body = b"request-body";
    let h = header_for(&s, body, 1_000_000);
    let w = ReplayWindow::with_default_window();
    assert!(validate(&h, body, &ctx(1_000_000, &h.source_id), &verifier(&s), &w).is_ok());
}

#[test]
fn tampered_body_fails_signature() {
    let s = signer();
    let h = header_for(&s, b"original", 1_000_000);
    let w = ReplayWindow::with_default_window();
    assert_eq!(
        validate(&h, b"tampered", &ctx(1_000_000, &h.source_id), &verifier(&s), &w).unwrap_err(),
        ErrorCode::BadSignature
    );
}

#[test]
fn tampered_header_field_fails_signature() {
    let s = signer();
    let body = b"b";
    let mut h = header_for(&s, body, 1_000_000);
    // 攻击者改 epoch 试图降级到旧代
    h.key_epoch = 2;
    let w = ReplayWindow::with_default_window();
    assert_eq!(
        validate(&h, body, &ctx(1_000_000, &h.source_id), &verifier(&s), &w).unwrap_err(),
        ErrorCode::BadSignature,
        "header 字段在签名覆盖范围内"
    );
}

#[test]
fn expired_deadline_rejected_before_signature() {
    let s = signer();
    let body = b"b";
    let h = header_for(&s, body, 1_000_000); // deadline = 6_000_000
    let w = ReplayWindow::with_default_window();
    // deadline 已过（now 超过 deadline）
    let c = ctx(7_000_000, &h.source_id);
    assert_eq!(
        validate(&h, body, &c, &verifier(&s), &w).unwrap_err(),
        ErrorCode::DeadlineExpired
    );
    assert!(w.is_empty(), "过期请求不得占用 nonce 窗口");
}

#[test]
fn future_timestamp_rejected() {
    let s = signer();
    let body = b"b";
    let h = header_for(&s, body, 10_000_000); // 远在未来
    let w = ReplayWindow::with_default_window();
    assert_eq!(
        validate(&h, body, &ctx(1_000_000, &h.source_id), &verifier(&s), &w).unwrap_err(),
        ErrorCode::DeadlineExpired,
        "未来时间戳必须拒绝（否则 deadline 可被无限延长）"
    );
}

#[test]
fn replayed_nonce_rejected() {
    let s = signer();
    let body = b"b";
    let h = header_for(&s, body, 1_000_000);
    let w = ReplayWindow::with_default_window();
    let c = ctx(1_000_000, &h.source_id);
    assert!(validate(&h, body, &c, &verifier(&s), &w).is_ok());
    assert_eq!(
        validate(&h, body, &c, &verifier(&s), &w).unwrap_err(),
        ErrorCode::Replayed
    );
}

#[test]
fn replayed_nonce_does_not_poison_window_when_signature_invalid() {
    // 校验顺序的安全含义：伪造签名的请求不得占用 nonce 窗口，
    // 否则攻击者能靠垃圾请求把合法请求挤掉（拒绝服务）。
    let s = signer();
    let attacker = Sm2Signer::from_sk_bytes(&[0x22u8; 32]).unwrap();
    let body = b"b";
    let legit = header_for(&s, body, 1_000_000);
    let w = ReplayWindow::with_default_window();
    let c = ctx(1_000_000, &legit.source_id);

    // 攻击者复用同一 nonce，但用自己的密钥签名
    let forged = CommonHeader {
        signature: {
            let mut f = legit.clone();
            f.signature.clear();
            let msg = f.signing_message(body);
            attacker.sign(&msg)
        },
        ..legit.clone()
    };
    assert_eq!(
        validate(&forged, body, &c, &verifier(&s), &w).unwrap_err(),
        ErrorCode::BadSignature
    );
    assert!(w.is_empty(), "签名失败不得写入 nonce 窗口");
    // 合法请求仍可通过
    assert!(validate(&legit, body, &c, &verifier(&s), &w).is_ok());
}

#[test]
fn identity_mismatch_rejected() {
    let s = signer();
    let body = b"b";
    let h = header_for(&s, body, 1_000_000);
    let w = ReplayWindow::with_default_window();
    // mTLS 身份是 node-2，header 自称 node-1（借合法签名者身份冒充）
    let c = ctx(1_000_000, "jtdb://cluster-a/pageserver/node-2");
    assert_eq!(
        validate(&h, body, &c, &verifier(&s), &w).unwrap_err(),
        ErrorCode::BadSignature
    );
}

#[test]
fn stale_policy_rejected() {
    let s = signer();
    let body = b"b";
    let mut h = header_for(&s, body, 1_000_000);
    h.policy_version = 6;
    let msg = h.signing_message(body);
    h.signature = s.sign(&msg); // 合法签名，但策略版本落后
    let w = ReplayWindow::with_default_window();
    assert_eq!(
        validate(&h, body, &ctx(1_000_000, &h.source_id), &verifier(&s), &w).unwrap_err(),
        ErrorCode::PolicyStale
    );
}

#[test]
fn epoch_mismatch_rejected() {
    let s = signer();
    let body = b"b";
    let mut h = header_for(&s, body, 1_000_000);
    h.key_epoch = 2;
    let msg = h.signing_message(body);
    h.signature = s.sign(&msg);
    let w = ReplayWindow::with_default_window();
    assert_eq!(
        validate(&h, body, &ctx(1_000_000, &h.source_id), &verifier(&s), &w).unwrap_err(),
        ErrorCode::EpochMismatch
    );
}

#[test]
fn signature_covers_protocol_version() {
    let s = signer();
    let body = b"b";
    let mut h = header_for(&s, body, 1_000_000);
    h.protocol_ver = 2;
    let w = ReplayWindow::with_default_window();
    assert_eq!(
        validate(&h, body, &ctx(1_000_000, &h.source_id), &verifier(&s), &w).unwrap_err(),
        ErrorCode::BadSignature,
        "降级/篡改协议版本必须被发现"
    );
}

#[test]
fn header_shape_validation() {
    let s = signer();
    let body = b"b";
    let h = header_for(&s, body, 1_000_000);
    assert!(h.validate_shape().is_ok());
    let mut bad = h.clone();
    bad.request_id = String::new();
    assert!(bad.validate_shape().is_err(), "幂等键必填");
    let mut bad = h.clone();
    bad.source_id = String::new();
    assert!(bad.validate_shape().is_err());
    let mut bad = h.clone();
    bad.signature = Vec::new();
    assert!(bad.validate_shape().is_err());
    let mut bad = h.clone();
    bad.protocol_ver = 0;
    assert!(bad.validate_shape().is_err());
}

#[test]
fn canonical_header_roundtrips_through_signature() {
    // 规范编码的确定性：同一 header 多次编码必须一致（否则验签随机失败）
    let s = signer();
    let body = b"b";
    let h = header_for(&s, body, 1_000_000);
    assert_eq!(h.to_canonical(), h.to_canonical());
    assert_eq!(h.signing_message(body), h.signing_message(body));
    assert_ne!(
        h.signing_message(b"x"),
        h.signing_message(b"y"),
        "请求体必须参与签名"
    );
}
