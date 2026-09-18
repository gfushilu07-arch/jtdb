//! jt-kms 服务端状态与 API 集成测试（内存态 + 持久化 + HTTP 层）。

use crate::state::{KmsApiError, KmsState};
use std::time::Duration;

const TL: &str = "77777777777777777777777777777777";
const TL_BYTES: [u8; 16] = [0x77; 16];

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "jtkms-{}-{}-{}",
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

fn fresh_state(tag: &str) -> KmsState {
    KmsState::load_or_init(
        &tmpdir(tag),
        "cluster-a",
        "pageserver",
        Duration::from_secs(900),
    )
    .unwrap()
}

fn att(b: u8) -> String {
    hex::encode([b; 32])
}

#[test]
fn lease_issue_renew_revoke_flow() {
    let st = fresh_state("flow");
    let issued = st.issue_lease(TL, 0, "node-1", &att(1)).unwrap();
    assert_eq!(st.lease_state(TL, 0), jt_key_epoch::LeaseState::Valid);
    assert!(issued.lease.expires_at > issued.lease.issued_at);

    // 续租（新鲜 attestation）
    let renewed = st.renew_lease(TL, 0, &att(2)).unwrap();
    assert!(renewed.expires_at >= issued.lease.expires_at);

    // 撤销后拒绝
    assert!(st.revoke_lease(TL));
    assert_eq!(st.lease_state(TL, 0), jt_key_epoch::LeaseState::Revoked);
    assert!(matches!(
        st.renew_lease(TL, 0, &att(3)),
        Err(KmsApiError::Revoked)
    ));
}

#[test]
fn stale_attestation_rejected() {
    let st = fresh_state("stale");
    st.issue_lease(TL, 0, "node-1", &att(7)).unwrap();
    // 同一 attestation 再次签发 = 重放，拒绝
    assert!(matches!(
        st.issue_lease(TL, 0, "node-1", &att(7)),
        Err(KmsApiError::StaleAttestation)
    ));
    // 续租同样拒绝
    assert!(matches!(
        st.renew_lease(TL, 0, &att(7)),
        Err(KmsApiError::StaleAttestation)
    ));
}

#[test]
fn counter_rejects_regression_and_persists() {
    let dir = tmpdir("ctr");
    let st = KmsState::load_or_init(&dir, "cluster-a", "pageserver", Duration::from_secs(900))
        .unwrap();
    assert_eq!(st.counter_record(TL, 0, 100).unwrap(), 100);
    st.counter_record(TL, 0, 150).unwrap();
    // 回退拒绝
    assert!(matches!(
        st.counter_record(TL, 0, 149),
        Err(KmsApiError::Rollback(_))
    ));
    // 持久化：重新加载后计数器仍在
    drop(st);
    let st2 = KmsState::load_or_init(&dir, "cluster-a", "pageserver", Duration::from_secs(900))
        .unwrap();
    assert_eq!(st2.counter_get(TL, 0), 150);
    assert!(matches!(
        st2.counter_record(TL, 0, 10),
        Err(KmsApiError::Rollback(_))
    ));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wrap_unwrap_roundtrip_with_lease_gate() {
    let st = fresh_state("wrap");
    let w = st
        .wrap(TL, 0, "[0x0,0xFFFFFFFFFFFFFFFF]", None)
        .unwrap();
    // 未签发租约：unwrap 拒绝（需有效租约）
    assert!(matches!(
        st.unwrap(TL, 0, "[0x0,0xFFFFFFFFFFFFFFFF]", &w.wrapped_hex),
        Err(KmsApiError::NoValidLease)
    ));
    // 签发租约后：成功
    st.issue_lease(TL, 0, "node-1", &att(9)).unwrap();
    let dek_hex = st
        .unwrap(TL, 0, "[0x0,0xFFFFFFFFFFFFFFFF]", &w.wrapped_hex)
        .unwrap();
    assert_eq!(dek_hex, w.dek_hex);
}

#[test]
fn rotation_via_state_and_persistence() {
    let dir = tmpdir("rot");
    let st = KmsState::load_or_init(&dir, "cluster-a", "pageserver", Duration::from_secs(900))
        .unwrap();
    st.rotation_begin(TL, 5).unwrap();
    st.rotation_advance(TL, "prepare").unwrap();
    st.rotation_advance(TL, "cutover").unwrap();
    drop(st);

    // 崩溃恢复：重载后从 journal 恢复到 cutover
    let st2 = KmsState::load_or_init(&dir, "cluster-a", "pageserver", Duration::from_secs(900))
        .unwrap();
    let (from, to, state, _) = st2.rotation_status(TL).unwrap();
    assert_eq!((from, to), (5, 6));
    assert_eq!(state, "cutover");
    // 继续推进
    st2.rotation_advance(TL, "drain").unwrap();
    assert_eq!(st2.rotation_status(TL).unwrap().2, "drain");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn audit_fail_closed_blocks_issue() {
    let st = fresh_state("audit");
    st.set_audit_healthy(false);
    assert!(matches!(
        st.issue_lease(TL, 0, "node-1", &att(1)),
        Err(KmsApiError::AuditUnavailable)
    ));
    st.set_audit_healthy(true);
    assert!(st.issue_lease(TL, 0, "node-1", &att(1)).is_ok());
}

#[test]
fn dek_matches_pageserver_dev_provider() {
    // KMS 发出的 DEK 与 pageserver 侧 DevKeyProvider 派生一致（零迁移）
    let st = fresh_state("dek");
    let issued = st.issue_lease(TL, 4, "node-1", &att(1)).unwrap();
    let ps_dek = jt_key_epoch::KeyProvider::get_dek(
        &jt_key_epoch::DevKeyProvider::new(),
        &jt_key_epoch::DekScope {
            timeline_id: TL_BYTES,
            key_epoch: 4,
        },
    )
    .unwrap();
    assert_eq!(hex::encode(ps_dek), issued.dek_hex);
}
