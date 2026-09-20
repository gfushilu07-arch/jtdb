//! jt-audit-proto 测试。

use crate::event::{AuditAction, AuditLevel, AuditOutcome};
use crate::journal::{JournalError, WriteAheadAuditJournal};

fn tmpjournal(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "jaudit-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d.join("audit.jsonl")
}

#[test]
fn write_ahead_e3_works() {
    let path = tmpjournal("wa");
    let j = WriteAheadAuditJournal::open(path.clone(), 1000).unwrap();
    let seq = j
        .write_ahead(AuditAction::SecurityConfigChange, "secadmin", "tl-abc", "mac=true", "pageserver")
        .unwrap();
    assert_eq!(seq, 1);
    // E3 必须 pending delivery
    let pending = j.pending_delivery();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1, AuditLevel::Critical);
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[test]
fn journal_full_blocks_e3() {
    let path = tmpjournal("full");
    let j = WriteAheadAuditJournal::open(path.clone(), 3).unwrap();
    // 填满 journal
    j.write_ahead(AuditAction::SecurityConfigChange, "a", "o", "s", "ps").unwrap();
    j.append(AuditLevel::HighValue, AuditAction::MacDenied, "a", "o", "s", "ps").unwrap();
    j.append(AuditLevel::HighValue, AuditAction::Ddl, "a", "o", "s", "ps").unwrap();
    // E3 尝试写入：journal 满 → 阻断
    assert!(matches!(
        j.write_ahead(AuditAction::KeyOperation, "a", "o", "s", "ps"),
        Err(JournalError::Full { .. })
    ));
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[test]
fn hash_chain_integrity() {
    let path = tmpjournal("chain");
    let j = WriteAheadAuditJournal::open(path.clone(), 10000).unwrap();
    j.write_ahead(AuditAction::SecurityConfigChange, "secadmin", "tl", "test", "ps").unwrap();
    j.append(AuditLevel::HighValue, AuditAction::MacDenied, "component", "tl", "test", "ps").unwrap();
    j.append(AuditLevel::Normal, AuditAction::SqlSummary, "component", "db", "test", "ps").unwrap();
    // 校验 hash 链
    let count = j.verify().unwrap();
    assert_eq!(count, 3);
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[test]
fn delivery_ack_removes_pending() {
    let path = tmpjournal("ack");
    let j = WriteAheadAuditJournal::open(path.clone(), 10000).unwrap();
    let seq = j.write_ahead(AuditAction::KmsLeaseGrant, "kms", "tl", "grant", "kms").unwrap();
    assert_eq!(j.pending_delivery().len(), 1);
    assert!(j.delivery_ack(seq));
    assert_eq!(j.pending_delivery().len(), 0);
    // 重复 ack 返回 false
    assert!(!j.delivery_ack(seq));
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[test]
fn reopen_restores_chain_and_pending() {
    let path = tmpjournal("reopen");
    {
        let j = WriteAheadAuditJournal::open(path.clone(), 10000).unwrap();
        j.write_ahead(AuditAction::SecurityConfigChange, "sa", "tl", "s1", "ps").unwrap();
        j.append(AuditLevel::HighValue, AuditAction::MacDenied, "c", "tl", "s2", "ps").unwrap();
    }
    // 重开：恢复链 + pending delivery
    let j = WriteAheadAuditJournal::open(path.clone(), 10000).unwrap();
    let pending = j.pending_delivery();
    assert_eq!(pending.len(), 2, "重开后 pending 恢复");
    assert!(j.verify().is_ok(), "重开后 hash 链完整");
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[test]
fn e0_discardable_no_pending() {
    let path = tmpjournal("e0");
    let j = WriteAheadAuditJournal::open(path.clone(), 10000).unwrap();
    let seq = j.append(AuditLevel::Discardable, AuditAction::SqlSummary, "c", "db", "perf", "ps").unwrap();
    // E0 不需要 delivery ack
    assert!(j.pending_delivery().is_empty());
    assert!(!j.delivery_ack(seq));
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[test]
fn level_semantics_match_spec() {
    // docs/02 §7.2 表格语义
    use AuditLevel::*;
    assert_eq!(Critical.on_journal_full(), crate::event::JournalFullPolicy::BlockOperation);
    assert_eq!(HighValue.on_journal_full(), crate::event::JournalFullPolicy::BlockOperation);
    assert_eq!(Normal.on_journal_full(), crate::event::JournalFullPolicy::ThrottleNewSessions);
    assert_eq!(Discardable.on_journal_full(), crate::event::JournalFullPolicy::Discard);

    assert_eq!(Critical.on_audit_unavailable(), crate::event::AuditUnavailablePolicy::Block);
    assert_eq!(Normal.on_audit_unavailable(), crate::event::AuditUnavailablePolicy::Queue);
    assert_eq!(Discardable.on_audit_unavailable(), crate::event::AuditUnavailablePolicy::Discard);

    assert!(Critical.requires_delivery_ack());
    assert!(HighValue.requires_delivery_ack());
    assert!(!Normal.requires_delivery_ack());
    assert!(Critical.is_write_ahead());
    assert!(!HighValue.is_write_ahead());
}
