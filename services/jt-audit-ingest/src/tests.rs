use crate::store::AuditStore;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

fn tmpstore(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "jai-{}-{}-{}", tag, std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d.join("audit.jsonl")
}

#[test]
fn append_increments() {
    let store = AuditStore::open(tmpstore("ai")).unwrap();
    assert_eq!(store.count(), 0);
    store.append("ps", &json!({"a":1}), "h").unwrap();
    store.append("kms", &json!({"a":2}), "h").unwrap();
    assert_eq!(store.count(), 2);
}

#[test]
fn persist_across_reopen() {
    let path = tmpstore("persist");
    { AuditStore::open(path.clone()).unwrap().append("s", &json!({}), "h").unwrap(); }
    assert_eq!(AuditStore::open(path).unwrap().count(), 1);
}

#[test]
fn concurrent_append() {
    let store = std::sync::Arc::new(AuditStore::open(tmpstore("conc")).unwrap());
    let mut handles = Vec::new();
    for i in 0..4 {
        let s = store.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..10 { s.append(&format!("s{i}"), &json!({}), "h").unwrap(); }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(store.count(), 40);
}
