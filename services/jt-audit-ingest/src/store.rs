//! jt-audit-ingest 持久化存储（append-only JSONL）。

use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuditRecord {
    pub store_seq: u64,
    pub source: String,
    pub received_at_ms: u64,
    pub event: serde_json::Value,
    pub event_hash: String,
}

pub struct AuditStore {
    path: PathBuf,
    count_path: PathBuf,
    file: parking_lot::Mutex<std::fs::File>,
    count: parking_lot::Mutex<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl AuditStore {
    pub fn open(path: PathBuf) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        let count = if path.exists() {
            std::fs::read_to_string(&path)?.lines().filter(|l| !l.trim().is_empty()).count() as u64
        } else {
            0
        };
        let count_path = path.with_extension("count");
        std::fs::write(&count_path, count.to_string())?;
        Ok(Self {
            path,
            count_path,
            file: parking_lot::Mutex::new(file),
            count: parking_lot::Mutex::new(count),
        })
    }

    pub fn append(&self, source: &str, event: &serde_json::Value, event_hash: &str) -> Result<u64, StoreError> {
        let mut count = self.count.lock();
        *count += 1;
        let record = StoredAuditRecord {
            store_seq: *count,
            source: source.to_string(),
            received_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            event: event.clone(),
            event_hash: event_hash.to_string(),
        };
        let line = serde_json::to_string(&record)?;
        {
            let mut f = self.file.lock();
            writeln!(f, "{line}")?;
            f.sync_data()?;
        }
        std::fs::write(&self.count_path, count.to_string())?;
        Ok(*count)
    }

    pub fn count(&self) -> u64 {
        *self.count.lock()
    }
}
