//! Write-ahead 审计 journal（docs/02 §7.2：E3 审计先于生效）。
//!
//! 核心语义：
//! * E3：'write_ahead()' fsync 完成后才返回 'Ok'，操作才能继续；
//! *   操作失败/回滚时调用 'mark_aborted()'。
//! * E2：事务提交时 'append()' 同步写。
//! * E1：'append()' 可靠落盘（批量 fsync 可配）。
//! * hash 链：h(n) = SM3(event_json || h(n-1))。
//! * delivery ack：E3/E2 事件需 ack 后才从待交付队列淘汰。

use crate::event::{AuditAction, AuditEvent, AuditLevel, AuditOutcome};
use jt_crypto_sm::Sm3Digest;
use jt_crypto_api::Digest256 as _;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// journal 错误。
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal is full (capacity={capacity}, level={level:?}): operation must be blocked")]
    Full {
        capacity: usize,
        level: AuditLevel,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit chain broken at seq={seq}")]
    ChainBroken { seq: u64 },
    #[error("cannot write-ahead: journal unavailable")]
    Unavailable,
}

/// journal 单条记录（含 hash 链元数据）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub event: AuditEvent,
    /// 本条 hash（SM3(canonical json)）。
    pub hash: String,
    /// 是否已标记为 aborted（E3 回滚标记）。
    pub aborted: bool,
    /// 是否已收到 delivery ack（E3/E2 需要）。
    pub delivered: bool,
}

/// journal 统计信息。
#[derive(Debug, Clone, Serialize)]
pub struct JournalStats {
    pub total_entries: u64,
    pub pending_delivery: u64,
    pub pending_e3: u64,
    pub pending_e2: u64,
    pub journal_bytes: u64,
}

/// Write-ahead 审计 journal。
pub struct WriteAheadAuditJournal {
    path: PathBuf,
    file: Mutex<std::fs::File>,
    state: Mutex<JournalState>,
    capacity: usize,
}

#[derive(Debug)]
struct JournalState {
    seq: u64,
    last_hash: String,
    /// 待 delivery ack 的 E3/E2 事件队列（seq, level）。
    pending: VecDeque<(u64, AuditLevel)>,
    total: u64,
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl WriteAheadAuditJournal {
    /// 创建或打开 journal（重开时恢复 hash 链状态）。
    pub fn open(path: PathBuf, capacity: usize) -> Result<Self, JournalError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        // 恢复链状态（读现有文件校验并恢复 seq/hash）
        let mut seq = 0u64;
        let mut last_hash = GENESIS_HASH.to_string();
        let mut pending = VecDeque::new();
        let mut total = 0u64;

        let content = std::fs::read_to_string(&path)?;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: JournalEntry = serde_json::from_str(line)?;
            seq = entry.event.seq;
            last_hash = entry.hash.clone();
            total += 1;
            if !entry.delivered && entry.event.level.requires_delivery_ack() {
                pending.push_back((entry.event.seq, entry.event.level));
            }
        }

        // fsync 打开句柄
        file.sync_data().ok();

        Ok(Self {
            path,
            file: Mutex::new(file),
            state: Mutex::new(JournalState {
                seq,
                last_hash,
                pending,
                total,
            }),
            capacity,
        })
    }

    /// **Write-ahead 审计**（E3 关键）：同步写 + fsync 完成后才返回。
    ///
    /// 调用方在收到 Ok 后才能继续执行操作。操作失败/回滚时调用
    /// 'mark_aborted(seq)' 标记。
    ///
    /// journal 满时返回 'Err(JournalError::Full)' → 调用方阻断操作。
    pub fn write_ahead(
        &self,
        action: AuditAction,
        actor: &str,
        object: &str,
        summary: &str,
        source: &str,
    ) -> Result<u64, JournalError> {
        let st = self.state.lock();
        if st.pending.len() >= self.capacity {
            return Err(JournalError::Full {
                capacity: self.capacity,
                level: AuditLevel::Critical,
            });
        }
        let seq = st.seq + 1;
        let prev_hash = st.last_hash.clone();
        drop(st);

        let event = self.make_event(seq, &prev_hash, action, actor, object, summary, source);
        let entry = JournalEntry {
            event: event.clone(),
            hash: event.hash.clone(),
            aborted: false,
            delivered: false,
        };
        let line = serde_json::to_string(&entry)?;

        // 同步写 + fsync（write-ahead 审计：fsync 完成后才返回 Ok）
        {
            let mut f = self.file.lock();
            writeln!(f, "{line}")?;
            f.sync_data()?;
        }

        let mut st = self.state.lock();
        st.seq = seq;
        st.last_hash = event.hash.clone();
        st.pending.push_back((seq, AuditLevel::Critical));
        st.total += 1;
        Ok(seq)
    }

    /// 追加审计事件（E2/E1/E0；同步或异步由调用方控制 fsync 时机）。
    pub fn append(
        &self,
        level: AuditLevel,
        action: AuditAction,
        actor: &str,
        object: &str,
        summary: &str,
        source: &str,
    ) -> Result<u64, JournalError> {
        {
            let st = self.state.lock();
            if level.requires_delivery_ack() && st.pending.len() >= self.capacity {
                return Err(JournalError::Full {
                    capacity: self.capacity,
                    level,
                });
            }
        }
        let st = self.state.lock();
        let seq = st.seq + 1;
        let prev_hash = st.last_hash.clone();
        drop(st);

        let event = self.make_event_with_level(seq, &prev_hash, level, action, actor, object, summary, source);
        let entry = JournalEntry {
            event: event.clone(),
            hash: event.hash.clone(),
            aborted: false,
            delivered: false,
        };
        let line = serde_json::to_string(&entry)?;

        {
            let mut f = self.file.lock();
            writeln!(f, "{line}")?;
            if level >= AuditLevel::HighValue {
                f.sync_data()?;
            }
        }

        let mut st = self.state.lock();
        st.seq = seq;
        st.last_hash = event.hash.clone();
        if level.requires_delivery_ack() {
            st.pending.push_back((seq, level));
        }
        st.total += 1;
        Ok(seq)
    }

    /// 标记 E3 事件为 aborted（操作回滚时调用；docs/02 §7.2 补充规则）。
    pub fn mark_aborted(&self, seq: u64) -> Result<(), JournalError> {
        // 重写文件标记 aborted（追加 aborted 标记行；生产改为原地更新）
        let aborted_line = serde_json::json!({
            "audit_mark": "aborted",
            "seq": seq,
            "ts_ms": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        });
        let mut f = self.file.lock();
        writeln!(f, "{}", aborted_line)?;
        f.sync_data()?;
        Ok(())
    }

    /// 获取待 delivery ack 的事件（jt-audit-ingest 拉取）。
    pub fn pending_delivery(&self) -> Vec<(u64, AuditLevel)> {
        self.state.lock().pending.iter().cloned().collect()
    }

    /// 交付确认（从待交付队列移除）。
    pub fn delivery_ack(&self, seq: u64) -> bool {
        let mut st = self.state.lock();
        if let Some(pos) = st.pending.iter().position(|&(s, _)| s == seq) {
            st.pending.remove(pos);
            true
        } else {
            false
        }
    }

    /// 统计信息。
    pub fn stats(&self) -> JournalStats {
        let st = self.state.lock();
        JournalStats {
            total_entries: st.total,
            pending_delivery: st.pending.len() as u64,
            pending_e3: st.pending.iter().filter(|(_, l)| *l == AuditLevel::Critical).count() as u64,
            pending_e2: st.pending.iter().filter(|(_, l)| *l == AuditLevel::HighValue).count() as u64,
            journal_bytes: std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0),
        }
    }

    /// 校验 hash 链完整性（外部审计触发）。
    pub fn verify(&self) -> Result<u64, JournalError> {
        let content = std::fs::read_to_string(&self.path)?;
        let mut prev = GENESIS_HASH.to_string();
        let mut count = 0u64;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: JournalEntry = serde_json::from_str(line)?;
            if entry.event.prev_hash != prev {
                return Err(JournalError::ChainBroken { seq: entry.event.seq });
            }
            prev = entry.hash;
            count += 1;
        }
        Ok(count)
    }

    /// 构造审计事件并计算 hash 链。
    #[allow(clippy::too_many_arguments)]
    fn make_event(
        &self,
        seq: u64,
        prev_hash: &str,
        action: AuditAction,
        actor: &str,
        object: &str,
        summary: &str,
        source: &str,
    ) -> AuditEvent {
        let level = action.default_level();
        let mut event = AuditEvent {
            seq,
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            level,
            action,
            actor: actor.to_string(),
            object: object.to_string(),
            outcome: AuditOutcome::Ok,
            summary: summary.to_string(),
            prev_hash: prev_hash.to_string(),
            hash: String::new(),
            aborted: None,
            source: source.to_string(),
        };
        // 计算本条 hash = SM3(canonical json minus hash field)
        let json = serde_json::to_string(&event).unwrap_or_default();
        let dg = Sm3Digest;
        event.hash = hex::encode(dg.digest(json.as_bytes()));
        event
    }

    /// 带等级的 make_event（append 用）。
    #[allow(clippy::too_many_arguments)]
    fn make_event_with_level(
        &self,
        seq: u64,
        prev_hash: &str,
        level: AuditLevel,
        action: AuditAction,
        actor: &str,
        object: &str,
        summary: &str,
        source: &str,
    ) -> AuditEvent {
        let mut event = AuditEvent {
            seq,
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            level,
            action,
            actor: actor.to_string(),
            object: object.to_string(),
            outcome: AuditOutcome::Ok,
            summary: summary.to_string(),
            prev_hash: prev_hash.to_string(),
            hash: String::new(),
            aborted: None,
            source: source.to_string(),
        };
        let json = serde_json::to_string(&event).unwrap_or_default();
        let dg = Sm3Digest;
        event.hash = hex::encode(dg.digest(json.as_bytes()));
        event
    }
}
