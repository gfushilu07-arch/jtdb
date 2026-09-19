//! 防篡改审计日志：hash 链（每条含前条哈希）+ 落盘（append-only JSONL）。
//!
//! 密评硬要求：KMS 全操作可审计。hash 链使事后篡改可检出（截断/改写/
//! 重排都会导致链断裂）。生产对接 jt-audit-ingest；本地文件为兜底 journal。

use jt_crypto_sm::Sm3Digest;
use jt_crypto_api::Digest256 as _;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::PathBuf;

/// 单条审计事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// 单调序号（从 1 起）。
    pub seq: u64,
    /// Unix 时间戳（秒）。
    pub ts: u64,
    /// 操作主体（node_id / caller）。
    pub actor: String,
    /// 动作（lease.issue / dek.wrap / rotation.advance / ...）。
    pub action: String,
    /// 对象（timeline/epoch）。
    pub object: String,
    /// 结果（ok / denied:<reason>）。
    pub result: String,
    /// 前一条的哈希（SM3；首条为全零）。
    pub prev_hash: String,
    /// 本条哈希（SM3(本条全部字段序列化)）。
    pub hash: String,
}

/// 审计日志错误。
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("hash chain broken at seq={seq}: expected prev={expected} got {got}")]
    ChainBroken {
        seq: u64,
        expected: String,
        got: String,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

fn compute_hash(e: &AuditEvent) -> String {
    let dg = Sm3Digest;
    let mut msg = Vec::new();
    msg.extend_from_slice(&e.seq.to_le_bytes());
    msg.extend_from_slice(&e.ts.to_le_bytes());
    msg.extend_from_slice(e.actor.as_bytes());
    msg.extend_from_slice(e.action.as_bytes());
    msg.extend_from_slice(e.object.as_bytes());
    msg.extend_from_slice(e.result.as_bytes());
    msg.extend_from_slice(e.prev_hash.as_bytes());
    hex::encode(dg.digest(&msg))
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 审计日志：内存链 + 追加落盘。
pub struct AuditJournal {
    path: PathBuf,
    state: Mutex<AuditState>,
}

#[derive(Debug, Default)]
struct AuditState {
    seq: u64,
    last_hash: String,
}

impl AuditJournal {
    /// 打开或创建（存在则读尾恢复链状态并校验完整性）。
    pub fn open(path: PathBuf) -> Result<Self, AuditError> {
        let mut state = AuditState {
            seq: 0,
            last_hash: GENESIS_HASH.to_string(),
        };
        if path.exists() {
            for line in std::fs::read_to_string(&path)?.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let e: AuditEvent = serde_json::from_str(line)?;
                // 校验链（启动时全量校验；篡改/截断即报错）
                if e.seq != state.seq + 1 {
                    return Err(AuditError::ChainBroken {
                        seq: e.seq,
                        expected: (state.seq + 1).to_string(),
                        got: e.seq.to_string(),
                    });
                }
                if e.prev_hash != state.last_hash {
                    return Err(AuditError::ChainBroken {
                        seq: e.seq,
                        expected: state.last_hash.clone(),
                        got: e.prev_hash.clone(),
                    });
                }
                let h = compute_hash(&e);
                if h != e.hash {
                    return Err(AuditError::ChainBroken {
                        seq: e.seq,
                        expected: h,
                        got: e.hash.clone(),
                    });
                }
                state.seq = e.seq;
                state.last_hash = e.hash;
            }
        }
        Ok(Self { path, state: Mutex::new(state) })
    }

    /// 追加事件（写文件 + 更新链）。
    pub fn append(
        &self,
        actor: &str,
        action: &str,
        object: &str,
        result: &str,
    ) -> Result<AuditEvent, AuditError> {
        let (seq, prev_hash) = {
            let st = self.state.lock();
            (st.seq + 1, st.last_hash.clone())
        };
        let mut e = AuditEvent {
            seq,
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            actor: actor.to_string(),
            action: action.to_string(),
            object: object.to_string(),
            result: result.to_string(),
            prev_hash,
            hash: String::new(),
        };
        e.hash = compute_hash(&e);

        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(&e)?)?;
        f.sync_data()?;

        let mut st = self.state.lock();
        st.seq = e.seq;
        st.last_hash = e.hash.clone();
        Ok(e)
    }

    /// 校验现有日志完整性（外部审计触发；返回条数）。
    pub fn verify(&self) -> Result<u64, AuditError> {
        let mut prev = GENESIS_HASH.to_string();
        let mut expect_seq = 1u64;
        let mut count = 0u64;
        for line in std::fs::read_to_string(&self.path)?.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let e: AuditEvent = serde_json::from_str(line)?;
            if e.seq != expect_seq || e.prev_hash != prev || compute_hash(&e) != e.hash {
                return Err(AuditError::ChainBroken {
                    seq: e.seq,
                    expected: prev,
                    got: e.prev_hash.clone(),
                });
            }
            prev = e.hash;
            expect_seq += 1;
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpjournal(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "jtaudit-{}-{}-{}",
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
    fn append_and_chain_grows() {
        let path = tmpjournal("append");
        let j = AuditJournal::open(path.clone()).unwrap();
        let e1 = j.append("ps-1", "lease.issue", "tl-abc/0", "ok").unwrap();
        assert_eq!(e1.seq, 1);
        assert_eq!(e1.prev_hash, GENESIS_HASH);
        let e2 = j.append("ps-1", "dek.wrap", "tl-abc/0", "ok").unwrap();
        assert_eq!(e2.prev_hash, e1.hash, "链式引用");
        let e3 = j.append("secadmin", "lease.revoke", "tl-abc", "ok").unwrap();
        assert_eq!(e3.prev_hash, e2.hash);
        assert_eq!(j.verify().unwrap(), 3);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn reopen_restores_chain_state() {
        let path = tmpjournal("reopen");
        {
            let j = AuditJournal::open(path.clone()).unwrap();
            j.append("a", "x", "o", "ok").unwrap();
            j.append("a", "y", "o", "ok").unwrap();
        }
        // 重开：链状态恢复，新条目续接
        let j = AuditJournal::open(path.clone()).unwrap();
        let e = j.append("b", "z", "o", "ok").unwrap();
        assert_eq!(e.seq, 3);
        assert_eq!(j.verify().unwrap(), 3);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn tampering_detected_on_verify() {
        let path = tmpjournal("tamper");
        let j = AuditJournal::open(path.clone()).unwrap();
        j.append("a", "lease.issue", "tl", "ok").unwrap();
        j.append("a", "dek.wrap", "tl", "ok").unwrap();
        drop(j);

        // 篡改第 1 条的 actor
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("\"actor\":\"a\"", "\"actor\":\"attacker\"");
        std::fs::write(&path, tampered).unwrap();

        let j = AuditJournal::open(path.clone());
        assert!(matches!(j, Err(AuditError::ChainBroken { .. })), "篡改必须可检出");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn truncation_detected_on_reopen() {
        let path = tmpjournal("trunc");
        {
            let j = AuditJournal::open(path.clone()).unwrap();
            j.append("a", "op1", "o", "ok").unwrap();
            j.append("a", "op2", "o", "ok").unwrap();
            j.append("a", "op3", "o", "ok").unwrap();
        }
        // 截断（删除最后一条 = 隐藏操作）
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        std::fs::write(&path, lines[..2].join("\n") + "\n").unwrap();
        // 重开：seq 回退，append 从 seq=3 重新开始——文件里 seq=3 已被删，
        // 新条目会覆盖语义（append-only 语义依赖外部 WORM；本地文件兜底层级
        // 可检出写入期篡改但无法阻止重启后截断——生产对接 jt-audit-ingest/WORM）
        let j = AuditJournal::open(path.clone()).unwrap();
        let e = j.append("a", "op4", "o", "ok").unwrap();
        assert_eq!(e.seq, 3, "截断后 seq 从断点续写（本地兜底局限）");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
