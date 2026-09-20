//! WORM 段文件（write-once：段封口后只读）。

use crate::{chain_hash, GENESIS_HASH};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// 段错误。
#[derive(Debug, thiserror::Error)]
pub enum SegmentError {
    #[error("segment is sealed (read-only): {0}")]
    Sealed(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chain broken at seq={seq}: expected prev={expected}, got {got}")]
    ChainBroken {
        seq: u64,
        expected: String,
        got: String,
    },
    #[error("segment not found: {0}")]
    NotFound(String),
}

/// 段元信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub segment_id: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: u64,
    pub head_hash: String,
    pub sealed: bool,
    pub size_bytes: u64,
}

/// WORM 段（append-only + 封口后只读）。
pub struct WormSegment {
    path: PathBuf,
    info_path: PathBuf,
    file: Mutex<std::fs::File>,
    state: Mutex<SegmentState>,
}

#[derive(Debug)]
struct SegmentState {
    segment_id: u64,
    first_seq: u64,
    last_seq: u64,
    count: u64,
    head_hash: String,
    sealed: bool,
}

impl WormSegment {
    /// 创建新段（或打开已存在的未封口段继续追加）。
    pub fn open(dir: &Path, segment_id: u64) -> Result<Self, SegmentError> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("segment-{segment_id:08}.jsonl"));
        let info_path = dir.join(format!("segment-{segment_id:08}.info"));

        if path.exists() {
            // 打开已存在段：恢复状态
            let info: SegmentInfo = serde_json::from_str(&std::fs::read_to_string(&info_path)?)?;
            if info.sealed {
                // 已封口：只读打开
                let file = std::fs::OpenOptions::new().read(true).open(&path)?;
                return Ok(Self {
                    path,
                    info_path,
                    file: Mutex::new(file),
                    state: Mutex::new(SegmentState {
                        segment_id,
                        first_seq: info.first_seq,
                        last_seq: info.last_seq,
                        count: info.count,
                        head_hash: info.head_hash,
                        sealed: true,
                    }),
                });
            }
            let file = std::fs::OpenOptions::new().append(true).open(&path)?;
            Ok(Self {
                path,
                info_path,
                file: Mutex::new(file),
                state: Mutex::new(SegmentState {
                    segment_id,
                    first_seq: info.first_seq,
                    last_seq: info.last_seq,
                    count: info.count,
                    head_hash: info.head_hash,
                    sealed: false,
                }),
            })
        } else {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            let st = SegmentState {
                segment_id,
                first_seq: 0,
                last_seq: 0,
                count: 0,
                head_hash: GENESIS_HASH.to_string(),
                sealed: false,
            };
            let seg = Self {
                path,
                info_path,
                file: Mutex::new(file),
                state: Mutex::new(st),
            };
            seg.persist_info()?;
            Ok(seg)
        }
    }

    /// 追加一条记录（未封口时）。
    ///
    /// 记录格式：`{"seq":N,"event":{...},"hash":"...","prev_hash":"..."}`
    pub fn append(&self, seq: u64, event: &serde_json::Value) -> Result<String, SegmentError> {
        let mut st = self.state.lock();
        if st.sealed {
            return Err(SegmentError::Sealed(self.path.display().to_string()));
        }
        let event_json = serde_json::to_string(event)?;
        let hash = chain_hash(&event_json, &st.head_hash);
        let record = serde_json::json!({
            "seq": seq,
            "event": event,
            "hash": hash,
            "prev_hash": st.head_hash,
        });
        {
            let mut f = self.file.lock();
            writeln!(f, "{}", serde_json::to_string(&record)?)?;
            f.sync_data()?;
        }
        if st.count == 0 {
            st.first_seq = seq;
        }
        st.last_seq = seq;
        st.count += 1;
        st.head_hash = hash.clone();
        self.persist_info_inner(&st)?;
        Ok(hash)
    }

    /// 封口（之后只读；WORM 语义）。
    pub fn seal(&self) -> Result<SegmentInfo, SegmentError> {
        let mut st = self.state.lock();
        if !st.sealed {
            st.sealed = true;
            self.persist_info_inner(&st)?;
        }
        Ok(self.info_inner(&st))
    }

    pub fn info(&self) -> SegmentInfo {
        let st = self.state.lock();
        self.info_inner(&st)
    }

    pub fn is_sealed(&self) -> bool {
        self.state.lock().sealed
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 校验段内 hash 链完整性。
    pub fn verify(&self) -> Result<u64, SegmentError> {
        let content = std::fs::read_to_string(&self.path)?;
        let mut prev = GENESIS_HASH.to_string();
        let mut count = 0u64;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let rec: serde_json::Value = serde_json::from_str(line)?;
            let seq = rec.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
            let got_prev = rec.get("prev_hash").and_then(|v| v.as_str()).unwrap_or("");
            let event_json = serde_json::to_string(rec.get("event").unwrap_or(&serde_json::Value::Null))?;
            let expected = chain_hash(&event_json, &prev);
            let got_hash = rec.get("hash").and_then(|v| v.as_str()).unwrap_or("");
            if got_prev != prev || got_hash != expected {
                return Err(SegmentError::ChainBroken {
                    seq,
                    expected: prev.clone(),
                    got: got_prev.to_string(),
                });
            }
            prev = got_hash.to_string();
            count += 1;
        }
        Ok(count)
    }

    fn info_inner(&self, st: &SegmentState) -> SegmentInfo {
        SegmentInfo {
            segment_id: st.segment_id,
            first_seq: st.first_seq,
            last_seq: st.last_seq,
            count: st.count,
            head_hash: st.head_hash.clone(),
            sealed: st.sealed,
            size_bytes: std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0),
        }
    }

    fn persist_info(&self) -> Result<(), SegmentError> {
        let st = self.state.lock();
        self.persist_info_inner(&st)
    }

    fn persist_info_inner(&self, st: &SegmentState) -> Result<(), SegmentError> {
        let info = self.info_inner(st);
        std::fs::write(&self.info_path, serde_json::to_string_pretty(&info)?)?;
        Ok(())
    }
}

/// WORM 存储：多段管理（按 max_events_per_segment 自动轮转）。
pub struct WormStore {
    dir: PathBuf,
    max_events_per_segment: u64,
    current: Mutex<Option<WormSegment>>,
}

impl WormStore {
    pub fn open(dir: PathBuf, max_events_per_segment: u64) -> Result<Self, SegmentError> {
        std::fs::create_dir_all(&dir)?;
        // 找最大 segment_id
        let mut max_id = 0u64;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(rest) = name.strip_prefix("segment-") {
                if let Some(id_str) = rest.strip_suffix(".jsonl") {
                    if let Ok(id) = id_str.parse::<u64>() {
                        max_id = max_id.max(id);
                    }
                }
            }
        }
        let store = Self {
            dir,
            max_events_per_segment,
            current: Mutex::new(None),
        };
        // 打开最后一个段（若已封口则新建）
        if max_id > 0 {
            let seg = WormSegment::open(&store.dir, max_id)?;
            if seg.is_sealed() {
                *store.current.lock() = None;
            } else {
                *store.current.lock() = Some(seg);
            }
        }
        Ok(store)
    }

    /// 追加（自动轮转：当前段满则封口 + 开新段）。
    pub fn append(&self, seq: u64, event: &serde_json::Value) -> Result<String, SegmentError> {
        let mut cur = self.current.lock();
        let need_new = match cur.as_ref() {
            None => true,
            Some(seg) => seg.info().count >= self.max_events_per_segment,
        };
        if need_new {
            if let Some(old) = cur.take() {
                old.seal()?;
            }
            let next_id = self.next_segment_id();
            *cur = Some(WormSegment::open(&self.dir, next_id)?);
        }
        cur.as_ref().unwrap().append(seq, event)
    }

    /// 封口当前段（优雅关闭）。
    pub fn seal_current(&self) -> Result<Option<SegmentInfo>, SegmentError> {
        let mut cur = self.current.lock();
        match cur.take() {
            Some(seg) => Ok(Some(seg.seal()?)),
            None => Ok(None),
        }
    }

    /// 列出全部段信息（按 id 升序）。
    pub fn segments(&self) -> Result<Vec<SegmentInfo>, SegmentError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".info") {
                let info: SegmentInfo =
                    serde_json::from_str(&std::fs::read_to_string(entry.path())?)?;
                out.push(info);
            }
        }
        out.sort_by_key(|s| s.segment_id);
        Ok(out)
    }

    fn next_segment_id(&self) -> u64 {
        let mut max_id = 0u64;
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(rest) = name.strip_prefix("segment-") {
                    if let Some(id_str) = rest.strip_suffix(".jsonl") {
                        if let Ok(id) = id_str.parse::<u64>() {
                            max_id = max_id.max(id);
                        }
                    }
                }
            }
        }
        max_id + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "jworm-{}-{}-{}",
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

    #[test]
    fn append_and_verify_chain() {
        let dir = tmpdir("chain");
        let seg = WormSegment::open(&dir, 1).unwrap();
        let h1 = seg.append(1, &serde_json::json!({"a": 1})).unwrap();
        let h2 = seg.append(2, &serde_json::json!({"a": 2})).unwrap();
        assert_ne!(h1, h2);
        assert_eq!(seg.verify().unwrap(), 2);
        let info = seg.info();
        assert_eq!(info.first_seq, 1);
        assert_eq!(info.last_seq, 2);
        assert_eq!(info.count, 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sealed_segment_rejects_append() {
        let dir = tmpdir("sealed");
        let seg = WormSegment::open(&dir, 1).unwrap();
        seg.append(1, &serde_json::json!({})).unwrap();
        let info = seg.seal().unwrap();
        assert!(info.sealed);
        assert!(seg.is_sealed());
        // WORM：封口后拒绝追加
        assert!(matches!(
            seg.append(2, &serde_json::json!({})),
            Err(SegmentError::Sealed(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tamper_detected_in_segment() {
        let dir = tmpdir("tamper");
        let seg = WormSegment::open(&dir, 1).unwrap();
        seg.append(1, &serde_json::json!({"secret": "original"})).unwrap();
        seg.append(2, &serde_json::json!({"x": 2})).unwrap();
        drop(seg);
        // 篡改第 1 条的事件内容
        let path = dir.join("segment-00000001.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("original", "modified");
        std::fs::write(&path, tampered).unwrap();
        // 重开校验：链断裂
        let seg = WormSegment::open(&dir, 1).unwrap();
        assert!(matches!(
            seg.verify(),
            Err(SegmentError::ChainBroken { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn store_rotates_segments() {
        let dir = tmpdir("rotate");
        let store = WormStore::open(dir.clone(), 3).unwrap();
        for i in 1..=7 {
            store.append(i, &serde_json::json!({"i": i})).unwrap();
        }
        store.seal_current().unwrap();
        let segs = store.segments().unwrap();
        assert_eq!(segs.len(), 3, "7 条 / 每段 3 条 = 3 段");
        assert_eq!(segs[0].count, 3);
        assert_eq!(segs[1].count, 3);
        assert_eq!(segs[2].count, 1);
        assert!(segs.iter().all(|s| s.sealed));
        std::fs::remove_dir_all(&dir).ok();
    }
}
