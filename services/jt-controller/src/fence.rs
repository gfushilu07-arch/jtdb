//! generation 围栏日志（防脑裂的持久化基础，docs/02 §6.1、docs/13 §4）。
//!
//! generation 是**安全关键量**：它一旦回退，旧 generation 的组件就会被重新
//! 视为权威，"前一代失权"的语义随之失效——两个组件同时服务同一 timeline，
//! 即脑裂。因此本模块的职责只有一条：**在授权返回之前，把围栏令牌落盘**。
//!
//! 日志为 append-only JSONL；崩溃可能留下半行，读取时**只容忍末尾撕裂**
//! （无换行结尾的残行），任何完整行的损坏都 fail-closed 报错——损坏的围栏
//! 日志意味着无法确认当前代次，此时必须拒绝启动而不是猜。

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// 围栏作用域。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceScope {
    /// 组件级：node_id → generation。
    Node,
    /// timeline 级：timeline_id → 服务 generation。
    Timeline,
}

/// 一条围栏记录（日志的一行）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FenceRecord {
    pub scope: FenceScope,
    /// Node 作用域为十进制 node_id；Timeline 作用域为 32 位 hex。
    pub id: String,
    pub generation: u64,
    /// 记录时刻（Unix 秒）。
    pub at: u64,
    /// 原因（审计用）：register / bump / deregister。
    pub reason: String,
}

/// 日志重放结果（只保留高水位，不重建业务记录）。
#[derive(Debug, Default, Clone)]
pub struct JournalState {
    /// node_id → 已授予的最高 generation。
    pub nodes: HashMap<u64, u64>,
    /// timeline_id → 已授予的最高 serving generation。
    pub timelines: HashMap<[u8; 16], u64>,
}

impl JournalState {
    pub fn node_generation(&self, node_id: u64) -> Option<u64> {
        self.nodes.get(&node_id).copied()
    }

    pub fn timeline_generation(&self, timeline_id: &[u8; 16]) -> Option<u64> {
        self.timelines.get(timeline_id).copied()
    }
}

/// 围栏日志错误。
#[derive(Debug, thiserror::Error)]
pub enum FenceError {
    #[error("fence journal io: {0}")]
    Io(#[from] std::io::Error),
    #[error("fence journal encode: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("fence journal corrupt at line {line}: {detail}")]
    Corrupt { line: usize, detail: String },
    #[error("fence journal has invalid id at line {line}: {detail}")]
    BadId { line: usize, detail: String },
    #[error("fence journal path no longer names the open journal (replaced or removed?): {0}")]
    Replaced(PathBuf),
}

/// 打开的日志句柄是否仍与 `path` 指向同一文件。
///
/// 追加走的是已打开的 fd；若日志被轮转/删除/替换，写入会落进无人认领的
/// inode——进程内一切"成功"，重启后围栏却消失了。因此每次追加都要确认
/// 路径仍指向该 inode，不一致即 fail-closed。
///
/// 非 Unix 平台没有 dev/ino，退化为不做检查（本项目目标平台为信创 Linux）。
fn path_still_names_fd(fd: &std::fs::File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (Ok(open), Ok(named)) = (fd.metadata(), std::fs::metadata(path)) else {
            return false;
        };
        open.dev() == named.dev() && open.ino() == named.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (fd, path);
        true
    }
}

/// append-only 围栏日志。
pub struct GenerationJournal {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl GenerationJournal {
    /// 打开（不存在则创建）。
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, FenceError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 追加一条围栏记录并**落盘**（fsync）。
    ///
    /// 调用方必须在本函数返回后才对外授权：崩溃丢失围栏 = 防脑裂失效。
    pub fn append(&self, rec: &FenceRecord) -> Result<(), FenceError> {
        let mut line = serde_json::to_string(rec)?;
        line.push('\n');
        let mut f = self.file.lock();
        if !path_still_names_fd(&f, &self.path) {
            return Err(FenceError::Replaced(self.path.clone()));
        }
        f.write_all(line.as_bytes())?;
        f.sync_data()?;
        Ok(())
    }

    /// 重放日志，得到各作用域的高水位。
    pub fn load(&self) -> Result<JournalState, FenceError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(JournalState::default()),
            Err(e) => return Err(FenceError::Io(e)),
        };
        let mut state = JournalState::default();
        // 末尾无换行 → 最后一段是崩溃留下的残行，容忍丢弃
        let complete = match text.rfind('\n') {
            Some(pos) => &text[..=pos],
            None => "",
        };
        for (idx, raw) in complete.lines().enumerate() {
            let line_no = idx + 1;
            if raw.trim().is_empty() {
                continue;
            }
            let rec: FenceRecord = serde_json::from_str(raw).map_err(|e| FenceError::Corrupt {
                line: line_no,
                detail: e.to_string(),
            })?;
            match rec.scope {
                FenceScope::Node => {
                    let id: u64 = rec.id.parse().map_err(|e: std::num::ParseIntError| {
                        FenceError::BadId {
                            line: line_no,
                            detail: e.to_string(),
                        }
                    })?;
                    let slot = state.nodes.entry(id).or_insert(0);
                    *slot = (*slot).max(rec.generation);
                }
                FenceScope::Timeline => {
                    let bytes = hex::decode(&rec.id).map_err(|e| FenceError::BadId {
                        line: line_no,
                        detail: e.to_string(),
                    })?;
                    let arr: [u8; 16] = bytes.try_into().map_err(|_| FenceError::BadId {
                        line: line_no,
                        detail: format!("timeline id must be 16 bytes, got {}", rec.id.len() / 2),
                    })?;
                    let slot = state.timelines.entry(arr).or_insert(0);
                    *slot = (*slot).max(rec.generation);
                }
            }
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "jtctrl-fence-{}-{}-{}",
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

    fn rec(scope: FenceScope, id: &str, generation: u64) -> FenceRecord {
        FenceRecord {
            scope,
            id: id.to_string(),
            generation,
            at: 1000,
            reason: "test".into(),
        }
    }

    #[test]
    fn append_and_replay_high_water_mark() {
        let dir = tmpdir("hwm");
        let j = GenerationJournal::open(dir.join("generation.log")).unwrap();
        j.append(&rec(FenceScope::Node, "1", 1)).unwrap();
        j.append(&rec(FenceScope::Node, "1", 2)).unwrap();
        j.append(&rec(FenceScope::Node, "2", 7)).unwrap();
        j.append(&rec(FenceScope::Timeline, &hex::encode([9u8; 16]), 3))
            .unwrap();

        let st = j.load().unwrap();
        assert_eq!(st.node_generation(1), Some(2), "取高水位而非末条");
        assert_eq!(st.node_generation(2), Some(7));
        assert_eq!(st.timeline_generation(&[9u8; 16]), Some(3));
        assert_eq!(st.node_generation(99), None);
    }

    #[test]
    fn replay_is_monotonic_even_if_written_out_of_order() {
        let dir = tmpdir("order");
        let j = GenerationJournal::open(dir.join("generation.log")).unwrap();
        j.append(&rec(FenceScope::Node, "5", 9)).unwrap();
        j.append(&rec(FenceScope::Node, "5", 3)).unwrap(); // 乱序写入
        assert_eq!(j.load().unwrap().node_generation(5), Some(9));
    }

    #[test]
    fn torn_tail_is_tolerated() {
        let dir = tmpdir("torn");
        let path = dir.join("generation.log");
        let j = GenerationJournal::open(&path).unwrap();
        j.append(&rec(FenceScope::Node, "1", 4)).unwrap();
        drop(j);
        // 模拟崩溃：追加半行（无换行结尾）
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{\"scope\":\"node\",\"id\":\"1\",\"gene").unwrap();
        }
        let j2 = GenerationJournal::open(&path).unwrap();
        assert_eq!(
            j2.load().unwrap().node_generation(1),
            Some(4),
            "残行丢弃，已落盘的围栏保留"
        );
    }

    #[test]
    fn corrupt_complete_line_fails_closed() {
        let dir = tmpdir("corrupt");
        let path = dir.join("generation.log");
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"{\"scope\":\"node\",\"id\":\"1\",\"generation\":4,\"at\":1,\"reason\":\"x\"}\n")
                .unwrap();
            f.write_all(b"this is not json\n").unwrap();
        }
        let j = GenerationJournal::open(&path).unwrap();
        assert!(matches!(j.load(), Err(FenceError::Corrupt { line: 2, .. })));
    }

    #[test]
    fn bad_id_fails_closed() {
        let dir = tmpdir("badid");
        let path = dir.join("generation.log");
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"{\"scope\":\"node\",\"id\":\"not-a-number\",\"generation\":1,\"at\":1,\"reason\":\"x\"}\n")
                .unwrap();
            f.write_all(b"{\"scope\":\"timeline\",\"id\":\"abcd\",\"generation\":1,\"at\":1,\"reason\":\"x\"}\n")
                .unwrap();
        }
        let j = GenerationJournal::open(&path).unwrap();
        assert!(matches!(j.load(), Err(FenceError::BadId { line: 1, .. })));
    }

    #[test]
    fn append_fails_closed_when_path_replaced() {
        // 日志被替换/删除后，追加会写进无人认领的 inode：必须拒绝，而不是
        // 报告成功却让围栏在重启后消失。
        let dir = tmpdir("replaced");
        let path = dir.join("generation.log");
        let j = GenerationJournal::open(&path).unwrap();
        j.append(&rec(FenceScope::Node, "1", 1)).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            j.append(&rec(FenceScope::Node, "1", 2)),
            Err(FenceError::Replaced(_))
        ));
        // 路径被新文件顶替同样拒绝
        std::fs::write(&path, b"").unwrap();
        assert!(matches!(
            j.append(&rec(FenceScope::Node, "1", 3)),
            Err(FenceError::Replaced(_))
        ));
    }

    #[test]
    fn empty_and_missing_journal_yield_empty_state() {
        let dir = tmpdir("empty");
        let j = GenerationJournal::open(dir.join("absent.log")).unwrap();
        let st = j.load().unwrap();
        assert!(st.nodes.is_empty() && st.timelines.is_empty());

        let path = dir.join("zero.log");
        std::fs::write(&path, b"").unwrap();
        let j2 = GenerationJournal::open(&path).unwrap();
        assert!(j2.load().unwrap().nodes.is_empty());
    }
}
