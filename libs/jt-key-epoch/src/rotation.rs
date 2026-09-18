//! ADR-013：密钥轮换状态机与防回滚计数器。
//!
//! 状态机（ADR-013 结论第 3 条）：
//! ```text
//! Sealed ──prepare──▶ Prepare ──cutover──▶ Cutover ──drain──▶ Drain
//!   ▲                    │                    │                 │
//!   │                    │ abort              │                 │ rekey
//!   └────────────────────┘                    │                 ▼
//!                                             │              Rekey
//!                                             │                 │
//!                                             │                 ▼
//!                                             └───────────▶  Retire
//! ```
//!
//! 设计要点：
//! * **journal 化**：每次状态迁移先写 journal 记录再改内存态，崩溃后
//!   [`RotationJournal::replay`] 重放到确定状态（幂等）；
//! * **容忍混合 epoch**：Cutover 之后 Drain 之前，新旧 epoch 对象并存
//!   （旧对象可读、新写入用新 epoch）；
//! * **Retire 即加密擦除**：Retire 后旧 epoch DEK 不再供给
//!   （[`KeyProvider::get_dek`] 返回 [`KeyError::UnknownScope`]，ADR-011）；
//! * **防回滚计数器**：每个 (timeline, epoch) 维护单调计数器，持久化于
//!   KMS + 本地双份（本模块提供本地份与校验逻辑），恢复时校验对象
//!   generation 不得低于计数器（ADR-013 结论第 4 条）。

use parking_lot::RwLock;
use std::collections::HashMap;

/// 轮换状态（ADR-013 journal 化状态机的六个稳定点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RotationState {
    /// 当前 epoch 已封口，新写入停止（准备轮换）。
    Sealed,
    /// 新 epoch DEK 已生成并就绪（尚未切换写入）。
    Prepare,
    /// 写入切到新 epoch（切换点；此后新对象用新 epoch）。
    Cutover,
    /// 排空旧 epoch 的在途写入（容忍混合 epoch 的窗口）。
    Drain,
    /// 旧对象批量重加密为新 epoch（断点续传，对象粒度）。
    Rekey,
    /// 旧 epoch 退役（DEK 销毁 = 加密擦除）。
    Retire,
}

impl RotationState {
    /// 合法后继（状态机边）。
    fn next_states(self) -> &'static [RotationState] {
        use RotationState::*;
        match self {
            Sealed => &[Prepare],
            Prepare => &[Cutover, Sealed], // abort 回退
            Cutover => &[Drain],
            Drain => &[Rekey, Retire], // 无旧对象时可直接 Retire
            Rekey => &[Retire],
            Retire => &[],
        }
    }

    pub fn can_transition_to(self, next: RotationState) -> bool {
        self.next_states().contains(&next)
    }

    pub fn as_str(self) -> &'static str {
        use RotationState::*;
        match self {
            Sealed => "sealed",
            Prepare => "prepare",
            Cutover => "cutover",
            Drain => "drain",
            Rekey => "rekey",
            Retire => "retire",
        }
    }

    /// 从字符串解析（KMS journal 持久化用）。
    pub fn parse(s: &str) -> Option<Self> {
        use RotationState::*;
        match s {
            "sealed" => Some(Sealed),
            "prepare" => Some(Prepare),
            "cutover" => Some(Cutover),
            "drain" => Some(Drain),
            "rekey" => Some(Rekey),
            "retire" => Some(Retire),
            _ => None,
        }
    }
}

/// 轮换错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RotationError {
    #[error("illegal transition {from} -> {to}")]
    IllegalTransition {
        from: &'static str,
        to: &'static str,
    },
    #[error("no rotation in progress for timeline")]
    NoRotationInProgress,
    #[error("rotation already in progress: state={0}")]
    AlreadyInProgress(&'static str),
    #[error("rollback counter regression: seen={seen} recorded={recorded}")]
    RollbackDetected { seen: u64, recorded: u64 },
    #[error("epoch retired: {0} (cryptographic erasure)")]
    EpochRetired(u64),
}

/// journal 记录（每行一条，崩溃后重放）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub timeline_id: [u8; 16],
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub state: RotationState,
    /// 防回滚计数器快照（迁移时一并持久化）。
    pub rollback_counter: u64,
}

/// 轮换 journal：内存实现（生产替换为 WAL/对象存储后端；接口不变）。
#[derive(Debug, Default)]
pub struct RotationJournal {
    entries: RwLock<Vec<JournalEntry>>,
}

impl RotationJournal {
    pub fn new() -> Self {
        Self::default()
    }

    /// 追加一条（先写 journal 再改内存态 —— 崩溃安全的前提）。
    pub fn append(&self, entry: JournalEntry) {
        self.entries.write().push(entry);
    }

    /// 重放：返回每个 timeline 的最后一条记录（确定状态）。
    ///
    /// 幂等：重复重放同一 journal 得到同一结果（ADR-013 崩溃后重放要求）。
    pub fn replay(&self) -> HashMap<[u8; 16], JournalEntry> {
        let mut last: HashMap<[u8; 16], JournalEntry> = HashMap::new();
        for e in self.entries.read().iter() {
            last.insert(e.timeline_id, e.clone());
        }
        last
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// 全量快照（KMS/文件持久化用；顺序保持）。
    pub fn snapshot(&self) -> Vec<JournalEntry> {
        self.entries.read().clone()
    }
}

/// 单个 timeline 的轮换进度。
#[derive(Debug, Clone)]
pub struct RotationProgress {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub state: RotationState,
    /// Rekey 阶段的断点（已重加密的对象数；对象粒度续传，ADR-013）。
    pub rekeyed_objects: u64,
}

/// 轮换协调器：驱动状态机 + 维护防回滚计数器。
#[derive(Debug, Default)]
pub struct RotationCoordinator {
    /// 活跃轮换（timeline → 进度）。
    active: RwLock<HashMap<[u8; 16], RotationProgress>>,
    /// 防回滚计数器（timeline → epoch → 已见最大 generation）。
    rollback_counters: RwLock<HashMap<([u8; 16], u64), u64>>,
    /// 已退役 epoch（DEK 供给层据此拒绝，加密擦除）。
    retired: RwLock<HashMap<[u8; 16], Vec<u64>>>,
    journal: RotationJournal,
}

impl RotationCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn journal(&self) -> &RotationJournal {
        &self.journal
    }

    /// 开始轮换：Sealed 是起点（当前 epoch 封口）。
    pub fn begin(&self, timeline_id: [u8; 16], from_epoch: u64) -> Result<(), RotationError> {
        let mut active = self.active.write();
        if let Some(p) = active.get(&timeline_id) {
            return Err(RotationError::AlreadyInProgress(p.state.as_str()));
        }
        if self.is_retired(timeline_id, from_epoch) {
            return Err(RotationError::EpochRetired(from_epoch));
        }
        let progress = RotationProgress {
            from_epoch,
            to_epoch: from_epoch + 1,
            state: RotationState::Sealed,
            rekeyed_objects: 0,
        };
        self.journal.append(JournalEntry {
            timeline_id,
            from_epoch,
            to_epoch: progress.to_epoch,
            state: RotationState::Sealed,
            rollback_counter: self.counter(timeline_id, from_epoch),
        });
        active.insert(timeline_id, progress);
        Ok(())
    }

    /// 推进到下一状态（校验状态机边；写 journal 后改内存态）。
    pub fn advance(
        &self,
        timeline_id: [u8; 16],
        to: RotationState,
    ) -> Result<RotationState, RotationError> {
        let mut active = self.active.write();
        let p = active
            .get_mut(&timeline_id)
            .ok_or(RotationError::NoRotationInProgress)?;
        if !p.state.can_transition_to(to) {
            return Err(RotationError::IllegalTransition {
                from: p.state.as_str(),
                to: to.as_str(),
            });
        }
        self.journal.append(JournalEntry {
            timeline_id,
            from_epoch: p.from_epoch,
            to_epoch: p.to_epoch,
            state: to,
            rollback_counter: self.counter(timeline_id, p.from_epoch),
        });
        p.state = to;
        if to == RotationState::Retire {
            self.retired
                .write()
                .entry(timeline_id)
                .or_default()
                .push(p.from_epoch);
        }
        Ok(to)
    }

    /// Rekey 断点续传：记录已重加密对象数（对象粒度，ADR-013）。
    pub fn record_rekeyed(&self, timeline_id: [u8; 16], count: u64) -> Result<(), RotationError> {
        let mut active = self.active.write();
        let p = active
            .get_mut(&timeline_id)
            .ok_or(RotationError::NoRotationInProgress)?;
        if p.state != RotationState::Rekey {
            return Err(RotationError::IllegalTransition {
                from: p.state.as_str(),
                to: "rekey-progress",
            });
        }
        p.rekeyed_objects += count;
        Ok(())
    }

    /// 完成轮换（从活跃表移除；Retire 后调用）。
    pub fn finish(&self, timeline_id: [u8; 16]) -> Option<RotationProgress> {
        self.active.write().remove(&timeline_id)
    }

    pub fn progress(&self, timeline_id: [u8; 16]) -> Option<RotationProgress> {
        self.active.read().get(&timeline_id).cloned()
    }

    /// 旧 epoch 是否仍可用（Drain 窗口内新旧并存；Retire 后拒绝）。
    pub fn is_epoch_usable(&self, timeline_id: [u8; 16], epoch: u64) -> bool {
        !self.is_retired(timeline_id, epoch)
    }

    pub fn is_retired(&self, timeline_id: [u8; 16], epoch: u64) -> bool {
        self.retired
            .read()
            .get(&timeline_id)
            .map(|v| v.contains(&epoch))
            .unwrap_or(false)
    }

    // ---- 防回滚计数器（ADR-013 结论第 4 条）----

    /// 恢复时校验：对象 generation 不得低于已记录计数器（重放旧 Layer 检测）。
    pub fn check_generation(
        &self,
        timeline_id: [u8; 16],
        epoch: u64,
        generation: u64,
    ) -> Result<(), RotationError> {
        let recorded = self.counter(timeline_id, epoch);
        if generation < recorded {
            return Err(RotationError::RollbackDetected {
                seen: generation,
                recorded,
            });
        }
        Ok(())
    }

    /// 记录已见最大 generation（单调；恢复路径在通过校验后调用）。
    pub fn record_generation(&self, timeline_id: [u8; 16], epoch: u64, generation: u64) {
        let mut c = self.rollback_counters.write();
        let e = c.entry((timeline_id, epoch)).or_insert(0);
        if generation > *e {
            *e = generation;
        }
    }

    pub fn counter(&self, timeline_id: [u8; 16], epoch: u64) -> u64 {
        self.rollback_counters
            .read()
            .get(&(timeline_id, epoch))
            .copied()
            .unwrap_or(0)
    }

    /// journal 重放后恢复协调器状态（崩溃恢复入口）。
    pub fn recover_from_journal(&self) {
        let last = self.journal.replay();
        let mut active = self.active.write();
        let mut retired = self.retired.write();
        for (tid, e) in last {
            active.insert(
                tid,
                RotationProgress {
                    from_epoch: e.from_epoch,
                    to_epoch: e.to_epoch,
                    state: e.state,
                    rekeyed_objects: 0,
                },
            );
            self.rollback_counters
                .write()
                .insert((tid, e.from_epoch), e.rollback_counter);
            if e.state == RotationState::Retire {
                retired.entry(tid).or_default().push(e.from_epoch);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: [u8; 16] = [0x5A; 16];

    #[test]
    fn happy_path_full_rotation() {
        let c = RotationCoordinator::new();
        c.begin(T, 0).unwrap();
        for s in [
            RotationState::Prepare,
            RotationState::Cutover,
            RotationState::Drain,
            RotationState::Rekey,
            RotationState::Retire,
        ] {
            assert_eq!(c.advance(T, s).unwrap(), s);
        }
        assert!(c.is_retired(T, 0), "Retire 后旧 epoch 必须退役");
        assert!(!c.is_epoch_usable(T, 0));
        assert!(c.is_epoch_usable(T, 1), "新 epoch 可用");
    }

    #[test]
    fn drain_can_retire_directly_when_no_old_objects() {
        let c = RotationCoordinator::new();
        c.begin(T, 0).unwrap();
        c.advance(T, RotationState::Prepare).unwrap();
        c.advance(T, RotationState::Cutover).unwrap();
        c.advance(T, RotationState::Drain).unwrap();
        // 无旧对象：Drain → Retire 合法（跳过 Rekey）
        assert!(c.advance(T, RotationState::Retire).is_ok());
    }

    #[test]
    fn illegal_transitions_rejected() {
        let c = RotationCoordinator::new();
        c.begin(T, 0).unwrap();
        // Sealed → Cutover 非法（必须先 Prepare）
        assert!(matches!(
            c.advance(T, RotationState::Cutover),
            Err(RotationError::IllegalTransition { .. })
        ));
        // Sealed → Retire 非法
        assert!(c.advance(T, RotationState::Retire).is_err());
    }

    #[test]
    fn prepare_abort_returns_to_sealed() {
        let c = RotationCoordinator::new();
        c.begin(T, 0).unwrap();
        c.advance(T, RotationState::Prepare).unwrap();
        // abort：Prepare → Sealed
        assert!(c.advance(T, RotationState::Sealed).is_ok());
    }

    #[test]
    fn mixed_epoch_window_is_readable() {
        let c = RotationCoordinator::new();
        c.begin(T, 0).unwrap();
        c.advance(T, RotationState::Prepare).unwrap();
        c.advance(T, RotationState::Cutover).unwrap();
        c.advance(T, RotationState::Drain).unwrap();
        // Drain 窗口内：旧 epoch 可读、新 epoch 可写
        assert!(c.is_epoch_usable(T, 0), "Drain 窗口旧 epoch 必须仍可读");
        assert!(c.is_epoch_usable(T, 1));
        c.advance(T, RotationState::Retire).unwrap();
        assert!(!c.is_epoch_usable(T, 0), "Retire 后旧 epoch 拒绝（加密擦除）");
    }

    #[test]
    fn rekey_progress_resumes() {
        let c = RotationCoordinator::new();
        c.begin(T, 0).unwrap();
        for s in [RotationState::Prepare, RotationState::Cutover, RotationState::Drain, RotationState::Rekey] {
            c.advance(T, s).unwrap();
        }
        c.record_rekeyed(T, 100).unwrap();
        c.record_rekeyed(T, 50).unwrap();
        assert_eq!(c.progress(T).unwrap().rekeyed_objects, 150);
        // 非 Rekey 状态记录被拒
        c.advance(T, RotationState::Retire).unwrap();
        assert!(c.record_rekeyed(T, 1).is_err());
    }

    #[test]
    fn journal_replay_is_idempotent_and_deterministic() {
        let c = RotationCoordinator::new();
        c.begin(T, 3).unwrap();
        c.advance(T, RotationState::Prepare).unwrap();
        c.advance(T, RotationState::Cutover).unwrap();
        let n = c.journal().len();
        assert_eq!(n, 3);

        // 重放到新协调器（模拟崩溃恢复）
        let c2 = RotationCoordinator::new();
        // 直接复用同一 journal 内容：手工复制条目
        for e in c.journal().entries.read().iter() {
            c2.journal().append(e.clone());
        }
        c2.recover_from_journal();
        let p = c2.progress(T).unwrap();
        assert_eq!(p.state, RotationState::Cutover);
        assert_eq!(p.from_epoch, 3);
        assert_eq!(p.to_epoch, 4);

        // 幂等：再重放一次结果不变
        c2.recover_from_journal();
        assert_eq!(c2.progress(T).unwrap().state, RotationState::Cutover);
    }

    #[test]
    fn rollback_counter_detects_old_generation() {
        let c = RotationCoordinator::new();
        c.record_generation(T, 0, 42);
        assert_eq!(c.counter(T, 0), 42);
        // 同代或更新：通过
        assert!(c.check_generation(T, 0, 42).is_ok());
        assert!(c.check_generation(T, 0, 43).is_ok());
        // 旧代：拒绝（重放旧 Layer 攻击）
        assert!(matches!(
            c.check_generation(T, 0, 41),
            Err(RotationError::RollbackDetected { seen: 41, recorded: 42 })
        ));
        // 计数器单调（不回退）
        c.record_generation(T, 0, 10);
        assert_eq!(c.counter(T, 0), 42);
    }

    #[test]
    fn retired_epoch_cannot_start_new_rotation() {
        let c = RotationCoordinator::new();
        c.begin(T, 0).unwrap();
        for s in [RotationState::Prepare, RotationState::Cutover, RotationState::Drain, RotationState::Retire] {
            c.advance(T, s).unwrap();
        }
        c.finish(T);
        // 已退役的 epoch 0 不能再次作为轮换起点
        assert!(matches!(
            c.begin(T, 0),
            Err(RotationError::EpochRetired(0))
        ));
    }

    #[test]
    fn concurrent_rotation_rejected() {
        let c = RotationCoordinator::new();
        c.begin(T, 0).unwrap();
        assert!(matches!(
            c.begin(T, 0),
            Err(RotationError::AlreadyInProgress("sealed"))
        ));
    }
}
