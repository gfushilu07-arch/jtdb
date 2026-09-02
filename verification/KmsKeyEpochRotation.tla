------------------------------- MODULE KmsKeyEpochRotation -------------------------------
(***************************************************************************)
(* JTDB ADR-013 密钥轮换状态机 —— 骨架模型（阶段 0 协议评审用）             *)
(*                                                                         *)
(* 承接文档：                                                              *)
(*   《JTDB-架构决策记录》ADR-013；《信创安全数据库-实现方案》§6.3          *)
(*                                                                         *)
(* 建模范围：                                                              *)
(*   - 轮换状态机 Sealed -> Prepare -> Cutover -> Drain -> Rekey -> Retire *)
(*   - 每次状态迁移先写 journal（write-ahead），崩溃后可重放                *)
(*   - 组件崩溃/恢复：崩溃期间禁止写入                                      *)
(*   - 组件写入必须使用"已 Cutover 且未 Retire"的 epoch                     *)
(*                                                                         *)
(* 暂未建模（后续扩展）：DEK 租约与续租、attestation 绑定、防回滚计数器、   *)
(* 分支授权 BranchKeyGrant（ADR-014）、多 timeline 并发、Rekey 限速/续传。   *)
(*                                                                         *)
(* 不变式（TLC 验证目标）：                                                *)
(*   TypeOK              变量类型正确                                      *)
(*   MonotonicEpoch      组件写入 epoch 不超过当前 epoch                    *)
(*   SingleCutover       每个epoch至多完成一次Cutover                       *)
(*   NoWriteBeforeCutover 组件不写入尚未 Cutover 的 epoch                   *)
(*   JournalMatchesPhase phase 与 journal 尾部记录一致（先写日志后变更）    *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Components

ASSUME ComponentSetNE == Components # {}

(***************************************************************************)
(* 变量                                                                     *)
(***************************************************************************)
VARIABLES
    \* 当前目标 epoch（从 1 开始；Prepare 动作 +1）
    epoch,
    \* 轮换状态机当前相位
    phase,
    \* 已完成 Cutover 的 epoch 集合
    cutoverDone,
    \* 各组件最近一次写入所用的 epoch：[Components -> Nat]，0 表示从未写入
    writes,
    \* 已持久化的迁移日志，元素形如 <<epoch, 目标相位>>
    journal,
    \* 处于崩溃状态的组件集合
    crashed

vars == <<epoch, phase, cutoverDone, writes, journal, crashed>>

Phases == {"sealed", "prepared", "cutover", "drain", "rekeyed", "retired"}

(***************************************************************************)
(* 初始状态                                                                 *)
(***************************************************************************)
Init ==
    /\ epoch = 1
    /\ phase = "sealed"
    /\ cutoverDone = {}
    /\ writes = [c \in Components |-> 0]
    /\ journal = <<>>
    /\ crashed = {}

(***************************************************************************)
(* 协议动作                                                                 *)
(***************************************************************************)

\* 仅相位迁移（epoch 不变）：先写 journal，再变相位
AdvancePhase(p) ==
    /\ phase' = p
    /\ journal' = Append(journal, <<epoch, p>>)
    /\ UNCHANGED <<epoch, cutoverDone, writes, crashed>>

\* Prepare：提升 epoch，分发新 epoch 密钥（分发本身在此抽象）
Prepare ==
    /\ phase = "sealed"
    /\ epoch' = epoch + 1
    /\ phase' = "prepared"
    /\ journal' = Append(journal, <<epoch + 1, "prepared">>)
    /\ UNCHANGED <<cutoverDone, writes, crashed>>

\* Cutover：新写入切换到新 epoch（每个 epoch 至多一次）
Cutover ==
    /\ phase = "prepared"
    /\ epoch \notin cutoverDone
    /\ phase' = "cutover"
    /\ journal' = Append(journal, <<epoch, "cutover">>)
    /\ cutoverDone' = cutoverDone \union {epoch}
    /\ UNCHANGED <<epoch, writes, crashed>>

\* Drain：旧 epoch 转只读
Drain == /\ phase = "cutover" /\ AdvancePhase("drain")

\* Rekey：后台重加密旧对象（此抽象为瞬时完成；限速/续传后续建模）
Rekey == /\ phase = "drain" /\ AdvancePhase("rekeyed")

\* Retire：旧 epoch DEK 满足保留策略后销毁
Retire == /\ phase = "rekeyed" /\ AdvancePhase("retired")

\* 组件写入：仅在线组件，仅在 cutover/drain 相位，使用当前 epoch
Write(c) ==
    /\ c \notin crashed
    /\ phase \in {"cutover", "drain"}
    /\ writes' = [writes EXCEPT ![c] = epoch]
    /\ UNCHANGED <<epoch, phase, cutoverDone, journal, crashed>>

\* 组件崩溃：易失状态丢失，journal 与 epoch 保持
Crash(c) ==
    /\ c \notin crashed
    /\ crashed' = crashed \union {c}
    /\ UNCHANGED <<epoch, phase, cutoverDone, writes, journal>>

\* 组件恢复：按 journal 重放到确定状态后继续（此抽象：持久状态本就一致）
Recover(c) ==
    /\ c \in crashed
    /\ crashed' = crashed \ {c}
    /\ UNCHANGED <<epoch, phase, cutoverDone, writes, journal>>

Next ==
    \/ Prepare
    \/ Cutover
    \/ Drain
    \/ Rekey
    \/ Retire
    \/ \E c \in Components : Write(c) \/ Crash(c) \/ Recover(c)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* 不变式                                                                   *)
(***************************************************************************)
TypeOK ==
    /\ epoch \in Nat
    /\ phase \in Phases
    /\ cutoverDone \subseteq Nat
    /\ writes \in [Components -> Nat]
    /\ \A e \in 1..Len(journal) :
           /\ journal[e][1] \in Nat
           /\ journal[e][2] \in Phases
    /\ crashed \subseteq Components

\* 任何写入 epoch 不超过当前目标 epoch
MonotonicEpoch ==
    \A c \in Components : writes[c] <= epoch

\* 每个已完成 Cutover 的 epoch 都在 1..epoch 内；
\* 重复 Cutover 由动作守卫 epoch \notin cutoverDone 排除
SingleCutover ==
    cutoverDone \subseteq 1..epoch

\* 先切换后写入：组件写入的 epoch 必须已完成 Cutover
NoWriteBeforeCutover ==
    \A c \in Components : (writes[c] # 0) => writes[c] \in cutoverDone

\* journal 尾部记录与当前相位一致（write-ahead 的意图检查）
JournalMatchesPhase ==
    Len(journal) > 0 => phase = journal[Len(journal)][2]

Inv ==
    /\ TypeOK
    /\ MonotonicEpoch
    /\ SingleCutover
    /\ NoWriteBeforeCutover
    /\ JournalMatchesPhase

=============================================================================
