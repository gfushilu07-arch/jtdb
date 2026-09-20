//! 连接池与主体亲和（docs/14 §2/§5/§6）。

use crate::session::{ResetConfig, ResetOutcome, SessionState, SubjectIdentity};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 池配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// 池化模式：false = 会话级（默认），true = 事务级多路复用（opt-in）。
    pub transaction_mode: bool,
    /// 每池最大连接数。
    pub max_conns: usize,
    /// 队列上限（超限快速失败）。
    pub max_waiting: usize,
    /// 复位配置。
    pub reset: ResetConfig,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            transaction_mode: false, // 默认会话级（无状态泄漏面）
            max_conns: 32,
            max_waiting: 64,
            reset: ResetConfig::default(),
        }
    }
}

/// 池键（四级限额的复合键；docs/14 §5）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PoolKey {
    pub cluster: String,
    pub database: String,
    /// 主体（事务级模式下参与亲和键）。
    pub subject_id: String,
    /// 来源 IP（限额维度）。
    pub source_ip: String,
}

/// 后端连接状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnState {
    /// 空闲在池中（可复用）。
    Idle,
    /// 正在服务某客户端会话。
    Active,
    /// Pin（绑定某会话，不归还池）。
    Pinned,
    /// Stale（策略撤销/epoch 轮换导致，归还时强制重建）。
    Stale,
}

/// Stale 原因（docs/14 §4 失效传播）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaleReason {
    /// 策略版本撤销（PDP revoke）。
    PolicyRevoked,
    /// key_epoch 轮换（ADR-013）。
    EpochRotated,
    /// 租约过期。
    LeaseExpired,
}

impl StaleReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            StaleReason::PolicyRevoked => "policy_revoked",
            StaleReason::EpochRotated => "epoch_rotated",
            StaleReason::LeaseExpired => "lease_expired",
        }
    }
}

/// 后端连接。
#[derive(Debug)]
pub struct BackendConn {
    pub conn_id: u64,
    /// 亲和键（主体身份；docs/14 §2.1）。
    pub affinity: SubjectIdentity,
    pub state: ConnState,
    /// 当前绑定的客户端会话（Active/Pinned 时）。
    pub bound_session: Option<u64>,
    /// 会话状态（复位决策依据）。
    pub session_state: SessionState,
    /// Stale 原因（state == Stale 时）。
    pub stale_reason: Option<StaleReason>,
    /// 创建时刻（Unix 秒）。
    pub created_at: u64,
    /// 借出时的 stale 代际（归还时与池的代际对比，不等 = stale）。
    pub borrowed_generation: u64,
}

/// 网关错误。
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("pool exhausted (max_conns={0})")]
    PoolExhausted(usize),
    #[error("queue full (max_waiting={0})")]
    QueueFull(usize),
    #[error("affinity violation: connection belongs to subject '{owner}', requested by '{requester}'")]
    AffinityViolation { owner: String, requester: String },
    #[error("no idle connection with matching affinity")]
    NoMatchingConn,
    #[error("connection not found: {0}")]
    NotFound(u64),
}

/// 会话池（按 PoolKey 分桶；主体亲和由 affinity 字段保证）。
pub struct SessionPool {
    config: PoolConfig,
    /// 池内容（PoolKey → 连接列表）。
    pools: Mutex<HashMap<PoolKey, Vec<BackendConn>>>,
    /// 等待队列长度（PoolKey → 等待数）。
    waiting: Mutex<HashMap<PoolKey, usize>>,
    /// 连接 ID 分配器。
    next_conn_id: Mutex<u64>,
    /// 指标：pin 计数（按原因）。
    pinned_counts: Mutex<HashMap<&'static str, u64>>,
    /// 指标：stale 淘汰计数。
    stale_evictions: Mutex<u64>,
    /// 指标：复位次数。
    resets: Mutex<u64>,
    /// 活跃连接计数（池内 + 已借出；限额用）。
    live_counts: Mutex<HashMap<PoolKey, usize>>,
    /// Stale 代际（失效传播用；借出连接携带借出时的代际，归还时对比）。
    stale_generation: Mutex<u64>,
    /// 最近一次失效原因（诊断用）。
    last_stale_reason: Mutex<Option<StaleReason>>,
}

impl SessionPool {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            pools: Mutex::new(HashMap::new()),
            waiting: Mutex::new(HashMap::new()),
            next_conn_id: Mutex::new(0),
            pinned_counts: Mutex::new(HashMap::new()),
            stale_evictions: Mutex::new(0),
            resets: Mutex::new(0),
            live_counts: Mutex::new(HashMap::new()),
            stale_generation: Mutex::new(0),
            last_stale_reason: Mutex::new(None),
        }
    }

    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// 从池中获取连接（主体亲和：只复用相同 SubjectIdentity 的连接）。
    ///
    /// 返回 None = 池中无匹配连接（调用方应新建后端连接）。
    pub fn acquire(
        &self,
        key: &PoolKey,
        affinity: &SubjectIdentity,
        session_id: u64,
        now_secs: u64,
    ) -> Result<Option<BackendConn>, GatewayError> {
        let mut pools = self.pools.lock();
        let conns = match pools.get_mut(key) {
            Some(c) => c,
            None => return Ok(None),
        };

        // 主体亲和：只挑相同 SubjectIdentity 的 Idle 连接（docs/14 §2.1）
        let pos = conns.iter().position(|c| {
            c.state == ConnState::Idle && c.affinity == *affinity
        });

        match pos {
            Some(i) => {
                let mut conn = conns.remove(i);
                // Stale 连接不复用（归还时应已被淘汰；此处双保险）
                if conn.state == ConnState::Stale {
                    self.stale_evictions.lock().add_assign(1);
                    return Ok(None);
                }
                conn.state = ConnState::Active;
                conn.bound_session = Some(session_id);
                conn.session_state = SessionState::default();
                conn.borrowed_generation = *self.stale_generation.lock();
                let _ = now_secs;
                Ok(Some(conn))
            }
            None => Ok(None),
        }
    }

    /// 新建连接（Active；由调用方持有，归还时经 release 入池）。
    ///
    /// 限额按"该 key 的活跃连接总数"（池内 + 已借出）计算——用独立计数器，
    /// 因为借出的连接不在 pools 里。
    pub fn create(
        &self,
        key: &PoolKey,
        affinity: &SubjectIdentity,
        session_id: u64,
        now_secs: u64,
    ) -> Result<BackendConn, GatewayError> {
        {
            let mut live = self.live_counts.lock();
            let n = live.entry(key.clone()).or_insert(0);
            if *n >= self.config.max_conns {
                let mut waiting = self.waiting.lock();
                let w = waiting.entry(key.clone()).or_insert(0);
                if *w >= self.config.max_waiting {
                    return Err(GatewayError::QueueFull(self.config.max_waiting));
                }
                *w += 1;
                return Err(GatewayError::PoolExhausted(self.config.max_conns));
            }
            *n += 1;
        }
        let id = {
            let mut n = self.next_conn_id.lock();
            *n += 1;
            *n
        };
        Ok(BackendConn {
            conn_id: id,
            affinity: affinity.clone(),
            state: ConnState::Active,
            bound_session: Some(session_id),
            session_state: SessionState::default(),
            stale_reason: None,
            created_at: now_secs,
            borrowed_generation: *self.stale_generation.lock(),
        })
    }

    /// 归还连接（docs/14 §3 复位 → §3.1 pin 判定 → 入池或 pin）。
    ///
    /// 决策顺序：
    /// 1. Stale（策略撤销/epoch 轮换）→ 直接淘汰（不重置、不入池）；
    /// 2. 复位/pin 决策：pin 条件命中 → 连接保持绑定（不进池）；
    /// 3. 复位成功 → 入池（Idle）。
    pub fn release(&self, key: &PoolKey, mut conn: BackendConn) -> ResetOutcome {
        // 1. Stale 淘汰（代际对比：借出期间发生过失效传播，或已标记 stale）
        let current_gen = *self.stale_generation.lock();
        if conn.state == ConnState::Stale || conn.borrowed_generation != current_gen {
            self.stale_evictions.lock().add_assign(1);
            conn.state = ConnState::Stale;
            self.dec_live(key);
            return ResetOutcome::Pinned(vec![]); // 视为不复用（调用方应关闭连接）
        }

        // 2. 复位/pin 决策
        let outcome = conn.session_state.reset_or_pin(&self.config.reset);

        match &outcome {
            ResetOutcome::Pinned(reasons) => {
                // Pin：连接保持绑定，不进池（docs/14 §3.1 原则）
                conn.state = ConnState::Pinned;
                let mut counts = self.pinned_counts.lock();
                for r in reasons {
                    *counts.entry(r.as_str()).or_insert(0) += 1;
                }
            }
            ResetOutcome::Reset { .. } => {
                // 复位成功 → 入池
                self.resets.lock().add_assign(1);
                conn.state = ConnState::Idle;
                conn.bound_session = None;
                conn.session_state = SessionState::default();
                let mut pools = self.pools.lock();
                pools.entry(key.clone()).or_default().push(conn);
            }
        }
        outcome
    }

    /// 递减活跃连接计数（连接销毁时）。
    fn dec_live(&self, key: &PoolKey) {
        let mut live = self.live_counts.lock();
        if let Some(n) = live.get_mut(key) {
            *n = n.saturating_sub(1);
        }
    }

    /// 标记池中全部连接为 Stale（失效传播；docs/14 §4）。
    ///
    /// 触发：policy_version 撤销 / key_epoch 轮换。空闲连接立即淘汰；
    /// 活跃连接标记 stale（归还时强制重建）。
    pub fn invalidate_all(&self, reason: StaleReason) -> usize {
        // 递增代际：已借出的连接在归还时通过代际对比发现 stale
        *self.stale_generation.lock() += 1;
        *self.last_stale_reason.lock() = Some(reason);

        let mut pools = self.pools.lock();
        let mut evicted = 0;
        for conns in pools.values_mut() {
            conns.retain_mut(|c| {
                if c.state == ConnState::Idle {
                    evicted += 1;
                    false // 空闲连接立即淘汰
                } else {
                    c.state = ConnState::Stale;
                    c.stale_reason = Some(reason);
                    true // 池内活跃连接标记 stale，归还时处理
                }
            });
        }
        // 指标：空闲淘汰也计入 stale_evictions（与 release 路径统一口径）
        if evicted > 0 {
            self.stale_evictions.lock().add_assign(evicted as u64);
        }
        evicted
    }

    /// 池状态快照（指标；docs/14 §6）。
    pub fn stats(&self, key: &PoolKey) -> PoolStats {
        let pools = self.pools.lock();
        let conns = pools.get(key);
        let (idle, active, pinned, stale) = match conns {
            Some(c) => (
                c.iter().filter(|c| c.state == ConnState::Idle).count(),
                c.iter().filter(|c| c.state == ConnState::Active).count(),
                c.iter().filter(|c| c.state == ConnState::Pinned).count(),
                c.iter().filter(|c| c.state == ConnState::Stale).count(),
            ),
            None => (0, 0, 0, 0),
        };
        PoolStats {
            in_pool: idle,
            active,
            pinned,
            stale,
            waiting: self.waiting.lock().get(key).copied().unwrap_or(0),
            resets: *self.resets.lock(),
            stale_evictions: *self.stale_evictions.lock(),
            pinned_by_reason: self.pinned_counts.lock().clone(),
        }
    }
}

use std::ops::AddAssign;

/// 池指标快照。
#[derive(Debug, Clone, Serialize)]
pub struct PoolStats {
    pub in_pool: usize,
    pub active: usize,
    pub pinned: usize,
    pub stale: usize,
    pub waiting: usize,
    pub resets: u64,
    pub stale_evictions: u64,
    pub pinned_by_reason: HashMap<&'static str, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::PinReason;

    fn key(subject: &str) -> PoolKey {
        PoolKey {
            cluster: "c1".into(),
            database: "db1".into(),
            subject_id: subject.into(),
            source_ip: "10.0.0.1".into(),
        }
    }

    fn aff(subject: &str, level: i32) -> SubjectIdentity {
        SubjectIdentity::new(subject, level, 0)
    }

    #[test]
    fn affinity_prevents_cross_subject_reuse() {
        let pool = SessionPool::new(PoolConfig {
            transaction_mode: true,
            ..Default::default()
        });
        let k = key("alice");
        // alice 的连接归还池
        let conn = pool.create(&k, &aff("alice", 30), 1, 100).unwrap();
        pool.release(&k, conn);
        // bob 请求：主体亲和拒绝复用 alice 的连接
        let got = pool.acquire(&k, &aff("bob", 30), 2, 101).unwrap();
        assert!(got.is_none(), "跨主体复用必须被拒绝（docs/14 §2.1）");
        // alice 请求：可复用
        let got = pool.acquire(&k, &aff("alice", 30), 3, 101).unwrap();
        assert!(got.is_some(), "同主体可复用");
        assert_eq!(got.unwrap().affinity.subject_id, "alice");
    }

    #[test]
    fn affinity_includes_label_level() {
        let pool = SessionPool::new(PoolConfig {
            transaction_mode: true,
            ..Default::default()
        });
        let k = key("alice");
        let conn = pool.create(&k, &aff("alice", 30), 1, 100).unwrap();
        pool.release(&k, conn);
        // 同主体但标签档位不同 → 不复用（避免高密会话污染低密连接）
        let got = pool.acquire(&k, &aff("alice", 20), 2, 101).unwrap();
        assert!(got.is_none(), "标签档位不同不复用");
        let got = pool.acquire(&k, &aff("alice", 30), 3, 101).unwrap();
        assert!(got.is_some());
    }

    #[test]
    fn pin_on_advisory_lock() {
        let pool = SessionPool::new(PoolConfig::default());
        let k = key("alice");
        let mut conn = pool.create(&k, &aff("alice", 30), 1, 100).unwrap();
        conn.session_state.advisory_locks.push(42);
        let outcome = pool.release(&k, conn);
        assert!(matches!(outcome, ResetOutcome::Pinned(_)));
        let stats = pool.stats(&k);
        assert_eq!(stats.pinned, 0, "pin 的连接不进池（由调用方持有）");
        assert_eq!(
            stats.pinned_by_reason.get("session_advisory_lock"),
            Some(&1)
        );
    }

    #[test]
    fn reset_and_return_to_pool() {
        let pool = SessionPool::new(PoolConfig::default());
        let k = key("alice");
        let mut conn = pool.create(&k, &aff("alice", 30), 1, 100).unwrap();
        conn.session_state.prepared_statements.push("s1".into());
        let outcome = pool.release(&k, conn);
        assert!(matches!(outcome, ResetOutcome::Reset { .. }));
        let stats = pool.stats(&k);
        assert_eq!(stats.in_pool, 1, "复位成功后入池");
        assert_eq!(stats.resets, 1);
    }

    #[test]
    fn stale_eviction_on_policy_revoke() {
        let pool = SessionPool::new(PoolConfig::default());
        let k = key("alice");
        let conn = pool.create(&k, &aff("alice", 30), 1, 100).unwrap();
        pool.release(&k, conn); // 入池（Idle）
        assert_eq!(pool.stats(&k).in_pool, 1);
        // 策略撤销 → 空闲连接立即淘汰
        let evicted = pool.invalidate_all(StaleReason::PolicyRevoked);
        assert_eq!(evicted, 1);
        assert_eq!(pool.stats(&k).in_pool, 0, "stale 连接必须淘汰");
        assert_eq!(pool.stats(&k).stale_evictions, 1);
    }

    #[test]
    fn stale_active_conn_marked_for_rebuild() {
        let pool = SessionPool::new(PoolConfig::default());
        let k = key("alice");
        let conn = pool.create(&k, &aff("alice", 30), 1, 100).unwrap(); // Active（借出）
        // epoch 轮换 → 池内空闲连接淘汰（此例无）；借出连接靠代际对比检出
        let evicted = pool.invalidate_all(StaleReason::EpochRotated);
        assert_eq!(evicted, 0, "池内无空闲连接");
        // 归还时：stale 连接不复用
        let outcome = pool.release(&k, conn);
        assert!(matches!(outcome, ResetOutcome::Pinned(_)));
        assert_eq!(pool.stats(&k).stale_evictions, 1);
        assert_eq!(pool.stats(&k).in_pool, 0, "stale 连接不入池");
    }

    #[test]
    fn pool_capacity_enforced() {
        let pool = SessionPool::new(PoolConfig {
            max_conns: 2,
            max_waiting: 1,
            ..Default::default()
        });
        let k = key("alice");
        let c1 = pool.create(&k, &aff("alice", 30), 1, 100).unwrap();
        let c2 = pool.create(&k, &aff("alice", 30), 2, 100).unwrap();
        // 池满（c1/c2 仍 Active，未归还）
        let _ = c1;
        let _ = c2;
        // 第三次：排队
        assert!(matches!(
            pool.create(&k, &aff("alice", 30), 3, 100),
            Err(GatewayError::PoolExhausted(2))
        ));
        // 第四次：队列满
        assert!(matches!(
            pool.create(&k, &aff("alice", 30), 4, 100),
            Err(GatewayError::QueueFull(1))
        ));
    }

    #[test]
    fn session_mode_no_cross_leak_by_default() {
        // 默认会话级模式：连接不归还池（直到会话断开），无复用泄漏面
        let pool = SessionPool::new(PoolConfig::default());
        assert!(!pool.config().transaction_mode);
        let k = key("alice");
        let conn = pool.create(&k, &aff("alice", 30), 1, 100).unwrap();
        // 会话级：连接由会话独占（此处不 release，模拟会话进行中）
        assert_eq!(conn.state, ConnState::Active);
        assert_eq!(pool.stats(&k).in_pool, 0);
    }

    #[test]
    fn pin_reason_metrics_bucketed() {
        let pool = SessionPool::new(PoolConfig::default());
        let k = key("alice");
        for _ in 0..3 {
            let mut conn = pool.create(&k, &aff("alice", 30), 1, 100).unwrap();
            conn.session_state.listen_channels.push("c".into());
            pool.release(&k, conn);
        }
        let stats = pool.stats(&k);
        assert_eq!(stats.pinned_by_reason.get("listening"), Some(&3));
        assert_eq!(PinReason::Listening.as_str(), "listening");
    }
}
