//! 组件注册表、generation 与配置租约（docs/02 §6.1、docs/13 §4）。

use crate::fence::{FenceError, FenceRecord, FenceScope, GenerationJournal, JournalState};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// 组件类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComponentKind {
    Pageserver,
    Safekeeper,
    Compute,
    Gateway,
    Kms,
    Pdp,
    Attest,
    AuditIngest,
    AuditStore,
    Tsa,
}

impl ComponentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ComponentKind::Pageserver => "pageserver",
            ComponentKind::Safekeeper => "safekeeper",
            ComponentKind::Compute => "compute",
            ComponentKind::Gateway => "gateway",
            ComponentKind::Kms => "kms",
            ComponentKind::Pdp => "pdp",
            ComponentKind::Attest => "attest",
            ComponentKind::AuditIngest => "audit-ingest",
            ComponentKind::AuditStore => "audit-store",
            ComponentKind::Tsa => "tsa",
        }
    }
}

/// 节点标识。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeId(pub u64);

/// generation（单调递增；变化 = 前一代失权，防脑裂）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Generation(pub u64);

impl Generation {
    pub fn next(self) -> Generation {
        Generation(self.0 + 1)
    }
}

/// 组件状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentState {
    /// 已注册，心跳正常。
    Active,
    /// 心跳超时（可能故障；等待恢复或换代）。
    Suspect,
    /// 已下线（显式停止或换代）。
    Offline,
}

/// 组件记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentRecord {
    pub node_id: NodeId,
    pub kind: ComponentKind,
    /// 当前 generation（注册/换代时更新）。
    pub generation: Generation,
    pub state: ComponentState,
    /// 监听地址（内部通信）。
    pub address: String,
    /// 最近心跳时刻（Unix 秒）。
    pub last_heartbeat: u64,
    /// 注册时刻。
    pub registered_at: u64,
    /// 安全上下文材料摘要（attestation 结论摘要；docs/13 §4 绑定）。
    pub attestation_digest: Option<String>,
}

/// 配置租约（组件持有的配置快照 + TTL）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigLease {
    pub node_id: NodeId,
    pub generation: Generation,
    /// 配置版本（单调）。
    pub config_version: u64,
    /// 配置内容（键值；不含明文密钥——docs/02 §6.1）。
    pub config: HashMap<String, String>,
    pub issued_at: u64,
    pub ttl_secs: u64,
}

impl ConfigLease {
    /// 租约是否有效。
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.ttl_secs == 0 || now <= self.issued_at + self.ttl_secs
    }
}

/// 配置键名是否属于密钥材料（docs/02 §6.1：Controller 不持有明文数据密钥）。
///
/// 按 `_` 分段做词边界匹配，任一段命中材料词即拒绝。刻意 fail-closed：
/// 连 `key_epoch_id` 这类**引用**也拒绝——密钥引用必须走 jt-kms API，
/// 不得经控制平面配置通道传递，否则引用通道会变成事实上的材料通道。
fn is_key_material_key(key: &str) -> bool {
    const MATERIAL_SEGMENTS: [&str; 12] = [
        "key", "keys", "secret", "secrets", "password", "passwd", "dek", "kek", "seed",
        "private", "token", "credential",
    ];
    key.to_lowercase()
        .split('_')
        .any(|seg| MATERIAL_SEGMENTS.contains(&seg))
}

/// Timeline 记录（Timeline/Branch 管理）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineRecord {
    pub timeline_id: [u8; 16],
    pub tenant_id: String,
    /// 父 timeline（分支；None = 根）。
    pub parent: Option<[u8; 16]>,
    /// 分支点 LSN（分支时）。
    pub branch_lsn: Option<u64>,
    /// 服务的 pageserver generation（防脑裂）。
    pub serving_generation: Generation,
}

/// 控制平面错误。
#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("node not found: {0:?}")]
    NotFound(NodeId),
    #[error("stale generation: node has {has:?}, request carries {carried:?}")]
    StaleGeneration {
        has: Generation,
        carried: Generation,
    },
    #[error("timeline already exists")]
    TimelineExists,
    #[error("parent timeline not found")]
    ParentNotFound,
    #[error("timeline not found")]
    TimelineNotFound,
    #[error("config key carries key material, which the controller must not hold: {0}")]
    KeyMaterialNotAllowed(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("node is offline; re-register to obtain a new generation: {0:?}")]
    NodeOffline(NodeId),
    #[error("fence journal: {0}")]
    Fence(#[from] FenceError),
}

/// 控制平面（jt-controller 核心逻辑）。
///
/// 安全不变量（docs/02 §6.1、docs/13 §4）：
/// 1. **generation 单调**——包含跨 controller 重启。围栏令牌先落盘、后授权，
///    否则重启后旧代组件会被重新视为权威（脑裂）。
/// 2. **下线即吊销**——Offline 节点不能靠心跳自行复活，必须重新注册换取新代。
/// 3. **不持有明文密钥**——配置租约拒绝密钥类键。
pub struct Controller {
    /// 组件注册表（node_id → record）。
    components: Mutex<HashMap<NodeId, ComponentRecord>>,
    /// 配置租约（node_id → lease）。
    leases: Mutex<HashMap<NodeId, ConfigLease>>,
    /// Timeline 表。
    timelines: Mutex<HashMap<[u8; 16], TimelineRecord>>,
    /// 心跳超时（秒；超过则 Suspect）。
    heartbeat_timeout_secs: u64,
    /// 配置版本计数器（全局单调）。
    config_version: Mutex<u64>,
    /// generation 围栏日志（None = 纯内存，仅测试/单次运行）。
    journal: Option<GenerationJournal>,
    /// 已落盘的 generation 高水位（与 journal 同步维护）。
    fence: Mutex<JournalState>,
}

impl Controller {
    /// 纯内存控制平面（无持久化；重启即遗忘 generation）。
    ///
    /// **不得用于生产**：见 [`Controller::open`]。
    pub fn new(heartbeat_timeout_secs: u64) -> Self {
        Self {
            components: Mutex::new(HashMap::new()),
            leases: Mutex::new(HashMap::new()),
            timelines: Mutex::new(HashMap::new()),
            heartbeat_timeout_secs,
            config_version: Mutex::new(0),
            journal: None,
            fence: Mutex::new(JournalState::default()),
        }
    }

    /// 打开带围栏日志的控制平面（生产路径）。
    ///
    /// 启动即重放日志：即使 components 表为空，各节点/timeline 的 generation
    /// 高水位也已被恢复，新注册只会继续递增。
    pub fn open(
        heartbeat_timeout_secs: u64,
        journal_path: impl Into<PathBuf>,
    ) -> Result<Self, ControllerError> {
        let journal = GenerationJournal::open(journal_path)?;
        let fence = journal.load()?;
        Ok(Self {
            components: Mutex::new(HashMap::new()),
            leases: Mutex::new(HashMap::new()),
            timelines: Mutex::new(HashMap::new()),
            heartbeat_timeout_secs,
            config_version: Mutex::new(0),
            journal: Some(journal),
            fence: Mutex::new(fence),
        })
    }

    /// 落盘一条围栏记录并更新内存高水位。
    ///
    /// 必须在对外授权之前调用（write-ahead）：崩在授权之后、落盘之前，
    /// 会让已发出的 generation 在重启后消失。
    fn fence_append(
        &self,
        scope: FenceScope,
        id: String,
        generation: u64,
        reason: &str,
        now: u64,
    ) -> Result<(), ControllerError> {
        if let Some(j) = &self.journal {
            j.append(&FenceRecord {
                scope,
                id: id.clone(),
                generation,
                at: now,
                reason: reason.to_string(),
            })?;
        }
        let mut fence = self.fence.lock();
        match scope {
            FenceScope::Node => {
                let key: u64 = id.parse().unwrap_or(0);
                let slot = fence.nodes.entry(key).or_insert(0);
                *slot = (*slot).max(generation);
            }
            FenceScope::Timeline => {
                if let Ok(bytes) = hex::decode(&id) {
                    if let Ok(arr) = <[u8; 16]>::try_from(bytes.as_slice()) {
                        let slot = fence.timelines.entry(arr).or_insert(0);
                        *slot = (*slot).max(generation);
                    }
                }
            }
        }
        Ok(())
    }

    /// 组件注册（docs/02 §2.3 "register"）。
    ///
    /// 首次注册获得 generation = 1；重复注册（同 node_id）→ 换代
    /// （generation +1，前一代失权）。换代取内存与围栏日志的**高水位**，
    /// 因此 controller 重启不会让代次回退。
    pub fn register(
        &self,
        node_id: NodeId,
        kind: ComponentKind,
        address: &str,
        attestation_digest: Option<String>,
        now: u64,
    ) -> Result<ComponentRecord, ControllerError> {
        let mut comps = self.components.lock();
        let in_mem = comps.get(&node_id).map(|r| r.generation.0).unwrap_or(0);
        let journaled = self
            .fence
            .lock()
            .node_generation(node_id.0)
            .unwrap_or(0);
        let generation = Generation(in_mem.max(journaled) + 1);

        // write-ahead：先落盘围栏，再让它生效
        self.fence_append(
            FenceScope::Node,
            node_id.0.to_string(),
            generation.0,
            "register",
            now,
        )?;

        let record = ComponentRecord {
            node_id: node_id.clone(),
            kind,
            generation,
            state: ComponentState::Active,
            address: address.to_string(),
            last_heartbeat: now,
            registered_at: now,
            attestation_digest,
        };
        comps.insert(node_id.clone(), record.clone());
        // 换代时旧租约失效
        self.leases.lock().remove(&node_id);
        Ok(record)
    }

    /// 心跳（docs/02 §2.3 "health"）。携带 generation 以拒绝旧代组件。
    ///
    /// 已下线（Offline）的节点**不接受心跳**：下线是权威判定，组件不得
    /// 靠周期性心跳把自己从下线状态里捞回来。
    pub fn heartbeat(
        &self,
        node_id: &NodeId,
        carried_generation: Generation,
        now: u64,
    ) -> Result<ComponentState, ControllerError> {
        let mut comps = self.components.lock();
        let rec = comps.get_mut(node_id).ok_or(ControllerError::NotFound(node_id.clone()))?;
        if rec.state == ComponentState::Offline {
            return Err(ControllerError::NodeOffline(node_id.clone()));
        }
        if rec.generation != carried_generation {
            // 旧 generation 的心跳：拒绝（防脑裂）
            return Err(ControllerError::StaleGeneration {
                has: rec.generation,
                carried: carried_generation,
            });
        }
        rec.last_heartbeat = now;
        rec.state = ComponentState::Active;
        Ok(rec.state)
    }

    /// 扫描心跳超时（后台任务调用；返回转为 Suspect 的节点）。
    pub fn sweep_heartbeats(&self, now: u64) -> Vec<NodeId> {
        let mut comps = self.components.lock();
        let mut suspects = Vec::new();
        for rec in comps.values_mut() {
            if rec.state == ComponentState::Active
                && now > rec.last_heartbeat + self.heartbeat_timeout_secs
            {
                rec.state = ComponentState::Suspect;
                suspects.push(rec.node_id.clone());
            }
        }
        suspects
    }

    /// 签发配置租约（docs/02 §2.3 "config lease"）。
    ///
    /// **不持有明文数据密钥**（docs/02 §6.1）——配置项中若出现密钥类字段
    /// 直接拒绝。
    pub fn issue_config_lease(
        &self,
        node_id: &NodeId,
        generation: Generation,
        config: HashMap<String, String>,
        ttl_secs: u64,
        now: u64,
    ) -> Result<ConfigLease, ControllerError> {
        // 组件必须存在且 generation 匹配
        {
            let comps = self.components.lock();
            let rec = comps.get(node_id).ok_or(ControllerError::NotFound(node_id.clone()))?;
            if rec.generation != generation {
                return Err(ControllerError::StaleGeneration {
                    has: rec.generation,
                    carried: generation,
                });
            }
        }
        // 拒绝密钥类配置项（docs/02 §6.1：不直接持有明文数据密钥）
        for key in config.keys() {
            if is_key_material_key(key) {
                return Err(ControllerError::KeyMaterialNotAllowed(key.clone()));
            }
        }
        let version = {
            let mut v = self.config_version.lock();
            *v += 1;
            *v
        };
        let lease = ConfigLease {
            node_id: node_id.clone(),
            generation,
            config_version: version,
            config,
            issued_at: now,
            ttl_secs,
        };
        self.leases.lock().insert(node_id.clone(), lease.clone());
        Ok(lease)
    }

    /// 续租（返回是否成功；失败 = 调用方应降级）。
    pub fn renew_config_lease(
        &self,
        node_id: &NodeId,
        generation: Generation,
        now: u64,
        ttl_secs: u64,
    ) -> Result<ConfigLease, ControllerError> {
        let mut leases = self.leases.lock();
        let lease = leases.get_mut(node_id).ok_or(ControllerError::NotFound(node_id.clone()))?;
        if lease.generation != generation {
            return Err(ControllerError::StaleGeneration {
                has: lease.generation,
                carried: generation,
            });
        }
        lease.issued_at = now;
        lease.ttl_secs = ttl_secs;
        Ok(lease.clone())
    }

    /// 查询租约（组件侧校验）。
    pub fn get_config_lease(&self, node_id: &NodeId) -> Option<ConfigLease> {
        self.leases.lock().get(node_id).cloned()
    }

    /// 组件下线（显式停止或换代清理）。
    ///
    /// 下线时撤销租约，并落盘围栏——使重启后的 controller 也记得该节点已
    /// 被下线，其 generation 高水位保持，重新注册必然换取新代。
    pub fn deregister(&self, node_id: &NodeId, now: u64) -> Result<(), ControllerError> {
        let mut comps = self.components.lock();
        let rec = comps.get_mut(node_id).ok_or(ControllerError::NotFound(node_id.clone()))?;
        let generation = rec.generation.0;
        self.fence_append(
            FenceScope::Node,
            node_id.0.to_string(),
            generation,
            "deregister",
            now,
        )?;
        rec.state = ComponentState::Offline;
        // 下线时撤销租约
        self.leases.lock().remove(node_id);
        Ok(())
    }

    /// 列出组件（可按类型过滤）。
    pub fn list_components(&self, kind: Option<ComponentKind>) -> Vec<ComponentRecord> {
        let comps = self.components.lock();
        let mut out: Vec<_> = comps
            .values()
            .filter(|r| kind.map(|k| r.kind == k).unwrap_or(true))
            .cloned()
            .collect();
        out.sort_by_key(|r| r.node_id.clone());
        out
    }

    // ---- Timeline / Branch ----

    /// 创建 timeline（或分支）。
    ///
    /// `serving_generation` 同样落盘围栏：即便 timeline 记录本身尚未持久化，
    /// 重启后重新创建同一 timeline 也不会退回到更低的代次。
    pub fn create_timeline(
        &self,
        timeline_id: [u8; 16],
        tenant_id: &str,
        parent: Option<[u8; 16]>,
        branch_lsn: Option<u64>,
        serving_generation: Generation,
        now: u64,
    ) -> Result<TimelineRecord, ControllerError> {
        let mut tls = self.timelines.lock();
        if tls.contains_key(&timeline_id) {
            return Err(ControllerError::TimelineExists);
        }
        if let Some(p) = parent {
            if !tls.contains_key(&p) {
                return Err(ControllerError::ParentNotFound);
            }
        }
        let journaled = self
            .fence
            .lock()
            .timeline_generation(&timeline_id)
            .unwrap_or(0);
        let generation = Generation(serving_generation.0.max(journaled));
        self.fence_append(
            FenceScope::Timeline,
            hex::encode(timeline_id),
            generation.0,
            "create",
            now,
        )?;
        let rec = TimelineRecord {
            timeline_id,
            tenant_id: tenant_id.to_string(),
            parent,
            branch_lsn,
            serving_generation: generation,
        };
        tls.insert(timeline_id, rec.clone());
        Ok(rec)
    }

    /// 换代 timeline 的服务 generation（防脑裂：旧 generation 失权）。
    ///
    /// 与组件注册同样 write-ahead：围栏先落盘，再让新代生效。
    pub fn bump_timeline_generation(
        &self,
        timeline_id: &[u8; 16],
        now: u64,
    ) -> Result<Generation, ControllerError> {
        let mut tls = self.timelines.lock();
        let rec = tls
            .get_mut(timeline_id)
            .ok_or(ControllerError::TimelineNotFound)?;
        let journaled = self
            .fence
            .lock()
            .timeline_generation(timeline_id)
            .unwrap_or(0);
        // 内存值与围栏高水位取大，保证重启后代次不回退
        let base = rec.serving_generation.0.max(journaled);
        let next = Generation(base + 1);
        self.fence_append(
            FenceScope::Timeline,
            hex::encode(timeline_id),
            next.0,
            "bump",
            now,
        )?;
        rec.serving_generation = next;
        Ok(next)
    }

    pub fn get_timeline(&self, timeline_id: &[u8; 16]) -> Option<TimelineRecord> {
        self.timelines.lock().get(timeline_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("max_connections".to_string(), "100".to_string());
        m
    }

    #[test]
    fn register_assigns_generation_one() {
        let c = Controller::new(30);
        let rec = c
            .register(NodeId(1), ComponentKind::Pageserver, "127.0.0.1:64000", None, 100)
            .unwrap();
        assert_eq!(rec.generation, Generation(1));
        assert_eq!(rec.state, ComponentState::Active);
    }

    #[test]
    fn reregister_bumps_generation_and_invalidates_lease() {
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 100).unwrap();
        c.issue_config_lease(&NodeId(1), Generation(1), cfg(), 300, 100).unwrap();
        assert!(c.get_config_lease(&NodeId(1)).is_some());
        // 重新注册（换代）
        let rec = c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 200).unwrap();
        assert_eq!(rec.generation, Generation(2), "换代 +1");
        assert!(c.get_config_lease(&NodeId(1)).is_none(), "换代时旧租约失效");
    }

    #[test]
    fn stale_generation_heartbeat_rejected() {
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Safekeeper, "a", None, 100).unwrap();
        c.register(NodeId(1), ComponentKind::Safekeeper, "a", None, 110).unwrap(); // gen=2
        // 旧代（gen=1）心跳 → 拒绝（防脑裂）
        assert!(matches!(
            c.heartbeat(&NodeId(1), Generation(1), 120),
            Err(ControllerError::StaleGeneration { .. })
        ));
        // 当前代（gen=2）心跳 → 通过
        assert!(c.heartbeat(&NodeId(1), Generation(2), 120).is_ok());
    }

    #[test]
    fn heartbeat_timeout_marks_suspect() {
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Compute, "a", None, 100).unwrap();
        // 未超时
        assert!(c.sweep_heartbeats(120).is_empty());
        // 超时（100 + 30 = 130 < 131）
        let suspects = c.sweep_heartbeats(131);
        assert_eq!(suspects, vec![NodeId(1)]);
        assert_eq!(
            c.list_components(None)[0].state,
            ComponentState::Suspect
        );
        // 恢复心跳 → Active
        c.heartbeat(&NodeId(1), Generation(1), 140).unwrap();
        assert_eq!(c.list_components(None)[0].state, ComponentState::Active);
    }

    #[test]
    fn config_lease_ttl() {
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 100).unwrap();
        let lease = c
            .issue_config_lease(&NodeId(1), Generation(1), cfg(), 300, 100)
            .unwrap();
        assert!(lease.is_valid_at(300));
        assert!(!lease.is_valid_at(500), "超过 TTL 失效");
        // 续租
        let renewed = c.renew_config_lease(&NodeId(1), Generation(1), 400, 300).unwrap();
        assert!(renewed.is_valid_at(600));
    }

    #[test]
    fn config_lease_rejects_key_material() {
        // docs/02 §6.1：Controller 不直接持有明文数据密钥
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 100).unwrap();
        for bad_key in [
            "dek_hex",
            "master_secret",
            "kek_id",
            "sm4_key",
            "tenant_password",
            "signing_private",
            "api_token",
            "recovery_seed",
        ] {
            let mut bad = HashMap::new();
            bad.insert(bad_key.to_string(), "deadbeef".to_string());
            assert!(
                matches!(
                    c.issue_config_lease(&NodeId(1), Generation(1), bad, 300, 100),
                    Err(ControllerError::KeyMaterialNotAllowed(_))
                ),
                "配置键 {bad_key} 必须被拒绝"
            );
        }
        // 拒绝后不得留下租约
        assert!(c.get_config_lease(&NodeId(1)).is_none());
    }

    #[test]
    fn config_lease_allows_ordinary_tuning_keys() {
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 100).unwrap();
        let mut good = HashMap::new();
        good.insert("max_connections".to_string(), "100".to_string());
        good.insert("checkpoint_timeout".to_string(), "300".to_string());
        good.insert("kms_endpoint".to_string(), "https://127.0.0.1:7443".to_string());
        good.insert("keyring_size".to_string(), "4096".to_string());
        assert!(
            c.issue_config_lease(&NodeId(1), Generation(1), good, 300, 100)
                .is_ok(),
            "普通调优项与非密钥引用不得被误拒"
        );
    }

    #[test]
    fn lease_requires_matching_generation() {
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 100).unwrap();
        c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 110).unwrap(); // gen=2
        // 用旧 generation 申请租约 → 拒绝
        assert!(matches!(
            c.issue_config_lease(&NodeId(1), Generation(1), cfg(), 300, 120),
            Err(ControllerError::StaleGeneration { .. })
        ));
        assert!(c
            .issue_config_lease(&NodeId(1), Generation(2), cfg(), 300, 120)
            .is_ok());
    }

    #[test]
    fn deregister_revokes_lease() {
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Compute, "a", None, 100).unwrap();
        c.issue_config_lease(&NodeId(1), Generation(1), cfg(), 300, 100).unwrap();
        c.deregister(&NodeId(1), 200).unwrap();
        assert!(c.get_config_lease(&NodeId(1)).is_none());
        assert_eq!(c.list_components(None)[0].state, ComponentState::Offline);
    }

    #[test]
    fn timeline_and_branch() {
        let c = Controller::new(30);
        let root = [1u8; 16];
        let branch = [2u8; 16];
        c.create_timeline(root, "tenant-1", None, None, Generation(1), 100).unwrap();
        // 分支
        let b = c
            .create_timeline(branch, "tenant-1", Some(root), Some(0x1000), Generation(1), 100)
            .unwrap();
        assert_eq!(b.parent, Some(root));
        assert_eq!(b.branch_lsn, Some(0x1000));
        // 重复创建
        assert!(matches!(
            c.create_timeline(root, "tenant-1", None, None, Generation(1), 100),
            Err(ControllerError::TimelineExists)
        ));
        // 父不存在
        assert!(matches!(
            c.create_timeline([3u8; 16], "t", Some([9u8; 16]), None, Generation(1), 100),
            Err(ControllerError::ParentNotFound)
        ));
    }

    #[test]
    fn timeline_generation_bump_fences_old_serving() {
        let c = Controller::new(30);
        let tl = [1u8; 16];
        c.create_timeline(tl, "t1", None, None, Generation(1), 100).unwrap();
        let g = c.bump_timeline_generation(&tl, 110).unwrap();
        assert_eq!(g, Generation(2), "换代后旧 generation 失权（防脑裂）");
        assert_eq!(c.get_timeline(&tl).unwrap().serving_generation, Generation(2));
    }

    #[test]
    fn bump_unknown_timeline_is_not_found() {
        let c = Controller::new(30);
        assert!(matches!(
            c.bump_timeline_generation(&[7u8; 16], 110),
            Err(ControllerError::TimelineNotFound)
        ));
    }

    // ---- 围栏持久化（防脑裂的安全不变量）----

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "jtctrl-{}-{}-{}",
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
    fn generation_survives_controller_restart() {
        // 防脑裂的核心：controller 重启后旧代组件不得被重新准入。
        let dir = tmpdir("restart");
        let log = dir.join("generation.log");

        {
            let c = Controller::open(30, &log).unwrap();
            let r1 = c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 100).unwrap();
            assert_eq!(r1.generation, Generation(1));
            let r2 = c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 110).unwrap();
            assert_eq!(r2.generation, Generation(2));
        } // controller 进程结束（components 表随之丢失）

        let c2 = Controller::open(30, &log).unwrap();
        assert!(c2.list_components(None).is_empty(), "组件表本身不重建");
        let r3 = c2.register(NodeId(1), ComponentKind::Pageserver, "a", None, 200).unwrap();
        assert_eq!(
            r3.generation,
            Generation(3),
            "重启后代次必须继续递增，否则旧代组件会被重新视为权威"
        );
        // 重启前发出的第 2 代心跳必须被拒绝
        assert!(matches!(
            c2.heartbeat(&NodeId(1), Generation(2), 210),
            Err(ControllerError::StaleGeneration { .. })
        ));
    }

    #[test]
    fn timeline_generation_survives_restart() {
        let dir = tmpdir("tlrestart");
        let log = dir.join("generation.log");
        let tl = [4u8; 16];

        {
            let c = Controller::open(30, &log).unwrap();
            c.create_timeline(tl, "t1", None, None, Generation(1), 100).unwrap();
            c.bump_timeline_generation(&tl, 110).unwrap();
            assert_eq!(c.get_timeline(&tl).unwrap().serving_generation, Generation(2));
        }

        let c2 = Controller::open(30, &log).unwrap();
        // 重建同一 timeline，代次不得回退到 1
        let rec = c2.create_timeline(tl, "t1", None, None, Generation(1), 200).unwrap();
        assert_eq!(rec.serving_generation, Generation(2), "围栏高水位跨重启保留");
        let g = c2.bump_timeline_generation(&tl, 210).unwrap();
        assert_eq!(g, Generation(3));
    }

    #[test]
    fn offline_node_cannot_revive_via_heartbeat() {
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Compute, "a", None, 100).unwrap();
        c.deregister(&NodeId(1), 150).unwrap();
        assert!(matches!(
            c.heartbeat(&NodeId(1), Generation(1), 160),
            Err(ControllerError::NodeOffline(_))
        ));
        // 必须重新注册才能回到 Active，且换取新代
        let rec = c.register(NodeId(1), ComponentKind::Compute, "a", None, 170).unwrap();
        assert_eq!(rec.generation, Generation(2));
        assert_eq!(rec.state, ComponentState::Active);
        assert!(c.heartbeat(&NodeId(1), Generation(2), 180).is_ok());
    }

    #[test]
    fn fence_write_failure_blocks_registration() {
        // fail-closed：围栏落盘失败时不得授权新代
        let dir = tmpdir("failclosed");
        let log = dir.join("generation.log");
        let c = Controller::open(30, &log).unwrap();
        c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 100).unwrap();
        // 把日志路径变成目录，使后续 append 必然失败
        std::fs::remove_file(&log).unwrap();
        std::fs::create_dir(&log).unwrap();
        assert!(
            matches!(
                c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 200),
                Err(ControllerError::Fence(_))
            ),
            "围栏不可写时必须拒绝授权"
        );
    }

    #[test]
    fn list_components_filtered_by_kind() {
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 100).unwrap();
        c.register(NodeId(2), ComponentKind::Safekeeper, "b", None, 100).unwrap();
        c.register(NodeId(3), ComponentKind::Pageserver, "c", None, 100).unwrap();
        assert_eq!(c.list_components(Some(ComponentKind::Pageserver)).len(), 2);
        assert_eq!(c.list_components(Some(ComponentKind::Safekeeper)).len(), 1);
        assert_eq!(c.list_components(None).len(), 3);
    }

    #[test]
    fn config_version_monotonic() {
        let c = Controller::new(30);
        c.register(NodeId(1), ComponentKind::Pageserver, "a", None, 100).unwrap();
        let l1 = c.issue_config_lease(&NodeId(1), Generation(1), cfg(), 300, 100).unwrap();
        let l2 = c.issue_config_lease(&NodeId(1), Generation(1), cfg(), 300, 101).unwrap();
        assert!(l2.config_version > l1.config_version);
    }
}
