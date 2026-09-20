//! 审计事件格式定义（docs/02 §7.2）。

use serde::{Deserialize, Serialize};

/// 审计事件等级（docs/02 §7.2 表格）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuditLevel {
    /// E0 可丢弃：性能指标、页面级统计。
    Discardable = 0,
    /// E1 常规：普通 SQL 摘要、连接治理事件。
    Normal = 1,
    /// E2 高价值：登录/登出、授权变更、MAC 拒绝、DDL、GRANT/REVOKE。
    HighValue = 2,
    /// E3 关键：安全配置变更、标签变更、三权角色操作、密钥操作。
    Critical = 3,
}

impl AuditLevel {
    /// 中断/journal 满时的处置（docs/02 §7.2 语义）。
    pub fn on_journal_full(&self) -> JournalFullPolicy {
        match self {
            AuditLevel::Critical | AuditLevel::HighValue => JournalFullPolicy::BlockOperation,
            AuditLevel::Normal => JournalFullPolicy::ThrottleNewSessions,
            AuditLevel::Discardable => JournalFullPolicy::Discard,
        }
    }

    /// 审计平面中断时的处置。
    pub fn on_audit_unavailable(&self) -> AuditUnavailablePolicy {
        match self {
            AuditLevel::Critical | AuditLevel::HighValue => AuditUnavailablePolicy::Block,
            AuditLevel::Normal => AuditUnavailablePolicy::Queue,
            AuditLevel::Discardable => AuditUnavailablePolicy::Discard,
        }
    }

    /// 是否需要 delivery ack 才能淘汰。
    pub fn requires_delivery_ack(&self) -> bool {
        matches!(self, AuditLevel::Critical | AuditLevel::HighValue)
    }

    /// E3 是否使用 write-ahead 模式（审计 fsync 完成后才允许操作继续）。
    pub fn is_write_ahead(&self) -> bool {
        matches!(self, AuditLevel::Critical)
    }
}

/// journal 满时的处置策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalFullPolicy {
    /// 阻断操作（fail-closed，E3/E2）。
    BlockOperation,
    /// 限流新会话（E1）。
    ThrottleNewSessions,
    /// 直接丢弃（E0）。
    Discard,
}

/// 审计平面中断时的处置策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditUnavailablePolicy {
    /// 阻断操作（E3/E2）。
    Block,
    /// 本地排队（E1）。
    Queue,
    /// 直接丢弃（E0）。
    Discard,
}

/// 审计动作分类（标准动作码，docs/02 §7.2 + docs/05 E3 清单）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditAction {
    // E3 关键
    /// 安全配置变更（MAC 开关、围栏开关）。
    SecurityConfigChange,
    /// 标签变更（SET SESSION LABEL / SET LABEL / relabel）。
    LabelChange,
    /// 三权角色操作（SET ROLE 切换到 secadmin/sysadmin/auditor）。
    RoleChange,
    /// 密钥操作确认（KMS 租约授予、DEK 分发、epoch 轮换确认）。
    KeyOperation,
    /// KMS 租约授予。
    KmsLeaseGrant,

    // E2 高价值
    /// 登录 / 登出。
    SessionStart,
    SessionEnd,
    /// 授权变更（GRANT / REVOKE）。
    PrivilegeChange,
    /// MAC 拒绝（BLP 不下读/不上写检查失败）。
    MacDenied,
    /// DDL 操作。
    Ddl,
    /// 扩展加载。
    ExtensionLoad,

    // E1 常规
    /// 普通 SQL 摘要。
    SqlSummary,
    /// 连接治理事件（连接池分配/回收）。
    ConnectionGovernance,

    // 组件事件
    /// KMS 操作（非关键路径）。
    KmsOperation,
    /// 轮换状态变更。
    RotationChange,
    /// 审计自身操作。
    AuditOperation,
}

impl AuditAction {
    /// 动作对应的默认审计等级。
    pub fn default_level(&self) -> AuditLevel {
        use AuditAction::*;
        match self {
            SecurityConfigChange | LabelChange | RoleChange | KeyOperation | KmsLeaseGrant => {
                AuditLevel::Critical
            }
            SessionStart | SessionEnd | PrivilegeChange | MacDenied | Ddl | ExtensionLoad => {
                AuditLevel::HighValue
            }
            SqlSummary | ConnectionGovernance => AuditLevel::Normal,
            KmsOperation | RotationChange | AuditOperation => AuditLevel::Normal,
        }
    }

    pub fn as_str(&self) -> &'static str {
        use AuditAction::*;
        match self {
            SecurityConfigChange => "security_config_change",
            LabelChange => "label_change",
            RoleChange => "role_change",
            KeyOperation => "key_operation",
            KmsLeaseGrant => "kms_lease_grant",
            SessionStart => "session_start",
            SessionEnd => "session_end",
            PrivilegeChange => "privilege_change",
            MacDenied => "mac_denied",
            Ddl => "ddl",
            ExtensionLoad => "extension_load",
            SqlSummary => "sql_summary",
            ConnectionGovernance => "connection_governance",
            KmsOperation => "kms_operation",
            RotationChange => "rotation_change",
            AuditOperation => "audit_operation",
        }
    }
}

/// 审计结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    /// 操作成功。
    Ok,
    /// 操作被拒绝（权限/MAC）。
    Denied,
    /// 操作失败。
    Error,
    /// 操作回滚（E3 事务绑定语义）。
    Aborted,
}

/// 审计事件（协议格式）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// 全局单调序号（组件内唯一；从 1 起）。
    pub seq: u64,
    /// Unix 时间戳（毫秒精度）。
    pub ts_ms: u64,
    /// 审计等级。
    pub level: AuditLevel,
    /// 动作分类。
    pub action: AuditAction,
    /// 操作主体（node_id / user / role）。
    pub actor: String,
    /// 操作对象（timeline/epoch/table/relation）。
    pub object: String,
    /// 结果。
    pub outcome: AuditOutcome,
    /// 摘要（非敏感参数；不含业务明文，docs/02 §7.2）。
    pub summary: String,
    /// 哈希链：前一条的 hash。
    pub prev_hash: String,
    /// 本条 hash = SM3(canonical_json(self minus hash))。
    pub hash: String,
    /// E3 回滚标记（journal 先写后操作回滚时标记）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aborted: Option<bool>,
    /// 组件来源标识。
    pub source: String,
}
