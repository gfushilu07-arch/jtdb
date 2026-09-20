//! 策略模型与决策（Cedar 风格 + JTDB MLS）。

use serde::{Deserialize, Serialize};

/// MLS 标签（与 jtsec 的 JtLabel 语义一致：Level + Categories 位图）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JtLabel {
    pub level: i32,
    pub categories: u32,
}

impl JtLabel {
    pub fn new(level: i32, categories: u32) -> Self {
        Self { level, categories }
    }

    /// dominate(a, b) = a.Level >= b.Level AND a.Categories ⊇ b.Categories
    pub fn dominate(&self, other: &JtLabel) -> bool {
        self.level >= other.level && (self.categories & other.categories) == other.categories
    }

    /// 标签传播：写入时新对象标签 = 主体标签 ∪ 对象原标签（取上界）。
    pub fn join(&self, other: &JtLabel) -> JtLabel {
        JtLabel {
            level: self.level.max(other.level),
            categories: self.categories | other.categories,
        }
    }
}

/// 策略效果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Permit,
    Forbid,
}

/// 决策结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// 允许。
    Allow,
    /// 拒绝（含理由）。
    Deny(String),
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// 策略请求（Cedar 四元组 + MLS 上下文）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    /// 主体（principal）：用户/角色标识。
    pub principal: String,
    /// 主体角色（三权分立：secadmin/sysadmin/auditor/trusted）。
    pub principal_roles: Vec<String>,
    /// 动作（action）：read/write/ddl/label_change/...
    pub action: String,
    /// 资源（resource）：表/模式/时间线标识。
    pub resource: String,
    /// 主体 MLS 标签。
    pub subject_label: JtLabel,
    /// 资源 MLS 标签（未标记时 None = 最低密级）。
    pub resource_label: Option<JtLabel>,
    /// 上下文（context）：会话属性。
    pub context: RequestContext,
}

/// 请求上下文。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestContext {
    /// 策略版本（快照版本；请求携带以确保用同一版本决策）。
    pub policy_version: u64,
    /// 节点标识。
    pub node_id: String,
    /// 时间戳（Unix 秒）。
    pub now_secs: u64,
    /// 是否可信主体（可降标写）。
    #[serde(default)]
    pub trusted: bool,
}

/// 策略版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyVersion(pub u64);

/// 策略错误。
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy version mismatch: request={request} snapshot={snapshot}")]
    VersionMismatch { request: u64, snapshot: u64 },
    #[error("no policy matched (default deny)")]
    NoMatch,
}

/// 单条策略规则（Cedar 风格：主体/动作/资源条件 + 效果）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub effect: Effect,
    /// 主体匹配（"*" = 任意；否则精确匹配 principal 或 principal_roles 成员）。
    pub principal: String,
    /// 动作匹配（"*" = 任意）。
    pub action: String,
    /// 资源匹配（"*" = 任意；支持 "prefix:*" 前缀匹配）。
    pub resource: String,
    /// MLS 条件：要求主体支配资源标签（读路径语义）。
    #[serde(default)]
    pub require_dominates: bool,
    /// MLS 条件：可信降标（允许 trusted 主体写低于自身标签的对象）。
    #[serde(default)]
    pub allow_trusted_downgrade: bool,
}

impl PolicyRule {
    fn matches_principal(&self, req: &PolicyRequest) -> bool {
        if self.principal == "*" {
            return true;
        }
        self.principal == req.principal || req.principal_roles.iter().any(|r| r == &self.principal)
    }

    fn matches_action(&self, req: &PolicyRequest) -> bool {
        self.action == "*" || self.action == req.action
    }

    fn matches_resource(&self, req: &PolicyRequest) -> bool {
        if self.resource == "*" {
            return true;
        }
        if let Some(prefix) = self.resource.strip_suffix('*') {
            return req.resource.starts_with(prefix);
        }
        self.resource == req.resource
    }

    /// MLS 条件求值。
    fn mls_ok(&self, req: &PolicyRequest) -> bool {
        if !self.require_dominates {
            return true;
        }
        match &req.resource_label {
            None => true, // 未标记资源视为最低密级
            Some(rl) => {
                if req.subject_label.dominate(rl) {
                    return true;
                }
                // 可信降标：写路径允许（*-属性豁免）
                self.allow_trusted_downgrade && req.context.trusted
            }
        }
    }

    fn applies(&self, req: &PolicyRequest) -> bool {
        self.matches_principal(req)
            && self.matches_action(req)
            && self.matches_resource(req)
            && self.mls_ok(req)
    }
}

/// 策略集（有序；forbid 优先于 permit——Cedar 语义）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub version: PolicyVersion,
    pub rules: Vec<PolicyRule>,
}

impl PolicySet {
    pub fn new(version: u64) -> Self {
        Self {
            version: PolicyVersion(version),
            rules: Vec::new(),
        }
    }

    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// 求值：**forbid 优先**（Cedar 语义）；无匹配 = 默认拒绝。
    ///
    /// 同时校验请求携带的 policy_version 与策略集版本一致（docs/05 §6
    /// "注入的标签谓词绑定 policy_version"）。
    pub fn evaluate(&self, req: &PolicyRequest) -> Result<Decision, PolicyError> {
        if req.context.policy_version != self.version.0 {
            return Err(PolicyError::VersionMismatch {
                request: req.context.policy_version,
                snapshot: self.version.0,
            });
        }

        // 1. 先查 forbid（任一 forbid 命中即拒绝）
        for rule in &self.rules {
            if rule.effect == Effect::Forbid && rule.applies(req) {
                return Ok(Decision::Deny(format!("forbidden by rule '{}'", rule.id)));
            }
        }

        // 2. 再查 permit
        for rule in &self.rules {
            if rule.effect == Effect::Permit && rule.applies(req) {
                return Ok(Decision::Allow);
            }
        }

        // 3. 默认拒绝
        Ok(Decision::Deny("no policy matched (default deny)".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(action: &str, subject: JtLabel, resource: Option<JtLabel>) -> PolicyRequest {
        PolicyRequest {
            principal: "alice".to_string(),
            principal_roles: vec!["sysadmin".to_string()],
            action: action.to_string(),
            resource: "table:public.t1".to_string(),
            subject_label: subject,
            resource_label: resource,
            context: RequestContext {
                policy_version: 1,
                node_id: "ps-1".to_string(),
                now_secs: 1_700_000_000,
                trusted: false,
            },
        }
    }

    fn base_policies() -> PolicySet {
        PolicySet::new(1)
            .with_rule(PolicyRule {
                id: "allow-read-with-domination".into(),
                effect: Effect::Permit,
                principal: "*".into(),
                action: "read".into(),
                resource: "*".into(),
                require_dominates: true,
                allow_trusted_downgrade: false,
            })
            .with_rule(PolicyRule {
                id: "deny-secret-table".into(),
                effect: Effect::Forbid,
                principal: "*".into(),
                action: "*".into(),
                resource: "table:public.secret*".into(),
                require_dominates: false,
                allow_trusted_downgrade: false,
            })
    }

    #[test]
    fn allow_when_subject_dominates() {
        let p = base_policies();
        let r = req("read", JtLabel::new(30, 0b01), Some(JtLabel::new(20, 0b01)));
        assert!(p.evaluate(&r).unwrap().is_allowed());
    }

    #[test]
    fn deny_when_subject_below_resource() {
        let p = base_policies();
        let r = req("read", JtLabel::new(20, 0b01), Some(JtLabel::new(30, 0b01)));
        assert!(!p.evaluate(&r).unwrap().is_allowed());
    }

    #[test]
    fn deny_when_categories_missing() {
        let p = base_policies();
        // 主体 30:finance，资源 20:finance,hr → 类别不包含
        let r = req("read", JtLabel::new(30, 0b01), Some(JtLabel::new(20, 0b11)));
        assert!(!p.evaluate(&r).unwrap().is_allowed());
    }

    #[test]
    fn forbid_takes_precedence_over_permit() {
        let p = base_policies();
        // 主体能支配（40 支配 20），但资源命中 forbid 规则
        let mut r = req("read", JtLabel::new(40, 0b01), Some(JtLabel::new(20, 0b01)));
        r.resource = "table:public.secret_data".to_string();
        let d = p.evaluate(&r).unwrap();
        assert!(!d.is_allowed(), "forbid 必须优先于 permit");
        assert!(matches!(d, Decision::Deny(ref s) if s.contains("deny-secret-table")));
    }

    #[test]
    fn trusted_downgrade_allows_write() {
        let p = PolicySet::new(1).with_rule(PolicyRule {
            id: "trusted-write".into(),
            effect: Effect::Permit,
            principal: "*".into(),
            action: "write".into(),
            resource: "*".into(),
            require_dominates: true,
            allow_trusted_downgrade: true,
        });
        let mut r = req("write", JtLabel::new(30, 0b01), Some(JtLabel::new(40, 0b01)));
        // 非可信：拒绝（不上写）
        assert!(!p.evaluate(&r).unwrap().is_allowed());
        // 可信：允许降标写
        r.context.trusted = true;
        assert!(p.evaluate(&r).unwrap().is_allowed());
    }

    #[test]
    fn version_mismatch_rejected() {
        let p = base_policies();
        let mut r = req("read", JtLabel::new(30, 0), None);
        r.context.policy_version = 2;
        assert!(matches!(
            p.evaluate(&r),
            Err(PolicyError::VersionMismatch { request: 2, snapshot: 1 })
        ));
    }

    #[test]
    fn default_deny_when_no_match() {
        let p = PolicySet::new(1); // 空策略集
        let r = req("read", JtLabel::new(40, 0), None);
        assert!(!p.evaluate(&r).unwrap().is_allowed());
    }

    #[test]
    fn role_based_matching() {
        let p = PolicySet::new(1).with_rule(PolicyRule {
            id: "secadmin-label-change".into(),
            effect: Effect::Permit,
            principal: "secadmin".into(), // 角色名匹配 principal_roles
            action: "label_change".into(),
            resource: "*".into(),
            require_dominates: false,
            allow_trusted_downgrade: false,
        });
        let mut r = req("label_change", JtLabel::new(30, 0), None);
        assert!(!p.evaluate(&r).unwrap().is_allowed(), "sysadmin 不能改标签");
        r.principal_roles = vec!["secadmin".to_string()];
        assert!(p.evaluate(&r).unwrap().is_allowed(), "secadmin 可以改标签");
    }

    #[test]
    fn label_join_propagation() {
        // 标签传播：写时取上界
        let subject = JtLabel::new(30, 0b01);
        let object = JtLabel::new(20, 0b10);
        let joined = subject.join(&object);
        assert_eq!(joined.level, 30);
        assert_eq!(joined.categories, 0b11);
        assert!(joined.dominate(&subject));
        assert!(joined.dominate(&object));
    }
}
