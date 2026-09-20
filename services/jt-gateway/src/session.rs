//! 会话状态与复位/pin 决策（docs/14 §2.1/§3）。

use serde::{Deserialize, Serialize};

/// 主体身份（主体亲和的键；docs/14 §2.1）。
///
/// 亲和键 = subject_id + 标签档位。**普通用户禁止 `SET SESSION AUTHORIZATION` /
/// `SET ROLE` 越出映射范围**（ADR-012 围栏），保证亲和键不被会话内篡改。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubjectIdentity {
    /// 主体标识（应用账号 / 用户）。
    pub subject_id: String,
    /// 安全标签档位（Level；同档位才允许复用——避免高密会话污染低密连接）。
    pub label_level: i32,
    /// 类别位图（参与亲和键：类别集合不同不复用）。
    pub label_categories: u32,
}

impl SubjectIdentity {
    pub fn new(subject_id: &str, label_level: i32, label_categories: u32) -> Self {
        Self {
            subject_id: subject_id.to_string(),
            label_level,
            label_categories,
        }
    }
}

/// Pin 原因（docs/14 §3.1：存在这些状态则连接保持绑定，不归还）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PinReason {
    /// 持有 session 级 advisory lock。
    SessionAdvisoryLock,
    /// LISTEN 生效。
    Listening,
    /// WITH HOLD cursor 打开。
    WithHoldCursor,
    /// 创建了 temp table（配置为 pin 时）。
    TempTable,
    /// SET 了非默认 GUC 且未复位（配置为 pin 时）。
    NonDefaultGuc,
}

impl PinReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            PinReason::SessionAdvisoryLock => "session_advisory_lock",
            PinReason::Listening => "listening",
            PinReason::WithHoldCursor => "with_hold_cursor",
            PinReason::TempTable => "temp_table",
            PinReason::NonDefaultGuc => "non_default_guc",
        }
    }
}

/// 会话状态（复位清单的运行时表示；docs/14 §3）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionState {
    /// 非默认 GUC 集合。
    pub non_default_gucs: Vec<String>,
    /// 具名 prepared statements。
    pub prepared_statements: Vec<String>,
    /// 打开的 cursor（含 WITH HOLD 标记）。
    pub cursors: Vec<(String, bool)>,
    /// 会话内创建的临时表。
    pub temp_tables: Vec<String>,
    /// session 级 advisory locks。
    pub advisory_locks: Vec<i64>,
    /// LISTEN 频道。
    pub listen_channels: Vec<String>,
    /// 未消费的异步协议消息数（异步缓冲）。
    pub pending_async_messages: usize,
}

/// 复位配置（docs/14 §3.1 "可配置"项）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetConfig {
    /// temp table 策略：true = pin（保守），false = 复位删除。
    pub pin_on_temp_table: bool,
    /// 非默认 GUC 策略：true = pin，false = 复位。
    pub pin_on_non_default_guc: bool,
}

impl Default for ResetConfig {
    fn default() -> Self {
        // 默认最保守：宁可 pin 降低池化率，不可复位出错（docs/14 §3.1）
        Self {
            pin_on_temp_table: true,
            pin_on_non_default_guc: true,
        }
    }
}

/// 复位结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResetOutcome {
    /// 复位成功，连接可归还池。
    Reset { actions: Vec<String> },
    /// 必须 pin（连接保持绑定，不归还）。
    Pinned(Vec<PinReason>),
}

impl SessionState {
    /// 复位/pin 决策（docs/14 §3 复位清单 + §3.1 pin 条件）。
    ///
    /// 判定顺序：**先判 pin（不可复位状态），再执行复位清单**。
    /// 复位走协议级/内核级路径（本函数返回动作清单，由 Compute 内核
    /// 复位例程执行——**禁止转发 `DISCARD ALL` 文本**）。
    pub fn reset_or_pin(&self, cfg: &ResetConfig) -> ResetOutcome {
        let mut pins = Vec::new();

        // pin 条件（不可安全复位者）
        if !self.advisory_locks.is_empty() {
            pins.push(PinReason::SessionAdvisoryLock);
        }
        if !self.listen_channels.is_empty() {
            pins.push(PinReason::Listening);
        }
        if self.cursors.iter().any(|(_, with_hold)| *with_hold) {
            pins.push(PinReason::WithHoldCursor);
        }
        if cfg.pin_on_temp_table && !self.temp_tables.is_empty() {
            pins.push(PinReason::TempTable);
        }
        if cfg.pin_on_non_default_guc && !self.non_default_gucs.is_empty() {
            pins.push(PinReason::NonDefaultGuc);
        }

        if !pins.is_empty() {
            return ResetOutcome::Pinned(pins);
        }

        // 复位清单（全部可安全复位）
        let mut actions = Vec::new();
        if !self.non_default_gucs.is_empty() {
            actions.push(format!("RESET GUC ({})", self.non_default_gucs.join(",")));
        }
        if !self.prepared_statements.is_empty() {
            actions.push(format!(
                "DEALLOCATE ALL ({})",
                self.prepared_statements.join(",")
            ));
        }
        if !self.cursors.is_empty() {
            actions.push(format!("CLOSE ALL ({})", self.cursors.len()));
        }
        if !self.temp_tables.is_empty() {
            actions.push(format!("DROP TEMP TABLES ({})", self.temp_tables.join(",")));
        }
        if self.pending_async_messages > 0 {
            actions.push(format!(
                "FLUSH ASYNC BUFFER ({} msgs)",
                self.pending_async_messages
            ));
        }
        ResetOutcome::Reset { actions }
    }

    /// 是否处于干净状态（无需复位）。
    pub fn is_clean(&self) -> bool {
        self.non_default_gucs.is_empty()
            && self.prepared_statements.is_empty()
            && self.cursors.is_empty()
            && self.temp_tables.is_empty()
            && self.advisory_locks.is_empty()
            && self.listen_channels.is_empty()
            && self.pending_async_messages == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_state_resets_trivially() {
        let st = SessionState::default();
        assert!(st.is_clean());
        assert_eq!(
            st.reset_or_pin(&ResetConfig::default()),
            ResetOutcome::Reset { actions: vec![] }
        );
    }

    #[test]
    fn resettable_state_produces_actions() {
        let st = SessionState {
            non_default_gucs: vec!["work_mem".into()],
            prepared_statements: vec!["s1".into()],
            cursors: vec![("c1".into(), false)],
            pending_async_messages: 3,
            ..Default::default()
        };
        // 用不 pin GUC 的配置（默认配置对非默认 GUC 选择 pin）
        let cfg = ResetConfig {
            pin_on_non_default_guc: false,
            ..Default::default()
        };
        match st.reset_or_pin(&cfg) {
            ResetOutcome::Reset { actions } => {
                assert_eq!(actions.len(), 4, "GUC/DEALLOCATE/CLOSE/FLUSH");
            }
            other => panic!("expected Reset, got {other:?}"),
        }
    }

    #[test]
    fn advisory_lock_pins() {
        let st = SessionState {
            advisory_locks: vec![42],
            ..Default::default()
        };
        match st.reset_or_pin(&ResetConfig::default()) {
            ResetOutcome::Pinned(reasons) => {
                assert_eq!(reasons, vec![PinReason::SessionAdvisoryLock]);
            }
            other => panic!("expected Pinned, got {other:?}"),
        }
    }

    #[test]
    fn listen_pins() {
        let st = SessionState {
            listen_channels: vec!["chan1".into()],
            ..Default::default()
        };
        assert!(matches!(
            st.reset_or_pin(&ResetConfig::default()),
            ResetOutcome::Pinned(r) if r == vec![PinReason::Listening]
        ));
    }

    #[test]
    fn with_hold_cursor_pins_but_plain_cursor_resets() {
        let plain = SessionState {
            cursors: vec![("c1".into(), false)],
            ..Default::default()
        };
        assert!(matches!(
            plain.reset_or_pin(&ResetConfig::default()),
            ResetOutcome::Reset { .. }
        ));

        let with_hold = SessionState {
            cursors: vec![("c1".into(), true)],
            ..Default::default()
        };
        assert!(matches!(
            with_hold.reset_or_pin(&ResetConfig::default()),
            ResetOutcome::Pinned(r) if r == vec![PinReason::WithHoldCursor]
        ));
    }

    #[test]
    fn temp_table_configurable() {
        let st = SessionState {
            temp_tables: vec!["t_tmp".into()],
            ..Default::default()
        };
        // 默认：pin（保守）
        assert!(matches!(
            st.reset_or_pin(&ResetConfig::default()),
            ResetOutcome::Pinned(r) if r == vec![PinReason::TempTable]
        ));
        // 配置为复位删除
        let cfg = ResetConfig {
            pin_on_temp_table: false,
            ..Default::default()
        };
        assert!(matches!(
            st.reset_or_pin(&cfg),
            ResetOutcome::Reset { .. }
        ));
    }

    #[test]
    fn non_default_guc_configurable() {
        let st = SessionState {
            non_default_gucs: vec!["search_path".into()],
            ..Default::default()
        };
        assert!(matches!(
            st.reset_or_pin(&ResetConfig::default()),
            ResetOutcome::Pinned(r) if r == vec![PinReason::NonDefaultGuc]
        ));
        let cfg = ResetConfig {
            pin_on_non_default_guc: false,
            ..Default::default()
        };
        assert!(matches!(st.reset_or_pin(&cfg), ResetOutcome::Reset { .. }));
    }

    #[test]
    fn multiple_pin_reasons_reported() {
        let st = SessionState {
            advisory_locks: vec![1],
            listen_channels: vec!["c".into()],
            cursors: vec![("x".into(), true)],
            ..Default::default()
        };
        match st.reset_or_pin(&ResetConfig::default()) {
            ResetOutcome::Pinned(reasons) => {
                assert_eq!(reasons.len(), 3);
                assert!(reasons.contains(&PinReason::SessionAdvisoryLock));
                assert!(reasons.contains(&PinReason::Listening));
                assert!(reasons.contains(&PinReason::WithHoldCursor));
            }
            other => panic!("expected Pinned, got {other:?}"),
        }
    }
}
