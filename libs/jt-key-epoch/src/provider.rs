//! KeyProvider trait 与开发实现。

use jt_crypto_api::Digest256;
use parking_lot::RwLock;
use std::collections::HashMap;

/// DEK 作用域键：(timeline_id, key_epoch)。
/// docs/04 §6 与 ADR-013：DEK 作用域 = (cluster, timeline, epoch, lsn_range)，
/// lsn_range 维度由对象级 Key Envelope 承载，供给层按 timeline+epoch 粒度。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DekScope {
    pub timeline_id: [u8; 16],
    pub key_epoch: u64,
}

/// DEK 供给错误。
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("no DEK for scope (timeline/epoch): epoch retired or unknown")]
    UnknownScope,
    #[error("provider is in fail-closed state (RNG/KMS unavailable)")]
    FailClosed,
}

/// DEK 供给抽象。实现方：
/// * [`DevKeyProvider`] —— 开发模式（SM3 确定性派生，embedded-development 豁免）；
/// * jt-kms 租约实现（生产）—— 组件凭 attestation 租约获得 wrap DEK，
///   Retire 后 [`KeyProvider::get_dek`] 必须返回 [`KeyError::UnknownScope`]
///   （加密擦除语义，ADR-013）。
pub trait KeyProvider: Send + Sync {
    /// 获取 16 字节 DEK（SM4）。返回的 Vec 由调用方用后即弃（Zeroizing 包装）。
    fn get_dek(&self, scope: &DekScope) -> Result<[u8; 16], KeyError>;

    /// 供给状态标记（审计事件用）：true = 降级（软件熵源等）。
    fn is_degraded(&self) -> bool {
        false
    }
}

/// 开发模式供给：DEK = SM3("jtdev-dek:" || timeline || epoch)[..16]。
/// 确定性（同 scope 同 DEK），跨 scope 隔离（不同 timeline/epoch 不同 DEK）。
/// mode=embedded-development 豁免（docs/12 §4.1），is_degraded()=true。
#[derive(Debug, Default)]
pub struct DevKeyProvider {
    // 预留：显式注册表（测试可注入非派生 DEK）
    overrides: RwLock<HashMap<DekScope, [u8; 16]>>,
}

impl DevKeyProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// 测试注入：显式覆盖某 scope 的 DEK。
    pub fn insert_override(&self, scope: DekScope, dek: [u8; 16]) {
        self.overrides.write().insert(scope, dek);
    }
}

impl KeyProvider for DevKeyProvider {
    fn get_dek(&self, scope: &DekScope) -> Result<[u8; 16], KeyError> {
        if let Some(dek) = self.overrides.read().get(scope) {
            return Ok(*dek);
        }
        let dg = jt_crypto_sm::Sm3Digest;
        let mut msg = Vec::with_capacity(10 + 16 + 8);
        msg.extend_from_slice(b"jtdev-dek:");
        msg.extend_from_slice(&scope.timeline_id);
        msg.extend_from_slice(&scope.key_epoch.to_le_bytes());
        let d = dg.digest(&msg);
        let mut dek = [0u8; 16];
        dek.copy_from_slice(&d[..16]);
        Ok(dek)
    }

    fn is_degraded(&self) -> bool {
        true // 软件派生 = 降级标记（docs/12 §4.1）
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(t: u8, epoch: u64) -> DekScope {
        DekScope {
            timeline_id: [t; 16],
            key_epoch: epoch,
        }
    }

    #[test]
    fn deterministic_within_scope() {
        let p = DevKeyProvider::new();
        assert_eq!(p.get_dek(&scope(1, 7)).unwrap(), p.get_dek(&scope(1, 7)).unwrap());
    }

    #[test]
    fn isolated_across_timeline_and_epoch() {
        let p = DevKeyProvider::new();
        assert_ne!(p.get_dek(&scope(1, 7)).unwrap(), p.get_dek(&scope(2, 7)).unwrap());
        assert_ne!(p.get_dek(&scope(1, 7)).unwrap(), p.get_dek(&scope(1, 8)).unwrap());
    }

    #[test]
    fn override_takes_precedence() {
        let p = DevKeyProvider::new();
        let custom = [0xABu8; 16];
        p.insert_override(scope(9, 1), custom);
        assert_eq!(p.get_dek(&scope(9, 1)).unwrap(), custom);
        assert_ne!(p.get_dek(&scope(9, 2)).unwrap(), custom);
    }

    #[test]
    fn dev_provider_is_degraded() {
        // docs/12 §4.1：软件熵源/派生 = 降级标记，审计/KMS 层消费
        assert!(DevKeyProvider::new().is_degraded());
    }
}
