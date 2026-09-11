//! JTDB 密钥轮换与 DEK 供给（jt-key-epoch，ADR-013 骨架第一块）。
//!
//! 职责：为组件提供按 (timeline, epoch) 作用域的 DEK 供给接口
//! （[`KeyProvider`]），隔离"密钥从哪来"（KMS 租约/开发模式）与
//! "密钥怎么用"（jt-encrypted-object）。生产实现（KMS 租约、journal 化
//! 轮换状态机、Retire 加密擦除）按 ADR-013 逐步落地；当前提供
//! [`DevKeyProvider`]（开发模式：SM3 派生的确定性 DEK）。

pub mod provider;
pub use provider::{DevKeyProvider, DekScope, KeyError, KeyProvider};
