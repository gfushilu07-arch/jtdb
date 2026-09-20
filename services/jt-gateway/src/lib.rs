//! JTDB 连接网关（jt-gateway，docs/02 §6.1、docs/14）。
//!
//! 设计核心（docs/14 §1/§2.1）：
//! * **内建连接池**（中小企业不装 pgbouncer）；
//! * **池化与安全上下文的冲突是第一设计约束**——连接复用不得导致会话状态、
//!   权限、安全上下文跨主体泄漏；
//! * **主体亲和（subject affinity）**：后端连接只允许复用给相同 subject_id
//!   （及标签档位）的会话——即使复位逻辑有缺陷，跨主体泄漏在物理上不可能
//!   （复位从"唯一防线"降级为"第二道防线"）；
//! * **复位走协议级/内核级路径**，禁止转发 `DISCARD ALL` 文本（可被注入）；
//! * **Pin 原则**：宁可 pin 降低池化率，不可复位出错。
//!
//! 本模块为纯逻辑层（池 + 亲和 + 复位/pin 决策 + 限额 + 失效传播）；
//! TLCP 握手与 PG wire 协议编解码为后续。

pub mod pool;
pub mod session;

pub use pool::{
    BackendConn, ConnState, GatewayError, PoolConfig, PoolKey, SessionPool, StaleReason,
};
pub use session::{PinReason, ResetOutcome, SessionState, SubjectIdentity};
