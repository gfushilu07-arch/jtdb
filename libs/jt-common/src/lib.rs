//! JTDB 共享基础类型（jt-common，docs/02 §1.2）。
//!
//! 定位：跨组件（Compute 内核 / Pageserver / Safekeeper / Gateway / PDP /
//! KMS）共用的**语义单一来源**。凡是有两个实现就会产生分歧、而分歧会
//! 改变安全判决的类型，放这里。
//!
//! 当前内容：
//! * [`label`] —— MLS 标签（Level + Categories）。C 侧 `jtsec/jt_sec.h` 的
//!   `JtLabel`、Rust 侧 jt-pdp/jt-gateway 的标签**必须**与本模块语义一致。
//!
//! 为什么标签必须共享：标签的文本编解码是**跨语言接口**（SQL 文本进内核、
//! 策略快照进 PDP、审计事件进存储）。若两侧解析规则不同，同一个字符串在
//! 一侧被判为"秘密"、另一侧被判为"公开"，访问控制就在两组件之间漏了。
//! 因此本模块把编解码规则连同**失败模式**一起固化，并用测试锁死。

pub mod label;

pub use label::{CategorySet, LabelError, LabelLevel, MlsLabel};
