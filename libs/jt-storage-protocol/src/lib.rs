//! JTDB 存储/控制接口协议（jt-storage-protocol，docs/15）。
//!
//! 定位（docs/15 §6）：本 crate 是接口字段规格的**唯一事实源**——proto
//! 文件与 Rust 类型在此入库，`docs/15` 表格为评审视图。字段编号即
//! proto tag（docs/15 §1）。
//!
//! 覆盖（docs/15 §2~§5）：
//! * [`header::CommonHeader`] —— 所有接口共用的通用信封 + 校验顺序；
//! * [`kms`] —— KeyRequest/KeyScope/BranchKeyGrant/RotateNotify/Revoke；
//! * [`audit`] —— AuditEvent/IngestBatch/IngestAck/Checkpoint；
//! * [`error`] —— 统一错误码（§5）。
//!
//! 设计要点：
//! 1. **字段号冻结**——`tag` 常量与结构体字段一一对应，改号即协议破坏；
//! 2. **规范编码**——[`encode::Canonical`] 定义签名字节序（全大端、
//!    长度前缀），跨语言实现必须逐字节一致，否则验签失败；
//! 3. **校验顺序固定**——deadline → 签名 → nonce 防重放 → 身份一致 →
//!    policy/epoch 匹配（docs/15 §2），顺序本身是安全语义（先便宜的
//!    检查，且防重放必须在签名验证之后才可信）。

pub mod audit;
pub mod encode;
pub mod error;
pub mod header;
pub mod kms;
pub mod nonce;

pub use error::{ErrorCode, ProtoError};
pub use header::CommonHeader;

#[cfg(test)]
mod tests;
