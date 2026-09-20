//! 通用信封（docs/15 §2）与固定校验顺序。

use crate::encode::{encode_bytes, encode_opt, encode_str, Canonical, Digest};
use crate::error::{ErrorCode, ProtoError};
use crate::nonce::ReplayWindow;
use jt_crypto_api::SignatureVerifier;

/// 当前协议版本（docs/15 §6：向后兼容一版）。
pub const PROTOCOL_VER: u32 = 1;

/// 通用信封（docs/15 §2）。字段号即 proto tag。
///
/// 签名覆盖范围：**除 signature 自身以外的全部字段**（含 header 的其他
/// 字段与请求体）。签名字节序见 [`CommonHeader::signing_message`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonHeader {
    /// tag 1：幂等键，UUIDv7 字符串。
    pub request_id: String,
    /// tag 2：组件身份 `jtdb://cluster/component/node`。
    pub source_id: String,
    /// tag 3：策略版本。
    pub policy_version: u64,
    /// tag 4：密钥 epoch。
    pub key_epoch: u64,
    /// tag 5：16B 随机（docs/12 §4）。
    pub nonce: [u8; 16],
    /// tag 6：UTC 可信时间（微秒；ADR-013）。
    pub timestamp_us: i64,
    /// tag 7：超时时刻（微秒；过期拒绝）。
    pub deadline_us: i64,
    /// tag 8：SM2(请求体 ‖ header 除本字段)。
    pub signature: Vec<u8>,
    /// tag 9：协议版本。
    pub protocol_ver: u32,
}

/// proto tag 常量（字段号冻结；改动即协议破坏）。
pub mod tags {
    pub const REQUEST_ID: u32 = 1;
    pub const SOURCE_ID: u32 = 2;
    pub const POLICY_VERSION: u32 = 3;
    pub const KEY_EPOCH: u32 = 4;
    pub const NONCE: u32 = 5;
    pub const TIMESTAMP_US: u32 = 6;
    pub const DEADLINE_US: u32 = 7;
    pub const SIGNATURE: u32 = 8;
    pub const PROTOCOL_VER: u32 = 9;
}

impl CommonHeader {
    /// 待签字节序：`request_id ‖ source_id ‖ policy_version ‖ key_epoch ‖
    /// nonce(16) ‖ timestamp_us ‖ deadline_us ‖ protocol_ver ‖ body`。
    ///
    /// signature 字段本身不参与（否则无法自洽）。
    pub fn signing_message(&self, body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        encode_str(&mut msg, &self.request_id);
        encode_str(&mut msg, &self.source_id);
        self.policy_version.encode(&mut msg);
        self.key_epoch.encode(&mut msg);
        msg.extend_from_slice(&self.nonce);
        self.timestamp_us.encode(&mut msg);
        self.deadline_us.encode(&mut msg);
        self.protocol_ver.encode(&mut msg);
        encode_bytes(&mut msg, body);
        msg
    }

    /// 全量规范编码（含 signature；用于持久化/转发，**不用于签名**）。
    pub fn to_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_str(&mut out, &self.request_id);
        encode_str(&mut out, &self.source_id);
        self.policy_version.encode(&mut out);
        self.key_epoch.encode(&mut out);
        out.extend_from_slice(&self.nonce);
        self.timestamp_us.encode(&mut out);
        self.deadline_us.encode(&mut out);
        encode_bytes(&mut out, &self.signature);
        self.protocol_ver.encode(&mut out);
        out
    }

    /// 基本字段合法性（长度/取值）。
    pub fn validate_shape(&self) -> Result<(), ProtoError> {
        if self.request_id.is_empty() {
            return Err(ProtoError::BadField {
                field: "request_id",
                detail: "must not be empty (idempotency key)".into(),
            });
        }
        if self.source_id.is_empty() {
            return Err(ProtoError::BadField {
                field: "source_id",
                detail: "must not be empty".into(),
            });
        }
        if self.signature.is_empty() {
            return Err(ProtoError::BadField {
                field: "signature",
                detail: "must not be empty".into(),
            });
        }
        if self.protocol_ver == 0 {
            return Err(ProtoError::BadField {
                field: "protocol_ver",
                detail: "must not be 0".into(),
            });
        }
        Ok(())
    }
}

/// 校验上下文（对端身份、当前策略/epoch、可信时间）。
pub struct ValidationContext<'a> {
    /// 已验证的调用方身份（来自 mTLS 证书）——必须与 header.source_id 一致。
    pub peer_identity: &'a str,
    /// 当前策略版本（header 低于此值即 POLICY_STALE）。
    pub current_policy_version: u64,
    /// 当前 key epoch。
    pub current_key_epoch: u64,
    /// 当前可信时间（微秒）。
    pub now_us: i64,
    /// 允许的时钟偏移（微秒；防未来时间戳）。
    pub clock_skew_us: i64,
}

/// 校验结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 通过。
    Ok,
}

/// 按 docs/15 §2 的**固定顺序**校验请求头。
///
/// 顺序本身是安全语义，不得重排：
/// 1. **deadline**——最便宜的检查，且过期请求不应占用后续昂贵运算；
/// 2. **签名**——先确认完整性，之后的字段才可信；
/// 3. **nonce 防重放**——必须在签名通过之后：否则攻击者可用伪造 nonce
///    把合法请求挤出滑动窗口（拒绝服务）；
/// 4. **source_id 与 mTLS 身份一致**——防"借合法签名者的 header 冒充身份"；
/// 5. **policy/epoch 匹配**——版本落后或 epoch 不符按错误码返回，由调用方
///    走降级矩阵。
pub fn validate(
    header: &CommonHeader,
    body: &[u8],
    ctx: &ValidationContext<'_>,
    verifier: &dyn SignatureVerifier,
    replay: &ReplayWindow,
) -> Result<Verdict, ErrorCode> {
    // 1. deadline
    if header.deadline_us < ctx.now_us {
        return Err(ErrorCode::DeadlineExpired);
    }
    // 时间戳不得来自未来（超出允许偏移）
    if header.timestamp_us > ctx.now_us + ctx.clock_skew_us {
        return Err(ErrorCode::DeadlineExpired);
    }
    // 2. 签名
    let msg = header.signing_message(body);
    if !verifier.verify(&msg, &header.signature) {
        return Err(ErrorCode::BadSignature);
    }
    // 3. nonce 防重放（滑动窗口）
    if !replay.accept_at(&header.nonce, ctx.now_us) {
        return Err(ErrorCode::Replayed);
    }
    // 4. 身份一致性
    if header.source_id != ctx.peer_identity {
        return Err(ErrorCode::BadSignature);
    }
    // 5. policy / epoch
    if header.policy_version < ctx.current_policy_version {
        return Err(ErrorCode::PolicyStale);
    }
    if header.key_epoch != ctx.current_key_epoch {
        return Err(ErrorCode::EpochMismatch);
    }
    Ok(Verdict::Ok)
}

/// 摘要的 hex 表示辅助（协议 JSON 视图用）。
pub fn digest_hex(d: &Digest) -> String {
    hex::encode(d.0)
}

/// 可选字节字段的规范编码辅助。
pub fn encode_opt_bytes(out: &mut Vec<u8>, v: &Option<Vec<u8>>) {
    match v {
        Some(b) => {
            out.push(1);
            encode_bytes(out, b);
        }
        None => out.push(0),
    }
}

/// 可选定长字节字段的规范编码辅助。
pub fn encode_opt_fixed(out: &mut Vec<u8>, v: &Option<[u8; 32]>) {
    match v {
        Some(b) => {
            out.push(1);
            out.extend_from_slice(b);
        }
        None => out.push(0),
    }
}

/// 可选 u64 字段（用于 lsn 等）。
pub fn encode_opt_u64(out: &mut Vec<u8>, v: &Option<u64>) {
    encode_opt(out, v);
}
