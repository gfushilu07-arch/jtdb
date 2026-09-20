//! 规范编码（docs/15 §1/§2：签名字节序必须跨语言逐字节一致）。
//!
//! 编码规则（本 crate 冻结）：
//! * 定长整数：大端（网络序）；
//! * 变长字节串/字符串：`u32` 长度前缀（大端）+ 原始字节；
//! * 枚举：`u8`（与 proto tag 解耦，语义值单列）；
//! * `Option<T>`：`u8` 存在位（0/1）+ 存在时的编码——**必选字段不用
//!   Option**，缺失即编码错误（见 [`Canonical::encode`] 的校验）。
//!
//! 为什么不用 serde_json 做签名字节序：JSON 的对象键序、数字规范化、
//! Unicode 转义在不同语言/库间不一致，签名会随实现漂移。这里只做
//! 最小、无歧义的二进制拼接，任何语言都能复现。

/// 可做规范编码的类型。
pub trait Canonical {
    /// 追加编码到 `out`。
    fn encode(&self, out: &mut Vec<u8>);

    /// 编码为独立字节串。
    fn to_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

impl Canonical for u8 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
}

impl Canonical for u32 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl Canonical for u64 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl Canonical for i64 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl Canonical for bool {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }
}

/// 变长字节串：`u32` 长度前缀 + 内容。
pub fn encode_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// 变长字符串：`u32` 长度前缀 + UTF-8 字节。
pub fn encode_str(out: &mut Vec<u8>, s: &str) {
    encode_bytes(out, s.as_bytes());
}

/// 可选值：存在位 + 值。
pub fn encode_opt<T: Canonical>(out: &mut Vec<u8>, v: &Option<T>) {
    match v {
        Some(inner) => {
            out.push(1);
            inner.encode(out);
        }
        None => out.push(0),
    }
}

/// 可选 u64（lsn/version 等）。与 `encode_opt` 等价，保留具名便于阅读。
pub fn encode_opt_u64(out: &mut Vec<u8>, v: &Option<u64>) {
    encode_opt(out, v)
}

/// 可选字符串（变长）。
pub fn encode_opt_str(out: &mut Vec<u8>, v: &Option<String>) {
    match v {
        Some(s) => {
            out.push(1);
            encode_str(out, s);
        }
        None => out.push(0),
    }
}

/// 可选定长摘要（32B）。
pub fn encode_opt_digest(out: &mut Vec<u8>, v: &Option<Digest>) {
    match v {
        Some(d) => {
            out.push(1);
            d.encode(out);
        }
        None => out.push(0),
    }
}

/// 定长字节（无长度前缀；长度由类型保证，如 16B timeline_id / 32B 摘要）。
pub fn encode_fixed(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
}

/// 字节切片便捷编码（变长）。
pub struct Bytes<'a>(pub &'a [u8]);

impl Canonical for Bytes<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_bytes(out, self.0);
    }
}

/// 字符串便捷编码（变长）。
pub struct Str<'a>(pub &'a str);

impl Canonical for Str<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_str(out, self.0);
    }
}

/// 摘要（32B）与 timeline id（16B）的定长封装。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest(pub [u8; 32]);

impl Canonical for Digest {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_fixed(out, &self.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TimelineId(pub [u8; 16]);

impl Canonical for TimelineId {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_fixed(out, &self.0);
    }
}

impl TimelineId {
    pub fn from_hex(s: &str) -> Result<Self, crate::ProtoError> {
        let bytes = hex::decode(s).map_err(|e| crate::ProtoError::BadField {
            field: "timeline_id",
            detail: e.to_string(),
        })?;
        let arr: [u8; 16] = bytes.try_into().map_err(|_| crate::ProtoError::BadField {
            field: "timeline_id",
            detail: "must be 16 bytes".into(),
        })?;
        Ok(TimelineId(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_big_endian() {
        assert_eq!(1u32.to_canonical(), vec![0, 0, 0, 1]);
        assert_eq!(1u64.to_canonical(), vec![0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!((-1i64).to_canonical(), vec![0xff; 8]);
        assert_eq!(true.to_canonical(), vec![1]);
        assert_eq!(false.to_canonical(), vec![0]);
    }

    #[test]
    fn variable_length_has_prefix() {
        let mut out = Vec::new();
        encode_bytes(&mut out, b"abc");
        assert_eq!(out, vec![0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn empty_bytes_encodes_length_zero_only() {
        let mut out = Vec::new();
        encode_bytes(&mut out, b"");
        assert_eq!(out, vec![0, 0, 0, 0]);
    }

    #[test]
    fn option_presence_bit() {
        let mut out = Vec::new();
        encode_opt(&mut out, &Some(7u32));
        assert_eq!(out, vec![1, 0, 0, 0, 7]);
        let mut out = Vec::new();
        encode_opt(&mut out, &None::<u32>);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn fixed_length_has_no_prefix() {
        let d = Digest([0xAB; 32]);
        assert_eq!(d.to_canonical().len(), 32);
        let t = TimelineId([0x01; 16]);
        assert_eq!(t.to_canonical().len(), 16);
    }

    #[test]
    fn length_prefix_prevents_concatenation_ambiguity() {
        // 无长度前缀时 ("ab","c") 与 ("a","bc") 编码相同——签名会互相冒充。
        let mut a = Vec::new();
        encode_str(&mut a, "ab");
        encode_str(&mut a, "c");
        let mut b = Vec::new();
        encode_str(&mut b, "a");
        encode_str(&mut b, "bc");
        assert_ne!(a, b, "长度前缀必须消除拼接歧义");
    }

    #[test]
    fn timeline_id_hex_roundtrip_and_length_check() {
        let t = TimelineId([0x0a; 16]);
        assert_eq!(TimelineId::from_hex(&t.to_hex()).unwrap(), t);
        assert!(TimelineId::from_hex("aabb").is_err(), "长度不足必须拒绝");
        assert!(TimelineId::from_hex("zz").is_err());
    }
}
