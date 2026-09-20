//! MLS 标签（docs/05 §3.1、ADR-011/012）。
//!
//! 模型：`Label = (Level, Categories)`；`dominate(a,b) = a.Level >= b.Level
//! AND a.Categories ⊇ b.Categories`。
//!
//! # 与 C 侧（jtsec）的关系
//!
//! C 的 `JtLabel` 是 `{int32 level; uint32 categories;}`，文本形式
//! `"level:cat1,cat2"`（无类别时 C 侧 `to_string` 仍输出尾冒号，如
//! `"30:"`）。本模块与之**语义等价**，但收紧了两处 C 侧的宽容行为——见
//! [`MlsLabel::parse`] 的说明。两侧若要互通，必须以本模块的规则为准
//! （C 侧需同步收紧，否则"一侧拒绝、一侧接受"本身就是差异）。

use serde::{Deserialize, Serialize};
use std::fmt;

/// 默认 Level 档位（docs/05 §3.1；与 C 侧 JT_LEVEL_* 一致）。
pub const LEVEL_PUBLIC: i32 = 10;
pub const LEVEL_INTERNAL: i32 = 20;
pub const LEVEL_SECRET: i32 = 30;
pub const LEVEL_TOPSECRET: i32 = 40;

/// Level 上限（C 侧 `JT_MAX_LEVELS`）。
pub const MAX_LEVELS: i32 = 64;

/// 类别位宽（C 侧 `JT_MAX_CATEGORIES`）。
pub const MAX_CATEGORIES: usize = 32;

/// 类别名称表（**顺序即位序**，与 C 侧 `jt_category_names` 逐项一致）。
///
/// 位序是跨语言约定：改动顺序会让已落库的 categories 位图整体错位。
pub const CATEGORY_NAMES: [&str; 8] = [
    "finance", "hr", "legal", "medical", "defense", "intel", "infra", "custom8",
];

/// 标签错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    #[error("level out of range: {0} (allowed {min}..={max})", min = LEVEL_PUBLIC, max = LEVEL_PUBLIC + MAX_LEVELS)]
    LevelOutOfRange(i32),
    #[error("unknown category: {0}")]
    UnknownCategory(String),
    #[error("too many categories (max {MAX_CATEGORIES})")]
    TooManyCategories,
    #[error("malformed label text: {0}")]
    Malformed(String),
    #[error("empty category name")]
    EmptyCategory,
}

/// 密级档位（Level 的语义封装）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LabelLevel(pub i32);

impl LabelLevel {
    pub const PUBLIC: LabelLevel = LabelLevel(LEVEL_PUBLIC);
    pub const INTERNAL: LabelLevel = LabelLevel(LEVEL_INTERNAL);
    pub const SECRET: LabelLevel = LabelLevel(LEVEL_SECRET);
    pub const TOPSECRET: LabelLevel = LabelLevel(LEVEL_TOPSECRET);

    /// 构造并校验范围（C 侧接受 `[JT_LEVEL_PUBLIC, JT_LEVEL_PUBLIC+JT_MAX_LEVELS]`）。
    pub fn new(v: i32) -> Result<Self, LabelError> {
        if !(LEVEL_PUBLIC..=LEVEL_PUBLIC + MAX_LEVELS).contains(&v) {
            return Err(LabelError::LevelOutOfRange(v));
        }
        Ok(LabelLevel(v))
    }

    pub fn get(self) -> i32 {
        self.0
    }
}

/// 类别集合（位图 + 名称双向映射）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct CategorySet {
    bits: u32,
}

impl CategorySet {
    pub const EMPTY: CategorySet = CategorySet { bits: 0 };

    pub fn from_bits(bits: u32) -> Self {
        CategorySet { bits }
    }

    pub fn bits(self) -> u32 {
        self.bits
    }

    pub fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// 按名称添加（未知名称报错——见 [`MlsLabel::parse`] 的失败模式说明）。
    pub fn with_name(mut self, name: &str) -> Result<Self, LabelError> {
        let idx = category_index(name).ok_or_else(|| LabelError::UnknownCategory(name.to_string()))?;
        self.bits |= 1u32 << idx;
        Ok(self)
    }

    /// 包含关系（位子集）。
    pub fn contains(self, other: CategorySet) -> bool {
        (self.bits & other.bits) == other.bits
    }

    /// 并集（标签传播用）。
    pub fn union(self, other: CategorySet) -> CategorySet {
        CategorySet {
            bits: self.bits | other.bits,
        }
    }

    /// 交集。
    pub fn intersect(self, other: CategorySet) -> CategorySet {
        CategorySet {
            bits: self.bits & other.bits,
        }
    }

    /// 已置位类别的名称（按位序，与 C 侧 `to_string` 输出顺序一致）。
    pub fn names(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (i, name) in CATEGORY_NAMES.iter().enumerate() {
            if self.bits & (1u32 << i) != 0 {
                out.push(*name);
            }
        }
        out
    }

    /// 置位但无名称的位（第 8~31 位，C 侧 `custom8` 之后未命名）。
    pub fn unnamed_bits(self) -> u32 {
        self.bits & !((1u32 << CATEGORY_NAMES.len()) - 1)
    }
}

/// 类别名 → 位序。
pub fn category_index(name: &str) -> Option<usize> {
    CATEGORY_NAMES.iter().position(|n| *n == name)
}

/// MLS 标签。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MlsLabel {
    pub level: LabelLevel,
    pub categories: CategorySet,
}

impl MlsLabel {
    pub const PUBLIC: MlsLabel = MlsLabel {
        level: LabelLevel::PUBLIC,
        categories: CategorySet::EMPTY,
    };

    pub fn new(level: i32, categories: u32) -> Result<Self, LabelError> {
        Ok(MlsLabel {
            level: LabelLevel::new(level)?,
            categories: CategorySet::from_bits(categories),
        })
    }

    /// 不做范围校验的构造（内部/测试；生产路径请用 [`Self::new`]）。
    pub fn unchecked(level: i32, categories: u32) -> Self {
        MlsLabel {
            level: LabelLevel(level),
            categories: CategorySet::from_bits(categories),
        }
    }

    /// `dominate(a, b) = a.Level >= b.Level AND a.Categories ⊇ b.Categories`。
    pub fn dominate(&self, other: &MlsLabel) -> bool {
        self.level >= other.level && self.categories.contains(other.categories)
    }

    /// 标签传播（写时取上界）：`join(a,b) = (max level, union categories)`。
    pub fn join(&self, other: &MlsLabel) -> MlsLabel {
        MlsLabel {
            level: LabelLevel(self.level.0.max(other.level.0)),
            categories: self.categories.union(other.categories),
        }
    }

    /// 序列化：`"level:cat1,cat2"`。
    ///
    /// 无类别时输出 `"30:"`（**保留尾冒号**）——与 C 侧 `jt_label_to_string`
    /// 一致。若省略冒号，两侧文本比对会不一致。
    pub fn to_text(&self) -> String {
        let mut s = format!("{}:", self.level.0);
        let names = self.categories.names();
        s.push_str(&names.join(","));
        s
    }

    /// 解析 `"level"` 或 `"level:cat1,cat2"`。
    ///
    /// # 与 C 侧的差异（刻意收紧，fail-closed）
    ///
    /// C 侧 `jt_label_parse` 对**未知类别名静默忽略**。用于对象标签时这是
    /// 危险的：写 `"30:finace"`（finance 拼错）会得到 `30:`（无类别）——
    /// 对象看起来比预期**更低密**，于是本应被拒的读取被放行。**拼写错误
    /// 必须表现为拒绝，而不是静默降密**。故本实现返回
    /// [`LabelError::UnknownCategory`]。
    ///
    /// 另：C 侧空串视为最低密级，本实现同样接受空串为
    /// [`MlsLabel::PUBLIC`]（保持兼容——空标签是显式"未分类"语义，不是
    /// 拼写错误）。
    pub fn parse(s: &str) -> Result<Self, LabelError> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(MlsLabel::PUBLIC);
        }
        let (level_str, cats_str) = match s.split_once(':') {
            Some((l, c)) => (l, Some(c)),
            None => (s, None),
        };
        let level: i32 = level_str
            .trim()
            .parse()
            .map_err(|_| LabelError::Malformed(format!("bad level: {level_str:?}")))?;
        let level = LabelLevel::new(level)?;
        let mut cats = CategorySet::EMPTY;
        if let Some(cs) = cats_str {
            for raw in cs.split(',') {
                let name = raw.trim();
                if name.is_empty() {
                    continue; // "30:" 与 "30:,," 等价于无类别
                }
                cats = cats.with_name(name)?;
            }
        }
        Ok(MlsLabel {
            level,
            categories: cats,
        })
    }

    /// 文本往返（测试/审计便利）。
    pub fn roundtrip(s: &str) -> Result<String, LabelError> {
        Ok(MlsLabel::parse(s)?.to_text())
    }
}

impl fmt::Display for MlsLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl std::str::FromStr for MlsLabel {
    type Err = LabelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MlsLabel::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_range_enforced() {
        assert!(LabelLevel::new(LEVEL_PUBLIC).is_ok());
        assert!(LabelLevel::new(LEVEL_PUBLIC + MAX_LEVELS).is_ok());
        assert!(LabelLevel::new(LEVEL_PUBLIC - 1).is_err(), "低于最低密级");
        assert!(LabelLevel::new(LEVEL_PUBLIC + MAX_LEVELS + 1).is_err());
        assert!(LabelLevel::new(0).is_err());
        assert!(LabelLevel::new(-5).is_err());
    }

    #[test]
    fn dominate_requires_both_level_and_categories() {
        let secret_fin = MlsLabel::new(30, 0b01).unwrap();
        let internal_fin = MlsLabel::new(20, 0b01).unwrap();
        let secret_fin_hr = MlsLabel::new(30, 0b11).unwrap();
        assert!(secret_fin.dominate(&internal_fin), "更高密级 + 同类别");
        assert!(!internal_fin.dominate(&secret_fin), "反向不成立");
        assert!(
            !secret_fin.dominate(&secret_fin_hr),
            "类别不全不得支配（下读会被放行）"
        );
        assert!(secret_fin_hr.dominate(&secret_fin));
        assert!(secret_fin.dominate(&secret_fin), "自反");
    }

    #[test]
    fn join_takes_upper_bound() {
        let a = MlsLabel::new(20, 0b01).unwrap();
        let b = MlsLabel::new(30, 0b10).unwrap();
        let j = a.join(&b);
        assert_eq!(j.level.get(), 30);
        assert_eq!(j.categories.bits(), 0b11);
        // 传播结果必须同时支配两侧（否则写回会降密）
        assert!(j.dominate(&a));
        assert!(j.dominate(&b));
    }

    #[test]
    fn text_roundtrip_with_categories() {
        let l = MlsLabel::parse("30:finance,hr").unwrap();
        assert_eq!(l.level.get(), 30);
        assert_eq!(l.categories.bits(), 0b11);
        assert_eq!(l.to_text(), "30:finance,hr");
    }

    #[test]
    fn text_without_categories_keeps_trailing_colon() {
        // 与 C 侧 jt_label_to_string 一致：无类别也输出尾冒号。
        let l = MlsLabel::parse("30:").unwrap();
        assert_eq!(l.categories.bits(), 0);
        assert_eq!(l.to_text(), "30:", "尾冒号必须保留（跨语言文本比对）");
        // 无冒号形式也接受
        assert_eq!(MlsLabel::parse("30").unwrap().to_text(), "30:");
    }

    #[test]
    fn empty_text_is_public() {
        assert_eq!(MlsLabel::parse("").unwrap(), MlsLabel::PUBLIC);
        assert_eq!(MlsLabel::parse("   ").unwrap(), MlsLabel::PUBLIC);
    }

    #[test]
    fn unknown_category_is_rejected_not_silently_dropped() {
        // 这是与 C 侧刻意的差异：拼写错误必须拒绝，否则对象被静默降密。
        let err = MlsLabel::parse("30:finace").unwrap_err();
        assert_eq!(err, LabelError::UnknownCategory("finace".into()));
        // C 侧会把它解析成 30:（无类别）——那等于放行本应被拒的读取。
        assert_ne!(
            MlsLabel::parse("30:finace").ok(),
            Some(MlsLabel::parse("30:").unwrap()),
            "拼错的类别绝不能等价于无类别"
        );
    }

    #[test]
    fn malformed_level_rejected() {
        assert!(matches!(
            MlsLabel::parse("abc:finance"),
            Err(LabelError::Malformed(_))
        ));
        assert!(matches!(
            MlsLabel::parse("30.5"),
            Err(LabelError::Malformed(_))
        ));
        // 越界 level 走范围错误而非格式错误
        assert!(matches!(
            MlsLabel::parse("5:finance"),
            Err(LabelError::LevelOutOfRange(5))
        ));
    }

    #[test]
    fn category_bit_order_matches_c_side_table() {
        // 位序是跨语言约定：改顺序会让已落库的位图整体错位。
        assert_eq!(CATEGORY_NAMES[0], "finance");
        assert_eq!(CATEGORY_NAMES[1], "hr");
        assert_eq!(CATEGORY_NAMES[2], "legal");
        assert_eq!(CATEGORY_NAMES[3], "medical");
        assert_eq!(CATEGORY_NAMES[4], "defense");
        assert_eq!(CATEGORY_NAMES[5], "intel");
        assert_eq!(CATEGORY_NAMES[6], "infra");
        assert_eq!(CATEGORY_NAMES[7], "custom8");
        assert_eq!(category_index("finance"), Some(0));
        assert_eq!(category_index("custom8"), Some(7));
        assert_eq!(category_index("nope"), None);
    }

    #[test]
    fn names_are_emitted_in_bit_order() {
        let l = MlsLabel::new(30, 0b1011).unwrap(); // finance, hr, medical
        assert_eq!(l.categories.names(), vec!["finance", "hr", "medical"]);
        assert_eq!(l.to_text(), "30:finance,hr,medical");
    }

    #[test]
    fn unnamed_high_bits_preserved() {
        // 第 8 位以上 C 侧无名称，但位图必须原样保留（不得因"无名字"丢位）。
        let l = MlsLabel::new(30, 0b1_0000_0001).unwrap();
        assert_eq!(l.categories.bits(), 0b1_0000_0001);
        assert_eq!(l.categories.unnamed_bits(), 0b1_0000_0000);
        assert_eq!(l.to_text(), "30:finance");
        // 文本往返会丢失无名位——这是已知且刻意的：文本形式无法表达无名位。
        let back = MlsLabel::parse(&l.to_text()).unwrap();
        assert_eq!(back.categories.bits(), 0b1, "文本往返只保留具名类别");
    }

    #[test]
    fn whitespace_tolerated() {
        let l = MlsLabel::parse(" 30 : finance , hr ").unwrap();
        assert_eq!(l.level.get(), 30);
        assert_eq!(l.categories.bits(), 0b11);
    }

    #[test]
    fn contains_and_union_semantics() {
        let a = CategorySet::from_bits(0b01);
        let b = CategorySet::from_bits(0b11);
        assert!(b.contains(a));
        assert!(!a.contains(b));
        assert_eq!(a.union(b).bits(), 0b11);
        assert_eq!(a.intersect(b).bits(), 0b01);
        assert!(CategorySet::EMPTY.contains(CategorySet::EMPTY), "空集自包含");
        assert!(CategorySet::from_bits(0).contains(CategorySet::EMPTY));
    }

    #[test]
    fn from_str_and_display() {
        let l: MlsLabel = "30:finance".parse().unwrap();
        assert_eq!(l.to_string(), "30:finance");
        assert!("bogus".parse::<MlsLabel>().is_err());
    }
}
