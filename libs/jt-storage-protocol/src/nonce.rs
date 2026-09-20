//! nonce 防重放滑动窗口（docs/15 §2 校验顺序第 3 步）。
//!
//! 语义：每个 nonce 只接受一次；窗口按时间淘汰旧 nonce，使内存有界。
//! 窗口是**有意的近似**——它只保证"窗口内不重复"，跨窗口重放由 deadline
//! （§2 第 1 步）挡住：deadline 过期的请求在到达本步之前就已被拒。
//! 两者配合才构成完整防重放，缺一不可。

use parking_lot::Mutex;
use std::collections::HashMap;

/// 默认窗口长度（微秒）：与典型 deadline 同量级，覆盖最大容忍延迟。
pub const DEFAULT_WINDOW_US: i64 = 300 * 1_000_000;

/// 滑动窗口 nonce 集合。
pub struct ReplayWindow {
    inner: Mutex<Inner>,
    window_us: i64,
    max_entries: usize,
}

struct Inner {
    /// nonce → 首次接受时刻。
    seen: HashMap<[u8; 16], i64>,
    /// 上一次淘汰时刻（避免每请求全表扫描）。
    last_sweep: i64,
}

impl ReplayWindow {
    pub fn new(window_us: i64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                seen: HashMap::new(),
                last_sweep: 0,
            }),
            window_us,
            max_entries: 1 << 20,
        }
    }

    /// 默认窗口。
    pub fn with_default_window() -> Self {
        Self::new(DEFAULT_WINDOW_US)
    }

    /// 尝试接受一个 nonce。
    ///
    /// 返回 `true` = 首次出现（接受）；`false` = 重复（拒绝，调用方返回
    /// [`crate::ErrorCode::Replayed`]）。
    ///
    /// `now_us` 由调用方提供（可信时间），使测试可确定性推进。
    pub fn accept_at(&self, nonce: &[u8; 16], now_us: i64) -> bool {
        let mut inner = self.inner.lock();
        // 定期淘汰：窗口外的 nonce 已不可能再出现（deadline 会先拒绝）
        if now_us - inner.last_sweep > self.window_us / 4 {
            let cutoff = now_us - self.window_us;
            inner.seen.retain(|_, t| *t >= cutoff);
            inner.last_sweep = now_us;
        }
        if inner.seen.contains_key(nonce) {
            return false;
        }
        // 容量兜底：即使时间不推进（时钟异常）也不能无界增长
        if inner.seen.len() >= self.max_entries {
            let cutoff = now_us - self.window_us;
            inner.seen.retain(|_, t| *t >= cutoff);
            if inner.seen.len() >= self.max_entries {
                return false; // fail-closed：无法保证唯一性时拒绝
            }
        }
        inner.seen.insert(*nonce, now_us);
        true
    }

    /// 当前记录的 nonce 数（测试/指标）。
    pub fn len(&self) -> usize {
        self.inner.lock().seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(b: u8) -> [u8; 16] {
        [b; 16]
    }

    #[test]
    fn first_accept_then_reject() {
        let w = ReplayWindow::new(DEFAULT_WINDOW_US);
        assert!(w.accept_at(&n(1), 1_000_000), "首次接受");
        assert!(!w.accept_at(&n(1), 1_000_001), "重复拒绝");
        assert!(w.accept_at(&n(2), 1_000_001), "不同 nonce 接受");
    }

    #[test]
    fn window_eviction_allows_reuse_after_expiry() {
        let w = ReplayWindow::new(1_000_000);
        assert!(w.accept_at(&n(1), 0));
        // 窗口内仍拒绝
        assert!(!w.accept_at(&n(1), 500_000));
        // 推进到窗口外（并触发淘汰：last_sweep + window/4）
        let far = 10_000_000;
        assert!(w.accept_at(&n(2), far), "推进时钟触发淘汰");
        assert!(w.accept_at(&n(1), far), "窗口外 nonce 已淘汰");
    }

    #[test]
    fn distinct_nonces_all_accepted() {
        let w = ReplayWindow::new(DEFAULT_WINDOW_US);
        for i in 0..200u8 {
            assert!(w.accept_at(&n(i), 1_000_000));
        }
        assert_eq!(w.len(), 200);
    }

    #[test]
    fn concurrent_accepts_are_unique() {
        // 并发下同一 nonce 只能有一次成功（防重放的核心保证）。
        use std::sync::Arc;
        let w = Arc::new(ReplayWindow::new(DEFAULT_WINDOW_US));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let w = w.clone();
            handles.push(std::thread::spawn(move || w.accept_at(&n(42), 1_000_000)));
        }
        let mut accepted = 0;
        for h in handles {
            if h.join().unwrap() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 1, "同一 nonce 并发只允许一个成功");
    }
}
