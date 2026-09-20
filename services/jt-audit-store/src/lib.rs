//! JTDB WORM 审计存储（jt-audit-store，docs/02 §7.3）。
//!
//! 防篡改三层：
//! 1. **hash 链**（h(n) = SM3(event(n) || h(n-1))）——发现单点篡改；
//! 2. **segment checkpoint**（SM2 签名 segment_id/first_seq/last_seq/count/head_hash）
//!    ——防止整链删除/重建（签名锚定段边界）；
//! 3. **WORM 段文件**（只写一次 + 段封口后只读）——防重写。
//!
//! 规格（docs/02 §7.3）：
//! ```text
//! checkpoint = SM2_sign(segment_id || first_seq || last_seq || count || head_hash)
//! ```

pub mod checkpoint;
pub mod segment;

pub use checkpoint::{Checkpoint, CheckpointSigner, CheckpointVerifier};
pub use segment::{SegmentError, SegmentInfo, WormSegment, WormStore};

use jt_crypto_sm::Sm3Digest;
use jt_crypto_api::Digest256 as _;

/// 计算审计事件 hash（h(n) = SM3(event_json || prev_hash)）。
pub fn chain_hash(event_json: &str, prev_hash: &str) -> String {
    let dg = Sm3Digest;
    let mut msg = Vec::with_capacity(event_json.len() + prev_hash.len());
    msg.extend_from_slice(event_json.as_bytes());
    msg.extend_from_slice(prev_hash.as_bytes());
    hex::encode(dg.digest(&msg))
}

/// 创世 hash（段起点）。
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
