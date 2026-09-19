//! RK 分片保护：GF(2^8) 上的 Shamir 秘密分享（N-of-K 门限重建）。
//!
//! ADR-013/密评要求 RK 不以明文单点落盘——拆成 N 份交给不同保管人，
//! 集齐 ≥K 份才能重建（unseal 流程，Vault 同款）。单份泄露不泄露密钥；
//! 少于 K 份无法合谋（信息论安全）。
//!
//! 实现：RK 的每个字节独立做 K-1 次多项式分享，域 = GF(2^8)，
//! 不可约多项式 x^8+x^4+x^3+x+1（0x11B，AES 同款）。份额 =
//! share_index(1B) || 每秘密字节对应份额（共 RK_LEN 字节）。

use rand::RngCore;
use std::collections::HashSet;

/// GF(2^8) 乘法（模 0x11B）。
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a as u16;
    let mut b = b;
    let mut p: u16 = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= 0x11B;
        }
        b >>= 1;
    }
    p as u8
}

/// GF(2^8) 逆元（Fermat 小定理：a^-1 = a^254；0 无逆元）。
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0; // 约定：0 的逆元为 0（拉格朗日插值只在 x≠0 处用）
    }
    let mut result = 1u8;
    let mut exp = 254u16;
    let mut base = a;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// 拉格朗日插值在 x=0 处取值（重建秘密字节）。
///
/// `shares`: (x_i, y_i) 对，x_i 互异且均非 0。
fn lagrange_at_zero(shares: &[(u8, u8)]) -> u8 {
    let mut result = 0u8;
    for &(xi, yi) in shares {
        let mut num = 1u8; // ∏ (x_j)
        let mut den = 1u8; // ∏ (x_j - x_i)
        for &(xj, _) in shares {
            if xj == xi {
                continue;
            }
            num = gf_mul(num, xj);
            den = gf_mul(den, xj ^ xi); // GF 加法 = XOR
        }
        // result += y_i * num / den
        result ^= gf_mul(yi, gf_mul(num, gf_inv(den)));
    }
    result
}

/// 分片错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShamirError {
    #[error("threshold must be >= 2 and <= shares")]
    BadThreshold,
    #[error("too many shares (max 255)")]
    TooManyShares,
    #[error("need at least {needed} shares to reconstruct, got {got}")]
    InsufficientShares { needed: usize, got: usize },
    #[error("duplicate share index {0}")]
    DuplicateShare(u8),
    #[error("share index 0 is reserved")]
    ZeroShareIndex,
    #[error("share length mismatch")]
    LengthMismatch,
}

/// 将 32 字节秘密拆成 `shares` 份，任意 `threshold` 份可重建。
///
/// 返回 `shares` 个份额：每份 = share_index(1B) || 32B 份额值。
pub fn split(
    secret: &[u8; 32],
    threshold: usize,
    shares: usize,
    rng: &mut dyn RngCore,
) -> Result<Vec<[u8; 33]>, ShamirError> {
    if threshold < 2 || threshold > shares {
        return Err(ShamirError::BadThreshold);
    }
    if shares > 255 {
        return Err(ShamirError::TooManyShares);
    }

    // 每个 secret 字节独立生成 threshold-1 个随机系数（f(x) = s + Σ a_i x^i）
    let mut polys = Vec::with_capacity(secret.len());
    for &byte in secret.iter() {
        let mut coeffs = Vec::with_capacity(threshold);
        coeffs.push(byte); // f(0) = secret
        for _ in 1..threshold {
            let mut c = [0u8; 1];
            rng.fill_bytes(&mut c);
            coeffs.push(c[0]);
        }
        polys.push(coeffs);
    }

    // 对每个 share index x ∈ [1, shares] 计算 f(x)（Horner 法）
    let mut out = Vec::with_capacity(shares);
    for idx in 1..=shares {
        let x = idx as u8;
        let mut share_val = [0u8; 32];
        for (si, poly) in polys.iter().enumerate() {
            let mut acc = 0u8;
            for coeff in poly.iter().rev() {
                acc = gf_mul(acc, x) ^ coeff;
            }
            share_val[si] = acc;
        }
        let mut share = [0u8; 33];
        share[0] = x;
        share[1..].copy_from_slice(&share_val);
        out.push(share);
    }
    Ok(out)
}

/// 从 ≥threshold 份份额重建秘密。
pub fn join(shares: &[[u8; 33]], threshold: usize) -> Result<[u8; 32], ShamirError> {
    if shares.len() < threshold {
        return Err(ShamirError::InsufficientShares {
            needed: threshold,
            got: shares.len(),
        });
    }
    // 去重校验
    let mut seen = HashSet::new();
    for s in shares {
        if s[0] == 0 {
            return Err(ShamirError::ZeroShareIndex);
        }
        if !seen.insert(s[0]) {
            return Err(ShamirError::DuplicateShare(s[0]));
        }
    }
    // 长度一致性（编译期已保证 33B，此处防将来改动态长度）
    if shares.iter().any(|s| s.len() != 33) {
        return Err(ShamirError::LengthMismatch);
    }

    let mut secret = [0u8; 32];
    for byte_idx in 0..32 {
        let points: Vec<(u8, u8)> = shares
            .iter()
            .take(threshold)
            .map(|s| (s[0], s[1 + byte_idx]))
            .collect();
        secret[byte_idx] = lagrange_at_zero(&points);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(42)
    }

    #[test]
    fn gf_arithmetic_basics() {
        // 加法 = XOR
        assert_eq!(0x53 ^ 0xCA, gf_mul(1, 0x53) ^ gf_mul(1, 0xCA));
        // 乘法单位元
        assert_eq!(gf_mul(0x57, 1), 0x57);
        // 0x57 * 0x83 = 0xC1（AES 规范用例）
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
        // 逆元
        assert_eq!(gf_mul(0x57, gf_inv(0x57)), 1);
        assert_eq!(gf_mul(0x53, gf_inv(0x53)), 1);
    }

    #[test]
    fn split_join_2of3() {
        let secret: [u8; 32] = (0..32).map(|i| (i * 7 + 1) as u8).collect::<Vec<_>>().try_into().unwrap();
        let mut r = rng();
        let shares = split(&secret, 2, 3, &mut r).unwrap();
        assert_eq!(shares.len(), 3);
        // 任意 2 份重建
        let s = join(&shares[..2], 2).unwrap();
        assert_eq!(s, secret);
        let s = join(&shares[1..], 2).unwrap();
        assert_eq!(s, secret);
        let s = join(&[shares[0], shares[2]], 2).unwrap();
        assert_eq!(s, secret);
    }

    #[test]
    fn split_join_3of5() {
        let secret = [0xA5u8; 32];
        let mut r = rng();
        let shares = split(&secret, 3, 5, &mut r).unwrap();
        // 恰好 3 份
        assert_eq!(join(&shares[..3], 3).unwrap(), secret);
        assert_eq!(join(&shares[2..5], 3).unwrap(), secret);
        // 只有 2 份：显式拒绝（不足阈值 → InsufficientShares，而非算出垃圾值）
        assert!(matches!(
            join(&shares[..2], 3),
            Err(ShamirError::InsufficientShares { needed: 3, got: 2 })
        ));
    }

    #[test]
    fn all_share_combinations_reconstruct() {
        let secret: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13));
        let mut r = rng();
        let shares = split(&secret, 2, 4, &mut r).unwrap();
        for i in 0..4 {
            for j in (i + 1)..4 {
                let s = join(&[shares[i], shares[j]], 2).unwrap();
                assert_eq!(s, secret, "shares {i}+{j} failed");
            }
        }
    }

    #[test]
    fn bad_threshold_rejected() {
        let secret = [0u8; 32];
        let mut r = rng();
        assert!(matches!(
            split(&secret, 1, 3, &mut r),
            Err(ShamirError::BadThreshold)
        ));
        assert!(matches!(
            split(&secret, 4, 3, &mut r),
            Err(ShamirError::BadThreshold)
        ));
    }

    #[test]
    fn insufficient_shares_rejected() {
        let secret = [0u8; 32];
        let mut r = rng();
        let shares = split(&secret, 3, 5, &mut r).unwrap();
        assert!(matches!(
            join(&shares[..2], 3),
            Err(ShamirError::InsufficientShares { needed: 3, got: 2 })
        ));
    }

    #[test]
    fn duplicate_share_index_rejected() {
        let secret = [0u8; 32];
        let mut r = rng();
        let shares = split(&secret, 2, 3, &mut r).unwrap();
        let dup = [shares[0], shares[0]];
        assert!(matches!(
            join(&dup, 2),
            Err(ShamirError::DuplicateShare(1))
        ));
    }
}
