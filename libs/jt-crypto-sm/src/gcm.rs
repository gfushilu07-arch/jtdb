//! SM4-GCM 组装（NIST SP 800-38D）。
//!
//! GCM 是分组无关的认证构造：GHASH（认证，GF(2^128)）+ CTR（加密），分组
//! 原语可替换。本实现在 SM4 分组上自含组装——等价 IEEE 1619.1-2018 GCM
//! 变体（docs/04 §4.5 对标口径）。要点：
//!
//! * J0 = IV || 0^31 || 1（IV 长度恒 96-bit，docs/04 全部场景 12B）；
//! * 计数器从 inc32(J0) 起，仅低 32 位递增；
//! * tag = GHASH_H(AAD || ciphertext || len) XOR E_K(J0)；
//! * GHASH 乘法取自 NIST SP 800-38D 算法 1（右移位实现，无查表——开发期
//!   性能足够，Tongsuo 后端另行优化）。

use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use jt_crypto_api::{Aead, CryptoError};
use sm4::{cipher, Sm4};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const SM4_KEY_LEN: usize = 16;
pub const GCM_NONCE_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;
const BLOCK: usize = 16;

/// GF(2^128) 乘法（SP 800-38D 算法 1；位序按 GCM 规范 MSB-first）。
fn gf128_mul(x: &[u8; BLOCK], y: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut z = [0u8; BLOCK];
    let mut v = *y;
    for i in 0..128 {
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        if bit == 1 {
            for b in 0..BLOCK {
                z[b] ^= v[b];
            }
        }
        // v >>= 1（LSB 方向），若原 LSB=1 则异或 R = E1 || 0^120
        let lsb = v[BLOCK - 1] & 1;
        shift_right_one(&mut v);
        if lsb == 1 {
            v[0] ^= 0xE1;
        }
    }
    z
}

fn shift_right_one(buf: &mut [u8]) {
    let mut carry = 0u8;
    for b in buf.iter_mut() {
        let next_carry = *b & 1;
        *b = (*b >> 1) | (carry << 7);
        carry = next_carry;
    }
}

fn xor16(a: &mut [u8; BLOCK], b: &[u8; BLOCK]) {
    for i in 0..BLOCK {
        a[i] ^= b[i];
    }
}

/// GHASH：GHASH_H(X) = X1·H ⊕ X2·H ⊕ ... （按 16B 分块，末块补零）。
fn ghash_blocks(h: &[u8; BLOCK], data: &[u8]) -> [u8; BLOCK] {
    let mut y = [0u8; BLOCK];
    for chunk in data.chunks(BLOCK) {
        let mut block = [0u8; BLOCK];
        block[..chunk.len()].copy_from_slice(chunk);
        xor16(&mut y, &block);
        y = gf128_mul(&y, h);
    }
    y
}

fn ghash(h: &[u8; BLOCK], aad: &[u8], ct: &[u8]) -> [u8; BLOCK] {
    // SP 800-38D §7.1：A 与 C 各自补零成整块后再拼接（不得跨域混块）
    let mut buf = Vec::with_capacity(aad.len() + ct.len() + BLOCK);
    buf.extend_from_slice(aad);
    while buf.len() % BLOCK != 0 {
        buf.push(0);
    }
    buf.extend_from_slice(ct);
    while buf.len() % BLOCK != 0 {
        buf.push(0);
    }
    let mut y = ghash_blocks(h, &buf);
    let mut len_block = [0u8; BLOCK];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    xor16(&mut y, &len_block);
    y = gf128_mul(&y, h);
    y
}

fn inc32(counter: &mut [u8; BLOCK]) {
    let n = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    counter[12..16].copy_from_slice(&n.wrapping_add(1).to_be_bytes());
}

fn ctr_xor(cipher: &Sm4, icb: &[u8; BLOCK], data: &mut [u8]) {
    let mut ctr = *icb;
    for chunk in data.chunks_mut(BLOCK) {
        let mut keystream = cipher::Block::<Sm4>::clone_from_slice(&ctr);
        cipher.encrypt_block(&mut keystream);
        for (b, k) in chunk.iter_mut().zip(keystream.as_slice().iter()) {
            *b ^= k;
        }
        inc32(&mut ctr);
    }
}

fn j0_from_nonce(nonce: &[u8]) -> [u8; BLOCK] {
    let mut j0 = [0u8; BLOCK];
    j0[..GCM_NONCE_LEN].copy_from_slice(nonce);
    j0[BLOCK - 1] = 1;
    j0
}

fn tag_compute(cipher: &Sm4, h: &[u8; BLOCK], j0: &[u8; BLOCK], aad: &[u8], ct: &[u8]) -> [u8; BLOCK] {
    let mut s = ghash(h, aad, ct);
    let mut ekj0 = cipher::Block::<Sm4>::clone_from_slice(j0);
    cipher.encrypt_block(&mut ekj0);
    xor16(&mut s, ekj0.as_slice().try_into().unwrap());
    s
}

/// SM4-GCM 实例（零状态；每次调用独立完成）。
#[derive(Debug, Default, Clone, Copy)]
pub struct Sm4Gcm;

impl Sm4Gcm {
    fn ghash_key(cipher: &Sm4) -> [u8; BLOCK] {
        let mut h = cipher::Block::<Sm4>::default();
        cipher.encrypt_block(&mut h);
        h.into()
    }

    fn prepare(key: &[u8], nonce: &[u8]) -> Result<(Sm4, [u8; BLOCK], [u8; BLOCK]), CryptoError> {
        if key.len() != SM4_KEY_LEN {
            return Err(CryptoError::InvalidInput("SM4 key must be 16 bytes"));
        }
        if nonce.len() != GCM_NONCE_LEN {
            return Err(CryptoError::InvalidInput("GCM nonce must be 12 bytes"));
        }
        let cipher = Sm4::new_from_slice(key).map_err(|_| CryptoError::Backend("sm4 init"))?;
        let h = Self::ghash_key(&cipher);
        let j0 = j0_from_nonce(nonce);
        Ok((cipher, h, j0))
    }
}

impl Aead for Sm4Gcm {
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (cipher, h, j0) = Self::prepare(key, nonce)?;
        let mut icb = j0;
        inc32(&mut icb);
        let mut ct = plaintext.to_vec();
        ctr_xor(&cipher, &icb, &mut ct);
        let tag = tag_compute(&cipher, &h, &j0, aad, &ct);
        let mut out = ct;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if ciphertext_with_tag.len() < GCM_TAG_LEN {
            return Err(CryptoError::InvalidInput("ciphertext shorter than tag"));
        }
        let (cipher, h, j0) = Self::prepare(key, nonce)?;
        let split = ciphertext_with_tag.len() - GCM_TAG_LEN;
        let (ct, tag) = ciphertext_with_tag.split_at(split);
        let expected = tag_compute(&cipher, &h, &j0, aad, ct);
        if expected.as_slice().ct_eq(tag).unwrap_u8() != 1 {
            return Err(CryptoError::AuthenticationFailed);
        }
        let mut icb = j0;
        inc32(&mut icb);
        let mut pt = ct.to_vec();
        ctr_xor(&cipher, &icb, &mut pt);
        Ok(Zeroizing::new(pt))
    }

    fn nonce_len(&self) -> usize {
        GCM_NONCE_LEN
    }

    fn key_len(&self) -> usize {
        SM4_KEY_LEN
    }
}
