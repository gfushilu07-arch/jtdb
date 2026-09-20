//! Segment checkpoint 与 SM2 签名锚定（docs/02 §7.3）。
//!
//! `checkpoint = SM2_sign(segment_id || first_seq || last_seq || count || head_hash)`
//!
//! 作用：hash 链只能发现单点篡改；checkpoint 用节点密钥签名段边界，
//! 使**整段删除或重建**可检出（签名覆盖段身份 + 首尾序号 + 条数 + 头哈希）。

use crate::segment::SegmentInfo;
use jt_crypto_api::{SignatureKey, SignatureVerifier};
use jt_crypto_sm::{Sm2Signer, Sm2Verifier};
use serde::{Deserialize, Serialize};

/// 段 checkpoint（含签名）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub segment_id: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: u64,
    pub head_hash: String,
    /// 签名时间戳（Unix 秒）。
    pub signed_at: u64,
    /// SM2 签名（r||s 各 32B，hex）。
    pub signature: String,
    /// 签名者公钥（hex，64B 未压缩点）。
    pub signer_pk: String,
}

impl Checkpoint {
    /// 待签消息（docs/02 §7.3 字节级定义）。
    pub fn signing_message(info: &SegmentInfo) -> Vec<u8> {
        let mut msg = Vec::with_capacity(8 + 8 + 8 + 8 + 32);
        msg.extend_from_slice(&info.segment_id.to_be_bytes());
        msg.extend_from_slice(&info.first_seq.to_be_bytes());
        msg.extend_from_slice(&info.last_seq.to_be_bytes());
        msg.extend_from_slice(&info.count.to_be_bytes());
        msg.extend_from_slice(info.head_hash.as_bytes());
        msg
    }
}

/// Checkpoint 签名者（节点密钥；生产由组件证书链提供，docs/13）。
pub struct CheckpointSigner {
    signer: Sm2Signer,
    pk_hex: String,
}

impl CheckpointSigner {
    /// 从私钥字节构造（32B 大端）。
    pub fn from_sk(sk: &[u8]) -> Result<Self, String> {
        let signer = Sm2Signer::from_sk_bytes(sk).map_err(|e| format!("{e:?}"))?;
        let pk_hex = hex::encode(signer.public_key_bytes());
        Ok(Self { signer, pk_hex })
    }

    /// 对段信息签名生成 checkpoint。
    pub fn sign(&self, info: &SegmentInfo) -> Result<Checkpoint, String> {
        let msg = Checkpoint::signing_message(info);
        let sig = self.signer.sign(&msg);
        if sig.is_empty() {
            return Err("SM2 sign failed".to_string());
        }
        Ok(Checkpoint {
            segment_id: info.segment_id,
            first_seq: info.first_seq,
            last_seq: info.last_seq,
            count: info.count,
            head_hash: info.head_hash.clone(),
            signed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            signature: hex::encode(&sig),
            signer_pk: self.pk_hex.clone(),
        })
    }
}

/// Checkpoint 验证者。
pub struct CheckpointVerifier;

impl CheckpointVerifier {
    /// 验证 checkpoint 签名 + 与段信息一致。
    ///
    /// 返回 Ok(()) 表示：签名有效 且 段边界与签名内容完全一致。
    pub fn verify(cp: &Checkpoint, info: &SegmentInfo) -> Result<(), String> {
        // 1. 段信息一致性（防止"合法签名 + 篡改段"）
        if cp.segment_id != info.segment_id
            || cp.first_seq != info.first_seq
            || cp.last_seq != info.last_seq
            || cp.count != info.count
            || cp.head_hash != info.head_hash
        {
            return Err("checkpoint does not match segment info".to_string());
        }
        // 2. 签名验证
        let pk = hex::decode(&cp.signer_pk).map_err(|e| format!("bad pk hex: {e}"))?;
        let verifier = Sm2Verifier::from_pk_bytes(&pk).map_err(|e| format!("{e:?}"))?;
        let sig = hex::decode(&cp.signature).map_err(|e| format!("bad sig hex: {e}"))?;
        let msg = Checkpoint::signing_message(info);
        if !verifier.verify(&msg, &sig) {
            return Err("checkpoint signature invalid".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> SegmentInfo {
        SegmentInfo {
            segment_id: 7,
            first_seq: 100,
            last_seq: 199,
            count: 100,
            head_hash: "ab".repeat(32),
            sealed: true,
            size_bytes: 4096,
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let signer = CheckpointSigner::from_sk(&[0x11u8; 32]).unwrap();
        let i = info();
        let cp = signer.sign(&i).unwrap();
        assert_eq!(cp.segment_id, 7);
        assert_eq!(cp.count, 100);
        assert!(CheckpointVerifier::verify(&cp, &i).is_ok());
    }

    #[test]
    fn tampered_head_hash_rejected() {
        let signer = CheckpointSigner::from_sk(&[0x11u8; 32]).unwrap();
        let i = info();
        let cp = signer.sign(&i).unwrap();
        // 篡改段 head_hash（模拟整段重建）
        let mut i2 = i.clone();
        i2.head_hash = "cd".repeat(32);
        assert!(CheckpointVerifier::verify(&cp, &i2).is_err(), "段重建必须检出");
    }

    #[test]
    fn tampered_count_rejected() {
        let signer = CheckpointSigner::from_sk(&[0x11u8; 32]).unwrap();
        let i = info();
        let cp = signer.sign(&i).unwrap();
        let mut i2 = i.clone();
        i2.count = 99; // 删一条
        assert!(CheckpointVerifier::verify(&cp, &i2).is_err(), "删条必须检出");
    }

    #[test]
    fn wrong_signer_rejected() {
        let signer = CheckpointSigner::from_sk(&[0x11u8; 32]).unwrap();
        let i = info();
        let mut cp = signer.sign(&i).unwrap();
        // 换成另一把公钥
        let other = CheckpointSigner::from_sk(&[0x22u8; 32]).unwrap();
        cp.signer_pk = other.pk_hex.clone();
        assert!(CheckpointVerifier::verify(&cp, &i).is_err());
    }
}
