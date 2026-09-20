//! 时间戳令牌（TimestampToken）与 TSA 实现。

use jt_crypto_api::{SignatureKey, SignatureVerifier};
use jt_crypto_sm::{Sm2Signer, Sm2Verifier, Sm3Digest};
use jt_crypto_api::Digest256 as _;
use serde::{Deserialize, Serialize};

/// TSA 错误。
#[derive(Debug, thiserror::Error)]
pub enum TimestampError {
    #[error("signing failed")]
    SignFailed,
    #[error("signature invalid")]
    InvalidSignature,
    #[error("token message mismatch (tampered or wrong subject)")]
    SubjectMismatch,
    #[error("token expired or outside validity window")]
    OutsideValidity,
}

/// 时间戳令牌。
///
/// 语义：`message_imprint`（被锚定内容的 SM3 摘要）+ `gen_time`（可信时间）
/// 由 TSA 私钥签名——任何一方事后都无法否认"该内容在 gen_time 已存在"。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampToken {
    /// 令牌序号（TSA 单调）。
    pub serial: u64,
    /// 被锚定内容的 SM3 摘要（hex）。
    pub message_imprint: String,
    /// 被锚定内容的类型标签（如 "audit-checkpoint"）。
    pub imprint_kind: String,
    /// 锚定时刻（Unix 秒，可信时间源）。
    pub gen_time: u64,
    /// 有效期（秒；0 = 无期限）。
    pub validity_secs: u64,
    /// SM2 签名（r‖s 各 32B，hex）——覆盖上述全部字段的规范编码。
    pub signature: String,
    /// TSA 签名者公钥（hex）。
    pub signer_pk: String,
}

impl TimestampToken {
    /// 待签规范编码（字段顺序固定，全大端；不含 signature/signer_pk）。
    pub fn signing_message(
        serial: u64,
        message_imprint: &str,
        imprint_kind: &str,
        gen_time: u64,
        validity_secs: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&serial.to_be_bytes());
        msg.extend_from_slice(message_imprint.as_bytes());
        msg.push(b'|');
        msg.extend_from_slice(imprint_kind.as_bytes());
        msg.push(b'|');
        msg.extend_from_slice(&gen_time.to_be_bytes());
        msg.extend_from_slice(&validity_secs.to_be_bytes());
        msg
    }

    /// 令牌自身的规范编码（含签名，用于验证时重建签名消息）。
    fn signing_message_of(&self) -> Vec<u8> {
        Self::signing_message(
            self.serial,
            &self.message_imprint,
            &self.imprint_kind,
            self.gen_time,
            self.validity_secs,
        )
    }
}

/// TSA 服务（单进程内实现；生产为独立服务 + HSM 托管私钥）。
pub struct Tsa {
    signer: Sm2Signer,
    pk_hex: String,
    serial: parking_lot::Mutex<u64>,
    validity_secs: u64,
}

impl Tsa {
    /// 从私钥构造（32B 大端）。`validity_secs` = 令牌有效期（0 = 无期限）。
    pub fn from_sk(sk: &[u8], validity_secs: u64) -> Result<Self, TimestampError> {
        let signer = Sm2Signer::from_sk_bytes(sk).map_err(|_| TimestampError::SignFailed)?;
        let pk_hex = hex::encode(signer.public_key_bytes());
        Ok(Self {
            signer,
            pk_hex,
            serial: parking_lot::Mutex::new(0),
            validity_secs,
        })
    }

    /// 对任意内容签发时间戳令牌（内容先 SM3 摘要）。
    pub fn timestamp(
        &self,
        content: &[u8],
        imprint_kind: &str,
        now_secs: u64,
    ) -> Result<TimestampToken, TimestampError> {
        let dg = Sm3Digest;
        let imprint = hex::encode(dg.digest(content));
        self.timestamp_imprint(&imprint, imprint_kind, now_secs)
    }

    /// 对已有摘要签发（审计 checkpoint 场景：checkpoint 已含 head_hash，
    /// 但 TSA 锚定的是 checkpoint 整体编码）。
    pub fn timestamp_imprint(
        &self,
        imprint_hex: &str,
        imprint_kind: &str,
        now_secs: u64,
    ) -> Result<TimestampToken, TimestampError> {
        let serial = {
            let mut s = self.serial.lock();
            *s += 1;
            *s
        };
        let msg = TimestampToken::signing_message(
            serial,
            imprint_hex,
            imprint_kind,
            now_secs,
            self.validity_secs,
        );
        let sig = self.signer.sign(&msg);
        if sig.is_empty() {
            return Err(TimestampError::SignFailed);
        }
        Ok(TimestampToken {
            serial,
            message_imprint: imprint_hex.to_string(),
            imprint_kind: imprint_kind.to_string(),
            gen_time: now_secs,
            validity_secs: self.validity_secs,
            signature: hex::encode(&sig),
            signer_pk: self.pk_hex.clone(),
        })
    }

    /// 验证令牌签名（不含内容比对；`verify_content` 做完整校验）。
    pub fn verify_token(&self, token: &TimestampToken) -> Result<(), TimestampError> {
        let pk = hex::decode(&token.signer_pk).map_err(|_| TimestampError::InvalidSignature)?;
        let verifier =
            Sm2Verifier::from_pk_bytes(&pk).map_err(|_| TimestampError::InvalidSignature)?;
        let sig = hex::decode(&token.signature).map_err(|_| TimestampError::InvalidSignature)?;
        if !verifier.verify(&token.signing_message_of(), &sig) {
            return Err(TimestampError::InvalidSignature);
        }
        Ok(())
    }

    /// 完整验证：签名有效 + 内容摘要匹配 + （可选）有效期窗口内。
    ///
    /// `at_time`: Some(now) 时校验令牌未过期。
    pub fn verify_content(
        &self,
        token: &TimestampToken,
        content: &[u8],
        at_time: Option<u64>,
    ) -> Result<(), TimestampError> {
        self.verify_token(token)?;
        let dg = Sm3Digest;
        let imprint = hex::encode(dg.digest(content));
        if imprint != token.message_imprint {
            return Err(TimestampError::SubjectMismatch);
        }
        if let Some(now) = at_time {
            if token.validity_secs > 0 && now > token.gen_time + token.validity_secs {
                return Err(TimestampError::OutsideValidity);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SK: [u8; 32] = [0x33; 32];

    #[test]
    fn timestamp_and_verify_roundtrip() {
        let tsa = Tsa::from_sk(&SK, 0).unwrap();
        let content = b"audit-checkpoint:segment-1:head=abc";
        let token = tsa.timestamp(content, "audit-checkpoint", 1_700_000_000).unwrap();
        assert_eq!(token.serial, 1);
        assert_eq!(token.gen_time, 1_700_000_000);
        assert_eq!(token.imprint_kind, "audit-checkpoint");
        assert!(tsa.verify_content(&token, content, None).is_ok());
    }

    #[test]
    fn tampered_content_rejected() {
        let tsa = Tsa::from_sk(&SK, 0).unwrap();
        let token = tsa.timestamp(b"original", "audit-checkpoint", 1000).unwrap();
        assert!(matches!(
            tsa.verify_content(&token, b"modified", None),
            Err(TimestampError::SubjectMismatch)
        ));
    }

    #[test]
    fn tampered_gen_time_rejected() {
        let tsa = Tsa::from_sk(&SK, 0).unwrap();
        let mut token = tsa.timestamp(b"content", "audit-checkpoint", 1000).unwrap();
        token.gen_time = 999_999; // 伪造时间
        assert!(matches!(
            tsa.verify_token(&token),
            Err(TimestampError::InvalidSignature)
        ));
    }

    #[test]
    fn wrong_signer_rejected() {
        let tsa = Tsa::from_sk(&SK, 0).unwrap();
        let other = Tsa::from_sk(&[0x44; 32], 0).unwrap();
        let mut token = tsa.timestamp(b"c", "k", 1).unwrap();
        token.signer_pk = other.pk_hex.clone();
        assert!(tsa.verify_token(&token).is_err());
    }

    #[test]
    fn serial_monotonic() {
        let tsa = Tsa::from_sk(&SK, 0).unwrap();
        let t1 = tsa.timestamp(b"a", "k", 1).unwrap();
        let t2 = tsa.timestamp(b"b", "k", 1).unwrap();
        let t3 = tsa.timestamp(b"c", "k", 1).unwrap();
        assert_eq!((t1.serial, t2.serial, t3.serial), (1, 2, 3));
    }

    #[test]
    fn validity_window_enforced() {
        let tsa = Tsa::from_sk(&SK, 900).unwrap();
        let token = tsa.timestamp(b"c", "k", 1000).unwrap();
        // 窗口内
        assert!(tsa.verify_content(&token, b"c", Some(1500)).is_ok());
        // 过期
        assert!(matches!(
            tsa.verify_content(&token, b"c", Some(2000)),
            Err(TimestampError::OutsideValidity)
        ));
    }

    #[test]
    fn checkpoint_anchoring_flow() {
        // 审计 checkpoint → TSA 锚定 → 验证（端到端）
        let tsa = Tsa::from_sk(&SK, 0).unwrap();
        // 模拟 checkpoint 规范编码（jt-audit-store 的 signing_message 格式）
        let checkpoint_bytes: Vec<u8> = {
            let mut m = Vec::new();
            m.extend_from_slice(&7u64.to_be_bytes()); // segment_id
            m.extend_from_slice(&100u64.to_be_bytes()); // first_seq
            m.extend_from_slice(&199u64.to_be_bytes()); // last_seq
            m.extend_from_slice(&100u64.to_be_bytes()); // count
            m.extend_from_slice("ab".repeat(32).as_bytes()); // head_hash
            m
        };
        let token = tsa
            .timestamp(&checkpoint_bytes, "audit-checkpoint", 1_700_000_000)
            .unwrap();
        // 验证：内容一致
        assert!(tsa.verify_content(&token, &checkpoint_bytes, None).is_ok());
        // 验证：篡改 checkpoint（如改 count）→ 摘要不匹配
        let mut tampered = checkpoint_bytes.clone();
        tampered[24..32].copy_from_slice(&99u64.to_be_bytes());
        assert!(matches!(
            tsa.verify_content(&token, &tampered, None),
            Err(TimestampError::SubjectMismatch)
        ));
    }
}
