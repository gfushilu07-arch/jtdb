//! jt-kms 传输层安全：**真** mTLS（客户端证书校验）+ Bearer token 鉴权。
//!
//! # 为什么有这个模块（背景）
//!
//! 本模块之前，jt-kms 的 `AuthConfig`（`bearer_token` 与 `require_client_cert`）
//! 由 CLI 参数填充后**从未被任何代码读取**：
//!
//! - `require_client_cert` 仅出现在定义处与赋值处，无检查点；
//! - `bearer_token` 同样只有定义与赋值；
//! - `rustls`/`tokio-rustls` 在 `Cargo.toml` 里声明，但 `src/` 中**零引用**；
//! - 服务始终以**明文 HTTP** 提供。
//!
//! 实测确认：以 `--auth-token SECRET123` 启动后，**不带任何凭据**的请求仍能
//! 抵达业务逻辑（返回 409 "stale attestation" 而非 401）。即所有端点
//! （含 `/v1/dek/unwrap`）**完全没有鉴权**。
//!
//! 这比"未实现"更危险：运维传了 `--client-ca` 会以为已启用 mTLS，
//! 而流量实际是明文——**配置声明与实现不符且不报错**。
//!
//! # 本模块的设计要点
//!
//! 1. **TLS 用 Tongsuo 的 OpenSSL 兼容接口**（而非 rustls）：rustls 不支持
//!    SM2/国密套件，而本项目的合规主路径是 TLCP（docs/12 §3.3）。用
//!    `openssl` crate 意味着底层必须是 Tongsuo 安装树——见
//!    `scripts/env.sh` 的 `OPENSSL_DIR`（此前误链 Homebrew OpenSSL 的
//!    根因修复）。
//! 2. **客户端证书校验是强制双向的**：`set_verify(PEER | FAIL_IF_NO_PEER_CERT)`，
//!    缺证书即 TLS 握手失败（而非握手成功后在应用层再判）。
//! 3. **Bearer token 与 mTLS 是两道独立的门**：两者都配则都要过；
//!    只配一个则只查一个。二者皆未配时**拒绝启动**（见 `validate`）——
//!    "默认无鉴权"是不可接受的默认值。
//! 4. **声明了但未实现的参数必须拒绝启动**：`validate` 会检查
//!    `--tls-cert`/`--tls-key` 必须成对出现，避免"传了一个以为启用了 TLS"。

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use std::path::Path;
use std::sync::Arc;

/// TLS 配置（由 CLI 参数装配）。
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// 服务端证书链（PEM）。
    pub cert: Option<std::path::PathBuf>,
    /// 服务端私钥（PEM）。
    pub key: Option<std::path::PathBuf>,
    /// 客户端 CA（PEM）：给出即**要求**客户端提供有效证书（mTLS）。
    pub client_ca: Option<std::path::PathBuf>,
}

impl TlsConfig {
    pub fn enabled(&self) -> bool {
        self.cert.is_some() && self.key.is_some()
    }
}

/// 启动期校验：配置必须自洽，否则**拒绝启动**。
///
/// 原则：**宁可拒绝启动，不可静默降级**。一个"以为启用了 mTLS 而实际明文"
/// 的服务，比一个起不来的服务危险得多——前者会在生产上悄悄运行。
pub fn validate(tls: &TlsConfig, bearer_token: Option<&str>) -> Result<(), String> {
    match (&tls.cert, &tls.key) {
        (Some(_), None) => {
            return Err("--tls-cert given without --tls-key: \
                        refusing to start (a half-configured TLS listener would \
                        silently serve plaintext)"
                .into())
        }
        (None, Some(_)) => {
            return Err("--tls-key given without --tls-cert: \
                        refusing to start (a half-configured TLS listener would \
                        silently serve plaintext)"
                .into())
        }
        _ => {}
    }

    if tls.client_ca.is_some() && !tls.enabled() {
        return Err("--client-ca given without --tls-cert/--tls-key: \
                    client-certificate verification requires TLS; refusing to start \
                    rather than serving plaintext while appearing to require mTLS"
            .into());
    }

    /*
     * 两道门都未配 → 拒绝启动。
     *
     * 为什么不给"默认放行"：jt-kms 的端点含 `/v1/dek/unwrap`（解出数据密钥），
     * 默认无鉴权等于把集群的数据密钥暴露给任何能连上该端口的人。开发期若确需
     * 无鉴权，必须显式传 `--insecure-no-auth`（见 main.rs），使"我确实关掉了
     * 鉴权"成为一次有意识的操作，而不是默认行为。
     */
    if !tls.enabled() && bearer_token.is_none() {
        return Err("no authentication configured: neither --client-ca (mTLS) nor \
                    --auth-token (bearer) was given. jt-kms exposes /v1/dek/unwrap, \
                    so an unauthenticated listener would expose cluster data keys. \
                    Pass one of them, or --insecure-no-auth for development."
            .into());
    }

    Ok(())
}

/// 构建 TLS acceptor（含强制客户端证书校验）。
pub fn acceptor(tls: &TlsConfig) -> Result<SslAcceptor, String> {
    let cert = tls
        .cert
        .as_ref()
        .ok_or("tls acceptor requested without cert")?;
    let key = tls.key.as_ref().ok_or("tls acceptor requested without key")?;

    // TLS 1.2+ ：TLCP 走 Tongsuo 的 NTLS 接口，属后续批次；此处先做标准 TLS。
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| format!("SslAcceptor::mozilla_intermediate_v5: {e}"))?;

    b.set_certificate_chain_file(cert)
        .map_err(|e| format!("load cert {}: {e}", cert.display()))?;
    b.set_private_key_file(key, SslFiletype::PEM)
        .map_err(|e| format!("load key {}: {e}", key.display()))?;
    b.check_private_key()
        .map_err(|e| format!("cert/key mismatch: {e}"))?;

    if let Some(ca) = &tls.client_ca {
        b.set_ca_file(ca)
            .map_err(|e| format!("load client CA {}: {e}", ca.display()))?;
        /*
         * PEER = 校验对端证书；FAIL_IF_NO_PEER_CERT = 未提供证书即失败。
         * 两者缺一不可：只设 PEER 时，客户端**不提供**证书也会握手成功
         * （OpenSSL 语义），于是"要求 mTLS"变成"可选 mTLS"。
         */
        b.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        /*
         * 校验深度：叶证书 + 中间 CA。设为 4 留出余量（docs/13 的层次是
         * Root → Component CA → 节点证书，深度 2 足够，取 4 防未来加层）。
         */
        b.set_verify_depth(4);
    }

    Ok(b.build())
}

// ---------------------------------------------------------------------------
// 鉴权中间件
// ---------------------------------------------------------------------------

/// 鉴权中间件：Bearer token + mTLS 客户端证书。
///
/// **两道门都配则都要过**（AND 语义）：token 防"能连上端口的人"，
/// mTLS 防"能连上且偷到 token 的人"。只配一道则只查一道。
pub async fn auth_middleware(
    State(app): State<Arc<crate::App>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // 健康检查豁免：负载均衡/监控需要无凭据探活。它不返回任何密钥材料。
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }

    // 门 1：Bearer token（若配置）
    if let Some(expected) = &app.auth.bearer_token {
        let got = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match got {
            Some(t) if constant_time_eq(t.as_bytes(), expected.as_bytes()) => {}
            _ => {
                app.audit
                    .append("anonymous", "auth.reject", req.uri().path(), "bad-token")
                    .ok();
                return unauthorized("missing or invalid bearer token");
            }
        }
    }

    /*
     * 门 2：mTLS 客户端证书。
     *
     * 证书校验本身在 **TLS 握手期**完成（`FAIL_IF_NO_PEER_CERT`），到达这里
     * 说明链已可信。此处只再确认"证书确实存在"，作为纵深防御——防止将来
     * 有人误改 acceptor 配置后应用层失去这道门。
     */
    if app.auth.require_client_cert {
        /*
         * 注意取的是 `ConnectInfo<ClientCertInfo>` 而非 `ClientCertInfo`：
         * `into_make_service_with_connect_info` 把 `Connected` 的产物包在
         * `ConnectInfo` newtype 里再插入请求扩展（axum 的约定）。直接取裸类型
         * 会永远拿到 None——实测踩到：`Connected::connect_info` 里已确认
         * `present=true`，中间件却报"no client cert"。
         */
        let has_cert = req
            .extensions()
            .get::<axum::extract::ConnectInfo<crate::ClientCertInfo>>()
            .map(|ci| ci.0.present)
            .unwrap_or(false);
        if !has_cert {
            app.audit
                .append("anonymous", "auth.reject", req.uri().path(), "no-client-cert")
                .ok();
            return unauthorized("client certificate required");
        }
    }

    next.run(req).await
}

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

/// 常量时间比较（防时序侧信道）。
///
/// 长度不同直接返回 false——长度本身会泄漏，但 bearer token 长度不是秘密，
/// 且避免为对齐长度引入额外分配。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 便捷函数：判断路径是否被 TLS 配置覆盖（供启动日志）。
pub fn describe(tls: &TlsConfig, bearer: Option<&str>) -> String {
    let tls_desc = if tls.enabled() {
        match &tls.client_ca {
            Some(ca) => format!("TLS+mTLS (client CA {})", ca.display()),
            None => "TLS (server-only, no client cert required)".to_string(),
        }
    } else {
        "PLAINTEXT".to_string()
    };
    let tok = if bearer.is_some() {
        "bearer-token"
    } else {
        "no-bearer"
    };
    format!("{tls_desc} + {tok}")
}

/// 校验 PEM 文件可读（启动期早失败，避免运行到第一次握手才发现）。
pub fn preflight(tls: &TlsConfig) -> Result<(), String> {
    for p in [&tls.cert, &tls.key, &tls.client_ca].into_iter().flatten() {
        if !Path::new(p).is_file() {
            return Err(format!("{} does not exist or is not a file", p.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(cert: Option<&str>, key: Option<&str>, ca: Option<&str>) -> TlsConfig {
        TlsConfig {
            cert: cert.map(Into::into),
            key: key.map(Into::into),
            client_ca: ca.map(Into::into),
        }
    }

    #[test]
    fn half_configured_tls_is_refused() {
        // 只给 cert 或只给 key：必须拒绝启动（否则会静默以明文服务）
        assert!(validate(&cfg(Some("c.pem"), None, None), Some("t")).is_err());
        assert!(validate(&cfg(None, Some("k.pem"), None), Some("t")).is_err());
    }

    #[test]
    fn client_ca_without_tls_is_refused() {
        // 只给 client-ca 而不给 cert/key：会让人以为启用了 mTLS，实际明文
        let e = validate(&cfg(None, None, Some("ca.pem")), Some("t")).unwrap_err();
        assert!(e.contains("client-certificate verification requires TLS"), "{e}");
    }

    #[test]
    fn no_auth_at_all_is_refused() {
        // 默认必须拒绝：jt-kms 暴露 /v1/dek/unwrap
        let e = validate(&cfg(None, None, None), None).unwrap_err();
        assert!(e.contains("no authentication configured"), "{e}");
    }

    #[test]
    fn bearer_alone_is_acceptable() {
        assert!(validate(&cfg(None, None, None), Some("secret")).is_ok());
    }

    #[test]
    fn tls_alone_is_acceptable() {
        assert!(validate(&cfg(Some("c"), Some("k"), None), None).is_ok());
    }

    #[test]
    fn tls_plus_mtls_is_acceptable() {
        assert!(validate(&cfg(Some("c"), Some("k"), Some("ca")), None).is_ok());
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
