//! jt-identity HTTP 层（axum）+ TLS/mTLS 与鉴权。
//!
//! 鉴权设计与 jt-kms 一致（见该服务 `tls.rs` 的说明）：**两道独立的门**
//! （Bearer token 与 mTLS 客户端证书），配置不自洽即拒绝启动。
//!
//! # 为什么本服务同样必须有鉴权
//!
//! `/v1/enroll` 会**签发证书**——无鉴权等于任何人都能为自己取得集群凭据，
//! 进而通过 jt-kms 的 mTLS 拿到数据密钥。故"默认无鉴权"在本服务同样不可接受。

use crate::enrollment::{EnrollRequest, EnrollError};
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use std::path::PathBuf;
use std::sync::Arc;

/// TLS 配置。
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub client_ca: Option<PathBuf>,
}

impl TlsConfig {
    pub fn enabled(&self) -> bool {
        self.cert.is_some() && self.key.is_some()
    }
}

/// 应用状态。
pub struct AppState {
    pub enrollment: crate::enrollment::EnrollmentService,
    pub cluster: String,
    pub bearer_token: Option<String>,
    pub require_client_cert: bool,
}

pub type SharedState = Arc<AppState>;

/// 配置校验：与 jt-kms 同一原则——宁可起不来，不可静默无鉴权。
pub fn validate_auth(tls: &TlsConfig, bearer: Option<&str>) -> Result<(), String> {
    match (&tls.cert, &tls.key) {
        (Some(_), None) => {
            return Err("--tls-cert given without --tls-key: refusing to start".into())
        }
        (None, Some(_)) => {
            return Err("--tls-key given without --tls-cert: refusing to start".into())
        }
        _ => {}
    }
    if tls.client_ca.is_some() && !tls.enabled() {
        return Err("--client-ca given without --tls-cert/--tls-key: client-certificate \
                    verification requires TLS; refusing to serve plaintext while \
                    appearing to require mTLS"
            .into());
    }
    if !tls.enabled() && bearer.is_none() {
        return Err("no authentication configured: neither --client-ca (mTLS) nor \
                    --auth-token (bearer) was given. /v1/enroll issues cluster \
                    certificates, so an unauthenticated listener would let anyone \
                    obtain cluster credentials. Pass one of them, or \
                    --insecure-no-auth for development."
            .into());
    }
    Ok(())
}

/// TLS acceptor（含强制客户端证书校验）。
pub fn acceptor(tls: &TlsConfig) -> Result<SslAcceptor, String> {
    let cert = tls.cert.as_ref().ok_or("acceptor without cert")?;
    let key = tls.key.as_ref().ok_or("acceptor without key")?;

    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| format!("acceptor: {e}"))?;
    b.set_certificate_chain_file(cert)
        .map_err(|e| format!("load cert: {e}"))?;
    b.set_private_key_file(key, SslFiletype::PEM)
        .map_err(|e| format!("load key: {e}"))?;
    b.check_private_key().map_err(|e| format!("cert/key mismatch: {e}"))?;

    if let Some(ca) = &tls.client_ca {
        b.set_ca_file(ca).map_err(|e| format!("load client CA: {e}"))?;
        // 两个标志缺一不可（见 jt-kms 的说明）
        b.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        b.set_verify_depth(4);
    }
    Ok(b.build())
}

/// 连接级信息（是否带客户端证书）。
#[derive(Debug, Clone, Copy)]
pub struct ClientCertInfo {
    pub present: bool,
}

/// TLS 监听器。
pub struct TlsListener {
    inner: tokio::net::TcpListener,
    acceptor: Arc<SslAcceptor>,
}

impl TlsListener {
    pub fn new(inner: tokio::net::TcpListener, acceptor: SslAcceptor) -> Self {
        Self { inner, acceptor: Arc::new(acceptor) }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_openssl::SslStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, peer) = match self.inner.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            let ssl = match openssl::ssl::Ssl::new(self.acceptor.context()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Ssl::new failed: {e}");
                    continue;
                }
            };
            let mut tls_stream = match tokio_openssl::SslStream::new(ssl, stream) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("SslStream::new failed: {e}");
                    continue;
                }
            };
            if let Err(e) = std::pin::Pin::new(&mut tls_stream).accept().await {
                tracing::warn!("TLS handshake with {peer} rejected: {e}");
                continue;
            }
            return (tls_stream, peer);
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

impl<'a> axum::extract::connect_info::Connected<axum::serve::IncomingStream<'a, TlsListener>>
    for ClientCertInfo
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        let present = stream.io().ssl().peer_certificate().is_some();
        Self { present }
    }
}

/// 鉴权中间件。
pub async fn auth_middleware(
    State(app): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // 健康检查豁免（不返回任何密钥/证书材料）
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }

    if let Some(expected) = &app.bearer_token {
        let got = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match got {
            Some(t) if constant_time_eq(t.as_bytes(), expected.as_bytes()) => {}
            _ => return unauthorized("missing or invalid bearer token"),
        }
    }

    if app.require_client_cert {
        // 注意取 ConnectInfo<T> newtype（见 jt-kms 同处的说明）
        let has_cert = req
            .extensions()
            .get::<axum::extract::ConnectInfo<ClientCertInfo>>()
            .map(|ci| ci.0.present)
            .unwrap_or(false);
        if !has_cert {
            return unauthorized("client certificate required");
        }
    }

    next.run(req).await
}

fn unauthorized(msg: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": msg }))).into_response()
}

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

/// 启动日志用的传输层描述。
pub fn describe(tls: &TlsConfig, bearer: Option<&str>) -> String {
    let t = if tls.enabled() {
        match &tls.client_ca {
            Some(ca) => format!("TLS+mTLS (client CA {})", ca.display()),
            None => "TLS (server-only)".to_string(),
        }
    } else {
        "PLAINTEXT".to_string()
    };
    format!("{t} + {}", if bearer.is_some() { "bearer-token" } else { "no-bearer" })
}

// ---------------------------------------------------------------------------
// 路由
// ---------------------------------------------------------------------------

async fn health() -> &'static str {
    "ok"
}

/// 管理员预登记节点并取得一次性 token。
#[derive(serde::Deserialize)]
struct RegisterNodeReq {
    node_id: String,
    /// 预期度量摘要（hex）。留空 = 不校验度量（**仅开发**）。
    #[serde(default)]
    expected_measurement: String,
}

async fn register_node(
    State(app): State<SharedState>,
    Json(req): Json<RegisterNodeReq>,
) -> Result<Json<serde_json::Value>, IdentityApiError> {
    let token = app.enrollment.register_node(&req.node_id, &req.expected_measurement)?;
    // 不回显 expected_measurement（无必要，且减少泄漏面）
    Ok(Json(serde_json::json!({
        "node_id": req.node_id,
        "token": token,
        "token_ttl_secs": crate::enrollment::TOKEN_TTL.as_secs(),
        "measurement_enforced": !req.expected_measurement.is_empty(),
    })))
}

#[derive(serde::Deserialize)]
struct BeginReq {
    node_id: String,
    token: String,
}

/// 请求挑战（返回 nonce，节点用它做持钥证明）。
async fn begin(
    State(app): State<SharedState>,
    Json(req): Json<BeginReq>,
) -> Result<Json<serde_json::Value>, IdentityApiError> {
    let nonce = app.enrollment.begin(&req.node_id, &req.token)?;
    Ok(Json(serde_json::json!({
        "node_id": req.node_id,
        "nonce": nonce,
        "nonce_ttl_secs": crate::enrollment::NONCE_TTL.as_secs(),
    })))
}

/// 提交 CSR + 度量 + 持钥证明，换取节点证书。
async fn enroll(
    State(app): State<SharedState>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<serde_json::Value>, IdentityApiError> {
    let r = app.enrollment.enroll(&req)?;
    Ok(Json(serde_json::to_value(r).map_err(|e| {
        IdentityApiError::detail(EnrollError::BadRequest("serialize response failed"), e.to_string())
    })?))
}

/// 撤销证书。
#[derive(serde::Deserialize)]
struct RevokeReq {
    serial_hex: String,
    #[serde(default)]
    reason: String,
}

async fn revoke(
    State(app): State<SharedState>,
    Json(req): Json<RevokeReq>,
) -> Result<Json<serde_json::Value>, IdentityApiError> {
    let reason = if req.reason.is_empty() { "unspecified".to_string() } else { req.reason };
    app.enrollment.revoke(&req.serial_hex, &reason)?;
    Ok(Json(serde_json::json!({
        "revoked": req.serial_hex,
        "revoked_count": app.enrollment.revoked_serials().len(),
    })))
}

/// 取当前 CRL（DER，hex 编码）。
///
/// 组件定时拉取以实现"撤销传播 ≤5 分钟"（docs/13 §5）。
async fn crl_der(
    State(app): State<SharedState>,
) -> Result<Json<serde_json::Value>, IdentityApiError> {
    let serials = app.enrollment.revoked_serials();
    let mut entries = Vec::new();
    for s in &serials {
        // 撤销时间取已签发记录里的值（CRL 需要 revocationDate）
        if let Some(c) = app.enrollment.issued_certs().into_iter().find(|c| &c.serial_hex == s) {
            entries.push(crate::crl::RevokedEntry {
                serial_hex: s.clone(),
                revoked_at: c.revoked_at.unwrap_or_else(now_secs),
                reason: c.revoke_reason.unwrap_or_default(),
            });
        }
    }
    let der = crate::crl::sign_crl(app.enrollment.component_ca(), &entries)
        .map_err(|e| {
            IdentityApiError::detail(EnrollError::BadRequest("crl sign failed"), e.to_string())
        })?;
    Ok(Json(serde_json::json!({
        "crl_der_hex": hex::encode(&der),
        "revoked_count": entries.len(),
        "validity_hours": crate::crl::CRL_VALIDITY_HOURS,
    })))
}

/// 已签发证书列表（审计用；不含私钥）。
async fn issued(
    State(app): State<SharedState>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "issued": app.enrollment.issued_certs() }))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn router(app: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/nodes/register", post(register_node))
        .route("/v1/enroll/begin", post(begin))
        .route("/v1/enroll", post(enroll))
        .route("/v1/revoke", post(revoke))
        .route("/v1/crl", get(crl_der))
        .route("/v1/issued", get(issued))
        .layer(axum::middleware::from_fn_with_state(app.clone(), auth_middleware))
        .with_state(app)
}

/// API 错误包装（保留具体原因供日志，对外只给必要信息）。
pub struct IdentityApiError(EnrollError, Option<String>);

impl IdentityApiError {
    /// 带内部细节（只进日志，不外发——避免把内部状态泄漏给调用方）。
    fn detail(e: EnrollError, d: String) -> Self {
        IdentityApiError(e, Some(d))
    }
}

impl From<EnrollError> for IdentityApiError {
    fn from(e: EnrollError) -> Self {
        IdentityApiError(e, None)
    }
}

impl IntoResponse for IdentityApiError {
    fn into_response(self) -> Response {
        let IdentityApiError(e, detail) = self;
        if let Some(d) = &detail {
            tracing::warn!("enrollment error: {e} ({d})");
        } else {
            tracing::warn!("enrollment error: {e}");
        }
        let status = match &e {
            EnrollError::Ca(_) => StatusCode::INTERNAL_SERVER_ERROR,
            EnrollError::NodeNotPreRegistered(_) => StatusCode::NOT_FOUND,
            EnrollError::UnknownSerial(_) => StatusCode::NOT_FOUND,
            EnrollError::TokenExpired
            | EnrollError::TokenAlreadyUsed
            | EnrollError::ChallengeExpired
            | EnrollError::NoChallenge
            | EnrollError::UnknownToken
            | EnrollError::TokenNodeMismatch { .. } => StatusCode::FORBIDDEN,
            EnrollError::BadProof(_) | EnrollError::MeasurementMismatch { .. } => {
                StatusCode::FORBIDDEN
            }
            _ => StatusCode::BAD_REQUEST,
        };
        (status, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
    }
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
    fn no_auth_is_refused() {
        // /v1/enroll 会签发集群凭据，故默认必须拒绝无鉴权启动
        let e = validate_auth(&cfg(None, None, None), None).unwrap_err();
        assert!(e.contains("no authentication configured"), "{e}");
    }

    #[test]
    fn half_configured_tls_refused() {
        assert!(validate_auth(&cfg(Some("c"), None, None), Some("t")).is_err());
        assert!(validate_auth(&cfg(None, Some("k"), None), Some("t")).is_err());
    }

    #[test]
    fn client_ca_without_tls_refused() {
        let e = validate_auth(&cfg(None, None, Some("ca")), Some("t")).unwrap_err();
        assert!(e.contains("requires TLS"), "{e}");
    }

    #[test]
    fn bearer_or_tls_alone_accepted() {
        assert!(validate_auth(&cfg(None, None, None), Some("tok")).is_ok());
        assert!(validate_auth(&cfg(Some("c"), Some("k"), None), None).is_ok());
        assert!(validate_auth(&cfg(Some("c"), Some("k"), Some("ca")), None).is_ok());
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"x", b"x"));
        assert!(!constant_time_eq(b"x", b"y"));
        assert!(!constant_time_eq(b"x", b"xy"));
    }
}
