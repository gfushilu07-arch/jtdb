//! jt-kms HTTP API（axum）。

use crate::state::KmsApiError;
use crate::App;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;

/// API 鉴权配置。
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub bearer_token: Option<String>,
    pub require_client_cert: bool,
}

// handlers --------------------------------------------------------------

async fn health() -> &'static str {
    "ok"
}

async fn audit_health(
    State(app): State<Arc<App>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let healthy = body.get("healthy").and_then(|v| v.as_bool()).unwrap_or(true);
    app.audit.append("admin", "audit.health", "-", &format!("healthy={healthy}")).ok();
    app.state.set_audit_healthy(healthy);
    Json(serde_json::json!({ "audit_healthy": healthy }))
}

#[derive(Deserialize)]
pub struct LeaseIssueReq {
    pub timeline_id: String,
    pub key_epoch: u64,
    pub node_id: String,
    pub attestation_digest: String,
    #[serde(default)]
    pub lsn_range: Option<String>,
}

async fn lease_issue(
    State(app): State<Arc<App>>,
    Json(req): Json<LeaseIssueReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let issued = app.state.issue_lease(
        &req.timeline_id, req.key_epoch, &req.node_id, &req.attestation_digest,
    )?;
    let lsn = req.lsn_range.unwrap_or_else(|| "[0x0,0xFFFFFFFFFFFFFFFF]".into());
    let wrapped = app.state.wrap(&req.timeline_id, req.key_epoch, &lsn, None)?;
    app.audit.append(&req.node_id, "lease.issue", &req.timeline_id, "ok").ok();
    Ok(Json(serde_json::json!({
        "lease": issued.lease,
        "dek_hex": issued.dek_hex,
        "wrapped_hex": wrapped.wrapped_hex,
        "scope_digest_hex": wrapped.scope_digest_hex,
    })))
}

#[derive(Deserialize)]
pub struct LeaseRenewReq {
    pub timeline_id: String,
    pub key_epoch: u64,
    pub attestation_digest: String,
}

async fn lease_renew(
    State(app): State<Arc<App>>,
    Json(req): Json<LeaseRenewReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let lease = app.state.renew_lease(&req.timeline_id, req.key_epoch, &req.attestation_digest)?;
    app.audit.append("component", "lease.renew", &req.timeline_id, "ok").ok();
    Ok(Json(serde_json::json!({ "lease": lease })))
}

async fn lease_revoke(
    Path(timeline): Path<String>,
    State(app): State<Arc<App>>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let revoked = app.state.revoke_lease(&timeline);
    app.audit.append("secadmin", "lease.revoke", &timeline, "ok").ok();
    Ok(Json(serde_json::json!({ "revoked": revoked })))
}

#[derive(Deserialize)]
pub struct WrapReq {
    pub timeline_id: String,
    pub key_epoch: u64,
    #[serde(default = "default_lsn")]
    pub lsn_range: String,
    #[serde(default)]
    pub dek_hex: Option<String>,
}

async fn dek_wrap(
    State(app): State<Arc<App>>,
    Json(req): Json<WrapReq>,
) -> Result<Json<crate::state::WrappedDek>, KmsApiError> {
    let w = app.state.wrap(&req.timeline_id, req.key_epoch, &req.lsn_range, req.dek_hex.as_deref())?;
    app.audit.append("component", "dek.wrap", &req.timeline_id, "ok").ok();
    Ok(Json(w))
}

#[derive(Deserialize)]
pub struct UnwrapReq {
    pub timeline_id: String,
    pub key_epoch: u64,
    #[serde(default = "default_lsn")]
    pub lsn_range: String,
    pub wrapped_hex: String,
}

async fn dek_unwrap(
    State(app): State<Arc<App>>,
    Json(req): Json<UnwrapReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let dek = app.state.unwrap(&req.timeline_id, req.key_epoch, &req.lsn_range, &req.wrapped_hex)?;
    app.audit.append("component", "dek.unwrap", &req.timeline_id, "ok").ok();
    Ok(Json(serde_json::json!({ "dek_hex": dek })))
}

#[derive(Deserialize)]
pub struct CounterRecordReq {
    pub timeline_id: String,
    pub key_epoch: u64,
    pub generation: u64,
}

async fn counter_record(
    State(app): State<Arc<App>>,
    Json(req): Json<CounterRecordReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let max = app.state.counter_record(&req.timeline_id, req.key_epoch, req.generation)?;
    Ok(Json(serde_json::json!({ "max_generation": max, "accepted": true })))
}

async fn counter_get(
    Path((timeline, epoch)): Path<(String, u64)>,
    State(app): State<Arc<App>>,
) -> Json<serde_json::Value> {
    let max = app.state.counter_get(&timeline, epoch);
    Json(serde_json::json!({ "max_generation": max }))
}

#[derive(Deserialize)]
pub struct RotationBeginReq {
    pub timeline_id: String,
    pub from_epoch: u64,
}

async fn rotation_begin(
    State(app): State<Arc<App>>,
    Json(req): Json<RotationBeginReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    app.state.rotation_begin(&req.timeline_id, req.from_epoch)?;
    app.audit.append("secadmin", "rotation.begin", &req.timeline_id, "ok").ok();
    Ok(Json(serde_json::json!({ "started": true, "state": "sealed" })))
}

#[derive(Deserialize)]
pub struct RotationAdvanceReq {
    pub timeline_id: String,
    pub to: String,
}

async fn rotation_advance(
    State(app): State<Arc<App>>,
    Json(req): Json<RotationAdvanceReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let now = app.state.rotation_advance(&req.timeline_id, &req.to)?;
    app.audit.append("secadmin", "rotation.advance", &req.timeline_id, &now).ok();
    Ok(Json(serde_json::json!({ "state": now })))
}

async fn rotation_status(
    Path(timeline): Path<String>,
    State(app): State<Arc<App>>,
) -> Json<serde_json::Value> {
    match app.state.rotation_status(&timeline) {
        Some((from, to, st, rekeyed)) => Json(serde_json::json!({
            "active": true, "from_epoch": from, "to_epoch": to, "state": st, "rekeyed_objects": rekeyed,
        })),
        None => Json(serde_json::json!({ "active": false })),
    }
}

// errors ----------------------------------------------------------------

impl IntoResponse for crate::state::KmsApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match &self {
            Self::BadRequest | Self::BadTimeline => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::Revoked => (StatusCode::FORBIDDEN, self.to_string()),
            Self::Expired => (StatusCode::FORBIDDEN, self.to_string()),
            Self::NoValidLease => (StatusCode::FORBIDDEN, self.to_string()),
            Self::StaleAttestation => (StatusCode::CONFLICT, self.to_string()),
            Self::AuditUnavailable => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            Self::Rollback(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::Rotation(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::Lease(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::Crypto(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::State(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

fn default_lsn() -> String {
    "[0x0,0xFFFFFFFFFFFFFFFF]".to_string()
}

// router ----------------------------------------------------------------

/// 路由器状态别名（axum State 需要）。
pub type AppState = Arc<App>;

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/audit/healthy", post(audit_health))
        .route("/v1/lease/issue", post(lease_issue))
        .route("/v1/lease/renew", post(lease_renew))
        .route("/v1/lease/revoke/{timeline}", post(lease_revoke))
        .route("/v1/lease/state/{timeline}/{epoch}", get(lease_state_handler))
        .route("/v1/dek/wrap", post(dek_wrap))
        .route("/v1/dek/unwrap", post(dek_unwrap))
        .route("/v1/counter/{timeline}/{epoch}", get(counter_get))
        .route("/v1/counter/record", post(counter_record))
        .route("/v1/rotation/begin", post(rotation_begin))
        .route("/v1/rotation/advance", post(rotation_advance))
        .route("/v1/rotation/status/{timeline}", get(rotation_status))
        /*
         * 鉴权中间件。
         *
         * **必须挂在这里**（而非仅在 TLS acceptor 上）：mTLS 只保证"连接
         * 有可信证书"，而 Bearer token 是独立的一道门；且当运维选择
         * "仅 bearer token"（不开 TLS）时，中间件是**唯一**的鉴权点。
         *
         * 顺序：`from_fn_with_state` 的中间件在 handler 之前运行，故未通过
         * 鉴权的请求不会进入任何业务逻辑（也就不会触碰密钥材料）。
         */
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            crate::tls::auth_middleware,
        ))
        .with_state(app)
}

async fn lease_state_handler(
    Path((timeline, epoch)): Path<(String, u64)>,
    State(app): State<Arc<App>>,
) -> Json<serde_json::Value> {
    let s = app.state.lease_state(&timeline, epoch);
    Json(serde_json::json!({ "state": format!("{s:?}") }))
}
