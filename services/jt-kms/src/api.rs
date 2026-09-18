//! jt-kms HTTP API（axum）。

use crate::state::{KmsApiError, KmsState};
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

/// API 错误 → HTTP 状态映射（失效矩阵的对外表达）。
impl IntoResponse for KmsApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match &self {
            KmsApiError::BadRequest | KmsApiError::BadTimeline => (StatusCode::BAD_REQUEST, self.to_string()),
            KmsApiError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            KmsApiError::Revoked => (StatusCode::FORBIDDEN, self.to_string()),
            KmsApiError::Expired => (StatusCode::FORBIDDEN, self.to_string()),
            KmsApiError::NoValidLease => (StatusCode::FORBIDDEN, self.to_string()),
            KmsApiError::StaleAttestation => (StatusCode::CONFLICT, self.to_string()),
            KmsApiError::AuditUnavailable => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            KmsApiError::Rollback(_) => (StatusCode::CONFLICT, self.to_string()),
            KmsApiError::Rotation(_) => (StatusCode::CONFLICT, self.to_string()),
            KmsApiError::Lease(_) => (StatusCode::CONFLICT, self.to_string()),
            KmsApiError::Crypto(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            KmsApiError::State(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

#[derive(Deserialize)]
pub struct LeaseIssueReq {
    pub timeline_id: String,
    pub key_epoch: u64,
    pub node_id: String,
    /// attestation 摘要（hex；生产=TCM/TEE 度量，当前=组件提供的摘要）
    pub attestation_digest: String,
    /// 可选：lsn_range（scope digest 组成部分；默认全范围）
    #[serde(default)]
    pub lsn_range: Option<String>,
}

#[derive(Deserialize)]
pub struct LeaseRenewReq {
    pub timeline_id: String,
    pub key_epoch: u64,
    pub attestation_digest: String,
}

#[derive(Deserialize)]
pub struct CounterRecordReq {
    pub timeline_id: String,
    pub key_epoch: u64,
    pub generation: u64,
}

#[derive(Deserialize)]
pub struct WrapReq {
    pub timeline_id: String,
    pub key_epoch: u64,
    #[serde(default = "default_lsn")]
    pub lsn_range: String,
    /// 可选：外部提供 DEK；缺省由 KMS 生成
    #[serde(default)]
    pub dek_hex: Option<String>,
}

#[derive(Deserialize)]
pub struct UnwrapReq {
    pub timeline_id: String,
    pub key_epoch: u64,
    #[serde(default = "default_lsn")]
    pub lsn_range: String,
    pub wrapped_hex: String,
}

#[derive(Deserialize)]
pub struct RotationBeginReq {
    pub timeline_id: String,
    pub from_epoch: u64,
}

#[derive(Deserialize)]
pub struct RotationAdvanceReq {
    pub timeline_id: String,
    pub to: String,
}

fn default_lsn() -> String {
    "[0x0,0xFFFFFFFFFFFFFFFF]".to_string()
}

/// 路由表。
pub fn router(state: std::sync::Arc<KmsState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/audit/healthy", post(audit_health))
        .route("/v1/lease/issue", post(lease_issue))
        .route("/v1/lease/renew", post(lease_renew))
        .route("/v1/lease/revoke/{timeline}", post(lease_revoke))
        .route("/v1/lease/state/{timeline}/{epoch}", get(lease_state))
        .route("/v1/dek/wrap", post(dek_wrap))
        .route("/v1/dek/unwrap", post(dek_unwrap))
        .route("/v1/counter/{timeline}/{epoch}", get(counter_get))
        .route("/v1/counter/record", post(counter_record))
        .route("/v1/rotation/begin", post(rotation_begin))
        .route("/v1/rotation/advance", post(rotation_advance))
        .route("/v1/rotation/status/{timeline}", get(rotation_status))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn audit_health(
    State(state): State<std::sync::Arc<KmsState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let healthy = body.get("healthy").and_then(|v| v.as_bool()).unwrap_or(true);
    state.set_audit_healthy(healthy);
    Json(serde_json::json!({ "audit_healthy": healthy }))
}

async fn lease_issue(
    State(state): State<std::sync::Arc<KmsState>>,
    Json(req): Json<LeaseIssueReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let issued = state.issue_lease(
        &req.timeline_id,
        req.key_epoch,
        &req.node_id,
        &req.attestation_digest,
    )?;
    let lsn = req.lsn_range.unwrap_or_else(default_lsn);
    let wrapped = state.wrap(&req.timeline_id, req.key_epoch, &lsn, None)?;
    Ok(Json(serde_json::json!({
        "lease": issued.lease,
        "dek_hex": issued.dek_hex,
        "wrapped_hex": wrapped.wrapped_hex,
        "scope_digest_hex": wrapped.scope_digest_hex,
    })))
}

async fn lease_renew(
    State(state): State<std::sync::Arc<KmsState>>,
    Json(req): Json<LeaseRenewReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let lease = state.renew_lease(&req.timeline_id, req.key_epoch, &req.attestation_digest)?;
    Ok(Json(serde_json::json!({ "lease": lease })))
}

async fn lease_revoke(
    AxPath(timeline): AxPath<String>,
    State(state): State<std::sync::Arc<KmsState>>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let revoked = state.revoke_lease(&timeline);
    Ok(Json(serde_json::json!({ "revoked": revoked })))
}

async fn lease_state(
    AxPath((timeline, epoch)): AxPath<(String, u64)>,
    State(state): State<std::sync::Arc<KmsState>>,
) -> Json<serde_json::Value> {
    let s = state.lease_state(&timeline, epoch);
    Json(serde_json::json!({ "state": format!("{s:?}") }))
}

async fn dek_wrap(
    State(state): State<std::sync::Arc<KmsState>>,
    Json(req): Json<WrapReq>,
) -> Result<Json<crate::state::WrappedDek>, KmsApiError> {
    let w = state.wrap(&req.timeline_id, req.key_epoch, &req.lsn_range, req.dek_hex.as_deref())?;
    Ok(Json(w))
}

async fn dek_unwrap(
    State(state): State<std::sync::Arc<KmsState>>,
    Json(req): Json<UnwrapReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let dek = state.unwrap(&req.timeline_id, req.key_epoch, &req.lsn_range, &req.wrapped_hex)?;
    Ok(Json(serde_json::json!({ "dek_hex": dek })))
}

async fn counter_get(
    AxPath((timeline, epoch)): AxPath<(String, u64)>,
    State(state): State<std::sync::Arc<KmsState>>,
) -> Json<serde_json::Value> {
    let max = state.counter_get(&timeline, epoch);
    Json(serde_json::json!({ "max_generation": max }))
}

async fn counter_record(
    State(state): State<std::sync::Arc<KmsState>>,
    Json(req): Json<CounterRecordReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let max = state.counter_record(&req.timeline_id, req.key_epoch, req.generation)?;
    Ok(Json(serde_json::json!({ "max_generation": max, "accepted": true })))
}

async fn rotation_begin(
    State(state): State<std::sync::Arc<KmsState>>,
    Json(req): Json<RotationBeginReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    state.rotation_begin(&req.timeline_id, req.from_epoch)?;
    Ok(Json(serde_json::json!({ "started": true, "state": "sealed" })))
}

async fn rotation_advance(
    State(state): State<std::sync::Arc<KmsState>>,
    Json(req): Json<RotationAdvanceReq>,
) -> Result<Json<serde_json::Value>, KmsApiError> {
    let now = state.rotation_advance(&req.timeline_id, &req.to)?;
    Ok(Json(serde_json::json!({ "state": now })))
}

async fn rotation_status(
    AxPath(timeline): AxPath<String>,
    State(state): State<std::sync::Arc<KmsState>>,
) -> Json<serde_json::Value> {
    match state.rotation_status(&timeline) {
        Some((from, to, st, rekeyed)) => Json(serde_json::json!({
            "active": true, "from_epoch": from, "to_epoch": to, "state": st, "rekeyed_objects": rekeyed,
        })),
        None => Json(serde_json::json!({ "active": false })),
    }
}
