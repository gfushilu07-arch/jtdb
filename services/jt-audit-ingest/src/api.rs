//! jt-audit-ingest HTTP API。

use crate::store::AuditStore;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use jt_crypto_api::Digest256 as _;
use jt_crypto_sm::Sm3Digest;
use serde::Deserialize;
use std::sync::Arc;

pub struct AppState {
    pub store: Arc<AuditStore>,
}

async fn health() -> &'static str {
    "ok"
}

async fn ingest_event(
    State(app): State<Arc<AppState>>,
    Json(req): Json<IngestEventReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let event_str = serde_json::to_string(&req.event).unwrap_or_default();
    let dg = Sm3Digest;
    let computed = hex::encode(dg.digest(event_str.as_bytes()));
    if computed != req.event_hash {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "hash mismatch", "expected": computed, "got": req.event_hash })),
        ));
    }
    let seq = app.store.append(&req.source, &req.event, &req.event_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))))?;
    Ok(Json(serde_json::json!({ "ack": true, "seq": seq, "status": "Received" })))
}

#[derive(Deserialize)]
pub struct IngestEventReq {
    pub source: String,
    pub event: serde_json::Value,
    pub event_hash: String,
}

#[derive(Deserialize)]
pub struct BatchIngestReq {
    pub source: String,
    pub events: Vec<serde_json::Value>,
    pub event_hashes: Vec<String>,
}

async fn ingest_batch(
    State(app): State<Arc<AppState>>,
    Json(req): Json<BatchIngestReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if req.events.len() != req.event_hashes.len() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "length mismatch" }))));
    }
    let mut acked = Vec::new();
    for (event, hash) in req.events.iter().zip(req.event_hashes.iter()) {
        let event_str = serde_json::to_string(event).unwrap_or_default();
        let dg = Sm3Digest;
        let computed = hex::encode(dg.digest(event_str.as_bytes()));
        if computed != *hash {
            return Err((StatusCode::CONFLICT, Json(serde_json::json!({ "error": "hash mismatch" }))));
        }
        match app.store.append(&req.source, event, hash) {
            Ok(seq) => acked.push(serde_json::json!({ "seq": seq })),
            Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() })))),
        }
    }
    Ok(Json(serde_json::json!({ "acked_count": acked.len(), "acks": acked })))
}

async fn stats(State(app): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "total_events": app.store.count() }))
}

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/ingest/event", post(ingest_event))
        .route("/v1/ingest/batch", post(ingest_batch))
        .route("/v1/stats", get(stats))
        .with_state(app)
}
