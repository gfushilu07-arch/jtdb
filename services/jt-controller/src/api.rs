//! jt-controller HTTP API（docs/02 §2.3）。
//!
//! 接口面：`register / health / lifecycle / generation / config lease`。
//! 控制平面**不持有明文数据密钥**——配置租约入口拒绝密钥类键。

use crate::registry::{
    ComponentKind, ComponentRecord, ComponentState, ConfigLease, Controller, ControllerError,
    Generation, NodeId, TimelineRecord,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// 应用状态。
pub struct AppState {
    pub controller: Arc<Controller>,
    /// 鉴权 token（None = 不鉴权，仅限本机绑定）。
    pub auth_token: Option<String>,
    /// 时间源（测试可注入）。
    pub clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl AppState {
    pub fn now(&self) -> u64 {
        (self.clock)()
    }
}

/// 统一错误响应（把 ControllerError 映射为 HTTP 状态码）。
pub struct ApiError(ControllerError);

impl From<ControllerError> for ApiError {
    fn from(e: ControllerError) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let code = match &self.0 {
            ControllerError::NotFound(_) | ControllerError::TimelineNotFound => {
                StatusCode::NOT_FOUND
            }
            ControllerError::StaleGeneration { .. } => StatusCode::CONFLICT,
            ControllerError::NodeOffline(_) => StatusCode::CONFLICT,
            ControllerError::TimelineExists | ControllerError::ParentNotFound => {
                StatusCode::CONFLICT
            }
            ControllerError::KeyMaterialNotAllowed(_) | ControllerError::InvalidArgument(_) => {
                StatusCode::BAD_REQUEST
            }
            // 围栏不可写 = 控制平面无法保证防脑裂 → 服务不可用
            ControllerError::Fence(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            code,
            Json(serde_json::json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

async fn health() -> &'static str {
    "ok"
}

// ---- register ----

#[derive(Deserialize)]
pub struct RegisterReq {
    pub node_id: u64,
    pub kind: String,
    pub address: String,
    #[serde(default)]
    pub attestation_digest: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResp {
    pub node_id: u64,
    pub kind: String,
    pub generation: u64,
    pub state: ComponentState,
    pub address: String,
    pub registered_at: u64,
}

impl From<ComponentRecord> for RegisterResp {
    fn from(r: ComponentRecord) -> Self {
        Self {
            node_id: r.node_id.0,
            kind: r.kind.as_str().to_string(),
            generation: r.generation.0,
            state: r.state,
            address: r.address,
            registered_at: r.registered_at,
        }
    }
}

fn parse_kind(s: &str) -> Result<ComponentKind, ApiError> {
    let k = match s {
        "pageserver" => ComponentKind::Pageserver,
        "safekeeper" => ComponentKind::Safekeeper,
        "compute" => ComponentKind::Compute,
        "gateway" => ComponentKind::Gateway,
        "kms" => ComponentKind::Kms,
        "pdp" => ComponentKind::Pdp,
        "attest" => ComponentKind::Attest,
        "audit-ingest" => ComponentKind::AuditIngest,
        "audit-store" => ComponentKind::AuditStore,
        "tsa" => ComponentKind::Tsa,
        other => {
            return Err(bad_request(format!("unknown component kind: {other}")));
        }
    };
    Ok(k)
}

fn bad_request(msg: String) -> ApiError {
    ApiError(ControllerError::InvalidArgument(msg))
}

async fn register(
    State(app): State<Arc<AppState>>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<RegisterResp>, ApiError> {
    let kind = parse_kind(&req.kind)?;
    let rec = app.controller.register(
        NodeId(req.node_id),
        kind,
        &req.address,
        req.attestation_digest,
        app.now(),
    )?;
    Ok(Json(rec.into()))
}

// ---- heartbeat ----

#[derive(Deserialize)]
pub struct HeartbeatReq {
    pub node_id: u64,
    pub generation: u64,
}

async fn heartbeat(
    State(app): State<Arc<AppState>>,
    Json(req): Json<HeartbeatReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let state = app
        .controller
        .heartbeat(&NodeId(req.node_id), Generation(req.generation), app.now())?;
    Ok(Json(serde_json::json!({ "state": state })))
}

// ---- lifecycle ----

#[derive(Deserialize)]
pub struct DeregisterReq {
    pub node_id: u64,
}

async fn deregister(
    State(app): State<Arc<AppState>>,
    Json(req): Json<DeregisterReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    app.controller.deregister(&NodeId(req.node_id), app.now())?;
    Ok(Json(serde_json::json!({ "state": ComponentState::Offline })))
}

async fn list_components(
    State(app): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let kind = match q.get("kind") {
        Some(k) => Some(parse_kind(k)?),
        None => None,
    };
    let list: Vec<RegisterResp> = app
        .controller
        .list_components(kind)
        .into_iter()
        .map(RegisterResp::from)
        .collect();
    Ok(Json(serde_json::json!({ "components": list })))
}

// ---- generation ----

/// 换代 timeline 的服务 generation。
///
/// timeline_id 取自路径，不再要求请求体——同一标识有两个来源就会有
/// 两者不一致的写法，控制平面上这种歧义必须消除。
async fn bump_generation(
    State(app): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tl = parse_timeline_id(&id)?;
    let g = app.controller.bump_timeline_generation(&tl, app.now())?;
    Ok(Json(serde_json::json!({ "serving_generation": g.0 })))
}

// ---- timeline ----

#[derive(Deserialize)]
pub struct CreateTimelineReq {
    pub timeline_id: String,
    pub tenant_id: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub branch_lsn: Option<u64>,
    #[serde(default)]
    pub serving_generation: Option<u64>,
}

#[derive(Serialize)]
pub struct TimelineResp {
    pub timeline_id: String,
    pub tenant_id: String,
    pub parent: Option<String>,
    pub branch_lsn: Option<u64>,
    pub serving_generation: u64,
}

impl From<TimelineRecord> for TimelineResp {
    fn from(r: TimelineRecord) -> Self {
        Self {
            timeline_id: hex::encode(r.timeline_id),
            tenant_id: r.tenant_id,
            parent: r.parent.map(hex::encode),
            branch_lsn: r.branch_lsn,
            serving_generation: r.serving_generation.0,
        }
    }
}

fn parse_timeline_id(s: &str) -> Result<[u8; 16], ApiError> {
    let bytes = hex::decode(s).map_err(|e| bad_request(format!("bad timeline id: {e}")))?;
    <[u8; 16]>::try_from(bytes.as_slice())
        .map_err(|_| bad_request("timeline id must be 16 bytes (32 hex chars)".into()))
}

async fn create_timeline(
    State(app): State<Arc<AppState>>,
    Json(req): Json<CreateTimelineReq>,
) -> Result<Json<TimelineResp>, ApiError> {
    let tl = parse_timeline_id(&req.timeline_id)?;
    let parent = match &req.parent {
        Some(p) => Some(parse_timeline_id(p)?),
        None => None,
    };
    let rec = app.controller.create_timeline(
        tl,
        &req.tenant_id,
        parent,
        req.branch_lsn,
        Generation(req.serving_generation.unwrap_or(1)),
        app.now(),
    )?;
    Ok(Json(rec.into()))
}

async fn get_timeline(
    State(app): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<TimelineResp>, ApiError> {
    let tl = parse_timeline_id(&id)?;
    let rec = app
        .controller
        .get_timeline(&tl)
        .ok_or(ControllerError::TimelineNotFound)?;
    Ok(Json(rec.into()))
}

// ---- config lease ----

#[derive(Deserialize)]
pub struct ConfigLeaseReq {
    pub node_id: u64,
    pub generation: u64,
    pub config: HashMap<String, String>,
    pub ttl_secs: u64,
}

#[derive(Serialize)]
pub struct ConfigLeaseResp {
    pub node_id: u64,
    pub generation: u64,
    pub config_version: u64,
    pub config: HashMap<String, String>,
    pub issued_at: u64,
    pub ttl_secs: u64,
}

impl From<ConfigLease> for ConfigLeaseResp {
    fn from(l: ConfigLease) -> Self {
        Self {
            node_id: l.node_id.0,
            generation: l.generation.0,
            config_version: l.config_version,
            config: l.config,
            issued_at: l.issued_at,
            ttl_secs: l.ttl_secs,
        }
    }
}

async fn issue_config_lease(
    State(app): State<Arc<AppState>>,
    Json(req): Json<ConfigLeaseReq>,
) -> Result<Json<ConfigLeaseResp>, ApiError> {
    let lease = app.controller.issue_config_lease(
        &NodeId(req.node_id),
        Generation(req.generation),
        req.config,
        req.ttl_secs,
        app.now(),
    )?;
    Ok(Json(lease.into()))
}

#[derive(Deserialize)]
pub struct RenewLeaseReq {
    pub node_id: u64,
    pub generation: u64,
    pub ttl_secs: u64,
}

async fn renew_config_lease(
    State(app): State<Arc<AppState>>,
    Json(req): Json<RenewLeaseReq>,
) -> Result<Json<ConfigLeaseResp>, ApiError> {
    let lease = app.controller.renew_config_lease(
        &NodeId(req.node_id),
        Generation(req.generation),
        app.now(),
        req.ttl_secs,
    )?;
    Ok(Json(lease.into()))
}

async fn get_config_lease(
    State(app): State<Arc<AppState>>,
    Path(node_id): Path<u64>,
) -> Result<Json<ConfigLeaseResp>, ApiError> {
    let lease = app
        .controller
        .get_config_lease(&NodeId(node_id))
        .ok_or(ControllerError::NotFound(NodeId(node_id)))?;
    Ok(Json(lease.into()))
}

// ---- sweep（生命周期：心跳超时转 Suspect）----

async fn sweep(State(app): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let suspects: Vec<u64> = app
        .controller
        .sweep_heartbeats(app.now())
        .into_iter()
        .map(|n| n.0)
        .collect();
    Json(serde_json::json!({ "suspects": suspects }))
}

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/components", get(list_components))
        .route("/v1/components/register", post(register))
        .route("/v1/components/heartbeat", post(heartbeat))
        .route("/v1/components/deregister", post(deregister))
        .route("/v1/components/sweep", post(sweep))
        .route("/v1/timelines", post(create_timeline))
        .route("/v1/timelines/{id}", get(get_timeline))
        .route("/v1/timelines/{id}/generation", post(bump_generation))
        .route("/v1/config-lease", post(issue_config_lease))
        .route("/v1/config-lease/renew", post(renew_config_lease))
        .route("/v1/config-lease/{node_id}", get(get_config_lease))
        .with_state(app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    fn test_app(now: u64) -> Arc<AppState> {
        Arc::new(AppState {
            controller: Arc::new(Controller::new(30)),
            auth_token: None,
            clock: Box::new(move || now),
        })
    }

    async fn call(
        app: Arc<AppState>,
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = router(app).oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let val = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, val)
    }

    #[tokio::test]
    async fn register_then_heartbeat_roundtrip() {
        let app = test_app(1000);
        let (st, v) = call(
            app.clone(),
            "POST",
            "/v1/components/register",
            serde_json::json!({
                "node_id": 1, "kind": "pageserver", "address": "127.0.0.1:64000"
            }),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["generation"], 1);

        let (st, v) = call(
            app.clone(),
            "POST",
            "/v1/components/heartbeat",
            serde_json::json!({ "node_id": 1, "generation": 1 }),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["state"], "Active");

        // 旧代心跳 → 409
        let (st, _) = call(
            app,
            "POST",
            "/v1/components/heartbeat",
            serde_json::json!({ "node_id": 1, "generation": 99 }),
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn unknown_kind_is_bad_request() {
        let app = test_app(1000);
        let (st, v) = call(
            app,
            "POST",
            "/v1/components/register",
            serde_json::json!({ "node_id": 1, "kind": "warp-drive", "address": "a" }),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(v["error"].as_str().unwrap().contains("unknown component kind"));
    }

    #[tokio::test]
    async fn config_lease_rejects_key_material_over_http() {
        let app = test_app(1000);
        call(
            app.clone(),
            "POST",
            "/v1/components/register",
            serde_json::json!({ "node_id": 1, "kind": "pageserver", "address": "a" }),
        )
        .await;
        let (st, v) = call(
            app.clone(),
            "POST",
            "/v1/config-lease",
            serde_json::json!({
                "node_id": 1, "generation": 1, "ttl_secs": 300,
                "config": { "dek_hex": "deadbeef" }
            }),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(v["error"].as_str().unwrap().contains("key material"));

        // 普通配置通过
        let (st, v) = call(
            app,
            "POST",
            "/v1/config-lease",
            serde_json::json!({
                "node_id": 1, "generation": 1, "ttl_secs": 300,
                "config": { "max_connections": "100" }
            }),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["config_version"], 1);
    }

    #[tokio::test]
    async fn timeline_create_and_bump_generation() {
        let app = test_app(1000);
        let tl = hex::encode([7u8; 16]);
        let (st, v) = call(
            app.clone(),
            "POST",
            "/v1/timelines",
            serde_json::json!({ "timeline_id": tl, "tenant_id": "t1" }),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["serving_generation"], 1);

        let (st, v) = call(
            app.clone(),
            "POST",
            &format!("/v1/timelines/{tl}/generation"),
            serde_json::json!({}),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "body={v}");
        assert_eq!(v["serving_generation"], 2);

        let (st, v) = call(app, "GET", &format!("/v1/timelines/{tl}"), serde_json::Value::Null).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["serving_generation"], 2);
    }

    #[tokio::test]
    async fn bad_timeline_id_is_rejected() {
        let app = test_app(1000);
        let (st, _) = call(
            app.clone(),
            "POST",
            "/v1/timelines",
            serde_json::json!({ "timeline_id": "zz", "tenant_id": "t1" }),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        let (st, _) = call(
            app,
            "POST",
            "/v1/timelines",
            serde_json::json!({ "timeline_id": "aabb", "tenant_id": "t1" }),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "长度不足 16 字节必须拒绝");
    }

    #[tokio::test]
    async fn deregister_then_heartbeat_conflicts() {
        let app = test_app(1000);
        call(
            app.clone(),
            "POST",
            "/v1/components/register",
            serde_json::json!({ "node_id": 5, "kind": "compute", "address": "a" }),
        )
        .await;
        let (st, _) = call(
            app.clone(),
            "POST",
            "/v1/components/deregister",
            serde_json::json!({ "node_id": 5 }),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = call(
            app,
            "POST",
            "/v1/components/heartbeat",
            serde_json::json!({ "node_id": 5, "generation": 1 }),
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT, "下线节点不得靠心跳复活");
    }

    #[tokio::test]
    async fn list_components_filters_by_kind() {
        let app = test_app(1000);
        for (id, kind) in [(1u64, "pageserver"), (2, "safekeeper"), (3, "pageserver")] {
            call(
                app.clone(),
                "POST",
                "/v1/components/register",
                serde_json::json!({ "node_id": id, "kind": kind, "address": "a" }),
            )
            .await;
        }
        let (st, v) = call(
            app.clone(),
            "GET",
            "/v1/components?kind=pageserver",
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["components"].as_array().unwrap().len(), 2);

        let (_, v) = call(app, "GET", "/v1/components", serde_json::Value::Null).await;
        assert_eq!(v["components"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn health_is_ok() {
        let app = test_app(1000);
        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = router(app).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
