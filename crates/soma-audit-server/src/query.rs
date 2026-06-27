use axum::{
    extract::{Query, Request, State},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use soma_audit_pg::{AuditRecord, ListFilter, VerifyResult};

use crate::{auth::check_admin_auth, error::ApiError, state::AppState};

#[derive(Deserialize)]
pub struct ListParams {
    pub tenant_id: Uuid,
    pub event_type: Option<String>,
    pub source_service: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub cursor: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct ListResponse {
    pub items: Vec<AuditRecord>,
    pub next_cursor: Option<i64>,
}

pub async fn list_events(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
    req: Request,
) -> Result<Json<ListResponse>, ApiError> {
    check_admin_auth(&state, &req)?;

    let limit = params.limit.unwrap_or(100).clamp(1, 500);
    let filter = ListFilter {
        event_type: params.event_type.as_deref(),
        source_service: params.source_service.as_deref(),
        from: params.from,
        to: params.to,
        cursor: params.cursor,
    };
    let (items, next_cursor) = state
        .sink
        .list(params.tenant_id, filter, limit)
        .await
        .map_err(|e| {
            tracing::error!("failed to list events: {e}");
            ApiError::Internal
        })?;

    Ok(Json(ListResponse { items, next_cursor }))
}

#[derive(Deserialize)]
pub struct GlobalListParams {
    pub event_type: Option<String>,
    pub source_service: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub cursor: Option<i64>,
    pub limit: Option<i64>,
}

pub async fn list_global(
    State(state): State<AppState>,
    Query(params): Query<GlobalListParams>,
    req: Request,
) -> Result<Json<ListResponse>, ApiError> {
    check_admin_auth(&state, &req)?;

    let limit = params.limit.unwrap_or(100).clamp(1, 500);
    let filter = ListFilter {
        event_type: params.event_type.as_deref(),
        source_service: params.source_service.as_deref(),
        from: params.from,
        to: params.to,
        cursor: params.cursor,
    };
    let (items, next_cursor) = state.sink.list_global(filter, limit).await.map_err(|e| {
        tracing::error!("failed to list global events: {e}");
        ApiError::Internal
    })?;

    Ok(Json(ListResponse { items, next_cursor }))
}

#[derive(Deserialize)]
pub struct VerifyParams {
    pub tenant_id: Uuid,
}

pub async fn verify_chain(
    State(state): State<AppState>,
    Query(params): Query<VerifyParams>,
    req: Request,
) -> Result<Json<VerifyResult>, ApiError> {
    check_admin_auth(&state, &req)?;

    let result = state.sink.verify(params.tenant_id).await.map_err(|e| {
        tracing::error!("failed to verify chain: {e}");
        ApiError::Internal
    })?;

    Ok(Json(result))
}

#[derive(Serialize)]
pub struct JwkKey {
    pub kid: &'static str,
    pub kty: &'static str,
    pub crv: &'static str,
    pub x: String,
}

#[derive(Serialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

pub async fn get_keys(
    State(state): State<AppState>,
    req: Request,
) -> Result<Json<JwksResponse>, ApiError> {
    check_admin_auth(&state, &req)?;

    let key_bytes = state.keys.verifying_key().to_bytes();
    let x = URL_SAFE_NO_PAD.encode(key_bytes);

    Ok(Json(JwksResponse {
        keys: vec![JwkKey {
            kid: "soma-audit-v1",
            kty: "OKP",
            crv: "Ed25519",
            x,
        }],
    }))
}
