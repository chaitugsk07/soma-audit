use std::net::IpAddr;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use soma_audit_core::Outcome;
use soma_audit_pg::AuditEvent;

use crate::{auth::check_ingest_auth, error::ApiError, state::AppState};

#[derive(Deserialize)]
pub struct IngestRequest {
    pub source_service: String,
    pub idempotency_key: Uuid,
    pub tenant_id: Uuid,
    pub event_type: String,
    pub actor_id: Option<Uuid>,
    pub actor_role: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub outcome: Outcome,
    pub actor_ip: Option<IpAddr>,
    pub occurred_at: DateTime<Utc>,
    pub metadata: Option<Value>,
}

#[derive(Serialize)]
struct IngestResponse {
    id: Uuid,
    seq_num: i64,
    entry_hash: String,
}

pub async fn post_event(
    State(state): State<AppState>,
    req: Request,
) -> Result<impl IntoResponse, ApiError> {
    check_ingest_auth(&state, &req)?;

    let (_, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .map_err(|_| ApiError::BadRequest("failed to read body".into()))?;

    let payload: IngestRequest = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let event = AuditEvent {
        source_service: payload.source_service,
        idempotency_key: payload.idempotency_key,
        tenant_id: payload.tenant_id,
        event_type: payload.event_type,
        actor_id: payload.actor_id,
        actor_role: payload.actor_role,
        resource_type: payload.resource_type,
        resource_id: payload.resource_id,
        outcome: payload.outcome,
        actor_ip: payload.actor_ip,
        occurred_at: payload.occurred_at,
        metadata: payload.metadata.unwrap_or(Value::Null),
    };

    let record = state.sink.record(&event).await.map_err(|e| {
        tracing::error!("failed to record event: {e}");
        ApiError::Internal
    })?;

    Ok((
        StatusCode::CREATED,
        Json(IngestResponse {
            id: record.id,
            seq_num: record.seq_num,
            entry_hash: record.entry_hash,
        }),
    ))
}
