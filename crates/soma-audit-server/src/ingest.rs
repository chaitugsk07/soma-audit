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

use crate::{
    auth::{authenticate_ingest, extract_bearer, IngestIdentity},
    error::ApiError,
    state::AppState,
};

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

/// Returns `true` if the string contains the ASCII Record Separator (0x1E).
///
/// The RS byte is used as the field delimiter in the canonical chain message.
/// Allowing it in free-text fields would let a caller shift field boundaries
/// and forge a colliding canonical message.
fn has_rs(s: &str) -> bool {
    s.contains('\u{1e}')
}

pub async fn post_event(
    State(state): State<AppState>,
    req: Request,
) -> Result<impl IntoResponse, ApiError> {
    // Extract bearer token before consuming the request body. AppState is
    // Clone (Arc-backed), so we pass an owned copy to authenticate_ingest,
    // keeping the future 'static as axum's Handler trait requires.
    let token = extract_bearer(&req).map(str::to_owned);
    let identity = authenticate_ingest(state.clone(), token).await?;

    let (_, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .map_err(|_| ApiError::BadRequest("failed to read body".into()))?;

    let payload: IngestRequest = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Per-source key: enforce source binding — the key may only post events
    // for its registered (source_service, tenant_id). Any mismatch is an
    // impersonation attempt and must be rejected with 403.
    if let IngestIdentity::Source { source_service, tenant_id } = &identity {
        if payload.source_service != *source_service || payload.tenant_id != *tenant_id {
            return Err(ApiError::Forbidden);
        }
    }

    // Reject any free-text field containing the RS separator (0x1E).  The
    // canonical chain message joins fields with RS; injecting it into a field
    // value would shift field boundaries and allow forging a colliding hash.
    let rs_err = ApiError::BadRequest("field contains forbidden control character".into());
    if has_rs(&payload.source_service) || has_rs(&payload.event_type) {
        return Err(rs_err);
    }
    if payload.actor_role.as_deref().is_some_and(has_rs)
        || payload.resource_type.as_deref().is_some_and(has_rs)
        || payload.resource_id.as_deref().is_some_and(has_rs)
    {
        return Err(ApiError::BadRequest(
            "field contains forbidden control character".into(),
        ));
    }

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

    // Best-effort source upsert — don't fail ingest if this errors.
    if let Err(e) = sqlx::query(
        "INSERT INTO soma_audit.sources (source_service, tenant_id) \
         VALUES ($1, $2) \
         ON CONFLICT (source_service, tenant_id) DO UPDATE SET last_seen = now()",
    )
    .bind(&event.source_service)
    .bind(event.tenant_id)
    .execute(state.sink.pool())
    .await
    {
        tracing::warn!("source upsert failed: {e}");
    }

    Ok((
        StatusCode::CREATED,
        Json(IngestResponse {
            id: record.id,
            seq_num: record.seq_num,
            entry_hash: record.entry_hash,
        }),
    ))
}
