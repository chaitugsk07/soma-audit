use axum::{
    extract::{Request, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{auth::check_admin_auth, auth::check_ingest_auth, error::ApiError, state::AppState};

#[derive(Serialize, sqlx::FromRow)]
pub struct SourceRow {
    pub source_service: String,
    pub tenant_id: Uuid,
    pub host_url: Option<String>,
    pub version: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_count: i64,
}

#[derive(Serialize)]
pub struct SourcesResponse {
    pub sources: Vec<SourceRow>,
}

pub async fn list_sources(
    State(state): State<AppState>,
    req: Request,
) -> Result<Json<SourcesResponse>, ApiError> {
    check_admin_auth(&state, &req)?;

    // COUNT needs bypass = 'on' to cross tenant boundaries in fct_audit_events.
    let mut tx = state.sink.pool().begin().await.map_err(|e| {
        tracing::error!("list_sources begin tx: {e}");
        ApiError::Internal
    })?;
    sqlx::query("SET LOCAL soma_audit.bypass = 'on'")
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("list_sources bypass: {e}");
            ApiError::Internal
        })?;

    let sources: Vec<SourceRow> = sqlx::query_as(
        r#"
        SELECT
            s.source_service,
            s.tenant_id,
            s.host_url,
            s.version,
            s.first_seen,
            s.last_seen,
            COUNT(e.id)::bigint AS event_count
        FROM soma_audit.sources s
        LEFT JOIN soma_audit.fct_audit_events e
            ON e.source_service = s.source_service AND e.tenant_id = s.tenant_id
        GROUP BY s.source_service, s.tenant_id, s.host_url, s.version, s.first_seen, s.last_seen
        ORDER BY s.last_seen DESC
        "#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("list_sources query: {e}");
        ApiError::Internal
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("list_sources commit: {e}");
        ApiError::Internal
    })?;

    Ok(Json(SourcesResponse { sources }))
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub source_service: String,
    pub tenant_id: Uuid,
    pub host_url: Option<String>,
    pub version: Option<String>,
}

pub async fn register_source(
    State(state): State<AppState>,
    req: Request,
) -> Result<axum::http::StatusCode, ApiError> {
    check_ingest_auth(&state, &req)?;

    let (_, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| ApiError::BadRequest("failed to read body".into()))?;
    let payload: RegisterRequest = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    sqlx::query(
        "INSERT INTO soma_audit.sources (source_service, tenant_id, host_url, version) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (source_service, tenant_id) DO UPDATE \
         SET host_url = EXCLUDED.host_url, version = EXCLUDED.version, last_seen = now()",
    )
    .bind(&payload.source_service)
    .bind(payload.tenant_id)
    .bind(&payload.host_url)
    .bind(&payload.version)
    .execute(state.sink.pool())
    .await
    .map_err(|e| {
        tracing::error!("register_source: {e}");
        ApiError::Internal
    })?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    pub source_service: String,
    pub tenant_id: Uuid,
}

pub async fn heartbeat(
    State(state): State<AppState>,
    req: Request,
) -> Result<axum::http::StatusCode, ApiError> {
    check_ingest_auth(&state, &req)?;

    let (_, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| ApiError::BadRequest("failed to read body".into()))?;
    let payload: HeartbeatRequest = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    sqlx::query(
        "INSERT INTO soma_audit.sources (source_service, tenant_id) \
         VALUES ($1, $2) \
         ON CONFLICT (source_service, tenant_id) DO UPDATE SET last_seen = now()",
    )
    .bind(&payload.source_service)
    .bind(payload.tenant_id)
    .execute(state.sink.pool())
    .await
    .map_err(|e| {
        tracing::error!("heartbeat: {e}");
        ApiError::Internal
    })?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
    };
    use soma_audit_pg::{AuditKeys, LocalSink};
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    fn test_db_url() -> Option<String> {
        std::env::var("TEST_DATABASE_URL").ok()
    }

    async fn make_state(pool: sqlx::PgPool) -> AppState {
        let keys = Arc::new(AuditKeys::from_secret([0xab; 32], [0xcd; 32]));
        let sink = Arc::new(LocalSink::new(pool, keys.clone(), "test-svc"));
        AppState {
            sink,
            keys,
            ingest_secret: "test-ingest-secret".into(),
            admin_token: "test-admin-token".into(),
        }
    }

    async fn post_event_raw(
        app: &axum::Router,
        ingest_secret: &str,
        source_service: &str,
        tenant_id: Uuid,
    ) -> StatusCode {
        let body = serde_json::json!({
            "source_service": source_service,
            "idempotency_key": Uuid::new_v4(),
            "tenant_id": tenant_id,
            "event_type": "test.event",
            "outcome": "success",
            "occurred_at": "2026-06-26T00:00:00Z",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/internal/v1/events")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {}", ingest_secret))
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn test_sources_discovery() {
        let Some(url) = test_db_url() else {
            eprintln!("SKIP test_sources_discovery: TEST_DATABASE_URL not set");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect");
        soma_audit_pg::install(&pool).await.expect("install");

        let state = make_state(pool).await;
        let app = crate::routes::router(state.clone(), &[]);

        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();

        // 2 services for tenant_a, 1 for tenant_b
        assert_eq!(
            post_event_raw(&app, "test-ingest-secret", "svc-alpha", tenant_a).await,
            StatusCode::CREATED
        );
        assert_eq!(
            post_event_raw(&app, "test-ingest-secret", "svc-beta", tenant_a).await,
            StatusCode::CREATED
        );
        assert_eq!(
            post_event_raw(&app, "test-ingest-secret", "svc-alpha", tenant_b).await,
            StatusCode::CREATED
        );

        // GET /v1/sources
        let req = Request::builder()
            .method("GET")
            .uri("/v1/sources")
            .header(header::AUTHORIZATION, "Bearer test-admin-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let sources = json["sources"].as_array().unwrap();

        // Filter to our test tenants
        let our_sources: Vec<_> = sources
            .iter()
            .filter(|s| {
                let tid = s["tenant_id"].as_str().unwrap_or("");
                tid == tenant_a.to_string() || tid == tenant_b.to_string()
            })
            .collect();
        assert_eq!(our_sources.len(), 3, "expected 3 source rows");

        // Check event_count
        for src in &our_sources {
            let count = src["event_count"].as_i64().unwrap();
            assert_eq!(count, 1, "each source should have 1 event");
        }
    }

    #[tokio::test]
    async fn test_register_sets_host_url() {
        let Some(url) = test_db_url() else {
            eprintln!("SKIP test_register_sets_host_url: TEST_DATABASE_URL not set");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect");
        soma_audit_pg::install(&pool).await.expect("install");

        let state = make_state(pool).await;
        let app = crate::routes::router(state.clone(), &[]);

        let tenant_id = Uuid::new_v4();

        // Register with host_url and version.
        let reg_body = serde_json::json!({
            "source_service": "svc-registered",
            "tenant_id": tenant_id,
            "host_url": "https://example.com",
            "version": "1.2.3",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/internal/v1/sources/register")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-ingest-secret")
            .body(Body::from(serde_json::to_vec(&reg_body).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // GET /v1/sources and verify host_url/version.
        let req = Request::builder()
            .method("GET")
            .uri("/v1/sources")
            .header(header::AUTHORIZATION, "Bearer test-admin-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let sources = json["sources"].as_array().unwrap();
        let found = sources.iter().find(|s| {
            s["tenant_id"].as_str() == Some(&tenant_id.to_string())
                && s["source_service"].as_str() == Some("svc-registered")
        });
        let found = found.expect("registered source not found");
        assert_eq!(found["host_url"].as_str(), Some("https://example.com"));
        assert_eq!(found["version"].as_str(), Some("1.2.3"));
    }
}
