use axum::{
    extract::{Query, Request, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{auth::check_admin_auth, error::ApiError, state::AppState};

#[derive(Deserialize)]
pub struct MintKeyRequest {
    pub source_service: String,
    pub tenant_id: Uuid,
}

#[derive(Serialize)]
pub struct MintKeyResponse {
    pub key: String,
    pub source_service: String,
    pub tenant_id: Uuid,
}

/// POST /v1/sources/keys — mint (or rotate) a per-source ingest key.
/// Admin auth required.
/// Returns the plaintext key ONCE — it is never stored.
pub async fn mint_key(
    State(state): State<AppState>,
    req: Request,
) -> Result<impl IntoResponse, ApiError> {
    check_admin_auth(&state, &req)?;

    let (_, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| ApiError::BadRequest("failed to read body".into()))?;
    let payload: MintKeyRequest = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Generate 32 random bytes, hex-encode as the plaintext key.
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let plaintext: String = raw.iter().map(|b| format!("{b:02x}")).collect();

    // Hash with SHA-256 — only the hash is stored.
    let hash_bytes = Sha256::digest(plaintext.as_bytes());
    let key_hash: String = hash_bytes.iter().map(|b| format!("{b:02x}")).collect();

    sqlx::query(
        "INSERT INTO soma_audit.source_keys (source_service, tenant_id, key_hash) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (source_service, tenant_id) \
         DO UPDATE SET key_hash = EXCLUDED.key_hash, revoked_at = NULL, created_at = now()",
    )
    .bind(&payload.source_service)
    .bind(payload.tenant_id)
    .bind(&key_hash)
    .execute(state.sink.pool())
    .await
    .map_err(|e| {
        tracing::error!("mint_key insert: {e}");
        ApiError::Internal
    })?;

    Ok((
        StatusCode::OK,
        Json(MintKeyResponse {
            key: plaintext,
            source_service: payload.source_service,
            tenant_id: payload.tenant_id,
        }),
    ))
}

#[derive(Deserialize)]
pub struct RevokeKeyParams {
    pub source_service: String,
    pub tenant_id: Uuid,
}

/// DELETE /v1/sources/keys — revoke a per-source ingest key.
/// Admin auth required.
pub async fn revoke_key(
    State(state): State<AppState>,
    Query(params): Query<RevokeKeyParams>,
    req: Request,
) -> Result<impl IntoResponse, ApiError> {
    check_admin_auth(&state, &req)?;

    sqlx::query(
        "UPDATE soma_audit.source_keys \
         SET revoked_at = now() \
         WHERE source_service = $1 AND tenant_id = $2 AND revoked_at IS NULL",
    )
    .bind(&params.source_service)
    .bind(params.tenant_id)
    .execute(state.sink.pool())
    .await
    .map_err(|e| {
        tracing::error!("revoke_key update: {e}");
        ApiError::Internal
    })?;

    Ok(StatusCode::NO_CONTENT)
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

    fn test_db_url() -> Option<String> {
        std::env::var("TEST_DATABASE_URL").ok()
    }

    async fn make_state(pool: sqlx::PgPool) -> crate::state::AppState {
        let keys = Arc::new(AuditKeys::from_secret([0xab; 32], [0xcd; 32]));
        let sink = Arc::new(LocalSink::new(pool, keys.clone(), "test-svc"));
        crate::state::AppState {
            sink,
            keys,
            ingest_secret: "test-ingest-secret".into(),
            admin_token: "test-admin-token".into(),
        }
    }

    async fn mint_key_via_api(
        app: &axum::Router,
        source_service: &str,
        tenant_id: Uuid,
    ) -> (StatusCode, serde_json::Value) {
        let body = serde_json::json!({
            "source_service": source_service,
            "tenant_id": tenant_id,
        });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/sources/keys")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-admin-token")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn post_event_with_key(
        app: &axum::Router,
        bearer: &str,
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
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn test_mint_key_via_admin_endpoint() {
        let Some(url) = test_db_url() else {
            eprintln!("SKIP test_mint_key_via_admin_endpoint: TEST_DATABASE_URL not set");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect");
        soma_audit_pg::install(&pool).await.expect("install");

        let state = make_state(pool).await;
        let app = crate::routes::router(state, &[]);

        let tenant_id = Uuid::new_v4();
        let (status, json) = mint_key_via_api(&app, "svc-mint-test", tenant_id).await;
        assert_eq!(status, StatusCode::OK);
        let key = json["key"].as_str().expect("key field missing");
        assert_eq!(key.len(), 64, "key should be 32 bytes hex-encoded (64 chars)");
        assert_eq!(json["source_service"].as_str(), Some("svc-mint-test"));
        assert_eq!(json["tenant_id"].as_str(), Some(tenant_id.to_string().as_str()));
    }

    #[tokio::test]
    async fn test_ingest_with_per_source_key_correct_source() {
        let Some(url) = test_db_url() else {
            eprintln!(
                "SKIP test_ingest_with_per_source_key_correct_source: TEST_DATABASE_URL not set"
            );
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect");
        soma_audit_pg::install(&pool).await.expect("install");

        let state = make_state(pool).await;
        let app = crate::routes::router(state, &[]);

        let tenant_id = Uuid::new_v4();
        let (status, json) = mint_key_via_api(&app, "svc-correct", tenant_id).await;
        assert_eq!(status, StatusCode::OK);
        let key = json["key"].as_str().unwrap().to_string();

        let ingest_status = post_event_with_key(&app, &key, "svc-correct", tenant_id).await;
        assert_eq!(ingest_status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_ingest_with_per_source_key_wrong_source_is_forbidden() {
        let Some(url) = test_db_url() else {
            eprintln!(
                "SKIP test_ingest_with_per_source_key_wrong_source_is_forbidden: TEST_DATABASE_URL not set"
            );
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect");
        soma_audit_pg::install(&pool).await.expect("install");

        let state = make_state(pool).await;
        let app = crate::routes::router(state, &[]);

        let tenant_id = Uuid::new_v4();
        let (status, json) = mint_key_via_api(&app, "svc-bound", tenant_id).await;
        assert_eq!(status, StatusCode::OK);
        let key = json["key"].as_str().unwrap().to_string();

        // Try to post as a different service — impersonation attempt.
        let ingest_status = post_event_with_key(&app, &key, "svc-other", tenant_id).await;
        assert_eq!(ingest_status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_ingest_with_per_source_key_wrong_tenant_is_forbidden() {
        let Some(url) = test_db_url() else {
            eprintln!(
                "SKIP test_ingest_with_per_source_key_wrong_tenant_is_forbidden: TEST_DATABASE_URL not set"
            );
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect");
        soma_audit_pg::install(&pool).await.expect("install");

        let state = make_state(pool).await;
        let app = crate::routes::router(state, &[]);

        let tenant_id = Uuid::new_v4();
        let other_tenant = Uuid::new_v4();
        let (status, json) = mint_key_via_api(&app, "svc-tenant-bound", tenant_id).await;
        assert_eq!(status, StatusCode::OK);
        let key = json["key"].as_str().unwrap().to_string();

        // Same service but wrong tenant.
        let ingest_status =
            post_event_with_key(&app, &key, "svc-tenant-bound", other_tenant).await;
        assert_eq!(ingest_status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_ingest_with_master_secret_still_works() {
        let Some(url) = test_db_url() else {
            eprintln!(
                "SKIP test_ingest_with_master_secret_still_works: TEST_DATABASE_URL not set"
            );
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect");
        soma_audit_pg::install(&pool).await.expect("install");

        let state = make_state(pool).await;
        let app = crate::routes::router(state, &[]);

        let tenant_id = Uuid::new_v4();
        let status =
            post_event_with_key(&app, "test-ingest-secret", "any-svc", tenant_id).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_ingest_with_bogus_key_is_unauthorized() {
        let Some(url) = test_db_url() else {
            eprintln!(
                "SKIP test_ingest_with_bogus_key_is_unauthorized: TEST_DATABASE_URL not set"
            );
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect");
        soma_audit_pg::install(&pool).await.expect("install");

        let state = make_state(pool).await;
        let app = crate::routes::router(state, &[]);

        let tenant_id = Uuid::new_v4();
        let status = post_event_with_key(&app, "totally-bogus-key", "svc", tenant_id).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_revoke_key_then_ingest_is_unauthorized() {
        let Some(url) = test_db_url() else {
            eprintln!(
                "SKIP test_revoke_key_then_ingest_is_unauthorized: TEST_DATABASE_URL not set"
            );
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect");
        soma_audit_pg::install(&pool).await.expect("install");

        let state = make_state(pool).await;
        let app = crate::routes::router(state, &[]);

        let tenant_id = Uuid::new_v4();
        let (status, json) = mint_key_via_api(&app, "svc-to-revoke", tenant_id).await;
        assert_eq!(status, StatusCode::OK);
        let key = json["key"].as_str().unwrap().to_string();

        // Confirm it works before revocation.
        let before = post_event_with_key(&app, &key, "svc-to-revoke", tenant_id).await;
        assert_eq!(before, StatusCode::CREATED);

        // Revoke via DELETE /v1/sources/keys.
        let req = Request::builder()
            .method("DELETE")
            .uri(format!(
                "/v1/sources/keys?source_service=svc-to-revoke&tenant_id={}",
                tenant_id
            ))
            .header(header::AUTHORIZATION, "Bearer test-admin-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Now it should fail.
        let after = post_event_with_key(&app, &key, "svc-to-revoke", tenant_id).await;
        assert_eq!(after, StatusCode::UNAUTHORIZED);
    }
}
