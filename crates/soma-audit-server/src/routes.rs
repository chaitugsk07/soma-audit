use axum::{
    extract::DefaultBodyLimit,
    http::{HeaderName, HeaderValue, Method},
    routing::{get, post},
    Router,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    ingest::post_event,
    portal::portal_handler,
    query::{get_keys, list_events, list_global, verify_chain},
    seal::list_seals,
    source_keys::{mint_key, revoke_key},
    sources::{heartbeat, list_sources, register_source},
    state::AppState,
};

/// Build the CORS layer from a comma-separated allowlist of origins
/// (from `SOMA_AUDIT_CORS_ORIGINS`). When the list is empty, no cross-origin
/// requests are permitted — the admin portal is served same-origin from this
/// binary, so no permissive CORS is needed by default. The ingest endpoint is
/// service-to-service and never needs CORS. For production, the operator sets
/// `SOMA_AUDIT_CORS_ORIGINS` to their external dashboard origin(s).
pub fn cors_layer(allowed_origins: &[String]) -> CorsLayer {
    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
        ])
        .allow_origin(origins)
}

pub fn router(state: AppState, cors_origins: &[String]) -> Router {
    let cors = cors_layer(cors_origins);

    Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health))
        .route("/health/ready", get(health_ready))
        .route("/internal/v1/events", post(post_event))
        .route("/internal/v1/sources/register", post(register_source))
        .route("/internal/v1/heartbeat", post(heartbeat))
        .route("/v1/audit", get(list_events))
        .route("/v1/audit/global", get(list_global))
        .route("/v1/audit/verify", get(verify_chain))
        .route("/v1/audit/keys", get(get_keys))
        .route("/v1/audit/seals", get(list_seals))
        .route("/v1/sources", get(list_sources))
        .route("/v1/sources/keys", post(mint_key).delete(revoke_key))
        .fallback(portal_handler)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn health_ready(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl axum::response::IntoResponse {
    match sqlx::query("SELECT 1").execute(state.sink.pool()).await {
        Ok(_) => (axum::http::StatusCode::OK, "ok"),
        Err(_) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "db unavailable"),
    }
}
