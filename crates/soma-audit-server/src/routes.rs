use axum::{
    extract::DefaultBodyLimit,
    http::Method,
    routing::{get, post},
    Router,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    ingest::post_event,
    portal::portal_handler,
    query::{get_keys, list_events, verify_chain},
    seal::list_seals,
    state::AppState,
};

pub fn router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any)
        .allow_origin(Any);

    Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health))
        .route("/health/ready", get(health_ready))
        .route("/internal/v1/events", post(post_event))
        .route("/v1/audit", get(list_events))
        .route("/v1/audit/verify", get(verify_chain))
        .route("/v1/audit/keys", get(get_keys))
        .route("/v1/audit/seals", get(list_seals))
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
