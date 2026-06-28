use std::sync::Arc;

use anyhow::Context;
use soma_infra::config::{env_or, require_env};
use tokio::net::TcpListener;

mod auth;
mod error;
mod ingest;
mod portal;
mod query;
mod routes;
mod seal;
mod source_keys;
mod sources;
mod state;

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    soma_infra::telemetry::init();

    let bind_addr = env_or("SOMA_AUDIT_BIND", "0.0.0.0:8080");
    let ingest_secret = require_env("SOMA_AUDIT_INGEST_SECRET")?;
    let admin_token = require_env("SOMA_AUDIT_ADMIN_TOKEN")?;

    // Comma-separated allowlist of cross-origin dashboard origins. Empty by
    // default — the bundled portal is same-origin, so no permissive CORS.
    let cors_origins: Vec<String> = std::env::var("SOMA_AUDIT_CORS_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let keys = Arc::new(soma_audit_pg::AuditKeys::from_env()?);

    let pool = soma_infra::connect_from_env()
        .await
        .context("failed to connect to database")?;

    // install() runs all soma-audit-pg migrations: the audit events table (v1)
    // and the chain-seals table (v2). Idempotent, advisory-locked.
    soma_audit_pg::install(&pool)
        .await
        .context("schema install failed")?;

    let sink = Arc::new(soma_audit_pg::LocalSink::new(
        pool.clone(),
        keys.clone(),
        "soma-audit",
    ));

    let state = AppState {
        sink,
        keys,
        ingest_secret,
        admin_token,
    };

    let sweep_state = Arc::new(state.clone());
    let sweep_pool = pool.clone();
    tokio::spawn(seal::run_seal_sweep(sweep_state, sweep_pool));

    let app = routes::router(state, &cors_origins)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();

    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    tracing::info!("soma-audit-server listening on {bind_addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            soma_infra::signal::shutdown_signal().await;
            tracing::info!("shutdown signal received");
        })
        .await
        .context("server error")?;

    Ok(())
}
