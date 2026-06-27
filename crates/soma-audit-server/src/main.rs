use std::sync::Arc;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
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

fn init_telemetry() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let log_format = std::env::var("LOG_FORMAT").unwrap_or_default();

    if log_format == "json" {
        fmt().json().with_env_filter(filter).init();
    } else {
        fmt().with_env_filter(filter).init();
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_telemetry();

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL required")?;
    let bind_addr = std::env::var("SOMA_AUDIT_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let ingest_secret =
        std::env::var("SOMA_AUDIT_INGEST_SECRET").context("SOMA_AUDIT_INGEST_SECRET required")?;
    let admin_token =
        std::env::var("SOMA_AUDIT_ADMIN_TOKEN").context("SOMA_AUDIT_ADMIN_TOKEN required")?;

    // Comma-separated allowlist of cross-origin dashboard origins. Empty by
    // default — the bundled portal is same-origin, so no permissive CORS.
    let cors_origins: Vec<String> = std::env::var("SOMA_AUDIT_CORS_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let keys = Arc::new(soma_audit_pg::AuditKeys::from_env()?);

    let pool = PgPoolOptions::new()
        .min_connections(2)
        .connect(&database_url)
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
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
