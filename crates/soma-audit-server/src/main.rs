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

const SEALS_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS soma_audit.audit_chain_seals (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    up_to_seq_num   BIGINT NOT NULL,
    chain_head_hash TEXT NOT NULL,
    sealed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signature       BYTEA NOT NULL,
    public_key_id   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_chain_seals_tenant_seq
    ON soma_audit.audit_chain_seals(tenant_id, up_to_seq_num DESC);
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_telemetry();

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL required")?;
    let bind_addr =
        std::env::var("SOMA_AUDIT_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let ingest_secret = std::env::var("SOMA_AUDIT_INGEST_SECRET")
        .context("SOMA_AUDIT_INGEST_SECRET required")?;
    let admin_token =
        std::env::var("SOMA_AUDIT_ADMIN_TOKEN").context("SOMA_AUDIT_ADMIN_TOKEN required")?;

    let keys = Arc::new(soma_audit_pg::AuditKeys::from_env()?);

    let pool = PgPoolOptions::new()
        .min_connections(2)
        .connect(&database_url)
        .await
        .context("failed to connect to database")?;

    soma_audit_pg::install(&pool).await.context("schema install failed")?;

    sqlx::raw_sql(SEALS_DDL).execute(&pool).await.context("seals DDL failed")?;

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

    let app =
        routes::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();

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
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
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
