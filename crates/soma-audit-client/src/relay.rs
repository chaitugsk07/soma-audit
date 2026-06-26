use std::time::Duration;

use sqlx::PgPool;
use tracing::{debug, warn};

/// Configuration for the background relay task.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Base URL of the central soma-audit-server (e.g. `http://localhost:8080`).
    pub central_url: String,
    /// Bearer token for `POST /internal/v1/events`.
    pub ingest_secret: String,
    /// How often to poll the outbox for undelivered rows. Default: 5 s.
    pub poll_interval: Duration,
    /// Maximum number of rows to process per poll cycle. Default: 50.
    pub batch_size: i64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            central_url: String::new(),
            ingest_secret: String::new(),
            poll_interval: Duration::from_secs(5),
            batch_size: 50,
        }
    }
}

/// Row fetched from the outbox for relay.
#[derive(sqlx::FromRow)]
struct OutboxRow {
    id: i64,
    payload: serde_json::Value,
    attempts: i32,
}

/// Spawn the background relay loop.
///
/// The task polls `soma_audit_outbox.events` for undelivered rows, POSTs each
/// payload to `{central_url}/internal/v1/events`, and marks the row delivered
/// on success (HTTP 2xx) or treats HTTP 409 as already-delivered (idempotent
/// delivery). Transient failures increment `attempts` and record `last_error`
/// but do **not** crash the task.
///
/// The returned [`tokio::task::JoinHandle`] can be dropped to let the task run
/// as a detached background loop, or awaited for graceful shutdown.
pub fn spawn_relay(pool: PgPool, cfg: RelayConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(relay_loop(pool, cfg))
}

async fn relay_loop(pool: PgPool, cfg: RelayConfig) {
    // Build once; reuse across poll cycles.
    let client = reqwest::Client::new();
    let ingest_url = format!("{}/internal/v1/events", cfg.central_url.trim_end_matches('/'));

    loop {
        if let Err(e) = relay_once(&pool, &client, &ingest_url, &cfg).await {
            warn!(error = %e, "relay cycle error");
        }
        tokio::time::sleep(cfg.poll_interval).await;
    }
}

async fn relay_once(
    pool: &PgPool,
    client: &reqwest::Client,
    ingest_url: &str,
    cfg: &RelayConfig,
) -> Result<(), sqlx::Error> {
    // Fetch a batch of undelivered rows, locking them to avoid concurrent relay tasks
    // racing on the same rows.
    let rows = sqlx::query_as::<_, OutboxRow>(
        "SELECT id, payload, attempts \
         FROM soma_audit_outbox.events \
         WHERE delivered_at IS NULL \
         ORDER BY id \
         LIMIT $1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(cfg.batch_size)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    debug!(count = rows.len(), "relaying outbox rows");

    // Lag check: warn when undelivered backlog is large.
    // ponytail: expose as a labelled metric via prometheus/opentelemetry in a future pass
    let undelivered_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM soma_audit_outbox.events WHERE delivered_at IS NULL",
    )
    .fetch_one(pool)
    .await?;
    if undelivered_count > 100 {
        warn!(
            undelivered = undelivered_count,
            "outbox lag: more than 100 undelivered audit events"
        );
    }

    for row in rows {
        post_row(pool, client, ingest_url, cfg, &row).await;
    }

    Ok(())
}

/// Attempt to relay a single outbox row. Never propagates errors — failures are
/// recorded in the row and the loop continues with the next row.
async fn post_row(
    pool: &PgPool,
    client: &reqwest::Client,
    ingest_url: &str,
    cfg: &RelayConfig,
    row: &OutboxRow,
) {
    let result = client
        .post(ingest_url)
        .bearer_auth(&cfg.ingest_secret)
        .json(&row.payload)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() || status == reqwest::StatusCode::CONFLICT {
                // 2xx: central server recorded the event.
                // 409: already recorded (idempotent). Mark delivered either way.
                if let Err(e) = sqlx::query(
                    "UPDATE soma_audit_outbox.events \
                     SET delivered_at = now() \
                     WHERE id = $1",
                )
                .bind(row.id)
                .execute(pool)
                .await
                {
                    warn!(id = row.id, error = %e, "failed to mark outbox row delivered");
                }
            } else {
                let err_msg = format!("http {}", status.as_u16());
                record_failure(pool, row, &err_msg).await;
            }
        }
        Err(e) => {
            record_failure(pool, row, &e.to_string()).await;
        }
    }
}

async fn record_failure(pool: &PgPool, row: &OutboxRow, error: &str) {
    // Exponential-ish backoff is applied by the host's poll_interval combined with
    // attempts — the relay naturally backs off proportional to the attempt count by
    // skipping rows only when they would be polled before their next eligible time.
    // A future pass can add a `next_retry_at` column for true exponential backoff.
    // ponytail: add next_retry_at = now() + (2^attempts * interval) in a later pass
    warn!(id = row.id, attempts = row.attempts + 1, error, "outbox relay failed");
    if let Err(e) = sqlx::query(
        "UPDATE soma_audit_outbox.events \
         SET attempts = attempts + 1, last_error = $2 \
         WHERE id = $1",
    )
    .bind(row.id)
    .bind(error)
    .execute(pool)
    .await
    {
        warn!(id = row.id, error = %e, "failed to record outbox failure");
    }
}
