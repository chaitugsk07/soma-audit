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
    ///
    /// // ponytail: each batch holds a Postgres transaction open for the duration
    /// // of the HTTP POSTs (one per row). Keep batch_size modest (≤50) to bound
    /// // lock-hold time. For a batch of 50 at 30 s timeout each, worst-case is
    /// // ~25 min — tune batch_size and the HTTP timeout together.
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
pub(crate) struct OutboxRow {
    pub(crate) id: i64,
    pub(crate) payload: serde_json::Value,
    pub(crate) attempts: i32,
}

/// Spawn the background relay loop.
///
/// The task polls `soma_audit_outbox.events` for undelivered rows, POSTs each
/// payload to `{central_url}/internal/v1/events`, and marks the row delivered
/// on success (HTTP 2xx or 409). Transient failures increment `attempts`,
/// record `last_error`, and schedule a retry via exponential backoff
/// (`next_retry_at`). The task never crashes on transient errors.
///
/// The returned [`tokio::task::JoinHandle`] can be dropped to let the task run
/// as a detached background loop, or awaited for graceful shutdown.
pub fn spawn_relay(pool: PgPool, cfg: RelayConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(relay_loop(pool, cfg))
}

async fn relay_loop(pool: PgPool, cfg: RelayConfig) {
    // Bug 3 fix: build the client once with explicit timeouts so a hung central
    // server cannot stall the relay task indefinitely.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build reqwest client");

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
    // Bug 1 fix: open an explicit transaction so FOR UPDATE SKIP LOCKED holds
    // the row locks for the duration of processing. Without this the locks are
    // released immediately after the autocommit SELECT returns, letting two
    // concurrent relay tasks grab the same rows.
    //
    // The transaction stays open across the HTTP POSTs for this batch. With the
    // default batch_size of 50 and a 30 s per-request HTTP timeout this is
    // acceptable for a background task; see the batch_size doc comment.
    let mut tx = pool.begin().await?;

    // Bug 2 fix: filter on next_retry_at so failed rows are not re-tried on
    // every poll cycle. The index on (next_retry_at) WHERE delivered_at IS NULL
    // makes this efficient.
    let rows = sqlx::query_as::<_, OutboxRow>(
        "SELECT id, payload, attempts \
         FROM soma_audit_outbox.events \
         WHERE delivered_at IS NULL \
           AND next_retry_at <= now() \
         ORDER BY id \
         LIMIT $1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(cfg.batch_size)
    .fetch_all(&mut *tx)
    .await?;

    if rows.is_empty() {
        // Nothing to do; commit the empty tx (no-op but tidy).
        tx.commit().await?;
        return Ok(());
    }

    debug!(count = rows.len(), "relaying outbox rows");

    // Lag check: warn when undelivered backlog is large.
    // ponytail: expose as a labelled metric via prometheus/opentelemetry in a future pass
    let undelivered_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM soma_audit_outbox.events WHERE delivered_at IS NULL",
    )
    .fetch_one(&mut *tx)
    .await?;
    if undelivered_count > 100 {
        warn!(
            undelivered = undelivered_count,
            "outbox lag: more than 100 undelivered audit events"
        );
    }

    for row in &rows {
        post_row(&mut tx, client, ingest_url, cfg, row).await;
    }

    tx.commit().await?;
    Ok(())
}

/// Attempt to relay a single outbox row. Never propagates errors — failures are
/// recorded in the row (with exponential backoff via `next_retry_at`) and the
/// loop continues with the next row.
async fn post_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
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
                .execute(&mut **tx)
                .await
                {
                    warn!(id = row.id, error = %e, "failed to mark outbox row delivered");
                }
            } else {
                let err_msg = format!("http {}", status.as_u16());
                record_failure(tx, row, &err_msg).await;
            }
        }
        Err(e) => {
            record_failure(tx, row, &e.to_string()).await;
        }
    }
}

/// Record a failed delivery attempt and schedule exponential backoff.
///
/// `next_retry_at` is set to `now() + 2^min(attempts, 10)` seconds, capped at
/// 1 hour (~3600 s). After 10 attempts the interval is ~17 min; it never grows
/// beyond 1 hour.
pub(crate) async fn record_failure(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &OutboxRow,
    error: &str,
) {
    // Bug 2 fix: exponential backoff via next_retry_at. SQL computes the
    // interval so there is no clock-skew between app and DB.
    warn!(id = row.id, attempts = row.attempts + 1, error, "outbox relay failed");
    if let Err(e) = sqlx::query(
        "UPDATE soma_audit_outbox.events \
         SET attempts = attempts + 1, \
             last_error = $2, \
             next_retry_at = now() + (interval '1 second' * LEAST(power(2, LEAST(attempts, 10))::int, 3600)) \
         WHERE id = $1",
    )
    .bind(row.id)
    .bind(error)
    .execute(&mut **tx)
    .await
    {
        warn!(id = row.id, error = %e, "failed to record outbox failure");
    }
}
