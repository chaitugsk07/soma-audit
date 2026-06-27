# soma-audit-client

Remote sink for soma-audit. Writes audit events into a durable local Postgres outbox (in the host service's own database) and relays them to a central `soma-audit-server` via a background task. Events are never lost when the central server is down — the outbox commits atomically with the business write, and the relay retries until delivery succeeds.

Use this crate instead of `soma-audit-pg` when your service should not own the audit storage — events are shipped to a shared central server operated by a platform team.

## Quickstart

### 1. Add the dependency

```toml
# Cargo.toml
soma-audit-client = { path = "../soma-audit-client" }
# or, inside the workspace:
soma-audit-client = { workspace = true }
```

### 2. Install the outbox schema at startup

```rust
soma_audit_client::install_outbox(&pool).await?;
```

Idempotent — safe to call at every startup. Creates schema `soma_audit_outbox` and table `soma_audit_outbox.events` with columns: `id` (BIGSERIAL PK), `event_id` (UUID UNIQUE), `payload` (JSONB), `created_at` (TIMESTAMPTZ), `delivered_at` (TIMESTAMPTZ), `attempts` (INT DEFAULT 0), `last_error` (TEXT); index `idx_outbox_undelivered` on `created_at WHERE delivered_at IS NULL`.

Uses soma-schema migrations under advisory lock key `6020250626000002_i64`. Pool must have `max_connections >= 2`.

### 3. Construct the sink

```rust
use soma_audit_client::RemoteSink;

let sink = RemoteSink::new(pool.clone());
```

`install_outbox` must have been called before any `enqueue` operations.

### 4. Enqueue events

**Atomic with a business transaction — preferred:**

```rust
sink.enqueue_in_tx(&event, &mut tx).await?;
```

The outbox row commits atomically with the business write. This eliminates the window where the business action commits but the audit event is lost. Idempotent on `event.idempotency_key`.

**Standalone — when there is no business transaction:**

```rust
sink.enqueue(&event).await?;
```

Uses its own connection. There is a gap between the business commit and the outbox row commit; prefer `enqueue_in_tx` when durability matters.

Note: `source_service` is not stamped by this crate. Set `event.source_service` on the `AuditEvent` before enqueuing.

### 5. Start the relay

```rust
use soma_audit_client::{spawn_relay, RelayConfig};
use std::time::Duration;

let _relay = spawn_relay(pool.clone(), RelayConfig {
    central_url: "http://soma-audit-server:8080".into(),
    ingest_secret: std::env::var("SOMA_AUDIT_INGEST_SECRET").unwrap(),
    poll_interval: Duration::from_secs(5),   // default
    batch_size: 50,                           // default
});
```

`spawn_relay` starts a Tokio background task. It polls `soma_audit_outbox.events` for undelivered rows (using `FOR UPDATE SKIP LOCKED` so multiple relay instances are safe) and `POST`s each payload to `{central_url}/internal/v1/events` with a `Bearer` token. On HTTP `2xx` or `409` (idempotent), the row is marked `delivered_at = now()`. On transient failure, `attempts` and `last_error` are updated without crashing the task.

Drop the returned `JoinHandle` to detach, or await it for graceful shutdown.

## Durability story

The outbox lives in the host service's own database. When the central server is unreachable:

1. `enqueue_in_tx` commits the outbox row together with the business write — the event exists in durable storage before the request returns.
2. The relay retries on every poll interval until the central server accepts the event.
3. Events are ordered by `created_at` per poll batch; no event is silently dropped.

Outbox rows are never deleted. `delivered_at` is set to mark them done; undelivered rows remain queryable.

## Public API

```rust
pub async fn install_outbox(pool: &PgPool) -> Result<(), ClientError>

pub struct RemoteSink { pool: PgPool }

impl RemoteSink {
    pub fn new(pool: PgPool) -> Self
    pub async fn enqueue(&self, event: &AuditEvent) -> Result<(), ClientError>
    pub async fn enqueue_in_tx(&self, event: &AuditEvent, tx: &mut Transaction<'_, Postgres>) -> Result<(), ClientError>
}

pub fn spawn_relay(pool: PgPool, cfg: RelayConfig) -> tokio::task::JoinHandle<()>

pub struct RelayConfig {
    pub central_url: String,
    pub ingest_secret: String,
    pub poll_interval: Duration,   // default: 5s
    pub batch_size: i64,           // default: 50
}

// Re-exported from soma-audit-core so you only need this crate as a direct dependency:
pub use soma_audit_core::{AuditEvent, Outcome};
```

## Error type

```rust
pub enum ClientError {
    Db(#[from] sqlx::Error),
    Schema(soma_schema::Error),
    Http(#[from] reqwest::Error),
    Serialization(#[from] serde_json::Error),
}
```

## Env vars

No env vars are read by this crate at runtime. Pass secrets (e.g. `ingest_secret`) directly into `RelayConfig` from wherever your service loads configuration. The env var `TEST_DATABASE_URL` is used only in integration tests (tests skip gracefully when absent).

## Gotchas

- **`enqueue_in_tx` vs `enqueue`**: always prefer `enqueue_in_tx` inside a business transaction — it commits the outbox row atomically with the business write, eliminating the window where the business action commits but the audit event is lost. `enqueue` has that gap.
- **Pool size**: `max_connections >= 2` is required during `install_outbox` (advisory lock + migration queries).
- **Advisory lock key**: `6020250626000002_i64` for the outbox migrations. Must not collide with other soma-schema users in the same Postgres cluster (the `soma-audit-pg` migrations use `6020250626000001_i64`).
- **HTTP 409 = success**: the relay marks a row delivered on either `2xx` or `409`. If the central server already has the event (by idempotency key), the outbox row is closed without re-inserting.
- **`FOR UPDATE SKIP LOCKED`**: multiple relay instances on the same outbox are safe — each locks a disjoint batch.
- **No auto-pruning**: outbox rows accumulate indefinitely; `delivered_at` marks them done but they are never deleted. Add your own maintenance job if table growth is a concern.
- **No exponential backoff yet**: relay failures only increment `attempts` + `last_error`; there is no `next_retry_at` or true backoff (noted as a future improvement).
- **Backlog warning**: a tracing `warn` is emitted when the undelivered backlog exceeds 100 rows.
- **`source_service` is not stamped**: set `event.source_service` before calling `enqueue` or `enqueue_in_tx`.
