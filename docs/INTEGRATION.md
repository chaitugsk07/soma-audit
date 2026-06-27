# Add audit logging to your Rust application

This guide is the canonical how-to for integrating soma-audit into a Rust service.
It covers every mode, every real API call, and the invariants that make the chain tamper-evident.

---

## 1. Choosing a mode

soma-audit offers three deployment modes.

| Mode | How events are stored | When to use |
| --- | --- | --- |
| **Local** | Written directly into the host service's own Postgres database, inside the `soma_audit` schema. | Single-service deployments, or services that own a private database and need the audit log co-located with business data. |
| **Remote** | Written to a durable local outbox table first, then relayed in the background to a central `soma-audit-server`. | Multi-service platforms where you want a single pane of glass across services. Events are never lost during server outages because the outbox is transactional. |
| **Both** | Local sink records events into the service's database; the outbox+relay also forwards them to the central server. | High-assurance platforms where you want cryptographic proof at the service level (Local) AND cross-service queryability and Ed25519-sealed snapshots at the platform level (Remote). |

**Decision rule:**

- If you have one service and one database, use **Local**.
- If you have multiple services and want a unified audit trail, use **Remote** (or **Both**).
- Use **Both** when you need the strongest tamper-evidence: a local HMAC chain proves integrity within the service's own DB, while the central server issues periodic Ed25519 seals over the chain head that can be verified even if the local DB is compromised.

---

## 2. Local mode walkthrough

### 2.1 Dependencies

Add to your service's `Cargo.toml`:

```toml
[dependencies]
soma-audit-pg   = { path = "../soma-audit-core/../soma-audit-pg" }  # adjust path for your layout
# soma-audit-pg re-exports AuditEvent, AuditRecord, Outcome, and VerifyResult,
# so you do not need soma-audit-core as a direct dependency unless you use the
# raw chain-math or Ed25519 primitives directly.
```

If you are inside the soma-audit workspace:

```toml
soma-audit-pg   = { workspace = true }
soma-audit-core = { workspace = true }  # only if you need raw primitives
```

### 2.2 Schema installation: what `install` creates

Call `soma_audit_pg::install(&pool).await?` once at service startup. It is idempotent — safe to call on every boot.

```rust
soma_audit_pg::install(&pool).await?;
```

Under the hood, `install` runs soma-audit's embedded migrations through soma-schema under the advisory lock key `6020250626000001_i64`. It creates:

**Schema:** `soma_audit`

**Table:** `soma_audit.fct_audit_events`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | `UUID` | Primary key, assigned by the sink |
| `tenant_id` | `UUID` | Required; used by the RLS policy |
| `seq_num` | `BIGINT` | Monotonically increasing per tenant; part of the HMAC chain |
| `source_service` | `TEXT` | The service that recorded the event |
| `event_type` | `TEXT` | Caller-supplied event name, e.g. `"note.create"` |
| `actor_id` | `UUID?` | Optional; the user or service account performing the action |
| `actor_role` | `TEXT?` | Optional role label |
| `resource_type` | `TEXT?` | Optional resource kind, e.g. `"note"` |
| `resource_id` | `TEXT?` | Optional resource identifier |
| `outcome` | `TEXT` | CHECK IN (`'success'`, `'denied'`, `'error'`) |
| `actor_ip` | `INET?` | Optional source IP |
| `occurred_at` | `TIMESTAMPTZ` | When the event happened (caller-supplied) |
| `metadata` | `JSONB DEFAULT '{}'` | Arbitrary structured payload |
| `prev_hash` | `TEXT?` | HMAC of the previous record in this tenant's chain |
| `entry_hash` | `TEXT` | HMAC-SHA256 of this record's canonical fields |
| `chain_epoch` | `INT DEFAULT 1` | Signals canonical-format version; bump on breaking changes |
| `idempotency_key` | `UUID` | Unique per `(tenant_id, idempotency_key)`; prevents duplicate inserts on retry |
| `created_at` | `TIMESTAMPTZ DEFAULT now()` | Wall-clock insert time |

Unique constraints: `(tenant_id, seq_num)` and `(tenant_id, idempotency_key)`.

**Row-level security:** The table has `FORCE ROW LEVEL SECURITY`. The policy `tenant_isolation` filters every read and write using the transaction-local GUC `soma_audit.tenant_id`. Any query that does not set this GUC first will see no rows. `record_in_tx` and `record` set it for you; if you query the table directly, set it with:

```sql
SELECT set_config('soma_audit.tenant_id', $1::text, true);
```

**Append-only triggers:** Two triggers (`no_update`, `no_delete`) call `soma_audit.prevent_mutation()`, which raises `EXCEPTION 'soma_audit.fct_audit_events is append-only'` on any `UPDATE` or `DELETE`. There is no soft-delete path.

**Indexes:**

- `idx_audit_tenant_seq` on `(tenant_id, seq_num DESC)` — primary read path
- `idx_audit_tenant_time` BRIN on `occurred_at` — time-range scans
- `idx_audit_tenant_event` on `(tenant_id, event_type)` — filtered event-type queries

### 2.3 The advisory lock key and why it must be unique

`install` uses soma-schema's migration runner, which holds a Postgres advisory lock for the duration of the migration run to prevent concurrent migration attempts. The lock key is `6020250626000001_i64`.

This key must be unique across every service that shares the same Postgres cluster and also uses soma-schema. The soma-schema contract is **one schema per service, one advisory lock key per service**. If two services used the same key, one migration runner could block or interfere with the other.

For the outbox migrations (Remote mode), soma-audit-client uses `6020250626000002_i64` — a different key, same cluster, no collision.

If your own service has soma-schema migrations for your business schema, you must choose a third key that differs from both of these.

Because `install` is idempotent and checksum-verified, running it from multiple instances of the same service on startup is safe: the advisory lock serializes them, and already-applied migrations are skipped.

### 2.4 Loading keys

There are three ways to load keys depending on what you are running:

**Local-only apps — `from_env_local()` (recommended for embedded use):**

```rust
use soma_audit_pg::AuditKeys;

let keys = AuditKeys::from_env_local()?;
```

`from_env_local` reads only `SOMA_AUDIT_MASTER_SECRET` (exactly 64 lowercase hex characters / 32 bytes) and generates an ephemeral Ed25519 signing key in-process. The signing key is not persisted and not needed for local-only audit: Ed25519 seals are only issued by `soma-audit-server`. Use this constructor for all apps that write events into their own database without running the central server.

**Running `soma-audit-server` — `from_env()` (both keys required):**

```rust
let keys = AuditKeys::from_env()?;
```

`from_env` reads both environment variables:

- `SOMA_AUDIT_MASTER_SECRET` — 64 lowercase hex chars (32 bytes); HKDF master for per-tenant HMAC keys.
- `SOMA_AUDIT_SIGNING_KEY` — 64 lowercase hex chars (32 bytes); Ed25519 signing key for chain seals.

If either variable is missing or not valid hex, `from_env` returns `AuditPgError::Env` with a human-readable message.

**From a secret manager (vault-sourced):**

```rust
let master_bytes: [u8; 32] = decode_from_vault("soma-audit-master")?;
let signing_bytes: [u8; 32] = decode_from_vault("soma-audit-signing")?;

let keys = AuditKeys::from_secret(master_bytes, signing_bytes);
```

`AuditKeys` zeroes both secrets on drop. Do not derive `Clone` on any struct that holds the keys by value, and do not serialize them.

### 2.5 Constructing `LocalSink`

**Multi-tenant apps:**

```rust
use std::sync::Arc;
use soma_audit_pg::{AuditKeys, LocalSink};

let keys = Arc::new(AuditKeys::from_env_local()?);
let sink = LocalSink::new(pool.clone(), keys, "my-service");
```

`source_service` (`"my-service"` above) is stamped onto every event whose own `source_service` field is empty. Events that already carry a non-empty `source_service` (for example, events arriving via the relay ingest path) are left unchanged.

**Single-tenant apps — `new_single_tenant`:**

```rust
let tenant_id = Uuid::parse_str("...your fixed tenant uuid...")?;
let sink = LocalSink::new_single_tenant(pool.clone(), keys, "my-service", tenant_id);
```

With a single-tenant sink you can use `list_default` and `verify_default` instead of passing the tenant UUID at every call site:

```rust
// No tenant_id argument needed:
let (records, next_cursor) = sink.list_default(Some("user.login"), None, 50).await?;
let result = sink.verify_default().await?;
```

When the event's `tenant_id` field is `Uuid::nil()`, the sink automatically fills in the fixed tenant. Build events with nil tenant to use the shortcut:

```rust
let event = AuditEvent::builder(Uuid::nil(), "user.login", Outcome::Success)
    .actor_id(actor_id)
    .build();
sink.record(&event).await?; // tenant is filled by the sink
```

The pool must have `max_connections >= 2`: one connection is held for the per-tenant advisory lock inside each `record_in_tx` call; at least one more is needed for the insert.

### 2.6 Building an `AuditEvent`

The recommended way is the builder, which auto-stamps `occurred_at`, `metadata`, and `idempotency_key` when you leave them out:

```rust
use soma_audit_core::{AuditEvent, Outcome, idempotency_key};
use uuid::Uuid;
use serde_json::json;

// Minimal — only the three required fields:
let event = AuditEvent::builder(tenant_id, "document.create", Outcome::Success).build();

// With optional fields:
let event = AuditEvent::builder(tenant_id, "document.create", Outcome::Success)
    .actor_id(actor_id)
    .actor_role("editor")
    .resource("document", doc_id.to_string())
    .actor_ip(req.peer_addr().map(|a| a.ip()).unwrap())
    .metadata(json!({ "title": title, "size_bytes": size }))
    .build();

// With a deterministic idempotency key (retry-safe deduplication):
let event = AuditEvent::builder(tenant_id, "document.create", Outcome::Success)
    .idempotency_key(idempotency_key(tenant_id, request_id))
    .build();
```

Builder chain reference:

| Method | Type | Notes |
| --- | --- | --- |
| `.actor_id(Uuid)` | optional | The user or service performing the action |
| `.actor_role(impl Into<String>)` | optional | Role label, e.g. `"admin"` |
| `.resource(type, id)` | optional | Resource kind + identifier |
| `.actor_ip(IpAddr)` | optional | Source IP |
| `.metadata(serde_json::Value)` | optional | Arbitrary structured payload; defaults to `{}` |
| `.occurred_at(DateTime<Utc>)` | optional | Defaults to `Utc::now()` |
| `.source_service(impl Into<String>)` | optional | Override the service name; sink fills in its own name when empty |
| `.idempotency_key(Uuid)` | optional | Defaults to a random v4 UUID; use `idempotency_key(tenant_id, request_id)` for deterministic retry-safe keys |

`Outcome` has three variants: `Success`, `Denied`, `Error`. They serialize as `"success"`, `"denied"`, `"error"` in JSON and are stored as `TEXT` with a `CHECK` constraint in Postgres.

**For reference — the underlying struct fields:**

`AuditEvent` is a plain struct with fields `source_service`, `idempotency_key`, `tenant_id`, `event_type`, `actor_id`, `actor_role`, `resource_type`, `resource_id`, `outcome`, `actor_ip`, `occurred_at`, and `metadata`. You can construct it directly if you prefer, but the builder is shorter and handles the defaults.

### 2.7 Recording events

**The atomic path — `record_in_tx`:**

This is the recommended path for any write operation. The audit row commits with your business write or not at all:

```rust
// 1. Begin a transaction that covers the business write AND the audit write.
let mut tx = pool.begin().await?;

// 2. Your business logic runs inside the transaction.
sqlx::query("INSERT INTO app.documents (id, tenant_id, content) VALUES ($1, $2, $3)")
    .bind(doc_id)
    .bind(tenant_id)
    .bind(&content)
    .execute(&mut *tx)
    .await?;

// 3. Record the audit event inside the same transaction.
//    The sink sets GUC soma_audit.tenant_id, acquires a per-tenant
//    pg_advisory_xact_lock (released automatically when the tx ends),
//    reads the chain head, seals the HMAC record, and inserts it.
//    ON CONFLICT (tenant_id, idempotency_key) DO NOTHING makes this retry-safe.
sink.record_in_tx(&event, &mut tx).await?;

// 4. A single COMMIT makes both writes permanent simultaneously.
tx.commit().await?;
```

The headline guarantee: if the transaction rolls back (application error, network drop, process crash), neither the business row nor the audit row is written. If it commits, both are written. There is no window where a business action is committed without its audit record.

**The standalone path — `record`:**

Use when there is no surrounding business transaction to join (for example, auditing a read operation after it completes):

```rust
sink.record(&event).await?;
```

`record` opens its own transaction internally, calls `record_in_tx`, and commits. The audit event is always committed in its own transaction, separate from any business state. This is a weaker guarantee: if the process crashes between the business action and the `record` call, the audit event is lost.

---

## 3. Querying and verifying the chain

### 3.1 Listing events

`list` takes a `ListFilter` struct for its optional filters:

```rust
use soma_audit_pg::{ListFilter};

// Page 1 — most recent 50 events for the tenant (no filters).
let (records, next_cursor) = sink
    .list(tenant_id, ListFilter::default(), 50)
    .await?;

// Filter to a specific event type.
let (records, next_cursor) = sink
    .list(tenant_id, ListFilter { event_type: Some("document.create"), ..Default::default() }, 50)
    .await?;

// Filter by date range and source service.
use chrono::{DateTime, Utc};
let (records, next_cursor) = sink
    .list(tenant_id, ListFilter {
        source_service: Some("orders"),
        from: Some(DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")?.with_timezone(&Utc)),
        to: Some(Utc::now()),
        ..Default::default()
    }, 100)
    .await?;

// Page 2 — pass the cursor from the previous response.
let (records, next_cursor) = sink
    .list(tenant_id, ListFilter { cursor: next_cursor, ..Default::default() }, 50)
    .await?;
```

`ListFilter` fields:

| Field | Type | Filters on |
| --- | --- | --- |
| `event_type` | `Option<&str>` | Exact match on `event_type` |
| `source_service` | `Option<&str>` | Exact match on `source_service` |
| `from` | `Option<DateTime<Utc>>` | `occurred_at >= from` |
| `to` | `Option<DateTime<Utc>>` | `occurred_at <= to` |
| `cursor` | `Option<i64>` | Keyset: `seq_num < cursor` (for next-page pagination) |

Results are returned in descending `seq_num` order (newest first). `limit` is clamped to 1–500. `next_cursor` is `Some(seq_num)` when more pages exist, `None` on the last page.

`list` sets the `soma_audit.tenant_id` GUC before querying, satisfying RLS automatically.

**Single-tenant shortcut — `list_default`:**

```rust
// Only event_type and cursor filters; uses the sink's fixed tenant.
let (records, next_cursor) = sink.list_default(Some("user.login"), None, 50).await?;
```

`list_default` is only available on sinks constructed with `new_single_tenant`. It returns `AuditPgError::Env` otherwise.

### 3.2 Verifying the chain

```rust
use soma_audit_pg::VerifyResult;

let result: VerifyResult = sink.verify(tenant_id).await?;

if result.ok {
    println!("chain intact, {} entries checked", result.entries_checked);
} else {
    eprintln!(
        "chain broken at seq_num {:?} after checking {} entries",
        result.first_broken_seq, result.entries_checked
    );
}
```

`verify` reads all rows for the tenant in ascending `seq_num` order and re-derives the per-tenant HMAC key from the master secret via `derive_tenant_hmac_key`. It then delegates to `soma_audit_core::verify_chain`, which detects three tampering classes:

- **Field mutation** — HMAC recomputed from stored fields does not match `entry_hash`.
- **Row deletion** — a gap in consecutive `seq_num` values.
- **Reordering or `prev_hash` tampering** — `prev_hash` in record N does not match `entry_hash` in record N-1.

`verify` stops at the first broken record and reports its `seq_num` in `first_broken_seq`.

`verify` streams rows incrementally (O(1) memory), so chain length is not a concern for memory. For very large chains it may still be slow wall-clock time; consider scheduling it as a background task rather than running it on-demand in a request handler.

**Single-tenant shortcut — `verify_default`:**

```rust
let result = sink.verify_default().await?;
```

`verify_default` is only available on sinks constructed with `new_single_tenant`.

---

## 4. Remote mode and Both mode

Remote mode adds a durable outbox table to the host service's own database. A background relay task polls the outbox and forwards events to a central `soma-audit-server` over HTTP. The outbox ensures events are not lost if the central server is temporarily unavailable.

### 4.1 Installing the outbox

```rust
use soma_audit_client::install_outbox;

install_outbox(&pool).await?;
```

This runs soma-schema migrations under advisory lock key `6020250626000002_i64`. It creates:

- Schema `soma_audit_outbox`
- Table `soma_audit_outbox.events` with columns: `id BIGSERIAL PK`, `event_id UUID UNIQUE`, `payload JSONB`, `created_at TIMESTAMPTZ`, `delivered_at TIMESTAMPTZ`, `attempts INT DEFAULT 0`, `last_error TEXT`, `next_retry_at TIMESTAMPTZ NOT NULL DEFAULT now()`, `failed_permanently_at TIMESTAMPTZ`
- Index `idx_outbox_undelivered` on `next_retry_at WHERE delivered_at IS NULL`

Pool must have `max_connections >= 2` for the same advisory lock reason as `install`.

### 4.2 Enqueuing events with `RemoteSink`

```rust
use soma_audit_client::{RemoteSink, AuditEvent, Outcome};
use std::sync::Arc;

let remote_sink = RemoteSink::new(pool.clone());
```

**Atomic path (preferred):**

```rust
let mut tx = pool.begin().await?;

// Business write.
sqlx::query("INSERT INTO app.orders ...")
    .execute(&mut *tx)
    .await?;

// Enqueue the audit event inside the same transaction.
// The outbox row commits atomically with the business write.
remote_sink.enqueue_in_tx(&event, &mut tx).await?;

tx.commit().await?;
```

**Standalone path:**

```rust
remote_sink.enqueue(&event).await?;
```

Both paths are idempotent on `event.idempotency_key`. Always set `source_service` on the event before enqueuing — unlike `LocalSink`, `RemoteSink` does not stamp a default service name.

### 4.3 Starting the relay

```rust
use soma_audit_client::{spawn_relay, RelayConfig};
use std::time::Duration;

let _relay = spawn_relay(
    pool.clone(),
    RelayConfig {
        central_url:   "http://soma-audit-server:8080".into(),
        ingest_secret: std::env::var("SOMA_AUDIT_INGEST_SECRET")?,
        poll_interval: Duration::from_secs(5),   // default
        batch_size:    50,                        // default; i64
        max_attempts:  20,                        // dead-letter after N attempts
        register:      None,                      // optional source self-registration
        heartbeat:     false,                     // periodic heartbeat to central
    },
);
// Drop _relay to detach, or await it for graceful shutdown.
```

The relay loop polls `soma_audit_outbox.events` for rows where `delivered_at IS NULL`, posts each payload to `{central_url}/internal/v1/events` with `Authorization: Bearer {ingest_secret}`, and marks rows `delivered_at = now()` on HTTP 2xx or 409 (idempotent conflict). Transient failures increment `attempts` and record `last_error` without crashing the task. `FOR UPDATE SKIP LOCKED` means multiple relay instances can run safely in parallel.

Outbox rows are never deleted automatically; `delivered_at` marks them done but they remain in the table. No built-in TTL pruning is provided.

### 4.4 The central `soma-audit-server`

The server is a standalone binary (`soma-audit-server`) that stores events from all services in its own Postgres database and exposes query, verify, seal, and key endpoints.

**Required environment variables:**

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | Postgres connection string for the central audit database |
| `SOMA_AUDIT_INGEST_SECRET` | Bearer token expected at `POST /internal/v1/events` (must match `RelayConfig.ingest_secret`) |
| `SOMA_AUDIT_ADMIN_TOKEN` | Bearer token for all `/v1/audit/*` query endpoints |
| `SOMA_AUDIT_MASTER_SECRET` | 64 lowercase hex chars (32 bytes); HKDF master for per-tenant HMAC keys |
| `SOMA_AUDIT_SIGNING_KEY` | 64 lowercase hex chars (32 bytes); Ed25519 signing key for chain seals |

**Optional:**

| Variable | Default | Description |
| --- | --- | --- |
| `SOMA_AUDIT_BIND` | `0.0.0.0:8080` | Bind address |
| `SOMA_AUDIT_CORS_ORIGINS` | (empty — same-origin only) | Comma-separated allowed origins for browser clients. |
| `RUST_LOG` | `info` | Tracing filter |
| `LOG_FORMAT` | human-readable | Set to `json` for structured log output |

**Running the server:**

```sh
DATABASE_URL=postgres://user:pass@host/audit_db \
SOMA_AUDIT_INGEST_SECRET=<random-token> \
SOMA_AUDIT_ADMIN_TOKEN=<random-token> \
SOMA_AUDIT_MASTER_SECRET=<64-hex-chars> \
SOMA_AUDIT_SIGNING_KEY=<64-hex-chars> \
soma-audit-server
```

On startup the server calls `soma_audit_pg::install(&pool)` (idempotent, advisory lock key `6020250626000001_i64`), which via its embedded migrations creates the `soma_audit.audit_chain_seals` table, then starts a background seal sweep that runs every 60 seconds, signs the current chain head for every tenant with new events, and inserts a row into `audit_chain_seals`.

**Server endpoints:**

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/health` | none | Liveness probe, returns `"ok"` |
| `GET` | `/health/live` | none | Liveness probe, returns `"ok"` |
| `GET` | `/health/ready` | none | Readiness probe, executes `SELECT 1`; 200 or 503 |
| `POST` | `/internal/v1/events` | Bearer `INGEST_SECRET` | Ingest one event from a relay |
| `POST` | `/internal/v1/sources/register` | Bearer `INGEST_SECRET` | Register/update source metadata (host_url, version) |
| `POST` | `/internal/v1/heartbeat` | Bearer `INGEST_SECRET` | Update `last_seen` for a source |
| `GET` | `/v1/audit` | Bearer `ADMIN_TOKEN` | List events. Query: `tenant_id`, `event_type?`, `source_service?`, `from?`, `to?`, `cursor?`, `limit?` |
| `GET` | `/v1/audit/global` | Bearer `ADMIN_TOKEN` | List events across all tenants. Query: `event_type?`, `source_service?`, `from?`, `to?`, `cursor?`, `limit?` |
| `GET` | `/v1/audit/verify` | Bearer `ADMIN_TOKEN` | Verify full HMAC chain for a tenant. Query: `tenant_id` |
| `GET` | `/v1/audit/keys` | Bearer `ADMIN_TOKEN` | JWKS endpoint — Ed25519 verifying key |
| `GET` | `/v1/audit/seals` | Bearer `ADMIN_TOKEN` | List Ed25519 chain seals for a tenant. Query: `tenant_id` |
| `GET` | `/v1/sources` | Bearer `ADMIN_TOKEN` | List all registered sources with event counts and last-seen timestamps |
| `POST` | `/v1/sources/keys` | Bearer `ADMIN_TOKEN` | Mint a per-source ingest key. Body: `{"source_service":"..","tenant_id":".."}`. Returns plaintext key once. |
| `DELETE` | `/v1/sources/keys` | Bearer `ADMIN_TOKEN` | Revoke a per-source key. Query: `source_service`, `tenant_id`. Returns 204. |

**Query filters for `/v1/audit`:** `from` and `to` are RFC3339 timestamps that filter on `occurred_at`. `source_service` is an exact match. `cursor` is the `next_cursor` value from the previous page (keyset on `seq_num`).

**`/v1/audit/global`:** Same filters as `/v1/audit` except no `tenant_id` (it queries all tenants). Cursor here is `occurred_at` in microseconds since epoch (the value returned as `next_cursor`).

**Auto-registration:** When an app sends its first event to `/internal/v1/events`, that `(source_service, tenant_id)` pair is automatically inserted into the `soma_audit.sources` table. It will appear in `GET /v1/sources` and in the dashboard Sources page without any additional configuration. Apps can enrich their entry by calling `POST /internal/v1/sources/register` with `host_url` and `version`.

**Per-source ingest keys:** Instead of sharing `SOMA_AUDIT_INGEST_SECRET` across all services, mint a dedicated key for each service. A per-source key is bound to its `source_service`+`tenant_id` — posting as a different source returns 403. The master ingest secret still works for bootstrap and admin tooling. See [SECURITY.md](../SECURITY.md) for the full security model.

**Cross-service dimension:** Because every `AuditEvent` carries a `source_service` field, events forwarded by multiple services are stored together in the central database but remain distinguishable by `source_service`. The server's `LocalSink` is constructed with `source_service = "soma-audit"` and only stamps that name on events that arrive with an empty `source_service`. Events forwarded via the relay already carry the originating service name and it is preserved verbatim.

### 4.5 Both mode

To use both Local and Remote simultaneously, call `install` and construct `LocalSink` as in section 2, and also call `install_outbox`, construct `RemoteSink`, and start the relay as in section 4. Record events to both sinks:

```rust
// Inside a business transaction:
sink.record_in_tx(&event, &mut tx).await?;
remote_sink.enqueue_in_tx(&event, &mut tx).await?;
tx.commit().await?;
```

Both sinks use `ON CONFLICT (tenant_id, idempotency_key) DO NOTHING`, so the same `idempotency_key` is safe to pass to both. The HMAC chain in the local database and the Ed25519-sealed chain on the central server are independent — compromise of one does not break the other.

---

## 5. The soma-schema relationship

soma-audit does not ask consuming applications to manage any SQL by hand. All migrations are embedded inside the crates at compile time using `include_dir` and run via soma-schema's migration runner.

When you call `soma_audit_pg::install(&pool)`, it calls soma-schema's `from_embedded` runner with the migrations baked into the `soma-audit-pg` binary. The runner:

1. Acquires the advisory lock (`6020250626000001_i64`) to serialize concurrent startup.
2. Reads the migration manifest from the embedded `migrations/migration-order.yaml`.
3. Compares each migration's checksum against what was previously applied.
4. Applies any unapplied migrations in manifest order, inside individual transactions.
5. Releases the advisory lock.

Migrations are immutable once applied: soma-schema will error if a previously applied migration's content has changed. You must never edit the embedded migration files — this is enforced at runtime by the checksum comparison.

The consuming application only needs to know: call `install` at startup, and the schema is ready. No separate migration CLI step is required for the audit schema.

If your application also uses soma-schema for its own business schema migrations, it must use a different advisory lock key and a different schema name. Two soma-schema migration sets coexist safely in one Postgres database as long as each has its own key and schema.

---

## 6. Multi-tenant vs single-tenant

The RLS policy on `fct_audit_events` enforces tenant isolation automatically at the database level. The sink sets `soma_audit.tenant_id` as a transaction-local GUC (using `set_config(..., true)`) before every read or write. The RLS `USING` clause checks that `tenant_id` matches this GUC.

For a single-tenant application, this still applies: you must always have a `tenant_id` UUID. You can use a fixed sentinel UUID for the single tenant.

For multi-tenant applications:

- `record_in_tx` sets the GUC for you using the `tenant_id` from the `AuditEvent`.
- `record` does the same.
- `list` and `verify` take `tenant_id` as an explicit parameter and set the GUC before querying.
- If you query `fct_audit_events` directly from application code (outside the sink), you must set the GUC yourself before the query, or RLS will return no rows silently.

The per-tenant HMAC key derivation (`HKDF-SHA256(IKM=master_secret, salt=None, info=b"soma-audit-hmac-v1" ++ tenant_id.as_bytes())`) gives each tenant a distinct key derived from the same master secret. Compromising one tenant's key does not compromise others.

---

## 7. Honest limits

**What the append-only triggers protect against:** The `no_update` and `no_delete` triggers block any `UPDATE` or `DELETE` issued through the application's database role. An attacker who compromises the application layer and its credentials cannot silently edit or remove audit rows.

**What they do not protect against:** A Postgres superuser or the role that owns the `soma_audit` schema can drop the schema, truncate the table, or disable the triggers. The append-only property is enforced at the application-role level, not at the superuser level. This is a standard constraint of in-database audit approaches.

**Defense for higher assurance:**

- **The central copy:** Remote mode stores a second copy of every event in the central server's database. An attacker who compromises the service's local database cannot retroactively alter the events already forwarded to the central server.
- **Ed25519 seals:** The seal sweep running on the central server signs the chain head every 60 seconds. A seal is a cryptographic commitment to the chain state at a point in time. Any subsequent deletion or mutation of events that predates the seal will cause `verify` to fail AND the seal signature to be invalid against the known public key (available at `GET /v1/audit/keys`). Seals are the primary defense for high-assurance environments.
- **HMAC chain:** The chain itself (`prev_hash` → `entry_hash` → `prev_hash` linkage) detects any mutation, gap, or reordering even without seals. `verify` walks the full chain and reports the first broken `seq_num`.

**Verify wall-clock cost:** `LocalSink::verify` streams the chain incrementally (constant memory), but must do a full sequential walk of every row. For tenants with very large event histories, run it as a scheduled background task or during a maintenance window, not inline in a request handler.

**Outbox retention:** Delivered outbox rows are never automatically pruned. For long-running services, plan a pruning job on `soma_audit_outbox.events WHERE delivered_at IS NOT NULL AND delivered_at < now() - interval '30 days'`.

---

## Full startup example

The following shows a complete service startup sequence for Local mode, condensed from the `notes-app` example:

```rust
use std::sync::Arc;
use soma_audit_pg::{AuditKeys, LocalSink};
use soma_audit_core::{AuditEvent, Outcome};
use serde_json::json;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Connect — pool needs max_connections >= 2.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(&std::env::var("DATABASE_URL")?)
        .await?;

    // 2. Install the soma_audit schema (idempotent).
    soma_audit_pg::install(&pool).await?;

    // 3. Load keys from environment.
    //    Local-only apps use from_env_local() — only SOMA_AUDIT_MASTER_SECRET required.
    //    from_env() is for soma-audit-server (also needs SOMA_AUDIT_SIGNING_KEY).
    let keys = Arc::new(AuditKeys::from_env_local()?);

    // 4. Build the sink.
    let sink = LocalSink::new(pool.clone(), keys, "my-service");

    // ---- later, inside a request handler ----

    let tenant_id = Uuid::parse_str("...")?;
    let actor_id  = Uuid::parse_str("...")?;

    let event = AuditEvent::builder(tenant_id, "order.place", Outcome::Success)
        .actor_id(actor_id)
        .actor_role("customer")
        .resource("order", "ord_123")
        .metadata(json!({ "amount_cents": 4999 }))
        .build();

    // Atomic path: business write + audit in one transaction.
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO app.orders (id, tenant_id) VALUES ($1, $2)")
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    sink.record_in_tx(&event, &mut tx).await?;
    tx.commit().await?;

    // Verify integrity at any time.
    let result = sink.verify(tenant_id).await?;
    assert!(result.ok);

    Ok(())
}
```
