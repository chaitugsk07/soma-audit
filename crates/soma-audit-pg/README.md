# soma-audit-pg

Postgres-backed local audit sink for soma-audit. This is the crate to adopt when a service writes audit events directly into its own database. It creates the `soma_audit` schema, installs an append-only, RLS-isolated `fct_audit_events` table, and provides `LocalSink` for writing HMAC-chained audit events.

## Quickstart

### 1. Add the dependency

```toml
# Cargo.toml
soma-audit-pg = { path = "../soma-audit-pg" }
# or, inside the workspace:
soma-audit-pg = { workspace = true }
```

### 2. Set env vars

For local-only use (no central server):

```sh
SOMA_AUDIT_MASTER_SECRET=<64 lowercase hex chars>   # 32-byte HKDF master for per-tenant HMAC keys
```

`AuditKeys::from_env_local()` reads only this variable and generates an ephemeral Ed25519 signing key in-process. `SOMA_AUDIT_SIGNING_KEY` is only required when running `soma-audit-server`.

`AuditKeys::from_env()` reads both variables if you need a stable signing key (e.g. you are running the server):

```sh
SOMA_AUDIT_MASTER_SECRET=<64 lowercase hex chars>
SOMA_AUDIT_SIGNING_KEY=<64 lowercase hex chars>     # 32-byte Ed25519 signing key — server only
```

Both must be exactly 64 hex characters. The relevant constructor returns an error mentioning "64 hex chars" or "invalid hex character" if they are wrong.

### 3. Install the schema at startup

```rust
soma_audit_pg::install(&pool).await?;
```

`install` is idempotent — safe to call every time the service starts. Internally it runs bundled migrations through soma-schema's `from_embedded` runner, protected by advisory lock key `6020250626000001_i64` so it coexists safely with the host app's own migrations even when both run concurrently at startup.

The migrations create:

- Schema `soma_audit`
- Table `soma_audit.fct_audit_events` with columns: `id` (UUID PK), `tenant_id` (UUID), `seq_num` (BIGINT), `source_service` (TEXT), `event_type` (TEXT), `actor_id` (UUID?), `actor_role` (TEXT?), `resource_type` (TEXT?), `resource_id` (TEXT?), `outcome` (TEXT CHECK IN (`'success'`,`'denied'`,`'error'`)), `actor_ip` (INET?), `occurred_at` (TIMESTAMPTZ), `metadata` (JSONB DEFAULT `'{}'`), `prev_hash` (TEXT?), `entry_hash` (TEXT), `chain_epoch` (INT DEFAULT 1), `idempotency_key` (UUID UNIQUE), `created_at` (TIMESTAMPTZ DEFAULT now()); UNIQUE on `(tenant_id, seq_num)` and `(idempotency_key)`
- RLS with `FORCE ROW LEVEL SECURITY`; policy `tenant_isolation` filters on GUC `soma_audit.tenant_id`
- Append-only triggers — any `UPDATE` or `DELETE` raises a Postgres exception
- Indexes: `idx_audit_tenant_seq` on `(tenant_id, seq_num DESC)`, `idx_audit_tenant_time` BRIN on `occurred_at`, `idx_audit_tenant_event` on `(tenant_id, event_type)`

Pool must have `max_connections >= 2`: one connection is held for the advisory lock, at least one more is needed for migration queries.

### 4. Construct AuditKeys and LocalSink

```rust
use std::sync::Arc;
use soma_audit_pg::{AuditKeys, LocalSink};

// Local-only apps — only SOMA_AUDIT_MASTER_SECRET needed:
let keys = Arc::new(AuditKeys::from_env_local()?);

// Running soma-audit-server — both env vars required:
let keys = Arc::new(AuditKeys::from_env()?);

// From raw bytes (tests / secret-manager integrations):
let keys = Arc::new(AuditKeys::from_secret(master_bytes, signing_bytes));

// Multi-tenant sink:
let sink = LocalSink::new(pool.clone(), keys.clone(), "my-service");

// Single-tenant sink — pins a fixed tenant, enables list_default/verify_default:
let sink = LocalSink::new_single_tenant(pool.clone(), keys, "my-service", tenant_id);
```

`source_service` is stamped onto events whose own `source_service` field is empty. Events that arrive with a non-empty `source_service` (e.g. forwarded from the relay/ingest path) are left unchanged.

### 5. Build and write audit events

Build events with the builder — `occurred_at`, `metadata`, and `idempotency_key` are auto-filled:

```rust
use soma_audit_core::{AuditEvent, Outcome, idempotency_key};
use uuid::Uuid;

let event = AuditEvent::builder(tenant_id, "order.place", Outcome::Success)
    .actor_id(actor_id)
    .actor_role("customer")
    .resource("order", "ord_123")
    .idempotency_key(idempotency_key(tenant_id, request_id)) // deterministic, retry-safe
    .build();
```

**Atomic with a business transaction — preferred:**

```rust
sink.record_in_tx(&event, &mut tx).await?;
```

The audit row commits atomically with the caller's business write. Under the hood, `record_in_tx` sets GUC `soma_audit.tenant_id`, acquires a per-tenant `pg_advisory_xact_lock` (released at transaction end), reads the chain head, calls `seal_record`, and inserts with `ON CONFLICT (idempotency_key) DO NOTHING`. On conflict, it fetches and returns the existing row rather than an error.

**Standalone — when there is no surrounding business transaction:**

```rust
sink.record(&event).await?;
```

Opens its own transaction, calls `record_in_tx`, and commits. There is a small window between when the business action commits and when the audit row commits; use `record_in_tx` if that gap is unacceptable.

### 6. Read and verify

```rust
use soma_audit_pg::ListFilter;

// Keyset-paginated list, DESC by seq_num (no filters):
let (records, next_cursor) = sink.list(tenant_id, ListFilter::default(), 100).await?;

// With filters (date range + source service):
let (records, next_cursor) = sink.list(tenant_id, ListFilter {
    source_service: Some("orders"),
    from: Some(start),
    to: Some(end),
    ..Default::default()
}, 100).await?;

// Single-tenant shortcut (requires new_single_tenant):
let (records, next_cursor) = sink.list_default(Some("order.place"), None, 100).await?;

// Walk the full chain and verify every HMAC link:
let result = sink.verify(tenant_id).await?;
let result = sink.verify_default().await?; // single-tenant shortcut
// result.ok, result.entries_checked, result.first_broken_seq
```

`list` clamps `limit` to 1–500. `verify` streams rows incrementally, O(1) memory.

## Public API

```rust
pub async fn install(pool: &sqlx::PgPool) -> Result<(), InstallError>

pub struct LocalSink { /* pool, keys, source_service, fixed_tenant */ }

impl LocalSink {
    pub fn new(pool: PgPool, keys: Arc<AuditKeys>, source_service: impl Into<String>) -> Self
    pub fn new_single_tenant(pool: PgPool, keys: Arc<AuditKeys>, source_service: impl Into<String>, tenant_id: Uuid) -> Self
    pub async fn record_in_tx(&self, event: &AuditEvent, tx: &mut Transaction<'_, Postgres>) -> Result<AuditRecord, AuditPgError>
    pub async fn record(&self, event: &AuditEvent) -> Result<AuditRecord, AuditPgError>
    pub async fn list(&self, tenant_id: Uuid, filter: ListFilter<'_>, limit: i64) -> Result<(Vec<AuditRecord>, Option<i64>), AuditPgError>
    pub async fn list_default(&self, event_type: Option<&str>, cursor: Option<i64>, limit: i64) -> Result<(Vec<AuditRecord>, Option<i64>), AuditPgError>
    pub async fn list_global(&self, filter: ListFilter<'_>, limit: i64) -> Result<(Vec<AuditRecord>, Option<i64>), AuditPgError>
    pub async fn verify(&self, tenant_id: Uuid) -> Result<VerifyResult, AuditPgError>
    pub async fn verify_default(&self) -> Result<VerifyResult, AuditPgError>
    pub fn pool(&self) -> &PgPool
}

pub struct ListFilter<'a> {
    pub event_type: Option<&'a str>,
    pub source_service: Option<&'a str>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub cursor: Option<i64>,
}

pub struct AuditKeys { /* master_secret: Zeroizing<[u8;32]>, signing_key: SigningKey */ }

impl AuditKeys {
    pub fn from_env_local() -> Result<Self, AuditPgError>  // local-only: SOMA_AUDIT_MASTER_SECRET only
    pub fn from_env() -> Result<Self, AuditPgError>         // server: both env vars required
    pub fn from_secret(master_secret: [u8; 32], signing_key: [u8; 32]) -> Self
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey
    pub fn sign_seal(&self, payload: &[u8]) -> Vec<u8>
}

// Re-exported from soma-audit-core so you only need this crate as a direct dependency:
pub use soma_audit_core::{AuditEvent, AuditEventBuilder, AuditRecord, Outcome, VerifyResult};
pub use soma_audit_core::idempotency_key;
```

## Error types

```rust
pub enum InstallError {
    Schema(soma_schema::Error),
    Env(String),
}

pub enum AuditPgError {
    Db(#[from] sqlx::Error),
    Core(#[from] soma_audit_core::AuditError),
    Env(String),
}
```

## Env vars

| Variable | Required by | Description |
| --- | --- | --- |
| `SOMA_AUDIT_MASTER_SECRET` | `from_env_local()`, `from_env()` | 64 lowercase hex chars (32 bytes). HKDF master for per-tenant HMAC keys. |
| `SOMA_AUDIT_SIGNING_KEY` | `from_env()` only | 64 lowercase hex chars (32 bytes). Ed25519 signing key for chain seals. Only needed when running `soma-audit-server`. |

## Gotchas

- **Pool size**: `max_connections >= 2` is required. `record_in_tx` holds one connection for `pg_advisory_xact_lock`; `install` needs a second for migration queries.
- **Advisory lock key**: `6020250626000001_i64` is used for migrations. Must be unique across all soma services sharing the same Postgres cluster.
- **Per-tenant lock key**: derived by XOR-folding the tenant UUID's u128 into i64 (`hi64 XOR lo64`). This is separate from the install advisory lock.
- **RLS GUC**: `soma_audit.tenant_id` is set as a transaction-local GUC before every read or write. Forgetting it causes RLS to silently reject rows.
- **Append-only**: `UPDATE` and `DELETE` are blocked by database triggers. There is no soft-delete or edit path.
- **Idempotency**: on `(idempotency_key)` conflict, `record_in_tx` fetches and returns the existing row — it does not error.
- **`AuditKeys` Debug**: redacts both secrets — safe in log output, but do not derive `Clone` or serialize the struct.
- **`record` vs `record_in_tx`**: prefer `record_in_tx` whenever you hold a business transaction. `record` has a commit-gap window where the business action can commit but the audit row has not yet.
