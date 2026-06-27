# soma-audit

Tamper-evident audit logging for Rust services — drop in a `LocalSink`, get a per-tenant HMAC hash chain that can't be quietly edited or deleted.

---

## Core idea

Two deployment modes, one chain:

- **Embedded** (`soma-audit-pg`): `LocalSink` writes audit events directly into the host service's own Postgres database. The audit row commits inside the same transaction as the business write — no separate round trip, no gap.
- **Central** (`soma-audit-client` + `soma-audit-server`): a durable local outbox in the host's Postgres relays events to a central server that aggregates them and exposes an admin portal.

Both modes produce the same HMAC-SHA256 hash chain per tenant. Each record covers the previous record's hash, so any edit, deletion, or reordering breaks the chain and is caught by `verify_chain`. Per-tenant keys are derived from a single 32-byte master secret via HKDF-SHA256, so a key compromise for one tenant does not affect others. The append-only guarantee is enforced at the Postgres layer (triggers block `UPDATE` and `DELETE` on `soma_audit.fct_audit_events`). Periodic Ed25519 seals checkpoint the chain head.

Storage: plain Postgres 16. No external queue, no separate process required for the embedded mode.

---

## Quick start — add audit to any Rust app

```toml
# Cargo.toml
[dependencies]
soma-audit-pg = { path = "path/to/soma-audit-pg" }
```

```rust
use std::sync::Arc;
use soma_audit_pg::{install, AuditKeys, LocalSink};
use soma_audit_core::{AuditEvent, Outcome, idempotency_key};
use uuid::Uuid;
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;

    // Create the soma_audit schema and fct_audit_events table.
    // Idempotent — safe to call every startup.
    // Requires SOMA_AUDIT_MASTER_SECRET in env (64 lowercase hex chars = 32 bytes).
    // Local-only apps do NOT need SOMA_AUDIT_SIGNING_KEY — use from_env_local().
    install(&pool).await?;

    let keys = Arc::new(AuditKeys::from_env_local()?);
    let sink = LocalSink::new(pool.clone(), keys, "my-service");

    // Record an event atomic with a business transaction.
    let mut tx = pool.begin().await?;

    // ... your business write here ...

    let tenant_id = Uuid::parse_str("...tenant uuid...")?;
    let request_id = Uuid::parse_str("...request uuid...")?;

    let event = AuditEvent::builder(tenant_id, "user.login", Outcome::Success)
        .actor_id(Uuid::parse_str("...user uuid...")?)
        .actor_role("admin")
        .resource("session", "sess-abc")
        .idempotency_key(idempotency_key(tenant_id, request_id)) // deterministic, retry-safe
        .build();

    sink.record_in_tx(&event, &mut tx).await?;
    tx.commit().await?;

    Ok(())
}
```

`AuditEvent::builder(tenant_id, event_type, outcome)` accepts the three required fields and lets you chain optional ones. `occurred_at`, `metadata`, and `idempotency_key` are auto-filled when omitted.

Environment variables for local-only apps (`AuditKeys::from_env_local()`):

| Variable | Format |
| --- | --- |
| `SOMA_AUDIT_MASTER_SECRET` | 64 lowercase hex chars (32 bytes) |

The Ed25519 signing key (`SOMA_AUDIT_SIGNING_KEY`) is only required when running `soma-audit-server`. Local-only apps use `from_env_local()` which generates an ephemeral signing key in-process.

---

## What you get

- **Atomic writes** via `record_in_tx`: the audit row commits with the business write inside a single Postgres transaction — there is no window where the action is committed but the audit event is missing.
- **Ergonomic builder**: `AuditEvent::builder(tenant_id, event_type, outcome)` chains optional fields and auto-stamps `occurred_at`, `metadata`, and `idempotency_key`.
- **Single-tenant shortcut**: `LocalSink::new_single_tenant(pool, keys, service, tenant_id)` pins a fixed tenant so you never pass the UUID to `list_default()` / `verify_default()`.
- **Deterministic idempotency**: `idempotency_key(tenant_id, request_id)` derives a stable v5 UUID so retries deduplicate without extra bookkeeping.
- **Per-tenant HMAC hash chain**: each record covers the previous record's `entry_hash`. Editing any field, deleting any row, or reordering rows breaks the chain.
- **Chain verification** via `LocalSink::verify(tenant_id)` (or `GET /v1/audit/verify?tenant_id=...` on the server): walks every row for a tenant and reports `VerifyResult { ok, entries_checked, first_broken_seq }`.
- **Ed25519 seals**: a background sweep runs every 60 s on the central server and signs the current chain head into `soma_audit.audit_chain_seals`. The public key is served as a JWK at `GET /v1/audit/keys`.
- **Central aggregation, fleet view, and admin portal**: `soma-audit-server` ingests events from multiple services, stores them in its own hash-chained Postgres, and serves a dashboard at the root. The dashboard opens on a Sources page showing all registered installs with health dots and event counts — click any source to drill into its events. See [docs/CENTRAL.md](docs/CENTRAL.md) for the full central deployment guide.
- **Sources inventory and auto-registration**: every app that sends events automatically appears in `GET /v1/sources` (admin). Apps can also push `host_url` + `version` via `POST /internal/v1/sources/register` for richer fleet metadata.
- **Per-source ingest keys**: admins mint a key per service via `POST /v1/sources/keys`. The key is bound to its `source_service`+`tenant_id` — using it to post as a different source returns 403. Revoke via `DELETE /v1/sources/keys`.
- **Append-only enforcement at the DB layer**: Postgres triggers on `soma_audit.fct_audit_events` raise an exception on any `UPDATE` or `DELETE` — the chain cannot be silently altered even with direct DB access.
- **Idempotent inserts**: `ON CONFLICT (idempotency_key) DO NOTHING` on every write path. Re-delivering an event never creates duplicates.
- **RLS tenant isolation**: `FORCE ROW LEVEL SECURITY` on `fct_audit_events`, enforced via the `soma_audit.tenant_id` GUC. One mis-scoped query cannot read another tenant's events.
- **Rich query filters**: `GET /v1/audit` accepts `from`, `to` (date-range on `occurred_at`), `source_service`, `event_type`, `cursor`, and `limit`. `GET /v1/audit/global` queries across all tenants for fleet-wide event browsing.

---

## Crates

| Crate | What it is |
| --- | --- |
| `soma-audit-core` | Pure zero-IO foundation: event types, HMAC-SHA256 hash-chain math, per-tenant HKDF key derivation, chain integrity verification, and Ed25519 sign/verify primitives. |
| `soma-audit-pg` | Postgres-backed local audit sink and schema installer: runs migrations to create the `soma_audit` schema and provides `LocalSink` for writing HMAC-chained, RLS-isolated audit events directly into the host service's database. |
| `soma-audit-client` | Remote sink: writes audit events into a durable local Postgres outbox (in the host's own DB) and relays them to a central `soma-audit-server` via a background task, so events are never lost during server outages. |
| `soma-audit-server` | Central audit ingestion and query server: receives events from remote services, stores them in a hash-chained Postgres log, and exposes query/verify/seal/key endpoints plus an embedded dashboard portal. |

---

## Architecture

```text
  Your Rust app
  ┌─────────────────────────────────────────────┐
  │  AuditEvent                                 │
  │      │                                      │
  │      ▼                                      │
  │  LocalSink (soma-audit-pg)                  │
  │  record_in_tx(&event, &mut tx)              │
  └──────────────┬──────────────────────────────┘
                 │  same Postgres transaction
                 ▼
        Host Postgres (soma_audit.fct_audit_events)
        append-only, HMAC chain, RLS per-tenant

                 │  optional: soma-audit-client outbox
                 ▼
        soma_audit_outbox.events
        (durable, in host DB)
                 │
                 │  background relay loop (spawn_relay)
                 │  POST /internal/v1/events
                 ▼
        soma-audit-server
        (central Postgres, hash chain)
                 │
                 ▼
        Admin portal + /v1/audit/* API
        (list, verify, seals, JWKS)
        /v1/sources fleet view + auto-discovery
        /v1/sources/keys per-source ingest keys
```

---

## Status

Early. The crates build and pass tests against Postgres 16. The API is not yet stable — expect breaking changes before 1.0.

---

## License

Apache-2.0
