# soma-audit-server

Central audit ingestion and query server. Receives events from remote services via the relay, stores them in a hash-chained Postgres log, exposes query/verify/seal/key endpoints for audit consumers and operators, and serves an embedded dashboard portal.

Binary name: `soma-audit-server`

## Required env vars

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | Postgres connection string |
| `SOMA_AUDIT_MASTER_SECRET` | 64 lowercase hex chars (32 bytes). HKDF master for per-tenant HMAC chain keys. |
| `SOMA_AUDIT_SIGNING_KEY` | 64 lowercase hex chars (32 bytes). Ed25519 signing key for chain seals. |
| `SOMA_AUDIT_INGEST_SECRET` | Bearer token for `POST /internal/v1/events` (matched by the relay's `ingest_secret`). |
| `SOMA_AUDIT_ADMIN_TOKEN` | Bearer token for all `/v1/audit/*` endpoints. |

## Optional env vars

| Variable | Default | Description |
| --- | --- | --- |
| `SOMA_AUDIT_BIND` | `0.0.0.0:8080` | TCP bind address. |
| `RUST_LOG` | `info` | Tracing filter. |
| `LOG_FORMAT` | human-readable | Set to `json` for structured JSON log output. |

## Running the server

```sh
DATABASE_URL=postgres://... \
SOMA_AUDIT_MASTER_SECRET=<64 hex chars> \
SOMA_AUDIT_SIGNING_KEY=<64 hex chars> \
SOMA_AUDIT_INGEST_SECRET=<secret> \
SOMA_AUDIT_ADMIN_TOKEN=<token> \
soma-audit-server
```

## Boot sequence

1. Initialise tracing (`RUST_LOG` / `LOG_FORMAT`).
2. Read all required env vars; fail fast if any are missing.
3. Build `AuditKeys` via `soma_audit_pg::AuditKeys::from_env()`.
4. Open `PgPool` with `min_connections = 2`.
5. Call `soma_audit_pg::install(&pool)` — creates schema `soma_audit`, runs embedded migrations, advisory lock key `6020250626000001`.
6. Execute inline DDL to create `soma_audit.audit_chain_seals` (with `IF NOT EXISTS`).
7. Construct `LocalSink::new(pool.clone(), keys.clone(), "soma-audit")`.
8. Spawn `seal::run_seal_sweep` background task (fires every 60 s).
9. Build the Axum router, bind on `SOMA_AUDIT_BIND`, serve with graceful shutdown on `SIGTERM` / `Ctrl-C`.

## Route table

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/health` | None | Liveness probe. Returns `"ok"`. |
| `GET` | `/health/live` | None | Liveness probe. Returns `"ok"`. |
| `GET` | `/health/ready` | None | Readiness probe. Executes `SELECT 1`; returns `200` or `503`. |
| `POST` | `/internal/v1/events` | Bearer `SOMA_AUDIT_INGEST_SECRET` or per-source key | Ingest an event from a relay. Body: `IngestRequest` JSON. Returns `201 {id, seq_num, entry_hash}`. |
| `POST` | `/internal/v1/sources/register` | Bearer `SOMA_AUDIT_INGEST_SECRET` | Register or update source metadata (`host_url`, `version`). Returns `204`. |
| `POST` | `/internal/v1/heartbeat` | Bearer `SOMA_AUDIT_INGEST_SECRET` | Update `last_seen` for a source without sending an event. Returns `204`. |
| `GET` | `/v1/audit` | Bearer `SOMA_AUDIT_ADMIN_TOKEN` | List events for a tenant. Query: `tenant_id`, `event_type?`, `source_service?`, `from?`, `to?`, `cursor?`, `limit?`. Keyset DESC by `seq_num`, default limit 100, max 500. |
| `GET` | `/v1/audit/global` | Bearer `SOMA_AUDIT_ADMIN_TOKEN` | List events across all tenants. Query: `event_type?`, `source_service?`, `from?`, `to?`, `cursor?`, `limit?`. Ordered `occurred_at DESC`. |
| `GET` | `/v1/audit/verify` | Bearer `SOMA_AUDIT_ADMIN_TOKEN` | Verify the full chain for a tenant. Query: `tenant_id`. Returns `VerifyResult`. |
| `GET` | `/v1/audit/keys` | Bearer `SOMA_AUDIT_ADMIN_TOKEN` | JWKS document — Ed25519 verifying key (`kid="soma-audit-v1"`, `kty="OKP"`, `crv="Ed25519"`). |
| `GET` | `/v1/audit/seals` | Bearer `SOMA_AUDIT_ADMIN_TOKEN` | List the last 100 chain seals for a tenant, DESC by `up_to_seq_num`. Query: `tenant_id`. |
| `GET` | `/v1/sources` | Bearer `SOMA_AUDIT_ADMIN_TOKEN` | Fleet inventory — all `(source_service, tenant_id)` pairs with `event_count`, `host_url`, `version`, `first_seen`, `last_seen`. |
| `POST` | `/v1/sources/keys` | Bearer `SOMA_AUDIT_ADMIN_TOKEN` | Mint a per-source ingest key bound to `source_service`+`tenant_id`. Body: `{"source_service":"..","tenant_id":".."}`. Returns `{"key":"<64-char hex>","source_service":"..","tenant_id":".."}` — plaintext shown once. |
| `DELETE` | `/v1/sources/keys` | Bearer `SOMA_AUDIT_ADMIN_TOKEN` | Revoke a per-source key. Query: `source_service`, `tenant_id`. Returns `204`. |
| `*` | (fallback) | None | Embedded dashboard SPA. Opens on the Sources fleet view. Falls back to `index.html` for SPA routing. If `dashboard/dist` was not built at compile time, serves a stub page. |

Body limit: 1 MiB on all routes.

### Query filter details

`GET /v1/audit` accepts `from` and `to` as RFC3339 timestamps filtering on `occurred_at`. `source_service` is an exact match. `cursor` is the `next_cursor` value from the previous page (keyset on `seq_num`).

`GET /v1/audit/global` uses the same filters except there is no `tenant_id` — it bypasses RLS to query all tenants. The cursor is `occurred_at` in microseconds since epoch; pass back the `next_cursor` value as-is.

### Per-source ingest keys

A per-source key is bound to a specific `(source_service, tenant_id)` pair at mint time. When the server receives an event authenticated with a per-source key, it verifies that the event's `source_service` and `tenant_id` match the binding. A mismatch returns `403 Forbidden`. The shared master `SOMA_AUDIT_INGEST_SECRET` continues to work alongside per-source keys and has no source binding check. See [SECURITY.md](../../SECURITY.md).

## Ed25519 seal sweep

Every 60 seconds, the `run_seal_sweep` background task signs the current chain head for every tenant that has unsealed events and inserts a row into `soma_audit.audit_chain_seals`. Seal rows carry: `id` (UUID), `tenant_id` (UUID), `up_to_seq_num` (i64), `chain_head_hash` (the `entry_hash` of the highest-seq record), `sealed_at` (TIMESTAMPTZ), and `public_key_id` (the key identifier string).

The seal payload format is: `"soma-audit-seal-v1\x1e{tenant_id}\x1e{up_to_seq}\x1e{chain_head_hash}\x1e{sealed_at_unix}"`. Changing this format breaks existing seal verification.

The `audit_chain_seals` table is created by inline DDL in `main.rs` (`CREATE TABLE IF NOT EXISTS`), not via the soma-schema migration runner. It lives in the `soma_audit` schema but is outside the versioned migration set.

The verifying key is published at `GET /v1/audit/keys` so external consumers can independently verify seals.

## Pointing a service at this server

In services that use `soma-audit-client`:

```rust
spawn_relay(pool, RelayConfig {
    central_url: "http://soma-audit-server:8080".into(),
    ingest_secret: std::env::var("SOMA_AUDIT_INGEST_SECRET").unwrap(),
    ..Default::default()
});
```

The `ingest_secret` in `RelayConfig` must match the `SOMA_AUDIT_INGEST_SECRET` env var set on this server.

## Gotchas

- **Pool size**: `min_connections = 2` is set at boot. One connection is held for the soma-schema advisory lock during `install()`; at least one more is needed for migration queries.
- **Advisory lock keys**: `6020250626000001_i64` for `soma_audit` migrations; `6020250626000002_i64` for client outbox migrations (used by downstream services, not this server). Both must be unique across the Postgres cluster.
- **`record` vs `record_in_tx`**: the ingest handler calls `sink.record()` (standalone transaction). `record_in_tx` is used by host services that need the audit row to commit atomically with their own business write.
- **`source_service` stamping**: `LocalSink` only fills `source_service` when the incoming event's field is empty. Events forwarded from remote services already carry the originating service name and it is preserved verbatim.
- **RLS GUC**: `soma_audit.tenant_id` is set as a transaction-local GUC before every read or write. Reads or writes without this GUC set will return no rows (RLS `USING` clause checks it is not `NULL`).
- **Append-only**: `UPDATE` and `DELETE` on `fct_audit_events` raise a Postgres exception via triggers.
- **Dashboard at compile time**: if `../../dashboard/dist` does not exist when the binary is built, the portal serves only a stub HTML page — no build error is raised.
- **`chain_epoch = 1`** is the only epoch in use. Any change to the canonical message format requires bumping `chain_epoch`.
