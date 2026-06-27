# Running the Central Auditing System

This document covers `soma-audit-server` as a fleet-wide aggregation point: the sources inventory, auto-registration, per-source ingest keys, the dashboard fleet view, and cross-tenant queries. For the relay integration in individual services, see [INTEGRATION.md](INTEGRATION.md).

---

## What the central server adds

Running `soma-audit-server` gives you:

- A **sources inventory** — every `(source_service, tenant_id)` pair that has ever sent an event is tracked automatically. No registration step required.
- A **fleet view dashboard** — the admin portal opens on a Sources page showing all installs with health dots (based on `last_seen`), event counts, host URLs, and versions. Click any source to drill into its event log.
- **Per-source ingest keys** — instead of sharing one master ingest secret across all services, each service gets its own key that is cryptographically bound to its identity. A key minted for `orders`+`tenant-A` cannot post as `payments`+`tenant-A`.
- **Cross-tenant event browsing** — `GET /v1/audit/global` queries events across all tenants in one call (admin only).
- **Ed25519 chain seals** — a background sweep signs the chain head every 60 seconds and publishes the verifying key at `GET /v1/audit/keys`.

---

## Starting the server

**Required environment variables:**

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | Postgres connection string for the central audit database |
| `SOMA_AUDIT_MASTER_SECRET` | 64 lowercase hex chars (32 bytes). HKDF master for per-tenant HMAC keys. |
| `SOMA_AUDIT_SIGNING_KEY` | 64 lowercase hex chars (32 bytes). Ed25519 signing key for chain seals. |
| `SOMA_AUDIT_INGEST_SECRET` | Shared master bearer token for `POST /internal/v1/events`. |
| `SOMA_AUDIT_ADMIN_TOKEN` | Bearer token for all `/v1/*` admin endpoints. |

**Optional:**

| Variable | Default | Description |
| --- | --- | --- |
| `SOMA_AUDIT_BIND` | `0.0.0.0:8080` | TCP bind address. |
| `SOMA_AUDIT_CORS_ORIGINS` | (empty — same-origin only) | Comma-separated allowed origins for browser clients. |
| `RUST_LOG` | `info` | Tracing filter. |
| `LOG_FORMAT` | human-readable | Set to `json` for structured output. |

```sh
DATABASE_URL=postgres://user:pass@host/audit_db \
SOMA_AUDIT_MASTER_SECRET=<64 hex chars> \
SOMA_AUDIT_SIGNING_KEY=<64 hex chars> \
SOMA_AUDIT_INGEST_SECRET=<random token> \
SOMA_AUDIT_ADMIN_TOKEN=<random token> \
soma-audit-server
```

On startup the server runs `soma_audit_pg::install(&pool)` (idempotent, creates `soma_audit` schema), creates the `audit_chain_seals` table, and spawns the seal sweep background task.

---

## Sources inventory and auto-registration

### Auto-registration

Every event posted to `POST /internal/v1/events` automatically upserts a row in `soma_audit.sources` for that `(source_service, tenant_id)` pair. The source appears in `GET /v1/sources` and the dashboard fleet view with no extra configuration.

### Enriched registration

Apps that want to show `host_url` and `version` in the fleet view call:

```http
POST /internal/v1/sources/register
Authorization: Bearer <SOMA_AUDIT_INGEST_SECRET>
Content-Type: application/json

{
  "source_service": "orders",
  "tenant_id": "<uuid>",
  "host_url": "https://orders.example.com",
  "version": "1.4.2"
}
```

Returns `204 No Content`. Safe to call on every service startup — it upserts.

### Heartbeat

To keep `last_seen` fresh without sending events (for example, from a health-check loop):

```http
POST /internal/v1/heartbeat
Authorization: Bearer <SOMA_AUDIT_INGEST_SECRET>
Content-Type: application/json

{"source_service": "orders", "tenant_id": "<uuid>"}
```

Returns `204 No Content`.

### Listing sources (admin)

```http
GET /v1/sources
Authorization: Bearer <SOMA_AUDIT_ADMIN_TOKEN>
```

Response:

```json
{
  "sources": [
    {
      "source_service": "orders",
      "tenant_id": "...",
      "host_url": "https://orders.example.com",
      "version": "1.4.2",
      "first_seen": "2026-06-01T00:00:00Z",
      "last_seen": "2026-06-27T10:30:00Z",
      "event_count": 4821
    }
  ]
}
```

`host_url` and `version` are `null` if the source has never called `/register`.

---

## Per-source ingest keys

The shared `SOMA_AUDIT_INGEST_SECRET` is a bootstrap credential — it authenticates any source for any tenant. For production, give each service its own key.

### Minting a key

```http
POST /v1/sources/keys
Authorization: Bearer <SOMA_AUDIT_ADMIN_TOKEN>
Content-Type: application/json

{"source_service": "orders", "tenant_id": "<uuid>"}
```

Response (200):

```json
{
  "key": "<64-char hex>",
  "source_service": "orders",
  "tenant_id": "<uuid>"
}
```

The plaintext key is returned exactly once and never stored. Store it in your secrets manager immediately. The server stores only the SHA-256 hash.

Calling `POST /v1/sources/keys` for the same `(source_service, tenant_id)` again rotates the key — the old key is immediately invalid.

### Using the key

The service passes the key as a standard bearer token when posting events:

```http
POST /internal/v1/events
Authorization: Bearer <per-source key>
Content-Type: application/json

{ ... event payload ... }
```

The server hashes the token, looks it up in `soma_audit.source_keys`, and verifies the `source_service`+`tenant_id` in the payload match the key's binding. A mismatch returns `403 Forbidden`. An unknown or revoked key returns `401 Unauthorized`.

The master `SOMA_AUDIT_INGEST_SECRET` continues to work alongside per-source keys — it is not replaced, only supplemented.

### Revoking a key

```http
DELETE /v1/sources/keys?source_service=orders&tenant_id=<uuid>
Authorization: Bearer <SOMA_AUDIT_ADMIN_TOKEN>
```

Returns `204 No Content`. The key is marked revoked immediately; subsequent ingest attempts with it return `401`.

---

## Querying events

### Per-tenant query

```http
GET /v1/audit?tenant_id=<uuid>&limit=100
Authorization: Bearer <SOMA_AUDIT_ADMIN_TOKEN>
```

Optional query parameters:

| Parameter | Description |
| --- | --- |
| `event_type` | Exact match on `event_type` |
| `source_service` | Exact match on `source_service` |
| `from` | RFC3339 timestamp — `occurred_at >= from` |
| `to` | RFC3339 timestamp — `occurred_at <= to` |
| `cursor` | `next_cursor` from the previous page (`seq_num`-based keyset) |
| `limit` | 1–500, default 100 |

Results are ordered `seq_num DESC` (newest first). `next_cursor` in the response is the `seq_num` of the last row when more pages exist, `null` on the last page.

### Cross-tenant (global) query

```http
GET /v1/audit/global?source_service=orders&limit=50
Authorization: Bearer <SOMA_AUDIT_ADMIN_TOKEN>
```

Same optional filters as `/v1/audit` except no `tenant_id` (it queries all tenants). Ordered `occurred_at DESC`. The cursor here is `occurred_at` in microseconds since epoch (opaque — pass back the `next_cursor` value as-is).

### Chain verification

```http
GET /v1/audit/verify?tenant_id=<uuid>
Authorization: Bearer <SOMA_AUDIT_ADMIN_TOKEN>
```

Response: `{"ok": true, "entries_checked": 4821, "first_broken_seq": null}`

Walks every row for the tenant in `seq_num ASC` order, recomputes each HMAC, and reports the first broken record. Streaming — O(1) memory regardless of chain length.

---

## Full route table

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/health` | none | Liveness probe. Returns `"ok"`. |
| `GET` | `/health/live` | none | Liveness probe. Returns `"ok"`. |
| `GET` | `/health/ready` | none | Readiness probe. `SELECT 1`; 200 or 503. |
| `POST` | `/internal/v1/events` | Bearer `INGEST_SECRET` or per-source key | Ingest one event. Returns `201`. |
| `POST` | `/internal/v1/sources/register` | Bearer `INGEST_SECRET` | Upsert source metadata. Returns `204`. |
| `POST` | `/internal/v1/heartbeat` | Bearer `INGEST_SECRET` | Update `last_seen`. Returns `204`. |
| `GET` | `/v1/audit` | Bearer `ADMIN_TOKEN` | List events for a tenant (keyset-paginated). |
| `GET` | `/v1/audit/global` | Bearer `ADMIN_TOKEN` | List events across all tenants. |
| `GET` | `/v1/audit/verify` | Bearer `ADMIN_TOKEN` | Verify HMAC chain for a tenant. |
| `GET` | `/v1/audit/keys` | Bearer `ADMIN_TOKEN` | JWKS — Ed25519 verifying key. |
| `GET` | `/v1/audit/seals` | Bearer `ADMIN_TOKEN` | List Ed25519 chain seals for a tenant. |
| `GET` | `/v1/sources` | Bearer `ADMIN_TOKEN` | Fleet view — all sources with event counts. |
| `POST` | `/v1/sources/keys` | Bearer `ADMIN_TOKEN` | Mint a per-source ingest key (returned once). |
| `DELETE` | `/v1/sources/keys` | Bearer `ADMIN_TOKEN` | Revoke a per-source key. |
| `*` | (fallback) | none | Embedded dashboard SPA. |

---

## Dashboard fleet view

The dashboard opens on the Sources page. Each source shows:

- Service name and tenant
- Health dot: green when `last_seen` is within the last 5 minutes, amber within 1 hour, red otherwise
- Total event count
- `host_url` and `version` if registered
- `first_seen` / `last_seen` timestamps

Click a source row to open its event log, pre-filtered to that `source_service`+`tenant_id`.

---

## Honest limits

**Chain authority:** The central server maintains its own HMAC chain over forwarded events. The chain linkage (`prev_hash` → `entry_hash`) in the central database is independent of the originating service's local chain. A combined-vs-per-source comparison (matching `idempotency_key` values between local and central) is the correct cross-chain consistency check — not comparing `seq_num` or `entry_hash` values directly.

**Append-only at the application-role level only:** A Postgres superuser can disable the append-only triggers. The Ed25519 seals (signed by `SOMA_AUDIT_SIGNING_KEY` and published at `GET /v1/audit/keys`) are the defense against this — any deletion or mutation that predates a seal causes both `verify` to fail and the seal signature to be invalid. See [SECURITY.md](../SECURITY.md) for the full threat model.

**Outbox retention:** Delivered outbox rows in service-side databases are never pruned automatically. Plan a maintenance job on `soma_audit_outbox.events WHERE delivered_at IS NOT NULL AND delivered_at < now() - interval '30 days'`.
