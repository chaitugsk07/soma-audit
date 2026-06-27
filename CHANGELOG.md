# Changelog

All notable changes to soma-audit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
semantic versioning once it reaches 1.0. Until then, expect breaking changes
between minor versions.

## [Unreleased]

### Added

- **`AuditEvent::builder(tenant_id, event_type, outcome)`** — ergonomic builder
  replaces 12-field struct literals as the recommended pattern. Chain optional
  fields (`.actor_id`, `.actor_role`, `.resource`, `.actor_ip`, `.metadata`,
  `.occurred_at`, `.source_service`, `.idempotency_key`) then call `.build()`.
  Auto-stamps `occurred_at`, `metadata`, and `idempotency_key` when omitted.
- **`idempotency_key(tenant_id, request_id) -> Uuid`** — deterministic v5 UUID
  helper; same inputs always produce the same key so retries deduplicate
  without extra bookkeeping.
- **`AuditKeys::from_env_local()`** — local-only apps now need only
  `SOMA_AUDIT_MASTER_SECRET`. `from_env_local` generates an ephemeral Ed25519
  signing key in-process; `SOMA_AUDIT_SIGNING_KEY` is required only when
  running `soma-audit-server`.
- **`LocalSink::new_single_tenant(pool, keys, source_service, tenant_id)`** —
  pins a fixed tenant on the sink. When the event's `tenant_id` is `Uuid::nil`
  the sink fills in the fixed tenant automatically.
- **`LocalSink::list_default` / `verify_default`** — convenience wrappers on
  single-tenant sinks that omit the `tenant_id` argument at every call site.
- **Central discovery — sources inventory**: every `(source_service, tenant_id)`
  pair that posts an event is automatically registered in `soma_audit.sources`.
  `GET /v1/sources` (admin) returns all installs with `event_count`, `host_url`,
  `version`, and `first_seen`/`last_seen`. Apps can enrich their entry via
  `POST /internal/v1/sources/register` (host_url + version) and keep
  `last_seen` fresh via `POST /internal/v1/heartbeat`.
- **Dashboard fleet view**: the admin portal now defaults to a Sources page
  showing all registered installs with health dots (green/amber/red based on
  `last_seen`), event counts, and click-to-drill into per-source event logs.
- **Per-source ingest keys**: `POST /v1/sources/keys` (admin) mints a key bound
  to a specific `source_service`+`tenant_id`; returns plaintext once, stores
  only SHA-256 hash. A per-source key used to post as a different source/tenant
  is rejected with 403. `DELETE /v1/sources/keys` revokes immediately (401
  thereafter). The shared master `SOMA_AUDIT_INGEST_SECRET` continues to work
  for bootstrap and admin tooling.
- **Query filters on `GET /v1/audit`**: new `from` / `to` date-range filters on
  `occurred_at` (RFC3339), and `source_service` exact-match filter, alongside
  existing `event_type`, `cursor`, and `limit`.
- **`GET /v1/audit/global`** — cross-tenant fleet-wide event browsing (admin
  only). Supports same filters as `/v1/audit` minus `tenant_id`; ordered
  `occurred_at DESC`; cursor is `occurred_at` in microseconds.
- **`soma-audit-core`** — pure, zero-IO foundation: the `AuditEvent` /
  `AuditRecord` envelope, HMAC-SHA256 hash-chain math (`canonical_msg`,
  `compute_entry_hash`, `seal_record`), per-tenant HKDF-SHA256 key derivation,
  chain verification (`verify_chain`, plus the incremental `verify_record` /
  `ChainCursor` helpers), and Ed25519 seal sign/verify primitives.
- **`soma-audit-pg`** — the embeddable Local sink. `install(&pool)` runs the
  bundled migrations through soma-schema's `from_embedded` to create the
  `soma_audit` schema, `fct_audit_events` (append-only triggers + FORCE RLS on
  the `soma_audit.tenant_id` GUC), and `audit_chain_seals`. `LocalSink`
  provides `record_in_tx` (audit row atomic with the caller's business
  transaction), `record`, `list`, and a streaming `verify`.
- **`soma-audit-client`** — the Remote sink: `install_outbox`, `RemoteSink`
  (`enqueue` / `enqueue_in_tx`), and a background `spawn_relay` that ships
  outbox rows to a central server with exponential backoff; dead-letter
  isolation on repeated failures.
- **`soma-audit-server`** — the central service: ingest, query, verify, seals,
  and JWKS key endpoints; a periodic Ed25519 seal sweep; sources inventory and
  registration endpoints; per-source key mint/revoke; and an embedded admin
  portal with fleet view.
- Admin dashboard (`dashboard/`), a runnable demo (`examples/notes-app/`), a
  static landing page (`website/`), integration/operations/central docs, and
  `docs/CENTRAL.md` (new — central deployment guide).
- CI (`.github/workflows/ci.yml`) running fmt, clippy, build, and the full test
  suite against Postgres 16.

### Fixed

- **Idempotency key scoping**: `ON CONFLICT` target is `(tenant_id,
  idempotency_key)` — an idempotency key from one tenant can no longer
  accidentally suppress a different tenant's event with the same key.
- **Seal deduplication for HA**: the seal sweep uses `ON CONFLICT DO NOTHING` so
  multiple server replicas running concurrently never produce duplicate seal rows.
- **Relay dead-letter handling**: events that exceed the retry threshold are
  moved to a dead-letter state rather than blocking the relay loop indefinitely.

### Security

- HMAC canonical message includes the event `metadata` (chain epoch 2);
  constant-time bearer-token comparison (`subtle::ConstantTimeEq`); ingest
  rejects the RS control character (0x1E) in free-text fields to prevent
  canonical-message boundary injection; CORS is deny-by-default and configured
  via `SOMA_AUDIT_CORS_ORIGINS`; per-source ingest keys stored as SHA-256 hashes
  only, bound to `source_service`+`tenant_id`.

### Known limitations

- Crates depend on each other by `path`, not a published version — not yet
  installable from crates.io.
- Rotating `SOMA_AUDIT_MASTER_SECRET` invalidates verification of existing
  records; seamless key rotation is not yet implemented (see
  [docs/OPERATIONS.md](docs/OPERATIONS.md)).
- soma-vault still runs its own separate audit implementation; the drop-in
  migration to soma-audit is planned but not done.
