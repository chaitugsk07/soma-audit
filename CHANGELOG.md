# Changelog

All notable changes to soma-audit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
semantic versioning once it reaches 1.0. Until then, expect breaking changes
between minor versions.

## [Unreleased]

### Added

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
  outbox rows to a central server with exponential backoff.
- **`soma-audit-server`** — the central service: ingest, query, verify, seals,
  and JWKS key endpoints; a periodic Ed25519 seal sweep; and an embedded Leptos
  admin portal.
- Admin dashboard (`dashboard/`), a runnable demo (`examples/notes-app/`), a
  static landing page (`website/`), and the integration/operations docs.
- CI (`.github/workflows/ci.yml`) running fmt, clippy, build, and the full test
  suite against Postgres 16.

### Security

- HMAC canonical message includes the event `metadata` (chain epoch 2);
  constant-time bearer-token comparison; ingest rejects the RS control
  character (0x1E) in free-text fields; CORS is deny-by-default and configured
  via `SOMA_AUDIT_CORS_ORIGINS`.

### Known limitations

- Crates depend on each other by `path`, not a published version — not yet
  installable from crates.io.
- Rotating `SOMA_AUDIT_MASTER_SECRET` invalidates verification of existing
  records; seamless key rotation is not yet implemented (see
  [docs/OPERATIONS.md](docs/OPERATIONS.md)).
- soma-vault still runs its own separate audit implementation; the drop-in
  migration to soma-audit is planned but not done.
