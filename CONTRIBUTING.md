# Contributing to soma-audit

## Building

```
cargo build
```

All crates are in the `crates/` directory and share a workspace at the repo root.

## Running tests

Integration tests require a local Postgres instance. Set the connection string before running:

```
export TEST_DATABASE_URL=postgres://user:password@localhost/soma_audit_test
cargo test
```

Tests that need a database skip gracefully when `TEST_DATABASE_URL` is absent, so `cargo test` always passes without a database (unit tests only).

## Building the dashboard

The embedded portal lives in `dashboard/`. It is a frontend project built with [Trunk](https://trunkrs.dev/).

```
cd dashboard
trunk build --release
```

The compiled assets land in `dashboard/dist/`. The `soma-audit-server` crate embeds this directory at compile time via rust-embed. If `dist/` does not exist the server still compiles and serves a stub HTML page instead.

## Crate layout

| Crate | Path | Role |
|---|---|---|
| `soma-audit-core` | `crates/soma-audit-core` | Pure zero-IO foundation: event types, HMAC-SHA256 chain math, HKDF key derivation, Ed25519 sign/verify. No database, no async, no network. |
| `soma-audit-pg` | `crates/soma-audit-pg` | Postgres-backed local sink. Runs migrations (schema `soma_audit`, table `fct_audit_events`), provides `LocalSink` for writing HMAC-chained, RLS-isolated events into the host service's database. |
| `soma-audit-client` | `crates/soma-audit-client` | Remote sink. Writes events into a durable local outbox (`soma_audit_outbox.events`) in the host's Postgres and relays them to a central `soma-audit-server` via a background Tokio task. |
| `soma-audit-server` | `crates/soma-audit-server` | Central binary. Receives relayed events, stores them via `soma-audit-pg`, exposes REST endpoints for query/verify/seal/keys, and serves the embedded dashboard portal. |

## Migration invariants

Migrations live under each crate's `migrations/` directory and are embedded at compile time with `include_dir`. They are run by the `soma-schema` migration runner under a per-crate advisory lock.

**Migrations are immutable once merged.** After a migration file has been applied to any environment (including `01_migrated` in the migration-order manifest), you must never edit it. Changing an applied migration breaks the checksum chain and will cause `soma-schema` to abort startup.

To change the schema, add a new migration file and append its name to `migration-order.yaml`. Never delete or reorder existing entries.
