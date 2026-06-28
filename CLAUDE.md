# CLAUDE.md — soma-audit

Tamper-evident audit logging service (Rust workspace; `soma-audit-core` → `soma-audit-pg` → `soma-audit-client` → `soma-audit-server`).

## Shared components — consume soma-infra, do NOT re-implement plumbing

The platform-wide rule lives in `../CLAUDE.md` ("Shared components"). Summary as it applies here:

- **All reusable backend plumbing comes from `soma-infra`** (`../soma-infra`, path dep). This service already consumes it for: the Postgres pool (`soma_infra::connect_from_env`), telemetry (`telemetry::init`), graceful shutdown (`signal::shutdown_signal`), crypto primitives (`crypto::hkdf_sha256` / `hmac_sha256_hex` / `sha256_hex`), env helpers (`config::require_env` / `env_or`), and the HTTP client in the relay (`http::client`). Reference it as `soma-infra = { path = "../../../soma-infra", features = [...] }`.
- **Do NOT hand-roll** a Postgres pool, a `tracing_subscriber` init, a `shutdown_signal`, an `Hkdf`/`Hmac`/`Sha256`-to-hex, or a `reqwest::Client` builder. If you need a primitive soma-infra lacks, add the generic primitive to soma-infra (this service supplying its own parameters), not a local copy.

### What stays in soma-audit (logic, NOT plumbing — correctly local)

- The audit **chain logic** (hash-linking, epoch sealing) and **ed25519 signing** — domain logic.
- The HKDF `info` string `b"soma-audit-hmac-v1"` and the per-tenant key-derivation policy — soma-audit passes these *into* `soma_infra::crypto::hkdf_sha256`; the strings are this service's policy.
- `Migrator` wiring in `soma-audit-pg/install.rs` — the `"soma_audit"` schema name + advisory lock key `6020250626000001` are service-owned (`from_embedded` via `include_dir!`).
- `decode_hex_32` in `soma-audit-pg/keys.rs` — stays local (soma-infra exposes no public hex→[u8;32] equivalent; too small to justify one).
- The integration-test harness in `soma-audit-pg/tests/` — deliberately shares one DB for chain-continuity assertions; do NOT swap to `soma_infra::TestDb` (it would change test semantics).

## Standard tenets

Think before coding; surgical changes (touch only what the task needs); ponytail (lazy senior-dev: simplest working solution, stdlib/native before deps, shortest diff); well-tested; explicit over clever. Never simplify away input validation at trust boundaries, error handling that prevents data loss, security, or anything explicitly requested.
