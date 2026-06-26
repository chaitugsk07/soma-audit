Now I have enough to write the report with full confidence in the verified findings.

---

# soma-audit — Final Review Report

## 1. Verdict

soma-audit is **not yet publishable to crates.io** and not ready for external adoption, but it is shippable as a **private internal library within the soma monorepo** today. The core guarantees — atomic in-tx recording, HMAC hash chain, HKDF per-tenant keys, idempotent writes — are correctly implemented and well-tested in isolation. The single biggest thing to fix before any publication: the seal sweep silently produces cryptographically valid but semantically wrong seals (wrong chain_head_hash), which is the only external tamper-evidence proof an auditor would independently verify.

---

## 2. Blockers

Must fix before any real adoption (internal or external):

| Issue | Where | Fix |
|---|---|---|
| **MAX(entry_hash) is lexicographic, not chain-tip hash** — every seal's `chain_head_hash` references the wrong row; independent seal verification fails on any log with >1 unsealed event (~50% failure rate with uniform HMAC-SHA256 output) | `crates/soma-audit-server/src/seal.rs:31` | Replace grouped aggregates with `SELECT DISTINCT ON (tenant_id) tenant_id, seq_num, entry_hash FROM soma_audit.fct_audit_events WHERE ... ORDER BY tenant_id, seq_num DESC`. Add an integration test: record N events → sweep_once → assert stored `chain_head_hash` equals `entry_hash` of the row at `MAX(seq_num)`. |

---

## 3. Should-Fix

High-value, do soon:

| Issue | Where | Fix |
|---|---|---|
| **Seal sweep returns zero rows under FORCE RLS** — no GUC set before querying `fct_audit_events`; all rows filtered; no seals ever inserted in a correctly-configured non-superuser deploy | `crates/soma-audit-server/src/seal.rs:29-40` | Either `GRANT BYPASSRLS` to the service DB role scoped to the sweep connection, or bootstrap a tenants registry (one row per tenant, no RLS) and set `SET LOCAL soma_audit.tenant_id = tenant_id::text` inside a per-tenant transaction before each query. |
| **metadata excluded from HMAC canonical message** — a superuser UPDATE to the `metadata` JSONB column passes `verify_chain` undetected; metadata commonly carries old/new values and request IDs | `crates/soma-audit-core/src/chain.rs:57-73` | Append `serde_json::to_string(&metadata)` as field 14 to the RS-delimited array; bump `chain_epoch` to 2; document that epoch-1 records verify with the 13-field formula. |
| **FOR UPDATE SKIP LOCKED released before Rust iterates rows** — relay runs via `fetch_all(pool)` in autocommit; row locks released before processing; concurrent relay tasks race and send duplicates (server idempotency_key prevents double-record but the mutex claim is false) | `crates/soma-audit-client/src/relay.rs:73-83` | Open `pool.begin()` before the SELECT; mark rows delivered inside the same transaction; commit. |
| **`audit_chain_seals` table created via raw inline DDL in `main.rs`** — outside soma-schema; no checksum, no DOWN migration, invisible to the manifest, no hook for future ALTERs | `crates/soma-audit-server/src/main.rs:31-43, 67` | Move to `20260626_02_audit-chain-seals.sql` (UP+DOWN) under `crates/soma-audit-pg/migrations/01_migrated/`; remove inline DDL from main.rs. |
| **Bearer token comparison not constant-time** — `tok == state.ingest_secret` / `tok == state.admin_token` short-circuit on first differing byte; `subtle` is already a transitive dep via ed25519-dalek | `crates/soma-audit-server/src/auth.rs:16, 24` | `tok.as_bytes().ct_eq(state.ingest_secret.as_bytes()).into()` — zero new dependencies. |
| **Outbox relay has no exponential backoff** — failed rows eligible for retry every 5 s; broken endpoint hammered indefinitely; TODO comment at relay.rs:157-161 already acknowledges this | `crates/soma-audit-client/src/relay.rs:155-161` | Add `next_retry_at TIMESTAMPTZ DEFAULT NOW()` column to outbox migration; set `now() + interval '1 second' * (2 ^ LEAST(attempts, 10))` in `record_failure`; add `AND next_retry_at <= now()` to the fetch WHERE clause. |
| **soma-vault has a diverging audit implementation** — structurally identical (HMAC chain, advisory xact lock) but different canonical format (9 vs 13 fields, `hashtext()` vs BIGINT key, no HKDF); two code paths to maintain | `soma-vault/crates/soma-storage/src/pg/audit.rs` | Migrate soma-vault to use `LocalSink::record_in_tx`; vault audit key becomes `AuditKeys::from_secret`. Already documented as planned in architecture rev 2.3. Do this before external publication to prove soma-audit works in a real soma service. |
| **`verify()` loads entire tenant chain into memory** — unbounded `fetch_all` into `Vec<AuditRecord>` with no LIMIT; admin-token-gated but still a privileged OOM trigger | `crates/soma-audit-pg/src/sink.rs:306-315`; `crates/soma-audit-server/src/query.rs:52-64` | Switch to `sqlx::query_as(...).fetch(pool)` stream; verify incrementally carrying only `prev_hash + seq_num`; O(1) memory; allows early exit on first broken link. |
| **RS separator (0x1E) not validated out of free-text fields** — `source_service`, `event_type`, `actor_role`, `resource_type`, `resource_id` carry no guard; a caller holding the ingest secret can inject 0x1E to shift field boundaries and produce a hash-colliding canonical message | `crates/soma-audit-core/src/chain.rs:5-7`; `crates/soma-audit-server/src/ingest.rs:56-68` | Reject any field containing `'\x1e'` at the ingest handler boundary before the event reaches the chain. |

---

## 4. What's Missing

### Testing
- [ ] CI pipeline (`.github/workflows/ci.yml`): Postgres 16 service, `TEST_DATABASE_URL` set, `cargo test --workspace`, `cargo clippy -- -D warnings`, `cargo fmt --check`
- [ ] Integration test for seal sweep correctness: record N events → `sweep_once` → assert `chain_head_hash == entry_hash` at `MAX(seq_num)`
- [ ] HTTP handler tests for soma-audit-server: 401 on missing/wrong bearer for each route, 201 on valid ingest, 422 on malformed body — use `tower::ServiceExt::oneshot` against the router
- [ ] Relay round-trip test: enqueue → `relay_once` against a local axum test server → assert `delivered_at IS NOT NULL`; also test 500 response → `attempts` incremented, row not marked delivered
- [ ] Concurrency test for `record_in_tx`: 20 concurrent `sink.record()` calls for same tenant → `sink.verify()` returns `ok=true`, `entries_checked==20`
- [ ] Tamper-detection integration test: write chain → superuser UPDATE a field → `sink.verify()` returns `ok=false`, `first_broken_seq` set
- [ ] CI job: `cargo check --manifest-path examples/notes-app/Cargo.toml` (example is not a workspace member; silently breaks on API changes)

### Ops & Deploy
- [ ] `.env.example` with all 5 required env vars and generation commands (`openssl rand -hex 32`)
- [ ] `Dockerfile` (multi-stage: cargo build release → slim runtime image)
- [ ] `docker-compose.yml` (postgres:16 + soma-audit-server)
- [ ] `docs/OPERATIONS.md`: secret generation, key rotation (new `SOMA_AUDIT_MASTER_SECRET` breaks historical verify — must be explicit), required Postgres grants, outbox lag monitoring, advisory-lock behavior on failover, chain verify after DB restore

### Security
- [ ] Constant-time bearer comparison (see Should-Fix above)
- [ ] RS field validation at ingest boundary (see Should-Fix above)
- [ ] Restrict CORS `allow_origin` from `Any` to a configurable origin list; `/internal/v1/events` needs no CORS at all (`crates/soma-audit-server/src/routes.rs:21-24`)
- [ ] Switch dashboard `localStorage` → `sessionStorage` for admin token; add autocomplete off; add "Clear credentials" button (`dashboard/src/app.rs:108, 128`)

### Docs
- [ ] Add `dashboard/dist/` to `.gitignore`; document in CONTRIBUTING.md that `trunk build --release` must run before `cargo build` for the server
- [ ] Remove or clearly mark AuditSink trait / CompositeSink / "Both mode" sections in `docs/soma-audit-architecture.md` as "Not Yet Implemented (Phase 2)"
- [ ] Add "Why not X" section to README and website: pgaudit logs SQL not business events; plain log table has no mutation detection; external SIEMs have a commit-to-delivery gap
- [ ] Add one-sentence superuser caveat to website hero/features card: "Protects against app-role tampering; use Ed25519 seals + out-of-band copy for superuser-level assurance"
- [ ] Add compatibility note to README quickstart: "Requires sqlx 0.8, tokio, Postgres 16+"
- [ ] `CHANGELOG.md` (Keep a Changelog format); document that any canonical_msg format change or chain_epoch bump is a breaking change requiring a major version bump

### Release
- [ ] Publish `soma-schema` to crates.io; swap workspace dep from `path = "../soma-schema"` to `version = "0.3"`
- [ ] Publish `soma-audit-core` → `soma-audit-pg` → `soma-audit-client` in dependency order
- [ ] Add `prune_delivered(pool, older_than: Duration)` to soma-audit-client (one DELETE, ~10 lines); wire as optional `cleanup_interval` in `RelayConfig`

---

## 5. Nice-to-Have / Later

- Forensic filter set in dashboard (date range, actor_id, resource_type, outcome) — the API QueryBuilder change is ~20 lines but the UI work is larger; deferred until there is an operator with real investigations to run
- Verify page UX: elapsed-time counter during execution; link broken `seq_num` to events page pre-filtered to that entry
- Multi-tenant switcher: replace raw UUID text input with a dropdown populated from `SELECT DISTINCT tenant_id FROM soma_audit.fct_audit_events`; scope to URL param for bookmarkability
- AuditSink trait + CompositeSink for "Both" mode — only worth implementing when an actual adopter needs it; until then the manual `record_in_tx + enqueue_in_tx` pattern documented in INTEGRATION.md is sufficient
- `reqwest::Client::builder().timeout(Duration::from_secs(30)).connect_timeout(...)` on the relay client (`relay.rs:54`) — background task only, not the hot path; errors already route to `record_failure`
- `docs/OPERATIONS.md` production runbook (full version) — the `.env.example` and a key-rotation note in README covers the critical 20%; full runbook is pre-user-zero work
- Streaming/chunked verify endpoint for large tenants — the incremental in-memory fix (Should-Fix) is the minimum; a server-sent-events or cursor-based HTTP verify endpoint is later

---

## 6. What's Genuinely Good

Do not second-guess these — they are the load-bearing correct decisions:

**Atomic in-transaction guarantee.** `record_in_tx` takes the caller's `sqlx::Transaction<'_, Postgres>` and runs inside it. The audit row either commits with the business operation or rolls back with it. This is the real differentiator versus any logging-table approach and it is implemented correctly.

**HKDF per-tenant key derivation.** One master secret, one deterministic `derive_tenant_hmac_key` call per tenant using HKDF-SHA256, `Zeroizing<Vec<u8>>` wipes both the master and derived key on drop. No per-tenant key storage, no key distribution problem, correct isolation.

**Honest tamper model documentation.** INTEGRATION.md section 7 explicitly states what triggers and RLS do and do not protect against, including the superuser caveat. This is unusually candid for security tooling and it builds the right kind of trust.

**Idempotent write path.** `ON CONFLICT (idempotency_key) DO NOTHING` followed by a fetch of the existing row makes every `record_in_tx` call retry-safe with zero caller ceremony.

**`verify_chain` implementation.** The three-check loop (HMAC recompute, seq_num gap, prev_hash continuity) is simple, correct, and exhaustively covered by unit tests. The logic is small enough to read and audit in under five minutes.

**INTEGRATION.md.** The best artifact in the repo. Complete, precise, has concrete code, and honest about limits. Rare for early-stage OSS.

---

## 7. Recommended Next 5 Actions

Ordered by risk-to-correctness, each under half a day:

**1. Fix the seal sweep SQL bug (2-3 hours)**
Replace `MAX(entry_hash)` with `DISTINCT ON (tenant_id) ... ORDER BY tenant_id, seq_num DESC` in `seal.rs:31`. Add the integration test asserting `chain_head_hash == entry_hash` of the highest-seq row. This is the only bug that silently produces wrong cryptographic proofs in the shipped code.

**2. Fix the RLS bootstrapping gap in sweep_once (2 hours)**
Grant `BYPASSRLS` to the service DB role (or add a `tenants` registry table without RLS). Without this, the seal sweep produces zero seals in any non-superuser deploy, making the Ed25519 layer silently dead.

**3. Add metadata to canonical_msg and bump chain_epoch to 2 (3 hours)**
Append `serde_json::to_string(&event.metadata)` as field 14. Bump `chain_epoch` to 2. Update `verify_chain` to dispatch on epoch. Add a unit test: same event, mutated metadata → different `entry_hash`. This closes the most meaningful gap in the tamper-evidence guarantee.

**4. Add CI (half day)**
`.github/workflows/ci.yml` with a `services: postgres:16` job, `TEST_DATABASE_URL` set, `cargo test --workspace`, `cargo clippy -- -D warnings`, `cargo fmt --check`, plus a `cargo check --manifest-path examples/notes-app/Cargo.toml` step. Without CI, every one of the above bugs could regress silently.

**5. Fix relay correctness issues (3 hours)**
- Wrap `relay_once`'s SELECT + mark-delivered in an explicit `pool.begin()`/`tx.commit()` transaction so `FOR UPDATE SKIP LOCKED` actually holds through processing.
- Add `next_retry_at` column to the outbox migration and implement exponential backoff in `record_failure`.
- Replace `reqwest::Client::new()` with `Client::builder().timeout(Duration::from_secs(30)).build()?`.

These five actions resolve every blocker and the two highest-severity correctness bugs. The constant-time comparison, RS field validation, and soma-vault migration follow naturally in the next session.