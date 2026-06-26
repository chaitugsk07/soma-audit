# soma-audit Architecture Decision Document

## Revision 2.3 — install via soma-schema embedded migrations (not sqlx-native); soma-iam first consumer; Both UI modes hosted-first; vault audit removed & replaced via Local in-transaction drop-in (no data migration); key/config sourced from soma-vault via `AuditKeys::from_secret` (library stays vault-agnostic), vault↔audit bootstrap cycle documented as acyclic

> **Supersedes Revision 1** (central-service-only design). All valid mechanics from
> Revision 1 (HMAC chain, Ed25519 seals, outbox guarantee, append-only, idempotency,
> RLS) are preserved and extended to the embeddable model.

---

## 1. TL;DR / Decision Summary

| Decision | Choice | One-line why |
|---|---|---|
| **Crate layering** | `soma-audit-core` / `soma-audit-pg` / `soma-audit-client` / `soma-audit-server` | OTel API/SDK/Exporter/Collector split; core has zero IO; each layer adds one capability |
| **Sink abstraction shape** | One-method `AuditSink` trait via `async_trait`; `LocalSink` adds concrete `record_in_tx` method | `dyn AuditSink` requires `async_trait` on Rust 1.82; in-tx is a concrete capability, not a trait |
| **Local / Remote / Both** | Three concrete impls behind one trait; Both = `CompositeSink([local, remote])` at runtime | No third code path; composition eliminates the fork; Vault at-least-one policy in `CompositeSink` |
| **Chain authority model** | Anchor, not re-chain; central stores event bodies + periodic signed anchor records | Re-chaining doubles central chain length and requires central to hold the HMAC key |
| **Where chain math lives** | Rust (`soma-audit-core`); DB trigger only for structural append-only (BEFORE UPDATE/DELETE) | HMAC key never enters the DB; plpgsql cannot be unit-tested; pgcrypto is an avoidable dep |
| **Schema install mechanism** | `soma-audit-pg::install(pool).await?`; migrations bundled via `include_dir!` and run through **soma-schema**'s new `Migrator::from_embedded` into schema `soma_audit` with a dedicated advisory lock key | Keeps the platform's single migration tool; no sqlx upgrade forced; non-soma apps get soma-schema as a clean transitive dep |
| **Migration tooling** | Extend soma-schema with `Migrator::from_embedded` (`include_dir`); reuse it everywhere | One migration tool platform-wide; small additive PR to soma-schema; stays on current sqlx 0.8 |
| **Feature-flag matrix** | `local` (default) and `remote`; no `both` alias | Explicit `features = ["local", "remote"]` is self-documenting; alias saves nothing |
| **Generic envelope** | Fixed envelope fields in `soma-audit-core`; free-form `event_type: String` + `metadata: JSONB` | Library fixes structure; app owns vocabulary; no semantic validation ever |
| **Key provider** | Plain `AuditKeys` struct (`from_secret` + `from_env`); host resolves bytes, library stays vault-agnostic | Soma hosts feed vault-sourced secrets in; non-soma hosts use env; no `KeyProvider` trait until runtime-swappable resolution is needed |
| **Env & config source** | Soma services pull soma-audit's secrets + `DATABASE_URL` from soma-vault; library itself takes resolved bytes | Vault is the platform secret source; library has no soma-vault dependency so it stays drop-in for any app |
| **Ed25519 batch seals** | Live in `soma-audit-server` only, not in every embedded install | Running a seal timer in every host app creates key management complexity in every app |
| **project_id dimension** | Stamped by the relay at forward time from `AuditConfig`, not per-event by the caller | One config value, stamped automatically; wrong to require caller correctness per event |

**What soma-audit is:** An embeddable Rust library that installs an append-only, HMAC-chained audit table directly into any host application's Postgres database, callable in-process with atomic in-transaction guarantees — plus a companion central service for cross-project query, Ed25519 batch seals, and external verifiability. Think of it as `cargo add soma-audit`: install it, it creates the audit schema inside the host app's own database, and the app calls `local_sink.record_in_tx(&event, &mut tx).await?` inside the same transaction as the business write. No network hop. No audit gap. The same library can also forward events to a central service when cross-project query is needed. The central service is `soma-audit-server` — exactly `soma-audit-pg` plus axum ingest handlers and a periodic Ed25519 seal sweep.

---

## 2. Product Shape and Goals

### The three deployment modes

**Local only.** Host app installs `soma-audit-pg` into its own Postgres. The `LocalSink::record_in_tx` call sits inside the same `sqlx::Transaction` as the business write. If the business transaction rolls back, the audit row rolls back with it. Zero network hops. This is categorically stronger than any central service can offer. HMAC chain lives in the host DB. No external seals, no cross-project query — just a tamper-evident local log.

**Remote only.** Host app installs `soma-audit-client`. The `RemoteSink::record` call inserts an outbox row in the host DB (durable) and a background relay task delivers to a central `soma-audit-server`. The local outbox row is the durability anchor; the central copy is the permanent record. Outbox rows are pruned after central acks. There is no "remote with no local durability" — the library enforces this by design. A pure fire-and-forget HTTP call that drops events on network failure is not an `AuditSink` implementation; it violates the security contract.

**Both.** Host app uses `LocalSink` + `RemoteSink` composed via `CompositeSink::at_least_one`. The local chain is the legal record (local-authoritative deployment) or the local table is a durable buffer pruned after central acks (central-authoritative deployment). The authority mode is a startup-time configuration choice, not a runtime toggle.

### What "product-specific events, generic system" means concretely

The library fixes the envelope (envelope fields listed in Section 8). The app supplies `event_type: String` — any string, no validation. `metadata: serde_json::Value` — any JSON, no validation. The library never knows what `"vault.secret.read"` means. Every app has its own `event_type` vocabulary. The library only guarantees that every event is durably recorded, hash-chained, and tenant-isolated.

Vault's existing `<resource>.<verb>` vocabulary (`secret.write`, `token.create`, etc.) continues unchanged. soma-iam will use a different vocabulary. The library treats them identically.

### Non-goals

- Not a general-purpose event bus or observability pipeline
- Not a SIEM (OCSF export is a Phase 3 read-side projection, not the storage schema)
- Not a session recording system
- Not a metrics or tracing system
- Not a config framework with a knob for everything

### The security guarantee, restated for the embedded case

**"No privileged action without a durable audit record."**

In Local mode, calling `local_sink.record_in_tx(&event, &mut tx).await?` before `tx.commit().await?` makes the audit row atomic with the business write. A crash between the two is impossible — they commit together or both roll back. This is stronger than the Revision 1 outbox model, where the audit row was in a separate (outbox) write that could lag the business commit.

The HMAC chain detects any post-hoc mutation. The append-only trigger deters application-layer tampering. The honest scope of the local guarantee: it holds against the application role and against rogue application code. A Postgres superuser who also knows the HMAC key can rewrite history without detection at the DB layer. For that threat level, the central copy (Both mode) combined with Ed25519 seals anchored to immutable external storage is the countermeasure — planned for Phase 3.

---

## 3. Crate Architecture

### Layer responsibilities

**`soma-audit-core`** — pure Rust, zero IO

Owns the canonical types and all cryptographic math. Nothing in this crate does network IO, file IO, or database access.

- `AuditEvent` struct (what the caller builds; all caller-supplied fields)
- `AuditRecord` struct (what gets stored: `AuditEvent` + `seq_num: i64`, `prev_hash: [u8; 32]`, `entry_hash: [u8; 32]`)
- `AuditSink` trait (one method; see below)
- `CompositeSink` (fan-out to `Vec<Box<dyn AuditSink>>` with at-least-one policy)
- `fn compute_entry_hash(event: &AuditEvent, seq_num: i64, prev_hash: Option<&[u8; 32]>, key: &[u8]) -> [u8; 32]`
- `fn verify_chain(records: &[AuditRecord], key: &[u8]) -> VerifyResult`
- HKDF-SHA256 per-tenant key derivation
- `AuditError`, `VerifyResult`, `ChainError` types

Dependencies: `serde`, `serde_json`, `uuid`, `chrono`, `hmac`, `sha2`, `hkdf` (0.12.4 stable — do not use 0.13.x RC), `ed25519-dalek` (2.2.0 stable — do not use 3.x pre-release), `zeroize`. No `sqlx`, no `axum`, no `tokio`, no `reqwest`.

**`soma-audit-pg`** — the Local sink

Installs the `soma_audit` schema into any host Postgres and provides `LocalSink`.

- `pub async fn install(pool: &PgPool) -> Result<(), soma_schema::Error>` — idempotent, called once at startup; migrations bundled via `include_dir!` and run via `soma_schema::Migrator::from_embedded`; tracking table is soma-schema's standard `00_schema_migrations` inside `soma_audit` schema
- `LocalSink` implementing `AuditSink`: acquires per-tenant advisory lock, fetches chain head, calls core chain math, inserts `AuditRecord`
- `LocalSink::record_in_tx` — concrete method (NOT a trait method; takes `&mut sqlx::Transaction`) for atomic in-transaction audit
- SQL migrations: `CREATE SCHEMA IF NOT EXISTS soma_audit`, `fct_audit_events`, append-only BEFORE trigger, `REVOKE UPDATE/DELETE`, RLS policy, BRIN index on `occurred_at`
- `AuditKeys` struct (v1 key management; `from_secret` for soma/vault-sourced, `from_env` for standalone — see Section 6)

Dependencies: `soma-audit-core`, `soma-schema`, `include_dir`, `sqlx` (Postgres feature, workspace version 0.8), `tokio`.

**`soma-audit-client`** — the Remote sink

- `RemoteSink` implementing `AuditSink`: inserts outbox row in host DB (durable); background relay task delivers to central's ingest endpoint
- Outbox DDL embedded via `include_str!` (two tables: `soma_audit_outbox`, `soma_audit_outbox_delivered`); installed alongside host's own schema via the host's pool
- Relay task: `SELECT FOR UPDATE SKIP LOCKED`, HTTP POST to `soma-audit-server`, mark delivered, exponential backoff, alert on lag
- `CompositeSink::at_least_one(local, remote)` constructor lives here — the Both-mode composition is three lines at the call site

Dependencies: `soma-audit-core`, `soma-schema`, `include_dir`, `sqlx` (Postgres feature, workspace version 0.8), `reqwest`, `tokio`.

**`soma-audit-server`** — the central service

A binary crate. IS `soma-audit-pg` for its own Postgres schema plus:

- axum ingest endpoint: `POST /internal/v1/events` (bearer auth, idempotent ON CONFLICT)
- Ed25519 batch seal sweep (one global tokio task, not one per host app)
- JWKS endpoint: `GET /v1/audit/keys`
- Cross-project query/verify API: `GET /v1/audit`, `GET /v1/audit/verify`, `GET /v1/audit/seals`
- `project_id` dimension stamping on forwarded events
- Anchor records from local-authoritative deployments

Not a library crate. Host apps never depend on it directly.

### AuditSink trait

```rust
// soma-audit-core/src/sink.rs
use async_trait::async_trait;

#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Record one audit event durably.
    ///
    /// Returns Ok(()) only when the event is on durable storage.
    /// A return of Ok(()) is a promise: this event will outlive the current
    /// process. Implementations MUST NOT return Ok(()) on best-effort writes.
    /// On failure the caller SHOULD roll back the surrounding business transaction.
    async fn record(&self, event: AuditEvent) -> Result<(), AuditError>;
}
```

One method. No `flush` (Local is transactional; Remote relay is a background task). No `verify` (read-path function in core, not a sink concern). No `batch_record` in v1. `&self` not `&mut self` — sinks live behind `Arc<dyn AuditSink>` in AppState.

The trait uses `async_trait` because Rust 1.82 AFIT does not support `dyn Trait` when the trait has `async fn` methods. `async_trait` is the mature solution with full `dyn` support. Revisit when native dyn-async is stable (no confirmed timeline as of June 2026 — do not add a forward reference to `dyner`).

### How Both composes (not a third code path)

```rust
// Both mode at the call site — three lines
let sink: Arc<dyn AuditSink> = Arc::new(CompositeSink::at_least_one(vec![
    Box::new(LocalSink::new(pool.clone(), key_provider.clone())),
    Box::new(RemoteSink::new(pool.clone(), relay.clone())),
]));
```

`CompositeSink` fans out concurrently (not sequentially — sequential adds latency for the common Local+Remote case):

```rust
pub struct CompositeSink {
    sinks: Vec<Box<dyn AuditSink>>,
}

impl CompositeSink {
    pub fn at_least_one(sinks: Vec<Box<dyn AuditSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl AuditSink for CompositeSink {
    async fn record(&self, event: AuditEvent) -> Result<(), AuditError> {
        let futures: Vec<_> = self.sinks.iter()
            .map(|s| s.record(event.clone()))
            .collect();
        let results = futures::future::join_all(futures).await;
        let any_ok = results.iter().any(|r| r.is_ok());
        if any_ok {
            Ok(())
        } else {
            Err(results.into_iter().filter_map(|r| r.err()).next().unwrap())
        }
    }
}
```

There is no `FailurePolicy::All` variant. Nobody asked for all-must-succeed. At-least-one is hardcoded, matching the HashiCorp Vault audit-device contract exactly.

### Feature-flag matrix

```toml
# In soma-audit-pg/Cargo.toml:
[dependencies]
soma-audit-core  = { path = "../soma-audit-core" }
soma-schema      = "0.3.0"
include_dir      = "0.7"
sqlx             = { workspace = true, features = ["postgres", "runtime-tokio", "uuid", "chrono"] }
tokio            = { version = "1", features = ["rt", "sync"] }
async-trait      = "0.1"

# Optional: gate Remote sink deps behind a feature
soma-audit-client = { path = "../soma-audit-client", optional = true }

[features]
default = []
remote  = ["dep:soma-audit-client"]
```

Host app that only stores locally:
```toml
soma-audit-pg = { version = "0.1" }
```

Host app that also forwards to central:
```toml
soma-audit-pg = { version = "0.1", features = ["remote"] }
```

No umbrella re-export crate. Host apps depend directly on `soma-audit-pg` or `soma-audit-client`. The umbrella adds a crate boundary that saves nothing at the install UX level.

---

## 4. The Sink Model and Durability Per Mode

### Local (the strong guarantee)

`LocalSink::record` opens its own transaction, chains, inserts, commits. Strong, but has a narrow failure window if used from outside a business transaction: a crash after business commit but before audit commit would lose the event (extremely unlikely with a connection-pool-backed pool, but possible).

`LocalSink::record_in_tx` eliminates this entirely:

```rust
impl LocalSink {
    /// Atomically audit within the caller's business transaction.
    /// Caller commits tx; if they roll back, the audit row rolls back too.
    /// This is the headline guarantee no central service can match.
    pub async fn record_in_tx(
        &self,
        event: AuditEvent,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<(), AuditError> {
        // 1. Per-tenant advisory lock (transaction-scoped, auto-released at commit/rollback)
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(tenant_lock_key(event.tenant_id))
            .execute(&mut **tx)
            .await?;
        // 2. Fetch chain head
        let (seq_num, prev_hash) = fetch_chain_head(&mut **tx, event.tenant_id).await?;
        // 3. Compute entry_hash in Rust (key never in DB)
        let entry_hash = compute_entry_hash(&event, seq_num, prev_hash.as_ref(), &self.key);
        // 4. Insert — ON CONFLICT (idempotency_key) DO NOTHING
        insert_audit_record(&mut **tx, &event, seq_num, prev_hash, entry_hash).await?;
        Ok(())
    }
}
```

Code that needs the in-tx guarantee holds `Arc<LocalSink>` (concrete type). Code that only needs substitutable sink behavior holds `Arc<dyn AuditSink>`. This is the correct Rust idiom.

### Remote (outbox-backed; no pure fire-and-forget)

```rust
#[async_trait]
impl AuditSink for RemoteSink {
    async fn record(&self, event: AuditEvent) -> Result<(), AuditError> {
        // The outbox insert IS the durability guarantee.
        // The relay delivers to central asynchronously.
        // record() returns Ok(()) as soon as the outbox row is committed.
        sqlx::query!(
            "INSERT INTO soma_audit_outbox (id, payload, created_at)
             VALUES ($1, $2, now())
             ON CONFLICT (id) DO NOTHING",
            event.idempotency_key,
            serde_json::to_value(&event)?
        )
        .execute(&self.outbox_pool)
        .await?;
        Ok(())
    }
}
```

The relay task runs separately (`tokio::spawn` at startup), picks up undelivered outbox rows, posts to central's ingest endpoint, and marks rows delivered. Relay failure does NOT propagate to `record()`. This is the outbox pattern from Revision 1, now embedded in the library rather than in each host app.

**What record() does when a backend is down, per mode:**

| Mode | Backend down | record() behavior |
|---|---|---|
| `LocalSink` | Postgres pool exhausted | Returns `Err(AuditError::Db(...))` immediately |
| `RemoteSink` | Central unreachable | Outbox insert succeeds locally; relay retries; `record()` returns `Ok(())` |
| `RemoteSink` | Host Postgres down | Returns `Err(AuditError::Db(...))` — outbox insert failed |
| `CompositeSink` | One sink fails | Returns `Ok(())` if either sink succeeded; `Err` only when both fail |

### Durability summary

```
              BUSINESS WRITE
                    │
         ┌──────────┼──────────┐
         │          │          │
    Local mode  Both mode  Remote mode
         │          │          │
  ┌──────┤    ┌─────┤     ┌────┤
  │ audit│    │audit│     │out-│
  │  row │    │ row │     │box │
  │ in   │    │ in  │     │row │
  │ same │    │ same│     │ in │
  │  tx  │    │  tx │     │ host
  └──────┘    │     │     │ DB │
              │out- │     └────┘
              │box  │          │
              │ row │     relay (async)
              └──────┘         │
                     relay     ▼
                   (async) central ingest
                          (assigns
                           seq_num if
                           central-auth)
```

### Where record() is called

For Local mode: inside the host's business transaction, before `tx.commit()`.

```rust
// Host application code
let mut tx = pool.begin().await?;
sqlx::query!("INSERT INTO vault.secrets ...").execute(&mut *tx).await?;
local_sink.record_in_tx(audit_event, &mut tx).await?;
tx.commit().await?; // both rows committed here; both roll back on failure
```

For Remote/Both: `record()` can be called after `tx.commit()` (outbox row is in a new tx). Slightly weaker: there is a tiny window between business commit and outbox commit. For Remote-only deployments this is the accepted tradeoff.

---

## 5. Where the Chain Lives

### Decision: Rust-driven chain math; DB trigger for structural append-only only

The chain math (seq_num assignment, HMAC-SHA256 computation, entry_hash storage) lives entirely in `soma-audit-core` and is executed by `LocalSink` in Rust. The Postgres trigger is limited to the 4-line structural check:

```sql
CREATE OR REPLACE FUNCTION soma_audit.deny_mutation()
  RETURNS trigger LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'soma_audit.fct_audit_events is append-only: % denied', TG_OP;
END;
$$;

CREATE TRIGGER audit_entries_immutable
  BEFORE UPDATE OR DELETE ON soma_audit.fct_audit_events
  FOR EACH ROW EXECUTE FUNCTION soma_audit.deny_mutation();
```

This trigger fires unconditionally for the app's DB role. It also fires for the schema owner and for superusers executing DML, though both can defeat it structurally (`ALTER TABLE ... DISABLE TRIGGER ALL` or `DROP TRIGGER`). The trigger is a deterrence and detection signal layer, not a security boundary against DB owners.

**Why the trigger must NOT do chain math:**

The HMAC key must never be stored in the database. The only way to make a trigger compute the HMAC is to pass the key as a GUC (`SET soma_audit.hmac_key = '...'`). This puts the key in the SET statement, which appears transiently in `pg_stat_activity.query` and is captured by statement logging (`log_min_duration_statement`, `log_statements=all`). It is also readable within the same session via `current_setting()`. A DB admin who reads the GUC can both disable the trigger AND compute valid chain hashes — defeating chain integrity entirely. The HMAC chain's tamper-evidence is only meaningful when the key is inaccessible to the party who might tamper. Key-in-GUC collapses this.

Additional reasons: pgcrypto is an avoidable dep (not available on all managed Postgres offerings), plpgsql functions cannot be unit-tested in Rust, and `row_to_json(ROW(...))` produces `{"f1":...,"f2":...}` (generic field names), not a readable canonical string.

**The correct trigger for structural enforcement:**
- Triggers enforce structure (block UPDATE/DELETE at the Postgres layer)
- Rust enforces semantics (HMAC chain integrity, key management)
- This split is the one-line rule: **triggers enforce structure; Rust enforces semantics**

### Per-tenant advisory lock

```rust
fn tenant_lock_key(tenant_id: Uuid) -> i64 {
    // Two-integer form for wider key space (avoids 32-bit hashtext collision)
    // Using the first 8 bytes of the tenant UUID as a deterministic i64
    let bytes = tenant_id.as_bytes();
    i64::from_be_bytes(bytes[0..8].try_into().unwrap())
}
```

Called inside a transaction via `SELECT pg_advisory_xact_lock($1)` — transaction-scoped, auto-released at commit or rollback. The chain head query (`SELECT MAX(seq_num), entry_hash FROM soma_audit.fct_audit_events WHERE tenant_id = $1 ORDER BY seq_num DESC LIMIT 1`) runs under this lock, ensuring seq_num monotonicity.

The 32-bit `hashtext()` from Revision 1 is dropped. Using the first 8 bytes of the UUID gives a uniform i64 with negligible collision probability across any realistic tenant count.

### Append-only enforcement: the honest privilege model

| Actor | REVOKE blocks DML? | Trigger blocks single DML? | Can defeat structurally? |
|---|---|---|---|
| `soma_audit_writer` (app role) | Yes | Yes | No |
| `soma_audit_owner` (schema owner, non-superuser) | No (owner re-grants self) | Yes | Yes (DROP TRIGGER) |
| Postgres superuser | No | Yes (for that DML) | Yes (DISABLE TRIGGER) |

**The local DB append-only mechanism is a defense against the application itself.** The HMAC chain is the tamper-detection mechanism against anyone who bypasses the trigger. The central copy (Both mode with Ed25519 seals anchored externally) is the defense against DB-owner-level tampering. Document this honestly. Do not claim local append-only is a security boundary against DBAs.

Also: a Postgres superuser can bypass ALL triggers via `SET session_replication_role = 'replica'`. This is an additional bypass vector not closed by the trigger. The HMAC chain is the only detection mechanism at that privilege level.

---

## 6. Dual-Chain Authority

### Anchor, not re-chain

When a deployment runs in Both mode, the central service does NOT re-chain individual forwarded events under a new central HMAC key. Instead:

- Central stores the event body verbatim (same `fct_audit_events` table, `source_instance_id` column identifying the originating deployment; `local_seq_num` and `local_entry_hash` preserved)
- Central anchors the local chain head periodically (every 1,000 events or 60 seconds, aligned with the seal cycle), producing a short chain of anchor records

Re-chaining was rejected because it requires the central service to hold (or re-compute under) the local HMAC key, makes the central chain semantics ambiguous ("is this a central event or a forwarded local event?"), and doubles central chain length for no user-visible benefit.

This is the SCITT/IETF time-anchor pattern and the same model used by Certificate Transparency (RFC 6962): independent logs with independent seq_num spaces; the event's identity is its `idempotency_key` UUID, not its chain position.

### Local-authoritative mode

The local chain is the legal record. Central holds a copy for cross-project query. Central stores periodic anchor records that prove it observed the local chain in state H at time T.

Anchor record (stored in central `soma_audit_chain_anchors` table):

```
anchor_id          UUID       -- generated at anchor creation
source_instance_id UUID       -- identifies the local deployment
tenant_id          UUID
local_seq_num      BIGINT     -- seq_num of the head event being anchored
local_entry_hash   TEXT       -- hex(HMAC) of the head event under local key
local_sealed_at    TIMESTAMPTZ
anchored_at        TIMESTAMPTZ
anchor_signature   BYTEA      -- Ed25519 signature by local key over canonical fields
```

Central does not chain anchor records in v1 (chaining anchors is a Phase 3 concern). Central simply stores each anchor with a timestamp and the local Ed25519 signature. An anchor proves: at `local_sealed_at`, the local chain for `(source_instance_id, tenant_id)` had its head at `local_seq_num` with hash `local_entry_hash`. Central cannot forge this proof without the local private key.

### Central-authoritative mode

In central-authoritative mode, the local table is a transactional outbox. No chain math is performed locally. The local `soma_audit_outbox` row is the durable buffer; the relay delivers to central; central assigns `seq_num` and computes `entry_hash`. Local outbox rows are pruned after central acks.

Calling `verify_chain` against a central-authoritative deployment's local table returns a structured error indicating the mode:

```
{ verified: false, error: "central-authoritative mode: chain not maintained locally; verify against central service" }
```

### The authority mode as a startup-time configuration

Chain authority is declared once per deployment in environment configuration. It never changes at runtime. It is read once at startup into `AuditConfig`. It is not a field on `AuditSink` or `CompositeSink`. The only place it matters is in the relay task: local-authoritative relays forward an already-chained event (preserving `local_seq_num` and `local_entry_hash`); central-authoritative relays forward an unchained event payload (central assigns chain fields on ingest).

There is no runtime switch. A running instance does not change authority mode without a restart and a config change.

### What verify() guarantees per mode

**Local-authoritative:** Full offline verifiability. Given an export of the events and the local public key (from JWKS), any party can confirm: no event was inserted, deleted, reordered, or field-mutated. Ed25519 seals (from `soma-audit-server` or the local CLI tool) confirm batch boundaries. Cross-chain consistency check (optional): every local event appears at central with matching `local_entry_hash` and `local_seq_num`.

**Central-authoritative:** Chain verifiability is at central only. Verify against central's `fct_audit_events`. The local buffer has no chain to verify.

**Caveat in all modes:** These guarantees hold against application-layer attackers and database roles without superuser privileges. A Postgres superuser who also obtains the HMAC key can rewrite history without DB-layer detection. External anchoring (Rekor v2, S3 Object Lock) is the countermeasure for this threat level — planned for Phase 3.

### Key provider (v1 key management)

A plain `AuditKeys` struct in `soma-audit-pg` that holds the already-resolved key material. No trait in v1 — extract a `KeyProvider` trait only when a second resolution path needs to be swappable at runtime. The user's own bias: "flexibility is where reusable libraries go to die." The library is deliberately agnostic about *where* the secret comes from: the host hands it in. This is what keeps soma-audit-core/-pg free of any soma-vault dependency, so the module drops into a non-soma app unchanged.

```rust
pub struct AuditKeys {
    master_secret: Zeroizing<[u8; 32]>, // resolved by the host (see below)
    signing_key: ed25519_dalek::SigningKey, // resolved by the host (seal-side only)
}

impl AuditKeys {
    /// Library convenience for standalone / non-soma hosts:
    /// reads SOMA_AUDIT_MASTER_SECRET + SOMA_AUDIT_SIGNING_KEY (hex) from env.
    pub fn from_env() -> Result<Self, AuditError> { ... }

    /// Host supplies the bytes it already holds (the soma path — see below).
    pub fn from_secret(master_secret: [u8; 32], signing_key: [u8; 32]) -> Self { ... }

    /// HKDF-SHA256(IKM=master_secret, info="audit-hmac-v1" || tenant_id_bytes)
    pub fn hmac_key(&self, tenant_id: Uuid) -> Zeroizing<[u8; 32]> { ... }

    /// Ed25519 sign — called at seal time only (not per-event)
    pub fn seal_sign(&self, payload: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.signing_key.sign(payload).to_bytes().to_vec()
    }

    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}
```

**Two resolution paths, one struct.** The library never reaches into a secrets manager itself — it takes resolved bytes. The host decides where they come from:

- **Soma services (use vault for env & config):** the host pulls `SOMA_AUDIT_MASTER_SECRET`, `SOMA_AUDIT_SIGNING_KEY`, and `DATABASE_URL` from soma-vault (via `soma-infra`'s config helpers / a `SecretsProvider`), then calls `AuditKeys::from_secret(...)`. This is the platform default: soma-vault is the source of truth for env and config across all services, soma-audit included.
- **Standalone / non-soma hosts:** call `AuditKeys::from_env()` — plain hex env vars, no soma-vault required. Keeps the module genuinely drop-in for any app.

**The vault↔audit bootstrap cycle (called out for eng review).** soma-vault is being made an *embedder* of `soma-audit-pg` (Local, in-process) AND the platform's secret source for `soma-audit-server`. That looks circular, but it is not, because the two relationships are at different layers and never form a runtime loop: (1) vault's own embedded `LocalSink` is in-process and needs no network and no vault-secret-fetch — vault already holds its master KEK in memory and derives the audit key directly via `from_secret`, so vault auditing never calls vault-the-service; (2) only the *separate* `soma-audit-server` (and other separate apps) fetch their audit secret from vault-the-service over the network, and the server does not emit audit events back into vault, so there is no cycle. First-boot ordering: a separate soma-audit-server needs vault reachable for its secret at startup, exactly like any other vault-consuming service; vault itself has no such dependency on soma-audit (its embedded audit is in-process). This ordering is a deployment fact to document, not a deadlock.

Forward-secure ratchet after each batch seal: `HKDF-SHA256(IKM=k[n], info=b"ratchet")` → `k[n+1]`; erase `k[n]` via `zeroize`. This limits key compromise to the current unsealed window.

---

## 7. Schema Install Into Host DB

### The install call

```rust
// soma-audit-pg/src/migrate.rs
use include_dir::{include_dir, Dir};
use soma_schema::{Migrator, PostgresConfig, PostgresDriver};

static MIGRATIONS: Dir = include_dir!("$CARGO_MANIFEST_DIR/migrations");

pub async fn install(pool: &sqlx::PgPool) -> Result<(), soma_schema::Error> {
    let driver = PostgresDriver::new(
        pool.clone(),
        PostgresConfig {
            schema: Some("soma_audit".into()),
            advisory_lock_key: 6020250626000001,  // soma-audit's reserved key; distinct from soma-iam (7318249506742315) and soma-vault's 01_vault
            ..Default::default()
        },
    )?;
    Migrator::from_embedded(&MIGRATIONS).up(&driver).await
}
```

`include_dir!` in a library crate resolves `$CARGO_MANIFEST_DIR` at soma-audit-pg's compile time, not the host app's compile time. The migration files are baked into the soma-audit-pg binary; the host app ships no extra files. This is the key difference from `sqlx::migrate!` (which resolves relative to the calling crate).

The only upstream change required is adding `Migrator::from_embedded(dir: &include_dir::Dir)` to soma-schema. This is a small, additive, backward-compatible PR to soma-schema; `from_root(path)` is unchanged. No sqlx version bump is needed anywhere.

The schema name is hardcoded as `soma_audit`. It is not a runtime parameter. If multi-instance coexistence were needed, the REVOKE grants, RLS policies, and trigger names would all need parameterization — that is a major feature, not a parameter. One install, one schema, one advisory lock namespace.

### Coexistence with host soma-schema

soma-schema manages `soma_iam`, `01_vault`, and similar host-service schemas. soma-audit-pg manages `soma_audit`. They share a PgPool but are fully isolated: each Migrator/driver has its own schema name, its own tracking table inside that schema (`soma_iam.00_schema_migrations` vs `soma_audit.00_schema_migrations` — both the soma-schema standard name, different schemas), and its own operator-supplied `advisory_lock_key: i64`. soma-schema's per-driver `SET LOCAL search_path` ensures non-overlapping schema namespaces. Running both on a fresh database is safe in any order.

For soma services: call `soma_audit_pg::install(&pool).await?` at startup alongside the soma-schema migration runner. No conflict.

For non-soma apps: call `soma_audit_pg::install(&pool).await?` at startup. No soma-schema required.

### Schema-versioning and upgrade story

Migrations follow soma-schema's contract: a `migrations/` dir with `migration-order.yaml` manifest + versioned folders; UP/DOWN split on the exact line `-- DOWN ==`; checksum covers the whole file. Editing an applied file changes its checksum and causes a checksum-mismatch error on every host app at startup. Write a new migration file instead.

- **Patch release (0.1.x → 0.1.y):** No new migrations. Bug fixes in Rust code only.
- **Minor release (0.1 → 0.2):** New additive migrations (new columns, new tables, new indexes). Host apps call the same `install()` at startup — soma-schema verifies applied entries by checksum and applies only new ones. Zero host app code change.
- **Major release (0.x → 1.0):** Potentially breaking schema changes. Document in CHANGELOG. Host apps may need manual intervention.

Chain epoch increments are independent of schema version. The canonical hash input is defined in Rust (in `soma-audit-core`). A schema migration that adds a column does not break chain verification as long as the canonical field set is unchanged. If the canonical set must change, increment the chain epoch in Rust code and document the epoch boundary.

### GUC namespacing

The RLS policy reads `soma_audit.tenant_id` (not `app.tenant_id`) to avoid collisions with host app GUCs:

```sql
CREATE POLICY tenant_isolation ON soma_audit.fct_audit_events
  USING (
    tenant_id = pg_catalog.current_setting('soma_audit.tenant_id', true)::uuid
  );
ALTER TABLE soma_audit.fct_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE soma_audit.fct_audit_events FORCE ROW LEVEL SECURITY;
```

The second argument `true` to `current_setting` returns NULL instead of raising if the GUC is not set.

**Single-tenant host apps:** At install time, if the host declares single-tenant (`AuditConfig { multi_tenant: false }`), the installer skips the RLS policy entirely. The `COALESCE` passthrough trick (matching `tenant_id` to itself) is obscure and adds overhead on every row read. A boolean at install time is simpler and honest.

The `soma_audit.tenant_id` GUC is set per-transaction by the application:

```rust
sqlx::query("SET LOCAL soma_audit.tenant_id = $1")
    .bind(tenant_id.to_string())
    .execute(&mut *tx)
    .await?;
```

---

## 8. Event Envelope and Project Dimensions

### AuditEvent (caller-built)

```rust
// soma-audit-core/src/event.rs
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    /// Stable identity across all chains and retries.
    pub idempotency_key: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    /// Who performed the action — opaque string (user UUID, service account, "svc:scheduler")
    pub actor: String,
    /// Free-form dot-notation string owned by the application. No validation.
    /// Examples: "secret.write", "user.login", "invoice.approved"
    pub event_type: String,
    /// When the operation occurred (caller clock). Distinct from DB stored_at.
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    /// Which microservice emitted this event.
    pub source_service: String,
    /// Application-specific context. No PII. No secrets. No validation by library.
    #[serde(default)]
    pub metadata: serde_json::Value,
}
```

### AuditRecord (what gets stored)

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    pub id: uuid::Uuid,           // generated by the sink on insert
    #[serde(flatten)]
    pub event: AuditEvent,
    // Chain fields — populated by LocalSink, never by the caller
    pub seq_num: i64,
    pub prev_hash: [u8; 32],      // zero-filled for the first event per tenant per epoch
    pub entry_hash: [u8; 32],
    pub chain_epoch: i32,         // for epoch boundary at vault cutover
    pub stored_at: chrono::DateTime<chrono::Utc>, // DB server clock
}
```

Two types, not one with `Option` fields. The caller builds `AuditEvent` (no chain fields). The sink produces `AuditRecord` (chain fields populated). A partial `AuditEvent` with `Option<i64>` seq_num is a partially-initialized type that is easy to misuse.

### Cross-project dimensions

The minimum dimension set for a useful cross-project query API at central:

**MUST (v1):**
- `project_id` — which deployment/installation sent this event. Stamped by the relay from `AuditConfig` at forward time. Not per-event caller-supplied. Not stored in the local DB (local has only one project). Example: `"acme-crm-prod"`.
- `tenant_id` — tenant within the project
- `source_service` — which microservice emitted it
- `actor` — who performed the action
- `event_type` — the application's vocabulary string
- `occurred_at` — range filter
- `seq_num` + `local_seq_num` — chain verification queries

**NICE (v2):**
- `actor_type` — discriminant: `"user"` vs `"service_account"` vs `"api_key"` (enables "show only human actions")
- `resource_type` + `resource_id` — via GIN index on `metadata` JSONB (`metadata @> '{"resource_id": "..."}'`); no dedicated columns unless query plans show GIN is insufficient

**YAGNI:**
- `region`, `environment`, `ip_address`, `user_agent` — belong in `metadata` JSONB, not indexed columns
- Per-project retention policy at central — punt to v2
- Real-time streaming / webhooks

### Event type namespacing

The library enforces no vocabulary. Each project owns its prefix by convention: `vault.*`, `iam.*`, `audit.*`. soma-audit self-audits under `audit.chain.seal`, `audit.install`, etc. Any `event_type` string is accepted.

Vault's existing vocabulary is preserved unchanged: `secret.write`, `secret.read`, `secret.delete`, `token.create`, `token.revoke`, `project.create`, `environment.create`. The `soma-audit-types` crate (from Revision 1) becomes a thin re-export of `soma-audit-core` types plus vault's vocabulary constants.

### OCSF

Not the internal schema. OCSF 1.8.0 mandates ~15 required fields and a versioned schema dependency. An OCSF export adapter at `GET /v1/audit?format=ocsf` maps stored rows to OCSF JSON on read. Phase 3. Not in Phase 1 scope.

---

## 9. Central Service and Cross-Project Query

### What soma-audit-server is

`soma-audit-server` is a Rust binary that runs `soma-audit-pg` on its own Postgres schema (`soma_audit` in its own DB) plus axum handlers for:

- `POST /internal/v1/events` — ingest from relay tasks (bearer auth, idempotent ON CONFLICT)
- `GET /v1/audit` — cross-project keyset-paginated query (filters: `project_id`, `tenant_id`, `source_service`, `actor`, `event_type`, time range)
- `GET /v1/audit/verify` — chain walk with `since_seq_num` cursor
- `GET /v1/audit/seals` — list Ed25519 batch seals
- `GET /v1/audit/keys` — JWKS endpoint with central Ed25519 public key
- `GET /health`, `GET /health/ready`

The crate layout mirrors soma-vault:

```
soma-audit/
  crates/
    soma-audit-core/    pure types, chain math, verify
    soma-audit-pg/      LocalSink, schema installer, AuditKeys
    soma-audit-client/  RemoteSink, outbox DDL, relay task, CompositeSink
    soma-audit-server/  binary: axum handlers + seal sweep task
  migrations/           soma-audit-server's own schema migrations (soma-schema runner)
  migration-order.yaml
```

Note: both the server and the embedded library use soma-schema as the migration tool. The server can use `Migrator::from_root(path)` (reads from disk) or `Migrator::from_embedded(&MIGRATIONS)` (compile-time bundle) — prefer `from_embedded` so it is identical to the library. The embedded library (`soma-audit-pg`) always uses `from_embedded`. Same tool, same SQL files, same contract.

### Ingest contract

```
POST /internal/v1/events
Authorization: Bearer <SOMA_AUDIT_INGEST_SECRET>
Content-Type: application/json

{
  "idempotency_key": "<uuid-v4>",
  "tenant_id":       "<uuid>",
  "actor":           "<string>",
  "event_type":      "<string>",
  "occurred_at":     "<rfc3339>",
  "source_service":  "<string>",
  "project_id":      "<string>",       -- added by relay, not the local emitter
  "local_seq_num":   <int>|null,       -- present for local-authoritative forwarding
  "local_entry_hash": "<hex>"|null,    -- present for local-authoritative forwarding
  "metadata":        {}
}

201 Created:  { "id": "<uuid>", "seq_num": <int>, "entry_hash": "<hex>" }
409 Conflict: { "id": "<uuid>", "seq_num": <int>, "entry_hash": "<hex>" }
422 Unprocessable Entity: malformed fields
```

Central assigns its own `seq_num` and `entry_hash` (central's chain) when `local_seq_num` and `local_entry_hash` are absent (central-authoritative mode). In local-authoritative mode, central stores `local_seq_num` and `local_entry_hash` verbatim and assigns a central-local row identifier, but does not re-chain.

### Vault drop-in replacement (decided)

**Remove vault's audit, adopt soma-audit-pg in Local + in-transaction mode. No data migration.**

#### Rationale for the simplification

Vault is a dev/early system with no audit rows worth preserving. Therefore: no epoch-0 migration, no dual-write window, no chain re-keying. The earlier plan's complexity existed solely to preserve a live chain; that constraint is gone. Vault simply deletes its audit code and depends on the module.

The swap is also an upgrade. Vault's current audit is best-effort: `record_audit` is called AFTER the business operation commits (fire-and-forget); outcome is hardcoded `"success"`; `actor_ip` is always `None`. The module's `LocalSink::record_in_tx` commits the audit row in the SAME `sqlx::Transaction` as the business write — atomic, no gap. Vault threads `&mut tx` into each call site as part of the swap. While doing so, fix the two long-standing gaps: emit real outcome (success/denied/error) and capture actor_ip.

#### What gets removed from soma-vault

**Files deleted entirely:**

| File | Reason |
|---|---|
| `crates/soma-storage/src/pg/audit.rs` | Contains `record_audit`, `list_audit`, `verify_audit_chain`, `canonical_msg`, `AuditRow` — all replaced by the module |
| `migrations/01_migrated/1/20260626_05_audit-events.sql` | Creates `01_vault.12_fct_audit_events`; replaced by a new migration that DROPs the table; also remove its entry from `migrations/migration-order.yaml` |
| `dashboard/src/pages/audit.rs` | Logic EXTRACTED first into the reusable AuditViewer component (see below), then this file is removed |

**Files edited (remove audit bits):**

| File | What to remove |
|---|---|
| `crates/soma-storage/src/types.rs` | Structs `AuditEvent`, `AuditFilters`, `AuditVerifyResult` (lines ~446-502) |
| `crates/soma-storage/src/store.rs` | `DataStore` trait methods `record_audit` / `list_audit` / `verify_audit_chain` + their imports |
| `crates/soma-storage/src/pg/mod.rs` | `mod audit;`, the `AuditEvent`/`AuditFilters`/`AuditVerifyResult` imports, the `audit_hmac_key` field on `PgDataStore` + its derivation in `::new`, and the 3 `DataStore` impl methods |
| `crates/soma-crypto/src/lib.rs` | `MasterKek::derive_audit_hmac_key()` (salt `b"soma-vault-audit-hmac-v1"`, info `b"audit"`) and `audit_hmac_hex()`; drop the `hmac` dep if now unused |
| `crates/soma-api/src/lib.rs` | The 2 routes (`/audit`, `/audit/verify`), `make_audit_event()` helper, all 11 `record_audit` call sites, `AuditQuery` struct, `list_audit_handler` + `verify_audit_handler`, and now-unused imports |
| `dashboard/src/pages/mod.rs`, `dashboard/src/app.rs` | Nav item + route for the old audit page |
| `dashboard/src/api.rs` | `AuditEvent`/`AuditVerifyResult` structs + `get_audit`/`verify_audit` fns |

#### What vault adds back (via the module)

1. Cargo dep on `soma-audit-pg` (+ `soma-audit-core` transitively).
2. Call `soma_audit_pg::install(&pool).await?` at startup — installs schema `soma_audit`. Note: vault's old audit lived in schema `01_vault` as table `12_fct_audit_events`; the module owns its own `soma_audit` schema, coexisting with `01_vault` via a distinct `advisory_lock_key`.
3. Construct `AuditKeys` via `from_secret`, passing the audit master secret and Ed25519 signing key that vault derives from the master KEK it already holds in-process (vault's removed `derive_audit_hmac_key` logic moves here as the derivation that feeds `from_secret`). Vault's embedded auditing therefore needs no network call and no fetch from vault-the-service — it is in-process, which is what makes the vault↔audit relationship acyclic (see Section 6). This is the "use vault for env & config" pattern: vault is the secret source; the library takes resolved bytes.
4. Construct a `LocalSink` from the pool + `AuditKeys`, hold it in `AppState` alongside the `DataStore`.
5. At each of the 11 former call sites, build the generic `AuditEvent` (event_type string unchanged) and call `local_sink.record_in_tx(&event, &mut tx).await?` inside the business transaction, before `tx.commit()`.
6. The query/verify HTTP API: vault keeps thin `/v1/audit` + `/v1/audit/verify` handlers backed by the module's `LocalSink` list/verify. (Later, in Phase 2, these may proxy to the central server instead.)

#### Vault event vocabulary (11 event_type strings)

The module must carry vault's full vocabulary as-emitted at the 11 call sites:

`token.create`, `token.revoke`, `project.create`, `environment.create`, `secret.write`, `secret.read`, `secret.rollback`, `secret.delete`, `config.write`, `config.rollback`, `config.delete`

Note: `config.read` is NOT emitted today — a gap. The swap is the opportunity to add it if desired.

#### Tests to port (not just delete)

- `crates/soma-storage/tests/integration.rs` — `test_audit_single_entry` / `test_audit_chain_links` / `test_audit_verify_intact` / `test_audit_verify_tampered` become tests of `soma-audit-pg`/`soma-audit-core` instead.
- `crates/soma-api/tests/integration.rs` — `test_audit_rbac` (admin 200 / reader 403 on `/v1/audit`) stays as a vault API test against the new handlers.

### First consumer: soma-iam

> **Note:** soma-vault is actually the FIRST drop-in consumer of `soma-audit-pg` (it already has the 11 call sites; the swap lands in Phase 1). soma-iam is the first GREENFIELD consumer that adopts the module from the start with `actor_user_id` populated.

soma-iam is currently docs-only. Its PRD already reserves schema `soma_iam`, advisory lock key `7318249506742315`, an append-only HMAC-chained `aud_events` table, and an audit-viewer dashboard page. It is the first greenfield plug-and-play target for `soma-audit-pg`:

1. `cargo add soma-audit-pg` in the soma-iam service crate.
2. Call `soma_audit_pg::install(&pool).await?` at startup — installs the `soma_audit` schema alongside `soma_iam` in the same Postgres, using soma-audit's reserved advisory lock key `6020250626000001` (a unique `i64`, distinct from soma-iam's `7318249506742315`) so it never conflicts with soma-iam's own migrations.
3. Emit via `local_sink.record_in_tx(&event, &mut tx).await?` inside each auth-operation transaction (login, token issue, permission check, user create/update/delete).

soma-iam is the **first emitter where `actor_user_id` is non-null** — vault only had token IDs as actors; soma-iam operations always have a real user UUID. The `actor` field carries the user UUID string; `source_service` is `"soma-iam"`; `event_type` uses the `iam.*` vocabulary (`iam.user.login`, `iam.token.issue`, `iam.permission.denied`, etc.).

The soma-iam audit-viewer dashboard page wires up once `soma-audit-server` is running (Phase 2). In Phase 1 local-only mode, `verify_chain` over the local `soma_audit.fct_audit_events` table is the integrity check.

---

## 10. Feature Set (Embeddable Product)

| Feature | Classification | Notes |
|---|---|---|
| `soma_audit` schema installer (`install(pool).await?`) | MUST Phase 1 | Core embeddable mechanism |
| `fct_audit_events` table with all envelope fields | MUST Phase 1 | Core storage |
| `LocalSink::record_in_tx` — in-transaction audit | MUST Phase 1 | The headline guarantee |
| `LocalSink::record` — pool-backed (for after-commit use) | MUST Phase 1 | Convenience for non-tx contexts |
| HMAC-SHA256 chain (seq_num, prev_hash, entry_hash) | MUST Phase 1 | Carry from Revision 1 |
| Per-tenant advisory lock serializing chain appends | MUST Phase 1 | Carry from Revision 1 |
| Append-only BEFORE trigger + REVOKE | MUST Phase 1 | Structural deterrence |
| FORCE RLS + `soma_audit.tenant_id` GUC | MUST Phase 1 | Tenant isolation |
| `idempotency_key UUID UNIQUE` | MUST Phase 1 | Relay dedup |
| `occurred_at TIMESTAMPTZ` (caller-supplied) | MUST Phase 1 | Distinct from `stored_at` |
| `chain_epoch INT` column | MUST Phase 1 | Vault cutover boundary |
| `verify_chain(records, key) -> VerifyResult` in core | MUST Phase 1 | Offline verifiability |
| `AuditKeys` (`from_secret` + `from_env`) | MUST Phase 1 | Key management; host resolves bytes (vault for soma hosts), no trait yet |
| Soma hosts source audit secret + DB creds from soma-vault | MUST Phase 1 | Platform "use vault for env & config"; library stays vault-agnostic |
| BRIN index on `occurred_at` | MUST Phase 1 | Time-range scans |
| `metadata JSONB NOT NULL DEFAULT '{}'` | MUST Phase 1 | App context bag |
| `soma-audit-core` with zero IO deps | MUST Phase 1 | Publishable as a standalone crate |
| Vault drop-in: remove vault audit, wire `LocalSink::record_in_tx` at 11 sites | MUST Phase 1 | First real embedder; validates the library contract end-to-end |
| `AuditViewer` Leptos component extracted into `soma-audit-ui` / `soma-ui` | MUST Phase 1 | Reusable per-app embedded view; parameterized by API URL + vocabulary |
| `CompositeSink::at_least_one` | MUST Phase 2 | Both mode; needed with RemoteSink |
| `RemoteSink` + outbox relay task | MUST Phase 2 | Remote/Both modes |
| `soma-audit-server` ingest endpoint | MUST Phase 2 | Central service |
| Cross-project query API | MUST Phase 2 | Central value prop |
| `project_id` dimension at central | MUST Phase 2 | Cross-project identity |
| `GET /v1/audit/keys` JWKS | MUST Phase 2 | External verifiability |
| `GET /v1/audit/seals` | MUST Phase 2 | Expose seals to verifiers |
| Ed25519 batch seals in server only | MUST Phase 2 | NOT in each embedded install |
| Outbox lag alerting | NICE Phase 2 | Operational safety |
| soma-iam JWT auth on query endpoints | NICE Phase 2 | When soma-iam exists |
| `actor_type` discriminant column | NICE Phase 2 | Filter human vs service actions |
| OCSF export projection | NICE Phase 3 | SIEM interop; read-side only |
| External anchor (Rekor v2, S3 Object Lock) | NICE Phase 3 | Defence against DB-owner tampering |
| Forward-secure HMAC ratchet after each seal | NICE Phase 3 | Limits blast radius |
| Monthly `created_at` RANGE partitions | NICE Phase 3 | Only at >50M events/tenant |
| Retention background task | NICE Phase 3 | Archive + drop old partitions |
| `resource_type` + `resource_id` indexed columns | YAGNI | GIN on metadata JSONB is sufficient |
| Full GIN index on `metadata` | YAGNI | 3–6x write overhead; add only for proven pattern |
| `KmsKeyProvider` / `VaultKeyProvider` *traits* | YAGNI | Vault-sourcing is done WITHOUT a trait — host resolves bytes from vault and calls `AuditKeys::from_secret`; a trait only earns its place when resolution must be runtime-swappable |
| `environment` indexed column at central | YAGNI | Put in `project_id` string or metadata |
| Kafka/NATS as relay transport | YAGNI | No fan-out requirement today |
| Multi-region replication | YAGNI | Wrong scale for now |
| Real-time streaming / webhooks | YAGNI | |
| AI anomaly summaries | YAGNI | |
| Session recording | YAGNI | Wrong product |

---

## 11. Phased Roadmap

### Phase 1 — Embeddable Local crate (standalone, usable without central service)

**This is the ponytail MVP.** Ship `soma-audit-core` + `soma-audit-pg` as standalone crates that any axum/sqlx/Postgres app can use with `cargo add soma-audit-pg`. No central service required. No relay. No cross-project query. Just: install the schema, call `record_in_tx` in your business transactions, run `verify_chain` to confirm integrity.

**Scope:**
- `soma-audit-core`: `AuditEvent`, `AuditRecord`, `AuditSink` trait, `CompositeSink`, chain math, `verify_chain`, `AuditError`
- `soma-audit-pg`: `install(pool)` with migrations bundled via `include_dir!` + soma-schema `Migrator::from_embedded`, `LocalSink` (including `record_in_tx`), `AuditKeys` (`from_secret` + `from_env`; vault wires its KEK-derived secret in via `from_secret`), RLS, append-only trigger
- Add `Migrator::from_embedded` to soma-schema (small additive PR — `from_root` unchanged)
- `soma-audit-types` thin wrapper (vault vocabulary constants)
- **Vault drop-in** (Local + in-transaction, no data migration): remove vault's audit code entirely (see Vault drop-in section above), wire `LocalSink::record_in_tx` at all 11 former call sites, drop the old `12_fct_audit_events` migration, fix `actor_ip` and `outcome` gaps, keep thin vault-served `/v1/audit` + `/v1/audit/verify` handlers backed by the module
- Port 4 chain integration tests from `crates/soma-storage/tests/integration.rs` into `soma-audit-pg`/`soma-audit-core` tests; retain `test_audit_rbac` as a vault API test
- **Extract `AuditViewer` Leptos component** from vault's `dashboard/src/pages/audit.rs` into a reusable crate (`soma-audit-ui` or `soma-ui`); parameterize API base URL and event-type vocabulary; vault's dashboard imports and mounts it

**Exit criteria:**
- `soma_audit_pg::install(&pool).await?` creates schema in a fresh Postgres; runs idempotently on repeat
- Calling `local_sink.record_in_tx(event, &mut tx).await?` inside a business txn commits atomically; rollback drops the audit row
- `verify_chain` passes on the resulting chain
- Vault has zero audit code of its own; all 11 event types recorded atomically in-tx via the module; chain verifies
- `/v1/audit` and `/v1/audit/verify` work in vault against the module
- `actor_ip` captured; `denied`/`error` outcomes emitted
- `AuditViewer` component renders correctly in vault's dashboard

#### AuditViewer component extraction contract (Phase 1)

Source: vault's `dashboard/src/pages/audit.rs`. The component already uses only generic soma-ui primitives (`Alert`, `Badge`, `Button`, `Empty`, `PageHeader`, `Select`, `Spinner`, `Table` family) and the generic `AuditEvent` shape — structurally clean to extract with no further decomposition needed.

Two coupling points must be parameterized:

1. **API base URL** — currently hardcoded same-origin `"/v1/audit"` in `dashboard/src/api.rs`; becomes a component prop/input so any host can point it at its own audit endpoint or at the central server.
2. **Event-type vocabulary** — currently a hardcoded `EVENT_TYPES` const of 11 strings (which includes the never-emitted `config.read`); becomes an input prop so vault passes its 11-string vocabulary (corrected) and soma-iam passes its own `iam.*` vocabulary.

The component lands in a `soma-audit-ui` crate (or `soma-ui`) that depends on `soma-ui`. Vault's dashboard removes `dashboard/src/pages/audit.rs` and imports/mounts `AuditViewer` instead. soma-iam later mounts the same component.

Note on build model: soma-ui is consumed as a Cargo path dep and compiled to WASM at each host app's build time (no runtime-pluggable UI). Importing `AuditViewer` forces a host-app rebuild when the component changes. This is the accepted tradeoff for per-app embedded views — it is fine to ship now because vault already compiles this exact code. The hosted-dashboard-first rationale (see Phase 2) still holds for the CENTRAL cross-project view, where the WASM-rebuild-per-host cost is avoided entirely.

### Phase 2 — Remote sink + Central service + Cross-project query + Hosted dashboard

**Scope:**
- `soma-audit-client`: `RemoteSink`, outbox DDL, relay task, `CompositeSink::at_least_one`
- `soma-audit-server`: binary, axum handlers, ingest endpoint, cross-project query API, Ed25519 batch seal sweep, JWKS endpoint
- `project_id` dimension at central
- **Hosted cross-project dashboard** in `soma-audit-server`: built on soma-ui primitives (DataTable, Pagination, Select, Badge, Timeline, Alert, Empty, PageHeader, Spinner); serves a unified audit view across all projects. Mounts the `AuditViewer` component (extracted in Phase 1 — see below) pointed at the central API. This is the primary UI delivery in Phase 2.
- Outbox lag alerting

**Exit criteria:**
- A Both-mode deployment (Local + relay to server) produces two copies of every event
- `GET /v1/audit` returns events across projects when filtered by `project_id`
- `GET /v1/audit/keys` returns Ed25519 public key; external verification script passes
- Vault's local audit table is no longer written to post-cutover; soma-audit-server holds the complete record
- Hosted dashboard renders events from at least two distinct `project_id` values; pagination and event-type filter work

### Phase 3 — Dual-chain anchoring, external verifiability, scale

**Scope (only if Phase 1/2 exit criteria reveal need):**

- Ed25519 seal anchors from local-authoritative deployments stored at central (`soma_audit_chain_anchors` table)
- External anchor: POST each batch seal to Rekor v2 (one HTTP call per seal cycle per tenant)
- Forward-secure HMAC key ratchet after each seal (add `zeroize` to `AuditKeys`)
- OCSF 1.8.0 export adapter (`GET /v1/audit?format=ocsf`)
- Monthly RANGE partitions on `occurred_at` (add when first tenant approaches 50M rows)
- Retention task: archive to S3 gzip CSV, drop old partition
- soma-iam JWT/JWKS auth on query endpoints (when soma-iam is built)
- Per-(tenant, source_service) chain sharding if advisory lock is a measured bottleneck

**Exit criteria:**
- Anchor records at central prove local chain state without requiring the local HMAC key
- External verifier confirms chain integrity using only the Ed25519 public key from JWKS and the Rekor inclusion proof
- Retention task archives and drops a partition without chain integrity errors

---

## 12. Open Questions and Risks

**soma-schema gains an embedded-migrations constructor.** `Migrator::from_embedded(dir: &include_dir::Dir)` is a small additive PR to soma-schema (a second repo touched). Backward-compatible: `from_root` is unchanged. This is the keystone enabling true library embeddability; without it a library crate cannot ship migrations into a host DB. Low risk, well-scoped. Block Phase 1 on this PR merging to soma-schema.

**IAM not built — high risk for Phase 2 auth.** soma-iam (JWT/JWKS, user UUID as actor, `audit:read` permission) is design-only. Query auth stays on opaque bearer tokens until soma-iam exists. The `actor` field stores an opaque string; it will be a user UUID for iam-issued operations when soma-iam is built.

**hkdf crate version.** Use `hkdf 0.12.4` (stable). The 0.13.x series is at release-candidate status as of June 2026. Do not depend on RC software in a security-critical library. Verify workspace Cargo.toml before assuming this is already pinned.

**ed25519-dalek API change.** v2.x uses `SigningKey`/`VerifyingKey`, not the old `Keypair`. Do not use the old API. The crate's `batch` feature is for batch signature verification (verifier-side); signing a seal is always one operation (`signing_key.sign(payload)`).

**Local DB tamper limitation — must be stated in documentation.** The local append-only mechanism and HMAC chain do not protect against a Postgres superuser who also knows the HMAC key. A superuser can bypass the trigger via `SET session_replication_role = 'replica'` and rewrite rows. The HMAC key must not be accessible to DB admins; if it is, tamper-evidence is lost. The central copy (Both mode) with externally-anchored Ed25519 seals is the countermeasure. Document this plainly.

**Vault's `actor_ip` and `outcome` gaps — fix in Phase 1.** These are security gaps independent of the embeddable redesign: denied and error paths are invisible in the current audit log. Wire `ConnectInfo` through vault handlers; emit `denied` from auth middleware and `error` from handler error paths. Phase 1 is not complete until these are fixed.

**Dashboard coupling — medium risk.** The dashboard calls same-origin `/v1/audit` paths. Phase 2 options: proxy-passthrough from vault to soma-audit-server, or configure the audit API base URL at trunk compile time (`VITE_AUDIT_API` env var) pointing directly to soma-audit-server. Decide at Phase 2 start.

**Global seal-sweep thundering herd.** The single 30-second seal sweep iterating over all tenants can take longer than 30 seconds at high tenant counts. Batch the sweep query (`SELECT tenant_id FROM unsealed LIMIT 100`) and process sequentially, yielding to the tokio runtime between tenants.

**Chain verification cost on large tenants.** `verify_chain` is O(n) sequential walk. The `since_seq_num` cursor parameter bounds the walk to a recent segment. Ensure the cursor is implemented in Phase 1. Ed25519 seals serve as anchor points for incremental verification.

**`project_id` propagation discipline.** The `project_id` is stamped by the relay at forward time, not by individual `AuditEvent` emitters. This means local-only deployments (Phase 1) have no `project_id`. Central must handle events with and without `project_id` gracefully at ingest. Define the default (empty string or `NULL`) before Phase 2 ingest is built.

**Low-confidence item: SCITT anchor format.** The anchor record design borrows conceptually from SCITT draft-ietf-scitt-architecture-22 (Oct 2025). The exact Receipt encoding (COSE_Sign1 with inclusion proof in unprotected header) is more complex than a plain Ed25519 signature over canonical fields. For v1/Phase 3, use plain Ed25519 over canonical fields; adopt the COSE format only if interoperability with external SCITT tooling is required.

---

## 13. Sources

**sqlx migration API:**
- [sqlx Migrator struct docs (0.9)](https://docs.rs/sqlx/latest/sqlx/migrate/struct.Migrator.html)
- [sqlx migrator.rs source](https://github.com/launchbadge/sqlx/blob/main/sqlx-core/src/migrate/migrator.rs)
- [sqlx configurable migrations table issue #3766](https://github.com/launchbadge/sqlx/issues/3766)

**Rust async trait / dyn:**
- [async_trait crate](https://docs.rs/async-trait)
- [Announcing async fn in traits (Rust Blog)](https://blog.rust-lang.org/2023/12/21/async-fn-rpit-in-traits/)
- [Dyn async traits, part 10: Box box box (babysteps)](https://smallcultfollowing.com/babysteps/blog/2025/03/24/box-box-box/)

**Sink abstraction prior art:**
- [tracing_subscriber::layer](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/index.html)
- [ObjectStore in object_store](https://docs.rs/object_store/latest/object_store/trait.ObjectStore.html)
- [HashiCorp Vault Audit Devices](https://developer.hashicorp.com/vault/docs/audit)
- [HashiCorp Vault Audit Best Practices](https://developer.hashicorp.com/vault/docs/audit/best-practices)

**Dual-chain / anchor prior art:**
- [RFC 6962 — Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [SCITT Architecture draft-ietf-scitt-architecture-22](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture-22)
- [Rekor v2 GA (Sigstore Blog)](https://blog.sigstore.dev/rekor-v2-ga/)
- [Trillian Personalities](https://github.com/google/trillian/blob/master/docs/Personalities.md)
- [Immutable audit log with HMAC hash chaining (Tracehold)](https://tracehold.ai/blog/immutable-audit-log-hmac-hash-chain/)
- [HMAC signatures don't survive a regulator audit (Medium)](https://medium.com/@ccie14019/hmac-signatures-dont-survive-a-regulator-audit-here-s-what-to-use-instead-ddbbc2e18a2b)
- [OpenTimestamps Wikipedia](https://en.wikipedia.org/wiki/OpenTimestamps)

**Schema install and Postgres:**
- [PostgreSQL Schemas doc](https://www.postgresql.org/docs/current/ddl-schemas.html)
- [CVE-2018-1058 Search Path Guide](https://wiki.postgresql.org/wiki/A_Guide_to_CVE-2018-1058%3A_Protect_Your_Search_Path)
- [PostgreSQL Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL Advisory Locks (Flavio Del Grosso)](https://flaviodelgrosso.com/blog/postgresql-advisory-locks)
- [pgcrypto docs](https://www.postgresql.org/docs/current/pgcrypto.html)
- [supa_audit (Supabase)](https://github.com/supabase/supa_audit)
- [refinery crate](https://github.com/rust-db/refinery)

**Prior-art embeddable audit:**
- [paper_trail (Rails)](https://github.com/paper-trail-gem/paper_trail)
- [django-auditlog](https://github.com/jazzband/django-auditlog)
- [Laravel Auditing — Audit Drivers](https://laravel-auditing.com/guide/audit-drivers)
- [Marten event store (.NET)](https://martendb.io/events/)
- [OpenTelemetry API vs SDK (Last9)](https://last9.io/blog/opentelemetry-api-vs-sdk/)

**Cross-project query prior art:**
- [AWS CloudTrail features](https://aws.amazon.com/cloudtrail/features/)
- [OpenAI Audit Logs API](https://platform.openai.com/docs/api-reference/audit-logs)
- [OTel Resource Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/resource/)

**Cryptographic libraries:**
- [hmac + sha2 (RustCrypto)](https://github.com/RustCrypto/MACs)
- [hkdf 0.12.4 (RustCrypto)](https://docs.rs/hkdf/0.12.4)
- [ed25519-dalek 2.2.0](https://docs.rs/ed25519-dalek/2.2.0)
- [zeroize crate](https://docs.rs/zeroize)

**Integrity, brokers, and Revision 1 sources:**
- [Outbox, Inbox patterns (event-driven.io)](https://event-driven.io/en/outbox_inbox_patterns_and_delivery_guarantees_explained/)
- [Transactional Outbox (microservices.io)](https://microservices.io/patterns/data/transactional-outbox.html)
- [OCSF Schema Browser 1.8.0](https://schema.ocsf.io/)
- [OWASP A09:2025 Security Logging Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
- [Postgres BRIN Indexes (Crunchy Data)](https://www.crunchydata.com/blog/postgresql-brin-indexes-big-data-performance-with-minimal-storage)
- [Postgres RLS multi-tenant (AWS)](https://aws.amazon.com/blogs/database/multi-tenant-data-isolation-with-postgresql-row-level-security/)
- [You Cannot Have Exactly-Once Delivery (Brave New Geek)](https://bravenewgeek.com/you-cannot-have-exactly-once-delivery/)
- [soma-schema CONSUMING.md](../../../soma-schema/CONSUMING.md)

---

<!-- AUTONOMOUS DECISION LOG (autoplan, single-voice — Codex unavailable) -->
## /autoplan Review — Decision Audit Trail (Rev 2.3)

Single-voice review (Claude subagent only; Codex CLI not installed). 4 phases: CEO, Eng, Design, DX. Findings below; taste/challenge decisions surfaced to the user at the approval gate rather than auto-applied, because several findings challenge the user's stated direction (a User Challenge per autoplan rules).

| # | Phase | Finding | Severity | Disposition |
|---|-------|---------|----------|-------------|
| 1 | Eng | Vault's 11 `record_audit` calls are in the API layer, AFTER the business tx commits inside the storage layer. Threading `&mut tx` at call sites is impossible; atomic-in-tx needs a storage-layer refactor (hold LocalSink in PgDataStore) | CRITICAL | MUST FIX plan before build — gate decision |
| 2 | Eng | `soma-schema::from_embedded` is NOT a small additive PR: Migrator/discover/SetupFile are filesystem-coupled; needs a source-agnostic abstraction + checksum/line-ending stability test | HIGH | Re-scope as medium PR; add checksum test |
| 3 | Eng | No concurrency test, no tamper-completeness test (delete/reorder, not just field overwrite), no rollback-atomicity test, no install-idempotency test | HIGH | Expand Phase 1 test plan |
| 4 | Eng | Both-mode CompositeSink cannot provide in-tx atomicity (`&mut tx` is !Send, can't fan out); doc implies it can | HIGH | Correct doc: Both uses pool-backed record, not record_in_tx |
| 5 | DX | AuditEvent has 6 required fields, no builder, no defaults; source_service copy-pasted per call; idempotency_key retry trap | CRITICAL (DX) | Add AuditEventBuilder + LocalSinkBuilder (stamps source_service, defaults occurred_at/idempotency_key) |
| 6 | Design | AuditViewer "two params" is insufficient: auth injection, tenant context, column set, actor/outcome rendering, AuditEvent-shape mismatch all hidden-coupled | CRITICAL (UI) | Add display DTO + auth callback + column/filter props before extraction |
| 7 | Design | Keyset "Load more" is wrong UX for forensic audit; needs date-range + actor + resource filters | HIGH | Add filters; reconsider pagination model |
| 8 | CEO | Sequencing: building generic embeddable + central + dual-chain before a 2nd consumer exists (iam is docs-only); vault audit already works | CRITICAL (strategy) | USER CHALLENGE — surface, do not auto-decide |
| 9 | CEO | Phase 1 bundles 4 interleaved workstreams with a cross-repo blocking dep; not one milestone | HIGH | Split Phase 1; library-first, vault refactor separate |
| 10 | Eng | Vault HMAC derivation (single global key) differs from plan (per-tenant HKDF); canonical msg format differs — chains genuinely incompatible (no migration, correctly) but chain_epoch must mark the key-derivation boundary | HIGH | Document epoch=key-derivation boundary |
| 11 | Eng | RLS GUC returns 0 rows (not error) when tenant GUC unset — silent. Add NOT NULL guard in policy | MEDIUM | Add to migration |
