# soma-audit Readiness Report

## 1. Bottom Line

**Goal 1 — Easy to adopt everywhere:** Close but not there. The 3-line install path and relay plumbing are solid; the single biggest gap is that every new adopter must write a 12-field struct literal (or their own wrapper), and `AuditKeys::from_env()` falsely requires an Ed25519 key that local-only apps never use — together these make apps 2–N noticeably more painful than they should be.

**Goal 2 — Central discovery and connection:** Not yet met. The relay pipeline works correctly, but the central server is a dumb event store with zero inventory: no sources table, no registration, no list-tenants endpoint, and a dashboard that opens to a blank UUID prompt. An admin cannot answer "what is connected to me" without querying the raw events table with a UUID they already know.

---

## 2. Goal 1 (Easy to Adopt Everywhere) — Punch List

| Gap | Fix | Effort |
|-----|-----|--------|
| No `AuditEvent` builder — 12-field struct literal at every call site; notes-app already had to write its own local wrapper | `AuditEvent::builder(tenant_id, event_type, outcome) -> AuditEventBuilder` with chainable `.actor_id()`, `.actor_role()`, `.resource(type, id)`, `.actor_ip()`, `.metadata()`, `.occurred_at()`, `.build()`. Builder auto-stamps `idempotency_key` (UUIDv5 from operation identity) and `occurred_at`. `source_service` is filled by the sink. | Small |
| `AuditKeys::from_env()` hard-requires `SOMA_AUDIT_SIGNING_KEY` that `LocalSink` never calls — local-only adopter fails at startup or must set a dummy value | Add `AuditKeys::from_env_local()` that reads only `SOMA_AUDIT_MASTER_SECRET` and fills `signing_key` with a random ephemeral key. Mark `SOMA_AUDIT_SIGNING_KEY` as "required only when running soma-audit-server" in README and crate docs. `from_env()` can stay as-is for server use. | Trivial |
| `idempotency_key: Uuid::new_v4()` at every call site — the `ON CONFLICT` guard is effectively dead; HTTP retries silently insert duplicate chain-linked events | Add `fn idempotency_key(tenant_id: Uuid, request_id: Uuid) -> Uuid` in `soma-audit-core` using `Uuid::new_v5`. Builder uses this automatically. Update vault and notes-app. | Small |
| README and `INTEGRATION.md` show only workspace path deps — first line a new dev reads signals "internal, not for you" | Add `cargo add soma-audit-pg` (and published version form) as the first code block in `README.md` and `INTEGRATION.md`. One line each; only meaningful once crates are published (guide exists per eed5407). | Trivial |
| No `LocalSink::new_single_tenant()` — single-tenant apps (the majority) must manually thread a fixed UUID into every event and every query/verify call | Add `fixed_tenant: Option<Uuid>` to `LocalSink`; add `new_single_tenant(pool, keys, service, tenant_id)` constructor. Auto-stamp events where `tenant_id` is nil. Add `list_default()` / `verify_default()` thin wrappers (cleaner than overloading nil as a sentinel). | Small |
| `record()` doc comment says "Record an audit event in its own transaction" — sounds equivalent to `record_in_tx`, hides the crash-gap risk | Change the doc comment on `record()` at `sink.rs:231` to open with "No atomicity guarantee with surrounding business writes — prefer `record_in_tx` when you hold a transaction." | Trivial |
| Pool `max_connections >= 2` requirement is a silent deadlock, not an actionable error | In `install()`, check `pool.options().get_max_connections()` and return a clear `Err` (or `panic!`) with the text "soma-audit: pool must have max_connections >= 2". | Trivial |
| No key-generation command in README — adopters must know `openssl rand -hex 32` | Add `openssl rand -hex 32` as a generation one-liner next to each env var in the README env-var table and `INTEGRATION.md §2.4`. | Trivial |
| `AuditEvent` fields `idempotency_key` and `occurred_at` force every adopter to add `uuid` and `chrono` crates — boilerplate the builder should own | Addressed by the builder above (auto-stamps both). Interim without builder: add `AuditEvent::new(tenant_id, event_type, outcome) -> Self` that sets the boilerplate fields. | Trivial |
| README incorrectly says `verify()` loads full chain into memory — will cause adopters to add unnecessary batching | Update `README.md:89` to: "streams rows via a server-side cursor, O(1) memory, suitable for any tenant size." | Trivial |

---

## 3. Goal 2 (Central Discovery and Connection) — Punch List

The central discovery feature is essentially a single coherent net-new feature, not a scatter of small fixes. Here is the minimal design followed by the gap table.

**Minimal discoverability design:**

*New table (one migration):*
```sql
CREATE TABLE soma_audit.sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_service  TEXT NOT NULL,
    tenant_id       UUID NOT NULL,
    host_url        TEXT,          -- nullable; populated only via explicit register
    version         TEXT,          -- nullable; same
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_service, tenant_id)
);
```
`event_count` is omitted from the table (compute via `COUNT(*)` at query time to avoid denormalization drift — per verifier note on finding #2).

*Auto-upsert on every ingest (zero client ceremony):*

Inside `post_event` in `ingest.rs`, after inserting the event, add:
```sql
INSERT INTO soma_audit.sources (source_service, tenant_id)
VALUES ($1, $2)
ON CONFLICT (source_service, tenant_id)
DO UPDATE SET last_seen = now();
```
This is the core of discoverability — no client changes required for existing apps.

*Opt-in registration endpoint (adds `host_url`, `version`):*
```
POST /internal/v1/sources/register
{ "source_service": "soma-vault", "tenant_id": "...", "host_url": "https://vault.prod.example.com", "version": "0.3.1" }
```
Bearer-authed with the same ingest secret (or per-source key once that lands). Updates `host_url` and `version` columns. Client calls this at startup if `SOMA_AUDIT_REGISTER=true`.

*New read endpoint:*
```
GET /v1/sources   (admin-auth)
```
Returns: `[{ source_service, tenant_id, host_url, version, first_seen, last_seen, event_count }]` with `event_count` from a join to `fct_audit_events`.

*Optional heartbeat (for quiet apps):*
```
POST /internal/v1/heartbeat
{ "source_service": "...", "tenant_id": "..." }
```
Just touches `last_seen`. Relay calls this on its polling interval when outbox is empty.

*Dashboard changes:*
- New default route `/sources` — table of all sources with `source_service`, `tenant_id`, `last_seen`, `event_count`, and a health dot (green < 5 min, yellow < 1 hr, red otherwise).
- Clicking a row sets `tenant_id` in context and navigates to `/audit`. The blank UUID prompt disappears entirely.
- Default redirect changes from `/audit` to `/sources`.

| Gap | Fix | Effort |
|-----|-----|--------|
| No sources table, no registration, no inventory — central server cannot answer "what is connected to me" | Add `soma_audit.sources` table + auto-upsert in `ingest.rs` `post_event` + `GET /v1/sources` endpoint. This is the entire core of Goal 2. | Medium |
| Admin must know a tenant UUID before querying anything — dashboard opens to a blank UUID prompt | Add `/sources` dashboard page as the new default home (feeds from `GET /v1/sources`); row click sets tenant context and navigates to `/audit`. Change default redirect. | Medium |
| No staleness/health tracking — central cannot detect a source that went dark | `sources.last_seen` auto-updates on every ingest (covered above). Expose with health dot in sources page. Add optional `POST /internal/v1/heartbeat` for apps that may be legitimately quiet. | Small (after sources table) |
| Single shared ingest secret — one leaked app compromises all sources; source_service is fully caller-controlled (spoofing is trivially possible) | Near-term: document that `source_service` is untrusted, add WARN in README. Medium-term: add `soma_audit.source_keys` table (per-source token, bound to `source_service` + `tenant_id`), change `check_ingest_auth` to look up against it. Existing single-secret path becomes a bootstrap fallback. | Medium |
| No cross-source or cross-tenant query — incident spanning multiple apps requires multiple manual queries | Add optional `source_service` filter to `GET /v1/audit`. Add `GET /v1/audit/global?source_service=&actor_id=&event_type=` (admin-only, uses existing `soma_audit.bypass` GUC pattern from `seal.rs:36`). | Small |
| No date-range filter on event queries — `occurred_at` BRIN index exists but is unused | Add `from: Option<DateTime<Utc>>` and `to: Option<DateTime<Utc>>` to `ListParams` in `query.rs`; add `WHERE occurred_at >= $from AND occurred_at <= $to` in the sink query; wire date inputs in dashboard filters panel. | Small |
| Relay outbox lag is warn-logged locally but central has no visibility | Include `X-Soma-Outbox-Lag: N` header in relay POST requests; store in `sources.last_known_lag` (add column). Show lag indicator in sources overview alongside health dot. | Small (after sources table) |
| No `environment` or `project_id` dimension — cannot distinguish staging vs prod in the fleet view | Add `environment TEXT NULLABLE` to `sources` table and to `POST /internal/v1/sources/register`. Group sources page by `(source_service, environment)`. Do not add to event rows. | Trivial (after sources table) |

---

## 4. Correctness / Polish Must-Fixes

These are the items that break correctness guarantees as more apps are onboarded, ordered by severity.

**Must fix before scaling to many apps:**

1. **`idempotency_key: Uuid::new_v4()` at every call site** (`soma-vault/crates/soma-storage/src/pg/mod.rs:297,842,963`, `soma-api/src/lib.rs:1263`, `notes-app/main.rs:107`). The `ON CONFLICT` guard in `sink.rs:190` is dead code today — every retry inserts a fresh UUID and creates a second chain-linked row. Fix: add `fn idempotency_key(tenant_id: Uuid, request_id: Uuid) -> Uuid` using `Uuid::new_v5` in `soma-audit-core`; the builder stamps it; vault and notes-app are updated. **This breaks the idempotency contract for every adopter.**

2. **Seal sweep duplicate seals in HA** (`seal.rs:69-88`, migration `20260626_02_audit-chain-seals.sql`). `ON CONFLICT DO NOTHING` targets the UUID PK which is always fresh (`Uuid::new_v4()`), so it never fires. Two concurrent pods both pass the `WHERE NOT EXISTS` guard and both insert distinct seals for the same `(tenant_id, up_to_seq_num)` with different signatures. Fix: add `UNIQUE (tenant_id, up_to_seq_num)` in a new migration and change INSERT to `ON CONFLICT (tenant_id, up_to_seq_num) DO NOTHING`. Write as a new file in `migration-order.yaml`, never edit the applied migration.

3. **Global `UNIQUE(idempotency_key)` not scoped to tenant** (`20260626_01_audit-events.sql:21`). The correct constraint is `UNIQUE (tenant_id, idempotency_key)`. UUID4 collision is astronomically unlikely but the semantic is wrong and must be fixed before any key-generation scheme change. Fix: new migration replacing the constraint and updating the `ON CONFLICT` clause in `sink.rs:190` to `ON CONFLICT (tenant_id, idempotency_key)`.

4. **Relay dead-letter: permanently rejected events retry forever** (`relay.rs:183-209`). A 422 from the central server (schema mismatch, malformed event) reschedules indefinitely at 1-hour backoff. Fix: add `max_attempts: Option<u32>` to `RelayConfig` (default 20); after `attempts >= max_attempts`, emit a `warn!` and mark a `failed_permanently_at TIMESTAMPTZ` column on the outbox row; skip permanently-failed rows in the poll query. New migration for the column.

**On the multi-source chain question (resolve definitively):**

The per-tenant chain (advisory lock and `seq_num` scoped to `tenant_id` only, `sink.rs:149,157-158`) proves **combined-timeline integrity** — that the interleaved stream of events from all sources for a tenant has not been tampered with. It does **not** prove per-service contiguity. An attacker with the HMAC key could delete a vault event and reforge all downstream hashes (without the key they cannot, so the attack requires key compromise). The practical gap is narrower: a forensic auditor cannot ask "are all soma-vault events present with no service-level gaps?" from the combined chain alone.

**Decision:** For the current use case, document the combined-chain semantics explicitly in the README and `verify()` rustdoc. Per-`(tenant_id, source_service)` chains (option b) are the correct answer for high-security multi-tenant SaaS but require a larger migration and are not the ponytail answer for now. Add a clear note to `verify.rs` and `README.md` stating: "The chain proves combined-timeline tamper-evidence per tenant; it does not verify per-source-service contiguity."

---

## 5. Recommended Build Order

### Quick ergonomic wins (Goal 1 — do first, each ≤ 1 day)

1. **`AuditKeys::from_env_local()`** — one constructor, 10 lines, removes false blocking requirement for local adopters. Update README to mark `SOMA_AUDIT_SIGNING_KEY` as server-only. (`crates/soma-audit-pg/src/keys.rs`)

2. **`AuditEvent::builder()`** — `soma-audit-core/src/event.rs`, 3 required fields, chainable optionals, auto-stamps `occurred_at`. Include `fn idempotency_key(tenant_id, request_id) -> Uuid` using `Uuid::new_v5` as the default idempotency stamp. This fixes both the builder gap and the idempotency anti-pattern in one shot.

3. **Update vault and notes-app** to use the builder and deterministic idempotency keys. (`soma-vault/crates/soma-storage/src/pg/mod.rs`, `examples/notes-app/src/main.rs`)

4. **Trivial doc fixes** (batch into one commit): README `verify()` memory claim, `record()` crash-gap doc comment, `openssl rand -hex 32` generation commands, published crate dep form in README/INTEGRATION.md, pool `max_connections` early error in `install()`.

5. **`LocalSink::new_single_tenant()`** + `list_default()` / `verify_default()` wrappers. (`crates/soma-audit-pg/src/sink.rs`)

6. **`UNIQUE (tenant_id, idempotency_key)`** migration — new file in `migration-order.yaml`, update `ON CONFLICT` in `sink.rs`.

7. **Seal sweep HA fix** — new migration adding `UNIQUE (tenant_id, up_to_seq_num)`, update `seal.rs` INSERT. (`crates/soma-audit-server/src/seal.rs`)

8. **Relay dead-letter** — `failed_permanently_at` column migration, `max_attempts` in `RelayConfig`, skip logic in poll query, `warn!` on exhaustion. (`crates/soma-audit-client/src/relay.rs`)

### Central discovery feature (Goal 2 — net-new, 2–4 days)

This is one coherent feature. Build in this order:

1. **`soma_audit.sources` migration** — table with `UNIQUE (source_service, tenant_id)`, `first_seen`, `last_seen`, `host_url`, `version`. New file in `migration-order.yaml`.

2. **Auto-upsert in `post_event`** (`crates/soma-audit-server/src/ingest.rs`) — `ON CONFLICT (source_service, tenant_id) DO UPDATE SET last_seen = now()`. Zero client ceremony required.

3. **`GET /v1/sources`** endpoint (`crates/soma-audit-server/src/routes.rs`, new handler in `query.rs`) — returns sources with `event_count` from a join. Admin-auth.

4. **`POST /internal/v1/sources/register`** — optional; allows apps to push `host_url` and `version`. Ingest-secret auth. Wire optional call in relay startup if `SOMA_AUDIT_REGISTER=true`.

5. **`POST /internal/v1/heartbeat`** — touches `last_seen` only. Relay calls on empty-outbox polling intervals.

6. **Dashboard `/sources` page** (`dashboard/src/pages/`) — table of sources, health dot, click-to-navigate. Change default route from `/audit` to `/sources`.

7. **Date-range filter** on `GET /v1/audit` (`query.rs` `ListParams`, sink query builder, dashboard filter panel). Exercises the existing BRIN index.

8. **Optional `source_service` filter** on `GET /v1/audit` + admin `GET /v1/audit/global` using the `soma_audit.bypass` GUC pattern from `seal.rs:36`.

9. **Per-source keys** (`soma_audit.source_keys` table, update `check_ingest_auth`) — this is the medium-term security fix for the shared-secret liability. Not a blocker for discoverability but should follow the sources table since registration naturally issues per-source keys.

---

## 6. What Is Already Genuinely Good

- **Local install path is real and proven.** `install(&pool)` + `AuditKeys` + `LocalSink` + `record_in_tx` is a 3-line adopt, and `soma-vault` is live evidence it works atomically with business transactions.
- **HMAC chain and `verify_chain` are sound.** Metadata-in-HMAC, seal-tip anchoring, and the RLS-bypass GUC for maintenance reads all hold. The `verify()` implementation is O(1) streaming (server-side cursor), not the full-load the README incorrectly claimed.
- **Relay pipeline is durable.** Outbox-in-same-transaction, exponential backoff, idempotent delivery to the central ingest endpoint — the delivery guarantee is correct and battle-tested.
- **Multi-source advisory lock is correct.** Advisory lock scoped to `(tenant_id)` serializes concurrent writers without cross-tenant contention, which is the right design for the current combined-chain model.
- **Ed25519 60-second seal sweep** is architecturally solid. The cryptographic anchoring of chain tips at a regular interval is the right tamper-evidence amplifier.
- **RLS is enforced correctly.** The three-role model (`maintenance`, `service`, `readonly`) and the `session_role` GUC pattern are implemented and tested. The seal sweep correctly bypasses RLS via the maintenance role rather than a superuser path.
- **The notes-app is a clear, working reference.** Even though it had to write a local wrapper, the end-to-end flow it demonstrates is accurate and will be the right starting point for future adopters once the builder exists.
- **`soma-schema` integration is clean.** Version-pinned migrations in `migration-order.yaml`, UP/DOWN pairs, advisory lock per service — the migration hygiene is correct and the schema is cleanly isolated in its own `soma_audit` namespace.