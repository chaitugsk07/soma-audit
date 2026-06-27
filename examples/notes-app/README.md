# notes-app — soma-audit integration demo

A minimal multi-tenant notes API that shows how any Rust/axum app adopts
soma-audit in **three lines of startup code** and **one call per operation**.

## What it demonstrates

| Thing | Where |
|-------|-------|
| One-line audit installation | `soma_audit_pg::install(&pool)` at boot |
| Atomic audit | `record_in_tx` commits the note and its audit event together |
| Coexisting schemas | `demo` (app data) and `soma_audit` (audit log) in the same database |
| Querying the audit trail | `GET /audit?tenant_id=` |
| Chain integrity verification | `GET /audit/verify?tenant_id=` |

---

## How to run

Prerequisites: Postgres running, a database the app can write to.

```bash
cd examples/notes-app
DATABASE_URL=postgres://soma:soma@localhost:5432/soma_audit_test cargo run
```

The app binds on `127.0.0.1:8090` by default.  Override with `BIND=<addr>`.

### Curl walkthrough

**1. Create a note** — the note and its audit event commit atomically:

```bash
TENANT=a1b2c3d4-e5f6-7890-abcd-ef1234567890
ACTOR=11111111-2222-3333-4444-555555555555

curl -s -X POST http://127.0.0.1:8090/notes \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"$TENANT\",\"actor_id\":\"$ACTOR\",\"title\":\"My first note\",\"body\":\"soma-audit is easy to add!\"}"
```

Expected shape:
```json
{
  "id":        "75cf8f9e-...",
  "tenant_id": "a1b2c3d4-...",
  "title":     "My first note",
  "body":      "soma-audit is easy to add!"
}
```

**2. List notes** (also records a `note.read` audit event via the non-tx path):

```bash
curl -s "http://127.0.0.1:8090/notes?tenant_id=$TENANT"
```

**3. Delete a note**:

```bash
NOTE_ID=<id from step 1>
curl -s -X DELETE "http://127.0.0.1:8090/notes/$NOTE_ID?tenant_id=$TENANT&actor_id=$ACTOR"
```

**4. View the audit trail**:

```bash
curl -s "http://127.0.0.1:8090/audit?tenant_id=$TENANT"
```

Expected shape (most-recent first):
```json
{
  "count": 2,
  "events": [
    {
      "seq_num":       2,
      "event_type":    "note.delete",
      "outcome":       "success",
      "source_service":"notes-app",
      "resource_type": "note",
      "resource_id":   "75cf8f9e-...",
      "entry_hash":    "deadbeef...",
      "prev_hash":     "abc123...",
      ...
    },
    {
      "seq_num":    1,
      "event_type": "note.create",
      "prev_hash":  null,
      ...
    }
  ]
}
```

**5. Verify chain integrity**:

```bash
curl -s "http://127.0.0.1:8090/audit/verify?tenant_id=$TENANT"
```

Expected:
```json
{
  "ok": true,
  "entries_checked": 2,
  "first_broken_seq": null,
  "tenant_id": "a1b2c3d4-..."
}
```

---

## How it was added to this app

These are the only soma-audit lines in `Cargo.toml`:

```toml
soma-audit-pg   = { path = "../../crates/soma-audit-pg" }
soma-audit-core = { path = "../../crates/soma-audit-core" }
```

And these are the only soma-audit lines in `src/main.rs` at startup:

```rust
use soma_audit_pg::{AuditEvent, AuditKeys, LocalSink, Outcome};

// Line 1 — install the soma_audit schema (idempotent, runs every startup)
soma_audit_pg::install(&pool).await?;

// Line 2 — load signing keys (from env in production, hardcoded for demo)
let keys = AuditKeys::from_env().unwrap_or_else(|_| demo_keys());

// Line 3 — create the sink that stamps every event with "notes-app"
let sink = Arc::new(LocalSink::new(pool.clone(), Arc::new(keys), "notes-app"));
```

At each write operation, wrap in a transaction and call `record_in_tx`:

```rust
let mut tx = pool.begin().await?;

// your normal business write
sqlx::query("INSERT INTO demo.notes ...").execute(&mut *tx).await?;

// atomic audit — commits together with the business write, or not at all
sink.record_in_tx(&audit_event(..., Outcome::Success), &mut tx).await?;

tx.commit().await?;
```

That's it.  The `demo` schema (your app's tables) and the `soma_audit` schema
(the audit log) coexist in the same Postgres database without interference.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://soma:soma@localhost:5432/soma_audit_test` | Postgres connection string |
| `BIND` | `127.0.0.1:8090` | Listen address |
| `SOMA_AUDIT_MASTER_SECRET` | *(demo fallback)* | 64-char hex — HMAC master key |
| `SOMA_AUDIT_SIGNING_KEY` | *(demo fallback)* | 64-char hex — Ed25519 signing key |
| `RUST_LOG` | *(unset)* | e.g. `notes_app=info,soma_audit_pg=debug` |

> **Warning**: when `SOMA_AUDIT_MASTER_SECRET` / `SOMA_AUDIT_SIGNING_KEY` are
> absent the app falls back to hardcoded demo keys and logs a `WARN`.  Use only
> for local exploration — in production always set real secrets.
