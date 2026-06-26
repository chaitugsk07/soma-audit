# soma-audit-core

Pure zero-IO foundation crate for soma-audit. Provides the event types, HMAC-SHA256 hash-chain math, per-tenant HKDF key derivation, chain integrity verification, and Ed25519 sign/verify primitives shared by every crate in the workspace.

This crate has no database access, no network I/O, and no async code. Because the chain logic lives here — not in any storage adapter — local and central verification are guaranteed to produce identical results.

You will rarely depend on this crate directly. `soma-audit-pg` and `soma-audit-client` re-export the types you need. Import this crate directly only when writing custom storage adapters or standalone verification tooling.

## What it provides

### Types

```rust
use soma_audit_core::{
    AuditEvent, AuditRecord, Outcome,   // event types
    AuditError, Result,                  // error types
    VerifyResult,                        // verify output
};
```

**`Outcome`** — typed result of the audited operation.

```rust
pub enum Outcome { Success, Denied, Error }
```

Serializes as snake_case JSON (`"success"`, `"denied"`, `"error"`).

**`AuditEvent`** — the caller-supplied envelope; everything a service knows at event time.

```rust
pub struct AuditEvent {
    pub source_service: String,
    pub idempotency_key: Uuid,
    pub tenant_id: Uuid,
    pub event_type: String,
    pub actor_id: Option<Uuid>,
    pub actor_role: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub outcome: Outcome,
    pub actor_ip: Option<std::net::IpAddr>,
    pub occurred_at: DateTime<Utc>,
    pub metadata: serde_json::Value,   // defaults to {} when omitted in JSON
}
```

This is the input to `seal_record`. It does not carry chain-envelope fields; those are added by the storage layer.

**`AuditRecord`** — a stored record: the caller's `AuditEvent` plus the chain-envelope fields added by the storage layer after it acquires the per-tenant advisory lock.

```rust
pub struct AuditRecord {
    pub id: Uuid,
    pub seq_num: i64,
    pub prev_hash: Option<String>,
    pub entry_hash: String,
    pub chain_epoch: i32,
    pub created_at: DateTime<Utc>,
    #[serde(flatten)]
    pub event: AuditEvent,    // all AuditEvent fields appear at the top level in JSON
}
```

**`VerifyResult`** — result of a `verify_chain` pass.

```rust
pub struct VerifyResult {
    pub ok: bool,
    pub entries_checked: u64,
    pub first_broken_seq: Option<i64>,  // Some only when ok is false
}
```

**`AuditError`** and **`Result`** — crate-level error type and convenience alias.

```rust
pub enum AuditError {
    Serialization(#[from] serde_json::Error),
    InvalidSignature,
    Chain(String),
}

pub type Result<T> = std::result::Result<T, AuditError>;
```

### Chain math

```rust
use soma_audit_core::{canonical_msg, compute_entry_hash, seal_record};
```

**`canonical_msg`** — builds the deterministic string for a record. Fields are joined with ASCII RS (`0x1E`) in a fixed order. The format is versioned by `chain_epoch`; any breaking change to field order or set requires a new epoch value.

```rust
pub fn canonical_msg(
    seq_num: i64,
    tenant_id: Uuid,
    source_service: &str,
    event_type: &str,
    actor_id: Option<Uuid>,
    actor_role: Option<&str>,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    outcome: Outcome,
    actor_ip: Option<std::net::IpAddr>,
    occurred_at: DateTime<Utc>,
    chain_epoch: i32,
    prev_hash: Option<&str>,
) -> String
```

**`compute_entry_hash`** — `HMAC-SHA256(key, canonical)` returning a lowercase hex string. This is the value stored in `AuditRecord::entry_hash`.

```rust
pub fn compute_entry_hash(canonical: &str, key: &[u8]) -> String
```

**`seal_record`** — build a fully-formed `AuditRecord` from an `AuditEvent` and chain-position fields. Calls `canonical_msg` then `compute_entry_hash` internally. Must be called after acquiring the per-tenant advisory lock and reading `MAX(seq_num)` + last `entry_hash` from the DB.

```rust
pub fn seal_record(
    event: &AuditEvent,
    id: Uuid,
    seq_num: i64,
    prev_hash: Option<&str>,
    chain_epoch: i32,
    created_at: DateTime<Utc>,
    key: &[u8],
) -> AuditRecord
```

### Key derivation

```rust
use soma_audit_core::derive_tenant_hmac_key;
```

**`derive_tenant_hmac_key`** — derive a 32-byte per-tenant HMAC key via `HKDF-SHA256(IKM=master_secret, salt=None, info=b"soma-audit-hmac-v1" ++ tenant_id.as_bytes())`. A separate key per tenant limits the blast radius of any single compromise. Returns `Zeroizing<[u8; 32]>` — the key is zeroed on drop.

```rust
pub fn derive_tenant_hmac_key(
    master_secret: &[u8; 32],
    tenant_id: Uuid,
) -> Zeroizing<[u8; 32]>
```

### Chain verification

```rust
use soma_audit_core::verify_chain;
```

**`verify_chain`** — walk a slice of `AuditRecord`s for a single tenant+epoch, sorted ascending by `seq_num`. Detects three tampering classes: field mutation (HMAC mismatch), row deletion (seq_num gap), and reordering/prev_hash tampering. Stops at the first broken record.

```rust
pub fn verify_chain(records: &[AuditRecord], key: &[u8]) -> VerifyResult
```

The slice must contain records for a single tenant and a single chain epoch. Mixing tenants or epochs produces incorrect results.

### Ed25519 primitives

```rust
use soma_audit_core::{sign_seal, verify_seal};
```

**`sign_seal`** — sign `payload` with an Ed25519 `SigningKey`. Returns the 64-byte signature as `Vec<u8>`.

```rust
pub fn sign_seal(signing_key: &SigningKey, payload: &[u8]) -> Vec<u8>
```

**`verify_seal`** — returns `true` if `sig` is a valid Ed25519 signature of `payload` under `verifying_key`. Returns `false` (not an error) on malformed sig bytes.

```rust
pub fn verify_seal(verifying_key: &VerifyingKey, payload: &[u8], sig: &[u8]) -> bool
```

These are raw primitives. The payload format is defined by the server's seal sweep, not by this module.

## Adding the dependency

```toml
# Cargo.toml
soma-audit-core = { path = "../soma-audit-core" }
# or, inside the workspace:
soma-audit-core = { workspace = true }
```

All public items are re-exported from the crate root (`lib.rs`). Import from `soma_audit_core::*` directly; do not reach into sub-modules.

## Env vars

None. This crate is pure computation.

## Gotchas

- `canonical_msg` uses ASCII RS (`0x1E`) as the field separator. UUIDs, IPs, RFC3339 timestamps, and enum strings cannot contain this byte by design. Do not change the separator or field order without bumping `chain_epoch`.
- `seal_record` must be called while holding the per-tenant advisory lock and inside a transaction. Calling it outside a transaction breaks chain linearizability.
- `chain_epoch` signals canonical-format or key boundaries. When the message format changes, bump `chain_epoch` so old and new records can coexist without confusing `verify_chain`.
- `derive_tenant_hmac_key` returns `Zeroizing<[u8; 32]>`. Do not copy the inner bytes into a long-lived allocation.
- `AuditRecord` uses `#[serde(flatten)]` for the embedded `AuditEvent`: all `AuditEvent` fields appear at the top level in JSON — there is no nested `"event"` key.
- `AuditEvent::metadata` defaults to `{}` (not null) via `#[serde(default)]` when the field is absent in incoming JSON.
