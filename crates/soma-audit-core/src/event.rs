use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Outcome of the audited operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Denied,
    Error,
}

/// Caller-supplied envelope: everything a service knows about an event at the
/// moment it occurs.  This is the input to [`crate::chain::seal_record`].
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Arbitrary structured metadata; defaults to an empty JSON object.
    #[serde(default = "default_metadata")]
    pub metadata: serde_json::Value,
}

fn default_metadata() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Stored record: the caller's event plus the hash-chain envelope fields added
/// by the storage layer after it holds the per-tenant advisory lock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: Uuid,
    pub seq_num: i64,
    /// Hex of the previous row's `entry_hash`; `None` for the first row in a
    /// tenant+epoch.
    pub prev_hash: Option<String>,
    /// Hex HMAC-SHA256 of the canonical message for this record.
    pub entry_hash: String,
    /// Epoch counter.  Incrementing it signals a canonical-format or key
    /// boundary, allowing in-place migration without breaking old chains.
    pub chain_epoch: i32,
    /// Wall-clock time the record was written to persistent storage.
    pub created_at: DateTime<Utc>,
    /// The original caller-supplied event.
    #[serde(flatten)]
    pub event: AuditEvent,
}
