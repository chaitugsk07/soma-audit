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

impl AuditEvent {
    /// Start building an [`AuditEvent`] with the three required fields.
    pub fn builder(
        tenant_id: Uuid,
        event_type: impl Into<String>,
        outcome: Outcome,
    ) -> AuditEventBuilder {
        AuditEventBuilder {
            tenant_id,
            event_type: event_type.into(),
            outcome,
            source_service: None,
            idempotency_key: None,
            actor_id: None,
            actor_role: None,
            resource_type: None,
            resource_id: None,
            actor_ip: None,
            occurred_at: None,
            metadata: None,
        }
    }
}

/// Builder for [`AuditEvent`].  Obtain via [`AuditEvent::builder`].
pub struct AuditEventBuilder {
    tenant_id: Uuid,
    event_type: String,
    outcome: Outcome,
    source_service: Option<String>,
    idempotency_key: Option<Uuid>,
    actor_id: Option<Uuid>,
    actor_role: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    actor_ip: Option<std::net::IpAddr>,
    occurred_at: Option<DateTime<Utc>>,
    metadata: Option<serde_json::Value>,
}

impl AuditEventBuilder {
    pub fn source_service(mut self, s: impl Into<String>) -> Self {
        self.source_service = Some(s.into());
        self
    }

    pub fn idempotency_key(mut self, k: Uuid) -> Self {
        self.idempotency_key = Some(k);
        self
    }

    pub fn actor_id(mut self, id: Uuid) -> Self {
        self.actor_id = Some(id);
        self
    }

    pub fn actor_role(mut self, role: impl Into<String>) -> Self {
        self.actor_role = Some(role.into());
        self
    }

    pub fn resource(mut self, resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    pub fn actor_ip(mut self, ip: std::net::IpAddr) -> Self {
        self.actor_ip = Some(ip);
        self
    }

    pub fn metadata(mut self, m: serde_json::Value) -> Self {
        self.metadata = Some(m);
        self
    }

    pub fn occurred_at(mut self, t: DateTime<Utc>) -> Self {
        self.occurred_at = Some(t);
        self
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent {
            tenant_id: self.tenant_id,
            event_type: self.event_type,
            outcome: self.outcome,
            source_service: self.source_service.unwrap_or_default(),
            idempotency_key: self.idempotency_key.unwrap_or_else(Uuid::new_v4),
            actor_id: self.actor_id,
            actor_role: self.actor_role,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            actor_ip: self.actor_ip,
            occurred_at: self.occurred_at.unwrap_or_else(Utc::now),
            metadata: self.metadata.unwrap_or_else(default_metadata),
        }
    }
}

/// Stable v5 UUID derived from `(tenant_id, request_id)`.
///
/// Same inputs always produce the same key, so retries deduplicate correctly.
/// Namespace: a fixed soma-audit-specific UUID constant (`SOMA_AUDIT_NS`).
pub fn idempotency_key(tenant_id: Uuid, request_id: Uuid) -> Uuid {
    const SOMA_AUDIT_NS: Uuid = uuid::uuid!("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    let mut name = [0u8; 32];
    name[..16].copy_from_slice(tenant_id.as_bytes());
    name[16..].copy_from_slice(request_id.as_bytes());
    Uuid::new_v5(&SOMA_AUDIT_NS, &name)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_required_fields_only() {
        let tenant = Uuid::new_v4();
        let event = AuditEvent::builder(tenant, "user.login", Outcome::Success).build();
        assert_eq!(event.tenant_id, tenant);
        assert_eq!(event.event_type, "user.login");
        assert_eq!(event.outcome, Outcome::Success);
        assert_eq!(event.source_service, "");
        assert!(event.actor_id.is_none());
        assert_eq!(event.metadata, serde_json::Value::Object(Default::default()));
    }

    #[test]
    fn builder_chained_optionals() {
        let tenant = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let key = Uuid::new_v4();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let meta = serde_json::json!({"k": "v"});
        let event = AuditEvent::builder(tenant, "order.placed", Outcome::Success)
            .source_service("orders")
            .idempotency_key(key)
            .actor_id(actor)
            .actor_role("admin")
            .resource("Order", "ord-123")
            .actor_ip(ip)
            .metadata(meta.clone())
            .build();
        assert_eq!(event.source_service, "orders");
        assert_eq!(event.idempotency_key, key);
        assert_eq!(event.actor_id, Some(actor));
        assert_eq!(event.actor_role.as_deref(), Some("admin"));
        assert_eq!(event.resource_type.as_deref(), Some("Order"));
        assert_eq!(event.resource_id.as_deref(), Some("ord-123"));
        assert_eq!(event.actor_ip, Some(ip));
        assert_eq!(event.metadata, meta);
    }

    #[test]
    fn builder_occurred_at_defaults_to_now() {
        let before = Utc::now();
        let event = AuditEvent::builder(Uuid::new_v4(), "x", Outcome::Error).build();
        let after = Utc::now();
        assert!(event.occurred_at >= before);
        assert!(event.occurred_at <= after);
    }

    #[test]
    fn idempotency_key_deterministic() {
        let t = Uuid::new_v4();
        let r = Uuid::new_v4();
        assert_eq!(idempotency_key(t, r), idempotency_key(t, r));
    }

    #[test]
    fn idempotency_key_different_inputs() {
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let r = Uuid::new_v4();
        assert_ne!(idempotency_key(t1, r), idempotency_key(t2, r));
        assert_ne!(idempotency_key(t1, Uuid::new_v4()), idempotency_key(t1, Uuid::new_v4()));
    }
}
