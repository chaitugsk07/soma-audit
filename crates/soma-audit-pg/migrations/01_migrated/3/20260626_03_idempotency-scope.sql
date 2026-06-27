-- Replace global UNIQUE(idempotency_key) with tenant-scoped UNIQUE(tenant_id, idempotency_key).
-- Two events from different tenants may legitimately share the same idempotency_key value;
-- only same-tenant duplicates are suppressed.

-- UP
ALTER TABLE soma_audit.fct_audit_events DROP CONSTRAINT IF EXISTS fct_audit_events_idempotency_key_key;
ALTER TABLE soma_audit.fct_audit_events ADD CONSTRAINT audit_events_tenant_idempotency_key UNIQUE (tenant_id, idempotency_key);

-- DOWN ==
ALTER TABLE soma_audit.fct_audit_events DROP CONSTRAINT IF EXISTS audit_events_tenant_idempotency_key;
ALTER TABLE soma_audit.fct_audit_events ADD CONSTRAINT fct_audit_events_idempotency_key_key UNIQUE (idempotency_key);
