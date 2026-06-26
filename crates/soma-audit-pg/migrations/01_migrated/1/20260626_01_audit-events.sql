CREATE TABLE soma_audit.fct_audit_events (
    id              UUID        NOT NULL PRIMARY KEY,
    tenant_id       UUID        NOT NULL,
    seq_num         BIGINT      NOT NULL,
    source_service  TEXT        NOT NULL,
    event_type      TEXT        NOT NULL,
    actor_id        UUID,
    actor_role      TEXT,
    resource_type   TEXT,
    resource_id     TEXT,
    outcome         TEXT        NOT NULL CHECK (outcome IN ('success','denied','error')),
    actor_ip        INET,
    occurred_at     TIMESTAMPTZ NOT NULL,
    metadata        JSONB       NOT NULL DEFAULT '{}',
    prev_hash       TEXT,
    entry_hash      TEXT        NOT NULL,
    chain_epoch     INT         NOT NULL DEFAULT 1,
    idempotency_key UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, seq_num),
    UNIQUE (idempotency_key)
);
CREATE INDEX idx_audit_tenant_seq ON soma_audit.fct_audit_events (tenant_id, seq_num DESC);
CREATE INDEX idx_audit_tenant_time ON soma_audit.fct_audit_events USING BRIN (occurred_at);
CREATE INDEX idx_audit_tenant_event ON soma_audit.fct_audit_events (tenant_id, event_type);

ALTER TABLE soma_audit.fct_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE soma_audit.fct_audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON soma_audit.fct_audit_events
    USING (
        current_setting('soma_audit.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('soma_audit.tenant_id', true)::uuid
    )
    WITH CHECK (
        current_setting('soma_audit.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('soma_audit.tenant_id', true)::uuid
    );

CREATE OR REPLACE FUNCTION soma_audit.prevent_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'soma_audit.fct_audit_events is append-only';
END;
$$;
CREATE TRIGGER no_update BEFORE UPDATE ON soma_audit.fct_audit_events
    FOR EACH ROW EXECUTE FUNCTION soma_audit.prevent_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON soma_audit.fct_audit_events
    FOR EACH ROW EXECUTE FUNCTION soma_audit.prevent_mutation();

-- DOWN ==
DROP TRIGGER IF EXISTS no_delete ON soma_audit.fct_audit_events;
DROP TRIGGER IF EXISTS no_update ON soma_audit.fct_audit_events;
DROP FUNCTION IF EXISTS soma_audit.prevent_mutation();
DROP POLICY IF EXISTS tenant_isolation ON soma_audit.fct_audit_events;
DROP INDEX IF EXISTS idx_audit_tenant_event;
DROP INDEX IF EXISTS idx_audit_tenant_time;
DROP INDEX IF EXISTS idx_audit_tenant_seq;
DROP TABLE IF EXISTS soma_audit.fct_audit_events;
