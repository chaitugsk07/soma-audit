-- Per-source ingest keys: one key per (source_service, tenant_id) pair.

-- UP
CREATE TABLE soma_audit.source_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_service  TEXT NOT NULL,
    tenant_id       UUID NOT NULL,
    key_hash        TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    UNIQUE (source_service, tenant_id)
);

-- DOWN ==
DROP TABLE IF EXISTS soma_audit.source_keys;
