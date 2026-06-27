-- Track which services/tenants are sending events (discovery for the admin dashboard).

-- UP
CREATE TABLE soma_audit.sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_service  TEXT NOT NULL,
    tenant_id       UUID NOT NULL,
    host_url        TEXT,
    version         TEXT,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_service, tenant_id)
);

-- DOWN ==
DROP TABLE IF EXISTS soma_audit.sources;
