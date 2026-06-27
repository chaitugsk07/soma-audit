-- Ed25519 chain-seal checkpoints. The seal sweep (in soma-audit-server) periodically
-- signs each tenant's chain head, providing externally verifiable tamper-evidence.
-- This table is cross-tenant maintenance data and is intentionally NOT under RLS.
CREATE TABLE soma_audit.audit_chain_seals (
    id              UUID        PRIMARY KEY,
    tenant_id       UUID        NOT NULL,
    up_to_seq_num   BIGINT      NOT NULL,
    chain_head_hash TEXT        NOT NULL,
    sealed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    signature       BYTEA       NOT NULL,
    public_key_id   TEXT        NOT NULL
);

CREATE INDEX audit_chain_seals_tenant_seq
    ON soma_audit.audit_chain_seals (tenant_id, up_to_seq_num DESC);

-- DOWN ==
DROP INDEX IF EXISTS soma_audit.audit_chain_seals_tenant_seq;
DROP TABLE IF EXISTS soma_audit.audit_chain_seals;
