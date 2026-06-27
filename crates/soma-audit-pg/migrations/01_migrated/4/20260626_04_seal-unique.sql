-- Prevent duplicate seals for the same (tenant, chain-head) checkpoint.
-- The seal sweep runs periodically; without this constraint, concurrent sweeps or
-- a restart could insert two seals for the same up_to_seq_num.

-- UP
ALTER TABLE soma_audit.audit_chain_seals ADD CONSTRAINT audit_chain_seals_tenant_up_to_seq UNIQUE (tenant_id, up_to_seq_num);

-- DOWN ==
ALTER TABLE soma_audit.audit_chain_seals DROP CONSTRAINT IF EXISTS audit_chain_seals_tenant_up_to_seq;
