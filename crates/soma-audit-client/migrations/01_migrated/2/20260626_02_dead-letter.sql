-- Add dead-letter support: rows that exhaust max_attempts are stamped with
-- failed_permanently_at so the relay skips them on future polls.

-- UP
ALTER TABLE soma_audit_outbox.events ADD COLUMN IF NOT EXISTS failed_permanently_at TIMESTAMPTZ;

-- DOWN ==
ALTER TABLE soma_audit_outbox.events DROP COLUMN IF EXISTS failed_permanently_at;
