CREATE TABLE soma_audit_outbox.events (
    id             BIGSERIAL    PRIMARY KEY,
    event_id       UUID         NOT NULL UNIQUE,   -- = AuditEvent.idempotency_key, stable across retries
    payload        JSONB        NOT NULL,          -- the full serialized AuditEvent
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    delivered_at   TIMESTAMPTZ,
    attempts       INT          NOT NULL DEFAULT 0,
    last_error     TEXT,
    next_retry_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_outbox_undelivered ON soma_audit_outbox.events (next_retry_at) WHERE delivered_at IS NULL;

-- DOWN ==
DROP INDEX IF EXISTS idx_outbox_undelivered;
DROP TABLE IF EXISTS soma_audit_outbox.events;
