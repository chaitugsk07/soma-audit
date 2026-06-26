use soma_audit_core::AuditEvent;
use soma_schema::include_dir::include_dir;
use sqlx::{PgPool, Postgres, Transaction};

use crate::error::ClientError;

static MIGRATIONS: soma_schema::include_dir::Dir =
    include_dir!("$CARGO_MANIFEST_DIR/migrations");

/// Install the outbox schema and run migrations into the host's Postgres.
///
/// Idempotent — safe to call every time the host service starts.
///
/// The pool must have `max_connections >= 2`. One connection is held for the
/// advisory lock; at least one more is needed for migration queries.
///
/// # Errors
///
/// Returns [`ClientError::Schema`] if the migration runner fails.
pub async fn install_outbox(pool: &PgPool) -> Result<(), ClientError> {
    let driver = soma_schema::PostgresDriver::new(
        pool.clone(),
        soma_schema::PostgresConfig {
            schema: Some("soma_audit_outbox".into()),
            advisory_lock_key: 6020250626000002_i64,
            ..Default::default()
        },
    )
    .map_err(ClientError::Schema)?;

    soma_schema::Migrator::from_embedded(&MIGRATIONS)
        .map_err(ClientError::Schema)?
        .up(&driver)
        .await
        .map_err(ClientError::Schema)
}

/// Durable outbox sink — writes events to a local Postgres outbox table so
/// they survive a central-server outage.
///
/// The background relay task (see [`crate::relay::spawn_relay`]) picks up
/// undelivered rows and forwards them to the central soma-audit-server.
pub struct RemoteSink {
    pool: PgPool,
}

impl RemoteSink {
    /// Create a new [`RemoteSink`] backed by the given pool.
    ///
    /// [`install_outbox`] must have been called at least once before any
    /// enqueue operations.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Durably enqueue an event using its own connection.
    ///
    /// Prefer [`enqueue_in_tx`](Self::enqueue_in_tx) when you hold the host's
    /// business transaction — that path commits the outbox row atomically with
    /// the business write, eliminating the window between "committed business
    /// action" and "queued audit event".
    ///
    /// This call is idempotent: a duplicate `idempotency_key` is silently
    /// discarded.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Db`] on a database failure, or
    /// [`ClientError::Serialization`] if the event cannot be serialized.
    pub async fn enqueue(&self, event: &AuditEvent) -> Result<(), ClientError> {
        let payload = serde_json::to_value(event)?;
        sqlx::query(
            "INSERT INTO soma_audit_outbox.events (event_id, payload) \
             VALUES ($1, $2) ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(event.idempotency_key)
        .bind(&payload)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Durably enqueue an event **inside the caller's business transaction**.
    ///
    /// This is the durability-preserving path: the outbox row commits atomically
    /// with the caller's business write.  A committed business action therefore
    /// always has a corresponding pending audit event — there is no window in
    /// which the business action is committed but the audit event is lost.
    ///
    /// This call is idempotent: a duplicate `idempotency_key` is silently
    /// discarded.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Db`] on a database failure, or
    /// [`ClientError::Serialization`] if the event cannot be serialized.
    pub async fn enqueue_in_tx(
        &self,
        event: &AuditEvent,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), ClientError> {
        let payload = serde_json::to_value(event)?;
        sqlx::query(
            "INSERT INTO soma_audit_outbox.events (event_id, payload) \
             VALUES ($1, $2) ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(event.idempotency_key)
        .bind(&payload)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}
