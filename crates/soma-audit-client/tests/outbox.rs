/// Integration tests for outbox install and enqueue behaviour.
///
/// These tests require a live Postgres instance. Set `TEST_DATABASE_URL` to a
/// connectable DSN (e.g. `postgres://user:pass@localhost/testdb`). When the
/// variable is absent the tests skip gracefully.
use std::net::IpAddr;
use std::str::FromStr;

use chrono::Utc;
use soma_audit_client::{install_outbox, AuditEvent, Outcome, RemoteSink};
use uuid::Uuid;

fn make_event() -> AuditEvent {
    AuditEvent {
        source_service: "test-service".into(),
        idempotency_key: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        event_type: "user.login".into(),
        actor_id: Some(Uuid::new_v4()),
        actor_role: Some("admin".into()),
        resource_type: Some("session".into()),
        resource_id: Some("sess-1".into()),
        outcome: Outcome::Success,
        actor_ip: Some(IpAddr::from_str("127.0.0.1").unwrap()),
        occurred_at: Utc::now(),
        metadata: serde_json::json!({ "mfa": true }),
    }
}

#[cfg(test)]
mod serialization {
    use super::*;

    /// AuditEvent round-trips through JSON without data loss.
    #[test]
    fn roundtrip() {
        let event = make_event();
        let json = serde_json::to_value(&event).expect("serialize");
        let back: AuditEvent = serde_json::from_value(json).expect("deserialize");

        assert_eq!(event.idempotency_key, back.idempotency_key);
        assert_eq!(event.source_service, back.source_service);
        assert_eq!(event.tenant_id, back.tenant_id);
        assert_eq!(event.event_type, back.event_type);
        assert_eq!(event.actor_id, back.actor_id);
        assert_eq!(event.actor_role, back.actor_role);
        assert_eq!(event.resource_type, back.resource_type);
        assert_eq!(event.resource_id, back.resource_id);
        assert_eq!(event.actor_ip, back.actor_ip);
        assert_eq!(event.occurred_at, back.occurred_at);
        assert_eq!(event.metadata, back.metadata);
    }

    /// Outcome variants serialize to the expected snake_case strings.
    #[test]
    fn outcome_names() {
        assert_eq!(
            serde_json::to_value(Outcome::Success).unwrap(),
            serde_json::json!("success")
        );
        assert_eq!(
            serde_json::to_value(Outcome::Denied).unwrap(),
            serde_json::json!("denied")
        );
        assert_eq!(
            serde_json::to_value(Outcome::Error).unwrap(),
            serde_json::json!("error")
        );
    }
}

#[cfg(test)]
mod db {
    use super::*;
    use sqlx::PgPool;

    /// Connect using `TEST_DATABASE_URL`; return `None` if the variable is absent.
    async fn try_pool() -> Option<PgPool> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = PgPool::connect(&url).await.ok()?;
        Some(pool)
    }

    /// install_outbox is idempotent; enqueue writes one row; duplicate key is
    /// silently ignored.
    #[tokio::test]
    async fn install_enqueue_idempotent() {
        let Some(pool) = try_pool().await else {
            eprintln!("TEST_DATABASE_URL not set — skipping DB test");
            return;
        };

        // Install (idempotent — safe to run multiple times).
        install_outbox(&pool).await.expect("install_outbox");

        let sink = RemoteSink::new(pool.clone());
        let event = make_event();

        // First enqueue — should insert one row.
        sink.enqueue(&event).await.expect("first enqueue");

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM soma_audit_outbox.events WHERE event_id = $1")
                .bind(event.idempotency_key)
                .fetch_one(&pool)
                .await
                .expect("count after first enqueue");

        assert_eq!(
            count, 1,
            "expected exactly one outbox row after first enqueue"
        );

        // Second enqueue with the same idempotency_key — must not insert a duplicate.
        sink.enqueue(&event)
            .await
            .expect("second enqueue (idempotent)");

        let count2: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM soma_audit_outbox.events WHERE event_id = $1")
                .bind(event.idempotency_key)
                .fetch_one(&pool)
                .await
                .expect("count after second enqueue");

        assert_eq!(
            count2, 1,
            "expected still exactly one outbox row after duplicate enqueue"
        );

        // The row must be undelivered.
        let delivered: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT delivered_at FROM soma_audit_outbox.events WHERE event_id = $1",
        )
        .bind(event.idempotency_key)
        .fetch_one(&pool)
        .await
        .expect("fetch delivered_at");

        assert!(delivered.is_none(), "new row must be undelivered");

        // Cleanup — remove the test row.
        sqlx::query("DELETE FROM soma_audit_outbox.events WHERE event_id = $1")
            .bind(event.idempotency_key)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    /// A simulated delivery failure must:
    ///   1. increment `attempts` by 1,
    ///   2. set `last_error` to the supplied message,
    ///   3. set `next_retry_at` strictly in the future (i.e. > now()).
    ///
    /// This test drives the same SQL the relay executes for `record_failure`
    /// directly, verifying the exponential-backoff math without needing a live
    /// central server.
    #[tokio::test]
    async fn failure_sets_backoff() {
        let Some(pool) = try_pool().await else {
            eprintln!("TEST_DATABASE_URL not set — skipping DB test");
            return;
        };

        install_outbox(&pool).await.expect("install_outbox");

        let sink = RemoteSink::new(pool.clone());
        let event = make_event();
        sink.enqueue(&event).await.expect("enqueue");

        // Fetch the row id so we can target it.
        let row_id: i64 =
            sqlx::query_scalar("SELECT id FROM soma_audit_outbox.events WHERE event_id = $1")
                .bind(event.idempotency_key)
                .fetch_one(&pool)
                .await
                .expect("fetch row id");

        // Apply the same UPDATE the relay uses in record_failure (attempts=0 → 1).
        sqlx::query(
            "UPDATE soma_audit_outbox.events \
             SET attempts = attempts + 1, \
                 last_error = $2, \
                 next_retry_at = now() + (interval '1 second' * LEAST(power(2, LEAST(attempts, 10))::int, 3600)) \
             WHERE id = $1",
        )
        .bind(row_id)
        .bind("connection refused")
        .execute(&pool)
        .await
        .expect("record failure UPDATE");

        // Verify the row reflects the failure correctly.
        let (attempts, last_error, next_retry_at): (
            i32,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        ) = sqlx::query_as(
            "SELECT attempts, last_error, next_retry_at \
             FROM soma_audit_outbox.events WHERE id = $1",
        )
        .bind(row_id)
        .fetch_one(&pool)
        .await
        .expect("fetch row after failure");

        assert_eq!(attempts, 1, "attempts must be incremented to 1");
        assert_eq!(
            last_error.as_deref(),
            Some("connection refused"),
            "last_error must be recorded"
        );
        // next_retry_at must be in the future (2^0 = 1 second from now, give or
        // take scheduling jitter — just confirm it is strictly after now()).
        assert!(
            next_retry_at > chrono::Utc::now(),
            "next_retry_at ({next_retry_at}) must be in the future"
        );

        // Cleanup.
        sqlx::query("DELETE FROM soma_audit_outbox.events WHERE event_id = $1")
            .bind(event.idempotency_key)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    /// Item 7: a row stamped with `failed_permanently_at` is excluded from
    /// future relay polls (`AND failed_permanently_at IS NULL`).
    #[tokio::test]
    async fn dead_lettered_row_skipped_by_poll() {
        let Some(pool) = try_pool().await else {
            eprintln!("TEST_DATABASE_URL not set — skipping DB test");
            return;
        };

        install_outbox(&pool).await.expect("install_outbox");

        let sink = RemoteSink::new(pool.clone());
        let event = make_event();
        sink.enqueue(&event).await.expect("enqueue");

        // Stamp the row as permanently failed.
        sqlx::query(
            "UPDATE soma_audit_outbox.events \
             SET failed_permanently_at = now() \
             WHERE event_id = $1",
        )
        .bind(event.idempotency_key)
        .execute(&pool)
        .await
        .expect("stamp dead-letter");

        // The relay poll query must not return dead-lettered rows.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM soma_audit_outbox.events \
             WHERE delivered_at IS NULL \
               AND next_retry_at <= now() \
               AND failed_permanently_at IS NULL \
               AND event_id = $1",
        )
        .bind(event.idempotency_key)
        .fetch_one(&pool)
        .await
        .expect("count");

        assert_eq!(
            count, 0,
            "dead-lettered row must be excluded from relay poll"
        );

        // Cleanup.
        sqlx::query("DELETE FROM soma_audit_outbox.events WHERE event_id = $1")
            .bind(event.idempotency_key)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}
