//! Integration tests — require a live Postgres.
//! Set TEST_DATABASE_URL to run; tests are skipped if the env var is absent.

use std::sync::Arc;
use uuid::Uuid;

use soma_audit_pg::{AuditEvent, AuditKeys, LocalSink, Outcome, install};

fn test_db_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL").ok()
}

fn make_keys() -> Arc<AuditKeys> {
    Arc::new(AuditKeys::from_secret([0xab; 32], [0xcd; 32]))
}

fn make_event(tenant_id: Uuid) -> AuditEvent {
    AuditEvent {
        source_service: "test".into(),
        idempotency_key: Uuid::new_v4(),
        tenant_id,
        event_type: "test.event".into(),
        actor_id: None,
        actor_role: None,
        resource_type: None,
        resource_id: None,
        outcome: Outcome::Success,
        actor_ip: None,
        occurred_at: chrono::Utc::now(),
        metadata: serde_json::Value::Null,
    }
}

#[tokio::test]
async fn test_install_idempotent() {
    let Some(url) = test_db_url() else {
        eprintln!("SKIP test_install_idempotent: TEST_DATABASE_URL not set");
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect");
    install(&pool).await.expect("first install");
    install(&pool).await.expect("second install should be idempotent");
}

#[tokio::test]
async fn test_record_and_verify() {
    let Some(url) = test_db_url() else {
        eprintln!("SKIP test_record_and_verify: TEST_DATABASE_URL not set");
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect");
    install(&pool).await.expect("install");

    let sink = LocalSink::new(pool, make_keys(), "test-service");
    let tenant = Uuid::new_v4();

    for _ in 0..3 {
        sink.record(&make_event(tenant)).await.expect("record");
    }

    let result = sink.verify(tenant).await.expect("verify");
    assert!(result.ok, "chain should be valid");
    assert_eq!(result.entries_checked, 3);
}

#[tokio::test]
async fn test_record_in_tx_atomic() {
    let Some(url) = test_db_url() else {
        eprintln!("SKIP test_record_in_tx_atomic: TEST_DATABASE_URL not set");
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect");
    install(&pool).await.expect("install");

    let sink = LocalSink::new(pool.clone(), make_keys(), "test-service");
    let tenant = Uuid::new_v4();
    let event = make_event(tenant);

    {
        let mut tx = pool.begin().await.expect("begin");
        sink.record_in_tx(&event, &mut tx).await.expect("record_in_tx");
        // Implicit ROLLBACK (tx dropped without commit)
    }

    // No rows should exist for this tenant
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('soma_audit.tenant_id', $1::text, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .expect("set guc");
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM soma_audit.fct_audit_events WHERE tenant_id = $1",
    )
    .bind(tenant)
    .fetch_one(&mut *tx)
    .await
    .expect("count");
    tx.commit().await.ok();
    assert_eq!(count.0, 0, "rollback should have removed the row");
}

#[tokio::test]
async fn test_idempotent_record() {
    let Some(url) = test_db_url() else {
        eprintln!("SKIP test_idempotent_record: TEST_DATABASE_URL not set");
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect");
    install(&pool).await.expect("install");

    let sink = LocalSink::new(pool, make_keys(), "test-service");
    let tenant = Uuid::new_v4();
    let event = make_event(tenant);

    let r1 = sink.record(&event).await.expect("first record");
    let r2 = sink.record(&event).await.expect("second record (idempotent)");
    assert_eq!(r1.id, r2.id, "idempotent call should return same record");
}

#[tokio::test]
async fn test_append_only_trigger() {
    let Some(url) = test_db_url() else {
        eprintln!("SKIP test_append_only_trigger: TEST_DATABASE_URL not set");
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect");
    install(&pool).await.expect("install");

    let sink = LocalSink::new(pool.clone(), make_keys(), "test-service");
    let tenant = Uuid::new_v4();
    let rec = sink.record(&make_event(tenant)).await.expect("record");

    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('soma_audit.tenant_id', $1::text, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .ok();
    let update_result = sqlx::query(
        "UPDATE soma_audit.fct_audit_events SET event_type = 'tampered' WHERE id = $1",
    )
    .bind(rec.id)
    .execute(&mut *tx)
    .await;
    tx.rollback().await.ok();
    assert!(update_result.is_err(), "UPDATE should be blocked by trigger");
}
