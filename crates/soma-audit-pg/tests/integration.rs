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

/// BUG 1 + BUG 2 regression test.
///
/// Records events for two tenants, then runs the seal-sweep SELECT (with
/// `SET LOCAL soma_audit.bypass = 'on'`) and asserts:
///   - Both tenants are returned (bypass GUC enables cross-tenant read).
///   - The `chain_head_hash` returned equals the `entry_hash` of the row
///     with the highest `seq_num` for each tenant (not the lexicographic
///     MAX of all entry_hashes).
#[tokio::test]
async fn test_seal_sweep_tip_hash_and_rls_bypass() {
    let Some(url) = test_db_url() else {
        eprintln!("SKIP test_seal_sweep_tip_hash_and_rls_bypass: TEST_DATABASE_URL not set");
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect");
    install(&pool).await.expect("install");

    let sink = LocalSink::new(pool.clone(), make_keys(), "test-service");
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    // Insert multiple events per tenant so seq_num > 1; the chain tip
    // is the last inserted record for each tenant.
    let mut tip_a = None;
    for _ in 0..3 {
        tip_a = Some(sink.record(&make_event(tenant_a)).await.expect("record a"));
    }
    let mut tip_b = None;
    for _ in 0..2 {
        tip_b = Some(sink.record(&make_event(tenant_b)).await.expect("record b"));
    }
    let tip_a = tip_a.unwrap();
    let tip_b = tip_b.unwrap();

    // Run the core sweep SELECT with the bypass GUC — omit the NOT EXISTS
    // clause that references audit_chain_seals (created only by the server
    // crate) to keep this test self-contained in soma-audit-pg.
    // This still proves: (a) bypass GUC lets us read all tenants, and (b)
    // DISTINCT ON returns the correct chain tip row per tenant.
    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query("SET LOCAL soma_audit.bypass = 'on'")
        .execute(&mut *tx)
        .await
        .expect("set bypass guc");

    let rows: Vec<(Uuid, i64, String)> = sqlx::query_as(
        r#"
        SELECT DISTINCT ON (e.tenant_id)
            e.tenant_id, e.seq_num AS up_to_seq, e.entry_hash AS chain_head_hash
        FROM soma_audit.fct_audit_events e
        WHERE e.tenant_id = ANY($1)
        ORDER BY e.tenant_id, e.seq_num DESC
        "#,
    )
    // Scope to our two test tenants to avoid interference from parallel tests.
    .bind(vec![tenant_a, tenant_b])
    .fetch_all(&mut *tx)
    .await
    .expect("sweep select");
    tx.commit().await.expect("commit");

    // Both tenants must be visible (BUG 2: bypass GUC works).
    let find = |id: Uuid| rows.iter().find(|(tid, _, _)| *tid == id).cloned();
    let row_a = find(tenant_a).expect("tenant_a not found — RLS bypass failed");
    let row_b = find(tenant_b).expect("tenant_b not found — RLS bypass failed");

    // BUG 1: the returned chain_head_hash must be the entry_hash of the tip row.
    assert_eq!(
        row_a.2, tip_a.entry_hash,
        "tenant_a chain_head_hash must equal tip entry_hash"
    );
    assert_eq!(
        row_a.1, tip_a.seq_num,
        "tenant_a up_to_seq must equal tip seq_num"
    );
    assert_eq!(
        row_b.2, tip_b.entry_hash,
        "tenant_b chain_head_hash must equal tip entry_hash"
    );
    assert_eq!(
        row_b.1, tip_b.seq_num,
        "tenant_b up_to_seq must equal tip seq_num"
    );
}
