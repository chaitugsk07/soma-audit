use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use soma_audit_core::{AuditEvent, AuditRecord, Outcome, VerifyResult};

use crate::error::AuditPgError;
use crate::keys::{tenant_lock_key, AuditKeys};

pub struct LocalSink {
    pool: PgPool,
    keys: Arc<AuditKeys>,
    source_service: String,
}

#[derive(sqlx::FromRow)]
struct PgAuditRow {
    id: Uuid,
    tenant_id: Uuid,
    seq_num: i64,
    source_service: String,
    event_type: String,
    actor_id: Option<Uuid>,
    actor_role: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    outcome: String,
    actor_ip: Option<IpAddr>,
    occurred_at: DateTime<Utc>,
    metadata: JsonValue,
    prev_hash: Option<String>,
    entry_hash: String,
    chain_epoch: i32,
    idempotency_key: Uuid,
    created_at: DateTime<Utc>,
}

fn outcome_from_str(s: &str) -> Result<Outcome, AuditPgError> {
    match s {
        "success" => Ok(Outcome::Success),
        "denied" => Ok(Outcome::Denied),
        "error" => Ok(Outcome::Error),
        other => Err(AuditPgError::Db(sqlx::Error::Decode(
            format!("unknown outcome: {other}").into(),
        ))),
    }
}

fn outcome_to_str(o: &Outcome) -> &'static str {
    match o {
        Outcome::Success => "success",
        Outcome::Denied => "denied",
        Outcome::Error => "error",
    }
}

fn row_to_record(row: PgAuditRow) -> Result<AuditRecord, AuditPgError> {
    let outcome = outcome_from_str(&row.outcome)?;
    Ok(AuditRecord {
        id: row.id,
        seq_num: row.seq_num,
        prev_hash: row.prev_hash,
        entry_hash: row.entry_hash,
        chain_epoch: row.chain_epoch,
        created_at: row.created_at,
        event: AuditEvent {
            source_service: row.source_service,
            idempotency_key: row.idempotency_key,
            tenant_id: row.tenant_id,
            event_type: row.event_type,
            actor_id: row.actor_id,
            actor_role: row.actor_role,
            resource_type: row.resource_type,
            resource_id: row.resource_id,
            outcome,
            actor_ip: row.actor_ip,
            occurred_at: row.occurred_at,
            metadata: row.metadata,
        },
    })
}

impl LocalSink {
    pub fn new(pool: PgPool, keys: Arc<AuditKeys>, source_service: impl Into<String>) -> Self {
        Self {
            pool,
            keys,
            source_service: source_service.into(),
        }
    }

    /// Record an audit event INSIDE the caller's transaction.
    /// The audit row is atomic with the caller's business write.
    pub async fn record_in_tx(
        &self,
        event: &AuditEvent,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<AuditRecord, AuditPgError> {
        let mut stamped = event.clone();
        // Stamp the sink's own service name only when the caller didn't supply one.
        // The embedded case (an app auditing itself) leaves source_service empty and
        // relies on this default. The central-ingest case forwards events that already
        // carry the originating service's name, which MUST be preserved — it's the
        // cross-service dimension. So only fill it in when absent.
        if stamped.source_service.is_empty() {
            stamped.source_service = self.source_service.clone();
        }

        // Set tenant GUC (transaction-local)
        sqlx::query("SELECT set_config('soma_audit.tenant_id', $1::text, true)")
            .bind(stamped.tenant_id.to_string())
            .execute(&mut **tx)
            .await?;

        // Acquire per-tenant advisory xact lock (auto-released at tx end)
        let lock_key = tenant_lock_key(stamped.tenant_id);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut **tx)
            .await?;

        // Read current chain head
        let head = sqlx::query_as::<_, (i64, String)>(
            "SELECT seq_num, entry_hash FROM soma_audit.fct_audit_events \
             WHERE tenant_id = $1 ORDER BY seq_num DESC LIMIT 1",
        )
        .bind(stamped.tenant_id)
        .fetch_optional(&mut **tx)
        .await?;

        let (seq_num, prev_hash) = match head {
            Some((last_seq, last_hash)) => (last_seq + 1, Some(last_hash)),
            None => (1_i64, None),
        };

        // Derive per-tenant HMAC key and seal the record
        let hmac_key = self.keys.hmac_key(stamped.tenant_id);
        let id = Uuid::new_v4();
        let created_at = Utc::now();
        let record = soma_audit_core::seal_record(
            &stamped,
            id,
            seq_num,
            prev_hash.as_deref(),
            2,
            created_at,
            &*hmac_key,
        );

        // INSERT with ON CONFLICT DO NOTHING for idempotency
        let rows_affected = sqlx::query(
            "INSERT INTO soma_audit.fct_audit_events \
             (id, tenant_id, seq_num, source_service, event_type, actor_id, actor_role, \
              resource_type, resource_id, outcome, actor_ip, occurred_at, metadata, \
              prev_hash, entry_hash, chain_epoch, idempotency_key, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) \
             ON CONFLICT (idempotency_key) DO NOTHING",
        )
        .bind(record.id)
        .bind(record.event.tenant_id)
        .bind(record.seq_num)
        .bind(&record.event.source_service)
        .bind(&record.event.event_type)
        .bind(record.event.actor_id)
        .bind(&record.event.actor_role)
        .bind(&record.event.resource_type)
        .bind(&record.event.resource_id)
        .bind(outcome_to_str(&record.event.outcome))
        .bind(record.event.actor_ip)
        .bind(record.event.occurred_at)
        .bind(&record.event.metadata)
        .bind(&record.prev_hash)
        .bind(&record.entry_hash)
        .bind(record.chain_epoch)
        .bind(record.event.idempotency_key)
        .bind(record.created_at)
        .execute(&mut **tx)
        .await?
        .rows_affected();

        if rows_affected == 0 {
            // Idempotent: fetch and return existing record
            let row = sqlx::query_as::<_, PgAuditRow>(
                "SELECT id, tenant_id, seq_num, source_service, event_type, actor_id, actor_role, \
                 resource_type, resource_id, outcome, actor_ip, occurred_at, metadata, \
                 prev_hash, entry_hash, chain_epoch, idempotency_key, created_at \
                 FROM soma_audit.fct_audit_events WHERE idempotency_key = $1",
            )
            .bind(stamped.idempotency_key)
            .fetch_one(&mut **tx)
            .await?;
            return row_to_record(row);
        }

        Ok(record)
    }

    /// Record an audit event in its own transaction.
    pub async fn record(&self, event: &AuditEvent) -> Result<AuditRecord, AuditPgError> {
        let mut tx = self.pool.begin().await?;
        let rec = self.record_in_tx(event, &mut tx).await?;
        tx.commit().await?;
        Ok(rec)
    }

    /// List audit events for a tenant, keyset-paginated DESC by seq_num.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        event_type: Option<&str>,
        cursor: Option<i64>,
        limit: i64,
    ) -> Result<(Vec<AuditRecord>, Option<i64>), AuditPgError> {
        let limit = limit.clamp(1, 500);
        let mut tx = self.pool.begin().await?;

        sqlx::query("SELECT set_config('soma_audit.tenant_id', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *tx)
            .await?;

        // Build query dynamically to avoid 4 separate query arms
        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            "SELECT id, tenant_id, seq_num, source_service, event_type, actor_id, actor_role, \
             resource_type, resource_id, outcome, actor_ip, occurred_at, metadata, \
             prev_hash, entry_hash, chain_epoch, idempotency_key, created_at \
             FROM soma_audit.fct_audit_events WHERE tenant_id = ",
        );
        qb.push_bind(tenant_id);

        if let Some(et) = event_type {
            qb.push(" AND event_type = ");
            qb.push_bind(et.to_owned());
        }
        if let Some(cur) = cursor {
            qb.push(" AND seq_num < ");
            qb.push_bind(cur);
        }
        qb.push(" ORDER BY seq_num DESC LIMIT ");
        qb.push_bind(limit + 1);

        let rows: Vec<PgAuditRow> = qb.build_query_as().fetch_all(&mut *tx).await?;
        tx.commit().await?;

        let has_more = rows.len() as i64 > limit;
        let rows_slice = if has_more {
            &rows[..limit as usize]
        } else {
            &rows[..]
        };
        let next_cursor = if has_more {
            rows_slice.last().map(|r| r.seq_num)
        } else {
            None
        };

        let records = rows_slice
            .iter()
            .map(|r| {
                let outcome = outcome_from_str(&r.outcome)?;
                Ok(AuditRecord {
                    id: r.id,
                    seq_num: r.seq_num,
                    prev_hash: r.prev_hash.clone(),
                    entry_hash: r.entry_hash.clone(),
                    chain_epoch: r.chain_epoch,
                    created_at: r.created_at,
                    event: AuditEvent {
                        source_service: r.source_service.clone(),
                        idempotency_key: r.idempotency_key,
                        tenant_id: r.tenant_id,
                        event_type: r.event_type.clone(),
                        actor_id: r.actor_id,
                        actor_role: r.actor_role.clone(),
                        resource_type: r.resource_type.clone(),
                        resource_id: r.resource_id.clone(),
                        outcome,
                        actor_ip: r.actor_ip,
                        occurred_at: r.occurred_at,
                        metadata: r.metadata.clone(),
                    },
                })
            })
            .collect::<Result<Vec<_>, AuditPgError>>()?;

        Ok((records, next_cursor))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Verify the HMAC chain for a tenant's audit log.
    pub async fn verify(&self, tenant_id: Uuid) -> Result<VerifyResult, AuditPgError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("SELECT set_config('soma_audit.tenant_id', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *tx)
            .await?;

        let rows = sqlx::query_as::<_, PgAuditRow>(
            "SELECT id, tenant_id, seq_num, source_service, event_type, actor_id, actor_role, \
             resource_type, resource_id, outcome, actor_ip, occurred_at, metadata, \
             prev_hash, entry_hash, chain_epoch, idempotency_key, created_at \
             FROM soma_audit.fct_audit_events \
             WHERE tenant_id = $1 ORDER BY seq_num ASC",
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;

        tx.commit().await?;

        let records = rows.into_iter().map(row_to_record).collect::<Result<Vec<_>, _>>()?;
        let hmac_key = self.keys.hmac_key(tenant_id);
        Ok(soma_audit_core::verify::verify_chain(&records, &*hmac_key))
    }
}
