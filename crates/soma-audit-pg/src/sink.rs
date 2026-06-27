use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use serde_json::Value as JsonValue;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use soma_audit_core::{AuditEvent, AuditRecord, ChainCursor, Outcome, VerifyResult};

use crate::error::AuditPgError;
use crate::keys::{tenant_lock_key, AuditKeys};

/// Optional filters for listing audit events.
#[derive(Default)]
pub struct ListFilter<'a> {
    pub event_type: Option<&'a str>,
    pub source_service: Option<&'a str>,
    pub from: Option<DateTime<Utc>>,  // occurred_at >= from
    pub to: Option<DateTime<Utc>>,    // occurred_at <= to
    pub cursor: Option<i64>,          // keyset: seq_num < cursor (DESC)
}

pub struct LocalSink {
    pool: PgPool,
    keys: Arc<AuditKeys>,
    source_service: String,
    fixed_tenant: Option<Uuid>,
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
            fixed_tenant: None,
        }
    }

    /// Convenience constructor for single-tenant embedded use.
    ///
    /// When `record_in_tx` or `record` receives an event whose `tenant_id` is
    /// [`Uuid::nil`], the `tenant_id` is automatically replaced with `tenant_id`.
    /// Use `list_default` and `verify_default` to avoid passing the tenant ID
    /// to every call.
    pub fn new_single_tenant(
        pool: PgPool,
        keys: Arc<AuditKeys>,
        source_service: impl Into<String>,
        tenant_id: Uuid,
    ) -> Self {
        Self {
            pool,
            keys,
            source_service: source_service.into(),
            fixed_tenant: Some(tenant_id),
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
        // For single-tenant sinks: fill in the fixed tenant when the event carries nil.
        if stamped.tenant_id == Uuid::nil() {
            if let Some(ft) = self.fixed_tenant {
                stamped.tenant_id = ft;
            }
        }

        // Defense-in-depth: reject the RS separator (0x1E) in free-text fields.
        // The canonical chain message uses RS as a field delimiter; injecting it
        // into a field value would shift boundaries and allow forging a colliding
        // canonical hash.  The ingest HTTP boundary validates this for remote
        // callers; this check guards the embedded (direct record_in_tx) path.
        let has_rs = |s: &str| s.contains('\u{1e}');
        for field in [
            stamped.source_service.as_str(),
            stamped.event_type.as_str(),
        ] {
            if has_rs(field) {
                return Err(AuditPgError::InvalidField(
                    "field contains forbidden control character (RS 0x1E)".into(),
                ));
            }
        }
        for opt in [
            stamped.actor_role.as_deref(),
            stamped.resource_type.as_deref(),
            stamped.resource_id.as_deref(),
        ] {
            if opt.is_some_and(has_rs) {
                return Err(AuditPgError::InvalidField(
                    "field contains forbidden control character (RS 0x1E)".into(),
                ));
            }
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
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
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

    /// No atomicity guarantee with surrounding business writes — prefer `record_in_tx` when you hold a transaction.
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
        filter: ListFilter<'_>,
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

        if let Some(et) = filter.event_type {
            qb.push(" AND event_type = ");
            qb.push_bind(et.to_owned());
        }
        if let Some(ss) = filter.source_service {
            qb.push(" AND source_service = ");
            qb.push_bind(ss.to_owned());
        }
        if let Some(from) = filter.from {
            qb.push(" AND occurred_at >= ");
            qb.push_bind(from);
        }
        if let Some(to) = filter.to {
            qb.push(" AND occurred_at <= ");
            qb.push_bind(to);
        }
        if let Some(cur) = filter.cursor {
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

    /// `list` using the fixed tenant set on this sink.
    ///
    /// Returns `AuditPgError::Env` if this sink was not constructed with
    /// [`LocalSink::new_single_tenant`].
    pub async fn list_default(
        &self,
        event_type: Option<&str>,
        cursor: Option<i64>,
        limit: i64,
    ) -> Result<(Vec<AuditRecord>, Option<i64>), AuditPgError> {
        let tenant_id = self
            .fixed_tenant
            .ok_or_else(|| AuditPgError::Env("no fixed_tenant set on this LocalSink".into()))?;
        self.list(
            tenant_id,
            ListFilter { event_type, cursor, ..Default::default() },
            limit,
        )
        .await
    }

    /// List events across ALL tenants (central admin fleet view).
    ///
    /// Uses RLS bypass (`SET LOCAL soma_audit.bypass = 'on'`).
    /// Ordered by `occurred_at DESC, id DESC`. Cursor is the `id` of the last
    /// returned row encoded as `i64` via `uuid_to_i64_cursor` (not meaningful
    /// as a number — treat as opaque). Actually simpler: use `seq_num` isn't
    /// globally unique per tenant, but `id` (UUID) can't be used as i64.
    ///
    /// We use `occurred_at` in microseconds as the cursor (i64). The cursor
    /// returned is the `occurred_at` of the last row in micros since epoch.
    /// On the next page: `AND occurred_at < cursor_dt OR (occurred_at = cursor_dt AND id < cursor_id)`.
    /// To keep it simple and match the existing i64 cursor convention, we use
    /// a row-number / offset-free approach: cursor = micros of `occurred_at`
    /// of last row, filter `AND occurred_at <= cursor AND id < last_id`.
    ///
    /// Simplest viable: order by `occurred_at DESC`, cursor is `occurred_at`
    /// micros. Use strict less-than for next page (may skip ties, acceptable).
    pub async fn list_global(
        &self,
        filter: ListFilter<'_>,
        limit: i64,
    ) -> Result<(Vec<AuditRecord>, Option<i64>), AuditPgError> {
        let limit = limit.clamp(1, 500);
        let mut tx = self.pool.begin().await?;

        sqlx::query("SET LOCAL soma_audit.bypass = 'on'")
            .execute(&mut *tx)
            .await?;

        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            "SELECT id, tenant_id, seq_num, source_service, event_type, actor_id, actor_role, \
             resource_type, resource_id, outcome, actor_ip, occurred_at, metadata, \
             prev_hash, entry_hash, chain_epoch, idempotency_key, created_at \
             FROM soma_audit.fct_audit_events WHERE true",
        );

        if let Some(et) = filter.event_type {
            qb.push(" AND event_type = ");
            qb.push_bind(et.to_owned());
        }
        if let Some(ss) = filter.source_service {
            qb.push(" AND source_service = ");
            qb.push_bind(ss.to_owned());
        }
        if let Some(from) = filter.from {
            qb.push(" AND occurred_at >= ");
            qb.push_bind(from);
        }
        if let Some(to) = filter.to {
            qb.push(" AND occurred_at <= ");
            qb.push_bind(to);
        }
        // Cursor for global: occurred_at in microseconds since epoch (i64).
        // Next page uses strict less-than on occurred_at.
        if let Some(cur_micros) = filter.cursor {
            let cursor_dt = DateTime::<Utc>::from_timestamp_micros(cur_micros)
                .unwrap_or(DateTime::<Utc>::from_timestamp(0, 0).unwrap());
            qb.push(" AND occurred_at < ");
            qb.push_bind(cursor_dt);
        }

        qb.push(" ORDER BY occurred_at DESC, id DESC LIMIT ");
        qb.push_bind(limit + 1);

        let rows: Vec<PgAuditRow> = qb.build_query_as().fetch_all(&mut *tx).await?;
        tx.commit().await?;

        let has_more = rows.len() as i64 > limit;
        let rows_slice = if has_more { &rows[..limit as usize] } else { &rows[..] };
        let next_cursor = if has_more {
            rows_slice.last().map(|r| r.occurred_at.timestamp_micros())
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

    /// `verify` using the fixed tenant set on this sink.
    ///
    /// Returns `AuditPgError::Env` if this sink was not constructed with
    /// [`LocalSink::new_single_tenant`].
    pub async fn verify_default(&self) -> Result<VerifyResult, AuditPgError> {
        let tenant_id = self
            .fixed_tenant
            .ok_or_else(|| AuditPgError::Env("no fixed_tenant set on this LocalSink".into()))?;
        self.verify(tenant_id).await
    }

    /// Verify the HMAC chain for a tenant's audit log.
    ///
    /// Streams rows in `seq_num ASC` order and verifies incrementally, carrying
    /// only the previous `(seq_num, entry_hash)` between rows.  This keeps
    /// memory consumption O(1) regardless of the number of audit entries.
    pub async fn verify(&self, tenant_id: Uuid) -> Result<VerifyResult, AuditPgError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("SELECT set_config('soma_audit.tenant_id', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *tx)
            .await?;

        let hmac_key = self.keys.hmac_key(tenant_id);
        let mut stream = sqlx::query_as::<_, PgAuditRow>(
            "SELECT id, tenant_id, seq_num, source_service, event_type, actor_id, actor_role, \
             resource_type, resource_id, outcome, actor_ip, occurred_at, metadata, \
             prev_hash, entry_hash, chain_epoch, idempotency_key, created_at \
             FROM soma_audit.fct_audit_events \
             WHERE tenant_id = $1 ORDER BY seq_num ASC",
        )
        .bind(tenant_id)
        .fetch(&mut *tx);

        let mut entries_checked: u64 = 0;
        let mut cursor: Option<ChainCursor> = None;

        while let Some(row) = stream.try_next().await? {
            let record = row_to_record(row)?;
            match soma_audit_core::verify::verify_record(&record, cursor.as_ref(), &*hmac_key) {
                Ok(()) => {}
                Err(seq) => {
                    drop(stream);
                    tx.commit().await?;
                    return Ok(VerifyResult {
                        ok: false,
                        entries_checked,
                        first_broken_seq: Some(seq),
                    });
                }
            }
            cursor = Some(ChainCursor {
                seq_num: record.seq_num,
                entry_hash: record.entry_hash,
            });
            entries_checked += 1;
        }

        drop(stream);
        tx.commit().await?;

        Ok(VerifyResult {
            ok: true,
            entries_checked,
            first_broken_seq: None,
        })
    }
}
