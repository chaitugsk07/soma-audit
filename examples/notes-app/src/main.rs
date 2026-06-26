//! # notes-app — soma-audit integration demo
//!
//! A minimal multi-tenant "notes" API that shows how any Rust/axum app can add
//! tamper-evident, cryptographically-chained audit logging in three lines of
//! startup code and one call per operation.
//!
//! ## The three lines that add audit to any app
//!
//! ```rust,ignore
//! soma_audit_pg::install(&pool).await?;                              // 1
//! let keys  = AuditKeys::from_env().unwrap_or_else(|_| demo_keys()); // 2
//! let sink  = Arc::new(LocalSink::new(pool.clone(), Arc::new(keys), "notes-app")); // 3
//! ```
//!
//! After that, wrap privileged writes in a transaction and call
//! `sink.record_in_tx(&event, &mut tx)` — the note and its audit record commit
//! together or not at all.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

// Pull the three audit types from the pg crate — no need for soma-audit-core
// directly because soma-audit-pg re-exports them.
use soma_audit_pg::{AuditEvent, AuditKeys, LocalSink, Outcome};

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    sink: Arc<LocalSink>,
}

// ---------------------------------------------------------------------------
// Domain model
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, sqlx::FromRow)]
struct Note {
    id: Uuid,
    tenant_id: Uuid,
    title: String,
    body: String,
    created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Request / response shapes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateNoteRequest {
    tenant_id: Uuid,
    actor_id: Uuid,
    title: String,
    body: String,
}

#[derive(Deserialize)]
struct TenantActorQuery {
    tenant_id: Uuid,
    actor_id: Uuid,
}

#[derive(Deserialize)]
struct TenantQuery {
    tenant_id: Uuid,
}

// ---------------------------------------------------------------------------
// Audit helper
//
// Builds an AuditEvent from the fields the call site already knows.
// Idempotency key and timestamp are set here so callers don't have to think
// about them.  source_service is left empty — the LocalSink stamps "notes-app"
// automatically when it sees an empty string.
//
// In a real app you'd use a builder; this local helper keeps the demo
// dependency-free.
// ---------------------------------------------------------------------------

fn audit_event(
    tenant_id: Uuid,
    actor_id: Option<Uuid>,
    event_type: impl Into<String>,
    resource_type: impl Into<String>,
    resource_id: impl Into<String>,
    outcome: Outcome,
) -> AuditEvent {
    AuditEvent {
        source_service: String::new(), // sink fills in "notes-app"
        idempotency_key: Uuid::new_v4(),
        tenant_id,
        event_type: event_type.into(),
        actor_id,
        actor_role: None,
        resource_type: Some(resource_type.into()),
        resource_id: Some(resource_id.into()),
        outcome,
        actor_ip: None,
        occurred_at: Utc::now(),
        metadata: json!({}),
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!(err = %self.0, "request error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /notes
///
/// The headline operation: the note INSERT and the audit record are wrapped in
/// a single Postgres transaction.  They commit together or not at all.
async fn create_note(
    State(state): State<AppState>,
    Json(req): Json<CreateNoteRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let note_id = Uuid::new_v4();

    // Begin a transaction — business write + audit write share this tx.
    let mut tx = state.pool.begin().await?;

    // 1. Insert the note (the app's normal business logic).
    sqlx::query(
        "INSERT INTO demo.notes (id, tenant_id, title, body) VALUES ($1, $2, $3, $4)",
    )
    .bind(note_id)
    .bind(req.tenant_id)
    .bind(&req.title)
    .bind(&req.body)
    .execute(&mut *tx)
    .await
    .context("insert note")?;

    // 2. Record the audit event INSIDE the same transaction.
    //    The note and its audit record commit together or not at all.
    let event = audit_event(
        req.tenant_id,
        Some(req.actor_id),
        "note.create",
        "note",
        note_id.to_string(),
        Outcome::Success,
    );
    state
        .sink
        .record_in_tx(&event, &mut tx)
        .await
        .context("audit record_in_tx")?;

    // 3. A single COMMIT makes both writes permanent simultaneously.
    tx.commit().await.context("commit")?;

    info!(note_id = %note_id, tenant = %req.tenant_id, "note created + audited");

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id":         note_id,
            "tenant_id":  req.tenant_id,
            "title":      req.title,
            "body":       req.body,
        })),
    ))
}

/// DELETE /notes/:id?tenant_id=&actor_id=
///
/// Deletes a note.  If the note exists, the delete and its audit event commit
/// together.  If the note isn't found, we record a Denied event via record()
/// (weaker guarantee: committed in its own transaction).
async fn delete_note(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantActorQuery>,
) -> Result<Json<Value>, AppError> {
    let mut tx = state.pool.begin().await?;

    let rows_affected = sqlx::query(
        "DELETE FROM demo.notes WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(q.tenant_id)
    .execute(&mut *tx)
    .await
    .context("delete note")?
    .rows_affected();

    if rows_affected == 0 {
        tx.rollback().await.ok();

        // Note not found — record a Denied event outside the (rolled-back) tx.
        // This uses the weaker record() path: committed in its own transaction,
        // so the audit event itself always lands even though there was nothing to delete.
        let event = audit_event(
            q.tenant_id,
            Some(q.actor_id),
            "note.delete",
            "note",
            id.to_string(),
            Outcome::Denied,
        );
        state.sink.record(&event).await.context("audit denied")?;

        return Ok(Json(json!({ "deleted": false, "reason": "not found" })));
    }

    // Note existed — audit and delete commit together.
    let event = audit_event(
        q.tenant_id,
        Some(q.actor_id),
        "note.delete",
        "note",
        id.to_string(),
        Outcome::Success,
    );
    state
        .sink
        .record_in_tx(&event, &mut tx)
        .await
        .context("audit record_in_tx")?;

    tx.commit().await.context("commit")?;
    info!(note_id = %id, tenant = %q.tenant_id, "note deleted + audited");

    Ok(Json(json!({ "deleted": true })))
}

/// GET /notes?tenant_id=
///
/// List notes for a tenant.  Optionally audit via record() to show the
/// non-transactional path — weaker guarantee (audit fires after the SELECT).
async fn list_notes(
    State(state): State<AppState>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<Value>, AppError> {
    let notes = sqlx::query_as::<_, Note>(
        "SELECT id, tenant_id, title, body, created_at FROM demo.notes WHERE tenant_id = $1 ORDER BY created_at DESC",
    )
    .bind(q.tenant_id)
    .fetch_all(&state.pool)
    .await
    .context("list notes")?;

    // Audit the read via record() — the non-tx path.
    // The SELECT already completed; this audit commit is a best-effort append.
    // Contrast with record_in_tx() on writes where the guarantee is atomic.
    let event = audit_event(
        q.tenant_id,
        None,
        "note.read",
        "note",
        "all",
        Outcome::Success,
    );
    if let Err(e) = state.sink.record(&event).await {
        // Non-fatal: the read succeeded even if the audit event failed.
        warn!(err = %e, "failed to record note.read audit event");
    }

    Ok(Json(json!({ "notes": notes, "count": notes.len() })))
}

/// GET /audit?tenant_id=
///
/// Return the audit trail for the tenant — useful for inspecting what was
/// recorded without needing the central soma-audit portal.
async fn list_audit(
    State(state): State<AppState>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<Value>, AppError> {
    let (records, next_cursor) = state
        .sink
        .list(q.tenant_id, None, None, 50)
        .await
        .context("list audit")?;

    Ok(Json(json!({
        "tenant_id":   q.tenant_id,
        "count":       records.len(),
        "next_cursor": next_cursor,
        "events":      records,
    })))
}

/// GET /audit/verify?tenant_id=
///
/// Verify the HMAC chain for the tenant's audit log.
/// ok:true means every record is intact; ok:false reports the first broken seq_num.
async fn verify_audit(
    State(state): State<AppState>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<Value>, AppError> {
    let result = state
        .sink
        .verify(q.tenant_id)
        .await
        .context("verify audit chain")?;

    Ok(Json(json!({
        "tenant_id":        q.tenant_id,
        "ok":               result.ok,
        "entries_checked":  result.entries_checked,
        "first_broken_seq": result.first_broken_seq,
    })))
}

/// GET /health
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

// ---------------------------------------------------------------------------
// Demo keys — used when env vars are absent (zero env-setup for quick demos)
// ---------------------------------------------------------------------------

fn demo_keys() -> AuditKeys {
    // Fixed 32-byte arrays — obviously not secret, for demo use only.
    // In production, load these from SOMA_AUDIT_MASTER_SECRET and
    // SOMA_AUDIT_SIGNING_KEY (64-char hex strings).
    let master:  [u8; 32] = *b"notes-app-demo-master-secret-key";
    let signing: [u8; 32] = *b"notes-app-demo-signing-key-bytes";
    AuditKeys::from_secret(master, signing)
}

// ---------------------------------------------------------------------------
// Boot sequence
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "notes_app=info,soma_audit_pg=info".parse().unwrap()),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://soma:soma@localhost:5432/soma_audit_test".into());

    let bind_addr: SocketAddr = std::env::var("BIND")
        .unwrap_or_else(|_| "127.0.0.1:8090".into())
        .parse()
        .context("invalid BIND address")?;

    // -----------------------------------------------------------------------
    // Step 1: Connect a single PgPool shared by the app AND soma-audit.
    //         The pool needs max_connections >= 2 (advisory lock uses one
    //         connection; at least one more is needed for queries).
    // -----------------------------------------------------------------------
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .context("connect to Postgres")?;

    info!("connected to Postgres");

    // -----------------------------------------------------------------------
    // Step 2: Create the app's own schema/table on boot.
    //         This is normal app startup — nothing audit-specific yet.
    // -----------------------------------------------------------------------
    sqlx::query("CREATE SCHEMA IF NOT EXISTS demo").execute(&pool).await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS demo.notes (
            id         uuid        PRIMARY KEY,
            tenant_id  uuid        NOT NULL,
            title      text        NOT NULL,
            body       text        NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        )",
    )
    .execute(&pool)
    .await
    .context("create demo.notes")?;

    info!("demo schema ready");

    // -----------------------------------------------------------------------
    // *** THE THREE LINES THAT ADD SOMA-AUDIT TO ANY APP ***
    //
    // Line 1 — soma_audit_pg::install(&pool).await?
    //   Runs soma-audit's bundled migrations via soma-schema.
    //   Creates the soma_audit schema, tables, append-only triggers, and RLS.
    //   Idempotent: safe to call on every startup.
    //   Uses advisory lock key 6020250626000001 so it never conflicts with
    //   your own migrations or other services sharing the same database.
    //   The demo schema (above) and soma_audit schema coexist in one database.
    // -----------------------------------------------------------------------
    soma_audit_pg::install(&pool).await.context("soma-audit install")?;
    info!("soma-audit installed");

    // -----------------------------------------------------------------------
    // Line 2 — AuditKeys
    //   Prefer env vars (production path); fall back to hardcoded demo keys.
    //   The demo keys let this example run with zero environment setup.
    // -----------------------------------------------------------------------
    let keys = match AuditKeys::from_env() {
        Ok(k) => {
            info!("AuditKeys loaded from environment");
            k
        }
        Err(_) => {
            warn!(
                "SOMA_AUDIT_MASTER_SECRET / SOMA_AUDIT_SIGNING_KEY not set — \
                 using hardcoded DEMO keys. Do NOT use this in production."
            );
            demo_keys()
        }
    };

    // -----------------------------------------------------------------------
    // Line 3 — LocalSink
    //   Wraps the pool + keys.  source_service="notes-app" is stamped on every
    //   audit record that doesn't supply its own service name.
    // -----------------------------------------------------------------------
    let sink = Arc::new(LocalSink::new(pool.clone(), Arc::new(keys), "notes-app"));

    // -----------------------------------------------------------------------
    // Build the router and wire state.
    // -----------------------------------------------------------------------
    let state = AppState { pool, sink };

    let app = Router::new()
        .route("/health",         get(health))
        .route("/notes",          post(create_note))
        .route("/notes",          get(list_notes))
        .route("/notes/{id}",     delete(delete_note))
        .route("/audit",          get(list_audit))
        .route("/audit/verify",   get(verify_audit))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind {bind_addr}"))?;

    info!(%bind_addr, "notes-app listening");
    axum::serve(listener, app).await?;

    Ok(())
}
