use std::sync::Arc;

use axum::{
    extract::{Query, Request, State},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{auth::check_admin_auth, error::ApiError, state::AppState};

const SEAL_INTERVAL_SECS: u64 = 60;

pub async fn run_seal_sweep(state: Arc<AppState>, pool: PgPool) {
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(SEAL_INTERVAL_SECS));
    loop {
        interval.tick().await;
        if let Err(e) = sweep_once(&state, &pool).await {
            tracing::error!("seal sweep error: {e}");
        }
    }
}

async fn sweep_once(state: &AppState, pool: &PgPool) -> anyhow::Result<()> {
    let tenants: Vec<(Uuid, i64, String)> = sqlx::query_as(
        r#"
        SELECT e.tenant_id, MAX(e.seq_num) AS up_to_seq, MAX(e.entry_hash) AS chain_head_hash
        FROM soma_audit.fct_audit_events e
        WHERE NOT EXISTS (
            SELECT 1 FROM soma_audit.audit_chain_seals s
            WHERE s.tenant_id = e.tenant_id AND s.up_to_seq_num >= e.seq_num
        )
        GROUP BY e.tenant_id
        "#,
    )
    .fetch_all(pool)
    .await?;

    for (tenant_id, up_to_seq, chain_head_hash) in tenants {
        let sealed_at = Utc::now();
        let sealed_at_unix = sealed_at.timestamp();

        let payload = format!(
            "soma-audit-seal-v1\x1e{tenant_id}\x1e{up_to_seq}\x1e{chain_head_hash}\x1e{sealed_at_unix}"
        );

        let signature = state.keys.sign_seal(payload.as_bytes());
        let public_key_bytes = state.keys.verifying_key().to_bytes();
        // Use base64url of first 6 bytes as short ID (no hex dep)
        let public_key_id = format!("b64:{}", URL_SAFE_NO_PAD.encode(&public_key_bytes[..6]));

        sqlx::query(
            r#"
            INSERT INTO soma_audit.audit_chain_seals
                (id, tenant_id, up_to_seq_num, chain_head_hash, sealed_at, signature, public_key_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(up_to_seq)
        .bind(&chain_head_hash)
        .bind(sealed_at)
        .bind(&signature)
        .bind(&public_key_id)
        .execute(pool)
        .await?;

        tracing::info!(%tenant_id, up_to_seq, "sealed audit chain");
    }

    Ok(())
}

// ── HTTP handler for listing seals ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SealsParams {
    pub tenant_id: Uuid,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SealRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub up_to_seq_num: i64,
    pub chain_head_hash: String,
    pub sealed_at: DateTime<Utc>,
    pub public_key_id: String,
}

#[derive(Serialize)]
pub struct SealsResponse {
    pub items: Vec<SealRecord>,
}

pub async fn list_seals(
    State(state): State<AppState>,
    Query(params): Query<SealsParams>,
    req: Request,
) -> Result<Json<SealsResponse>, ApiError> {
    check_admin_auth(&state, &req)?;

    let items: Vec<SealRecord> = sqlx::query_as(
        r#"
        SELECT id, tenant_id, up_to_seq_num, chain_head_hash, sealed_at, public_key_id
        FROM soma_audit.audit_chain_seals
        WHERE tenant_id = $1
        ORDER BY up_to_seq_num DESC
        LIMIT 100
        "#,
    )
    .bind(params.tenant_id)
    .fetch_all(state.sink.pool())
    .await
    .map_err(|e| {
        tracing::error!("list seals error: {e}");
        ApiError::Internal
    })?;

    Ok(Json(SealsResponse { items }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soma_audit_core::verify_seal;
    use soma_audit_pg::AuditKeys;

    #[test]
    fn seal_payload_roundtrip() {
        let master = [1u8; 32];
        let signing = [2u8; 32];
        let keys = AuditKeys::from_secret(master, signing);

        let tenant_id = Uuid::new_v4();
        let up_to_seq: i64 = 42;
        let chain_head_hash = "abc123def456";
        let sealed_at_unix: i64 = 1_700_000_000;

        let payload = format!(
            "soma-audit-seal-v1\x1e{tenant_id}\x1e{up_to_seq}\x1e{chain_head_hash}\x1e{sealed_at_unix}"
        );

        let sig = keys.sign_seal(payload.as_bytes());
        assert!(verify_seal(&keys.verifying_key(), payload.as_bytes(), &sig));
    }
}
