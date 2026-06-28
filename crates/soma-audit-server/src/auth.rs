use axum::extract::Request;
use uuid::Uuid;

use crate::{error::ApiError, state::AppState};

/// Constant-time string equality to prevent timing-oracle attacks on bearer
/// tokens.  Length difference is not secret; `ct_eq` from `subtle` requires
/// equal-length slices, so we guard that first.
fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Extract bearer token from Authorization header.
pub fn extract_bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Identity established after ingest authentication.
pub enum IngestIdentity {
    /// Authenticated with the shared master ingest secret.
    Master,
    /// Authenticated with a per-source key bound to a specific service/tenant.
    Source {
        source_service: String,
        tenant_id: Uuid,
    },
}

/// Authenticate an ingest request.
///
/// - Master secret (constant-time compare): returns `IngestIdentity::Master`.
/// - Per-source key (SHA-256 hash lookup): returns `IngestIdentity::Source`.
/// - Otherwise: `ApiError::Unauthorized`.
///
/// Takes the bearer token as an owned `String` and a clone of `AppState` so
/// the returned future is `'static` (required by axum's `Handler` trait).
pub async fn authenticate_ingest(
    state: AppState,
    token: Option<String>,
) -> Result<IngestIdentity, ApiError> {
    let token = token.ok_or(ApiError::Unauthorized)?;

    // Fast path: master secret (constant-time compare).
    if ct_eq(&token, &state.ingest_secret) {
        return Ok(IngestIdentity::Master);
    }

    // Slow path: per-source key — hash and look up in DB.
    let hash = soma_infra::crypto::sha256_hex(token.as_bytes());

    let row: Option<(String, Uuid)> = sqlx::query_as(
        "SELECT source_service, tenant_id \
         FROM soma_audit.source_keys \
         WHERE key_hash = $1 AND revoked_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(state.sink.pool())
    .await
    .map_err(|e| {
        tracing::error!("source_keys lookup failed: {e}");
        ApiError::Internal
    })?;

    match row {
        Some((source_service, tenant_id)) => Ok(IngestIdentity::Source {
            source_service,
            tenant_id,
        }),
        None => Err(ApiError::Unauthorized),
    }
}

/// Check ingest bearer token (master secret only — backwards compat).
pub fn check_ingest_auth(state: &AppState, req: &Request) -> Result<(), ApiError> {
    match extract_bearer(req) {
        Some(tok) if ct_eq(tok, &state.ingest_secret) => Ok(()),
        _ => Err(ApiError::Unauthorized),
    }
}

/// Check admin bearer token.
pub fn check_admin_auth(state: &AppState, req: &Request) -> Result<(), ApiError> {
    match extract_bearer(req) {
        Some(tok) if ct_eq(tok, &state.admin_token) => Ok(()),
        _ => Err(ApiError::Unauthorized),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn ct_eq_equal_strings() {
        assert!(ct_eq("secret-token", "secret-token"));
    }

    #[test]
    fn ct_eq_different_content_same_len() {
        assert!(!ct_eq("secret-token", "secret-AAAAA"));
    }

    #[test]
    fn ct_eq_different_lengths() {
        assert!(!ct_eq("short", "longer-token"));
    }

    #[test]
    fn ct_eq_empty_strings() {
        assert!(ct_eq("", ""));
    }

    #[test]
    fn ct_eq_one_empty() {
        assert!(!ct_eq("", "nonempty"));
    }
}
