use axum::extract::Request;

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

/// Check ingest bearer token.
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
