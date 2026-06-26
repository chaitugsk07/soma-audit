use axum::extract::Request;

use crate::{error::ApiError, state::AppState};

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
        Some(tok) if tok == state.ingest_secret => Ok(()),
        _ => Err(ApiError::Unauthorized),
    }
}

/// Check admin bearer token.
pub fn check_admin_auth(state: &AppState, req: &Request) -> Result<(), ApiError> {
    match extract_bearer(req) {
        Some(tok) if tok == state.admin_token => Ok(()),
        _ => Err(ApiError::Unauthorized),
    }
}
