//! Async API helpers for the soma-audit admin portal.
//! All endpoints require `Authorization: Bearer <token>` except /health.
//! The admin token is passed in as a parameter rather than stored globally —
//! callers read it from the app-level signal.

use serde::de::DeserializeOwned;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (HTTP {})", self.message, self.status)
    }
}

async fn handle_response<T: DeserializeOwned>(
    resp: gloo_net::http::Response,
) -> Result<T, ApiError> {
    let status = resp.status();
    if !resp.ok() {
        let body = resp.text().await.unwrap_or_default();
        let msg = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or(body);
        return Err(ApiError {
            status,
            message: msg,
        });
    }
    resp.json::<T>().await.map_err(|e| ApiError {
        status,
        message: e.to_string(),
    })
}

async fn get_json<T: DeserializeOwned>(path: &str, token: &str) -> Result<T, ApiError> {
    let resp = gloo_net::http::Request::get(path)
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?;
    handle_response(resp).await
}

// ── Domain types ──────────────────────────────────────────────────────────────

/// Pagination envelope returned by list endpoints.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<i64>,
}

/// Full audit record as returned by GET /v1/audit.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AuditRecord {
    pub id: String,
    pub tenant_id: String,
    pub seq_num: i64,
    pub source_service: String,
    pub event_type: String,
    pub actor_id: Option<String>,
    pub actor_role: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub actor_ip: Option<String>,
    pub occurred_at: String,
    pub metadata: serde_json::Value,
    pub prev_hash: Option<String>,
    pub entry_hash: String,
    pub chain_epoch: i64,
    pub created_at: String,
}

/// Result of GET /v1/audit/verify.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct VerifyResult {
    pub ok: bool,
    pub entries_checked: i64,
    pub first_broken_seq: Option<i64>,
}

/// One seal record from GET /v1/audit/seals.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SealRecord {
    pub id: String,
    pub up_to_seq_num: i64,
    pub chain_head_hash: String,
    pub sealed_at: String,
    pub public_key_id: String,
}

/// One Ed25519 public key from GET /v1/audit/keys.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PublicKey {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub x: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct KeysResponse {
    pub keys: Vec<PublicKey>,
}

// ── API functions ─────────────────────────────────────────────────────────────

/// Check server health. No auth required.
pub async fn get_health() -> bool {
    gloo_net::http::Request::get("/health")
        .send()
        .await
        .map(|r| r.ok())
        .unwrap_or(false)
}

/// GET /v1/audit — list audit records for a tenant.
/// Wired filters: tenant_id (required), event_type, source_service, from, to, cursor, limit.
pub async fn get_audit(
    token: &str,
    tenant_id: &str,
    event_type: Option<&str>,
    source_service: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    cursor: Option<i64>,
    limit: u32,
) -> Result<Page<AuditRecord>, ApiError> {
    let mut url = format!("/v1/audit?tenant_id={}&limit={}", tenant_id, limit);
    if let Some(et) = event_type {
        if !et.is_empty() {
            url.push_str(&format!("&event_type={}", et));
        }
    }
    if let Some(ss) = source_service {
        if !ss.is_empty() {
            url.push_str(&format!("&source_service={}", ss));
        }
    }
    if let Some(f) = from {
        if !f.is_empty() {
            url.push_str(&format!("&from={}", f));
        }
    }
    if let Some(t) = to {
        if !t.is_empty() {
            url.push_str(&format!("&to={}", t));
        }
    }
    if let Some(c) = cursor {
        url.push_str(&format!("&cursor={}", c));
    }
    get_json::<Page<AuditRecord>>(&url, token).await
}

/// GET /v1/audit/global — list audit records across all tenants (admin fleet view).
pub async fn get_audit_global(
    token: &str,
    event_type: Option<&str>,
    source_service: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    cursor: Option<i64>,
    limit: u32,
) -> Result<Page<AuditRecord>, ApiError> {
    let mut url = format!("/v1/audit/global?limit={}", limit);
    if let Some(et) = event_type {
        if !et.is_empty() {
            url.push_str(&format!("&event_type={}", et));
        }
    }
    if let Some(ss) = source_service {
        if !ss.is_empty() {
            url.push_str(&format!("&source_service={}", ss));
        }
    }
    if let Some(f) = from {
        if !f.is_empty() {
            url.push_str(&format!("&from={}", f));
        }
    }
    if let Some(t) = to {
        if !t.is_empty() {
            url.push_str(&format!("&to={}", t));
        }
    }
    if let Some(c) = cursor {
        url.push_str(&format!("&cursor={}", c));
    }
    get_json::<Page<AuditRecord>>(&url, token).await
}

/// GET /v1/audit/verify — walk the chain for a tenant and check hashes.
/// For large chains this is a full sequential walk; a progress UX is a future improvement.
pub async fn verify_chain(token: &str, tenant_id: &str) -> Result<VerifyResult, ApiError> {
    let url = format!("/v1/audit/verify?tenant_id={}", tenant_id);
    get_json::<VerifyResult>(&url, token).await
}

/// GET /v1/audit/seals — list chain seals for a tenant.
pub async fn get_seals(
    token: &str,
    tenant_id: &str,
    cursor: Option<i64>,
) -> Result<Page<SealRecord>, ApiError> {
    let mut url = format!("/v1/audit/seals?tenant_id={}", tenant_id);
    if let Some(c) = cursor {
        url.push_str(&format!("&cursor={}", c));
    }
    get_json::<Page<SealRecord>>(&url, token).await
}

/// GET /v1/audit/keys — list public signing keys.
pub async fn get_keys(token: &str) -> Result<KeysResponse, ApiError> {
    get_json::<KeysResponse>("/v1/audit/keys", token).await
}

/// Source record from GET /v1/sources.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SourceRecord {
    pub source_service: String,
    pub tenant_id: String,
    pub host_url: Option<String>,
    pub version: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub event_count: i64,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SourcesResponse {
    pub sources: Vec<SourceRecord>,
}

/// GET /v1/sources — list all source services.
pub async fn get_sources(token: &str) -> Result<Vec<SourceRecord>, ApiError> {
    let resp = get_json::<SourcesResponse>("/v1/sources", token).await?;
    Ok(resp.sources)
}
