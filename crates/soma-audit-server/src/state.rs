use std::sync::Arc;

use soma_audit_pg::{AuditKeys, LocalSink};

#[derive(Clone)]
pub struct AppState {
    pub sink: Arc<LocalSink>,
    pub keys: Arc<AuditKeys>,
    pub ingest_secret: String,
    pub admin_token: String,
}
