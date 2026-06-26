use thiserror::Error;

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("schema migration failed: {0}")]
    Schema(soma_schema::Error),
    #[error("environment variable error: {0}")]
    Env(String),
}

#[derive(Debug, Error)]
pub enum AuditPgError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("audit core error: {0}")]
    Core(#[from] soma_audit_core::AuditError),
    #[error("environment variable error: {0}")]
    Env(String),
}
