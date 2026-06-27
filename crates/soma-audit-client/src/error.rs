use thiserror::Error;

/// Errors produced by the soma-audit-client crate.
#[derive(Debug, Error)]
pub enum ClientError {
    /// A database operation failed.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    /// Schema migration failed.
    #[error("schema migration failed: {0}")]
    Schema(soma_schema::Error),

    /// An HTTP request to the central server failed.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// Serializing the event payload failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
