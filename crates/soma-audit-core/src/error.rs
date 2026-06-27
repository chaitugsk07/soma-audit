use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid Ed25519 signature")]
    InvalidSignature,

    #[error("chain error: {0}")]
    Chain(String),
}

pub type Result<T> = std::result::Result<T, AuditError>;
