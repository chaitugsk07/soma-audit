//! Postgres sink and schema installer for soma-audit.
#![forbid(unsafe_code)]

mod error;
mod install;
mod keys;
mod sink;

pub use error::{AuditPgError, InstallError};
pub use install::install;
pub use keys::AuditKeys;
pub use sink::LocalSink;

pub use soma_audit_core::{AuditEvent, AuditRecord, Outcome, VerifyResult};
