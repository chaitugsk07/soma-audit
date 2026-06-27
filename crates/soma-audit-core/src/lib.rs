//! `soma-audit-core` — pure, zero-IO foundation of the soma-audit library.
//!
//! This crate owns:
//! - Event types and the stored record type ([`AuditEvent`], [`AuditRecord`])
//! - Canonical serialization and HMAC-SHA256 hash-chain math ([`chain`])
//! - Per-tenant HMAC key derivation via HKDF-SHA256 ([`keys`])
//! - Hash-chain integrity verification ([`verify`])
//! - Ed25519 sign/verify primitives ([`seal`])
//! - Crate error type ([`AuditError`])
//!
//! No sqlx, no axum, no tokio, no network or file IO.

#![forbid(unsafe_code)]

pub mod chain;
pub mod error;
pub mod event;
pub mod keys;
pub mod seal;
pub mod verify;

// Public API re-exports
pub use error::{AuditError, Result};
pub use event::{AuditEvent, AuditRecord, Outcome};
pub use verify::{ChainCursor, VerifyResult};

pub use chain::{canonical_msg, compute_entry_hash, seal_record};
pub use keys::derive_tenant_hmac_key;
pub use seal::{sign_seal, verify_seal};
