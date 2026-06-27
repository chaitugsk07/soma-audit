//! `soma-audit-client` — Remote sink for the soma-audit library.
//!
//! Lets a host application forward audit events to a central `soma-audit-server`
//! **without losing events when the server is temporarily down**, via a durable
//! local outbox stored in the host's own Postgres database plus a background
//! relay task.
//!
//! ## How it works
//!
//! 1. The host calls [`install_outbox`] at startup to migrate the outbox schema
//!    into its own Postgres database.
//! 2. On each auditable action the host calls [`RemoteSink::enqueue_in_tx`]
//!    (inside its business transaction) so the outbox row commits atomically
//!    with the business write — the durability-preserving path.
//! 3. [`spawn_relay`] runs a background task that polls the outbox and POSTs
//!    undelivered rows to the central server.  Rows are marked delivered only
//!    after the server acknowledges them (HTTP 2xx or 409).
//!
//! ## Durability guarantee
//!
//! The local outbox row is the durability anchor.  A committed business action
//! always has a corresponding pending outbox row (when [`RemoteSink::enqueue_in_tx`]
//! is used).  The central server outage cannot cause event loss; it only increases
//! relay latency.
#![forbid(unsafe_code)]

mod error;
mod outbox;
mod relay;

pub use error::ClientError;
pub use outbox::{install_outbox, RemoteSink};
pub use relay::{spawn_relay, RelayConfig, SourceRegistration};

// Re-export core types so consumers only need one dependency.
pub use soma_audit_core::{AuditEvent, Outcome};
