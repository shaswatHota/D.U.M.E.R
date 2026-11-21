//! Append-only hash-chained audit logging and redaction helpers.
#![forbid(unsafe_code)]

pub mod chain;
pub mod error;
pub mod event;
pub mod redactor;

pub use chain::AuditChain;
pub use error::AuditError;
pub use event::{compute_event_hash, AuditEvent, AuditEventType};
pub use redactor::Redactor;
