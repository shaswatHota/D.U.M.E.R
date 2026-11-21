//! Error types for audit logging and hash chaining.
#![forbid(unsafe_code)]

use thiserror::Error;

/// Audit logging and verification errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    /// Audit chain verification failed due to data tampering or sequence break.
    #[error("Audit chain integrity violation at sequence {seq}: {reason}")]
    ChainTampered { seq: u64, reason: String },

    /// Serialization error during event hashing or persistence.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// File I/O error during persistence or recovery.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for AuditError {
    fn from(err: std::io::Error) -> Self {
        AuditError::Io(err.to_string())
    }
}
