//! Platform adapter error definitions.

use std::path::PathBuf;
use thiserror::Error;

/// Platform adapter errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlatformError {
    #[error("Invalid app id: {0}")]
    InvalidAppId(String),

    #[error("Unregistered application: {0}")]
    UnregisteredApp(String),

    #[error("Executable not found: {0}")]
    ExecutableNotFound(PathBuf),

    #[error("Invalid publisher signature: {0}")]
    InvalidSignature(String),

    #[error("Publisher mismatch: expected '{expected}', got '{actual}'")]
    PublisherMismatch { expected: String, actual: String },

    #[error("Executable hash mismatch")]
    HashMismatch,

    #[error("Disallowed arguments: {0}")]
    DisallowedArguments(String),

    #[error("Workstation session is locked")]
    SessionLocked,

    #[error("Pipe squatting attempt detected: pipe instance already exists")]
    PipeSquattingDetected,

    #[error("Peer verification failed: {0}")]
    PeerVerificationFailed(String),

    #[error("Failed to query process privilege token")]
    PrivilegeCheckFailed,

    #[error("IPC communication error: {0}")]
    IpcError(String),

    #[error("OS platform error: {0}")]
    OsError(String),
}
