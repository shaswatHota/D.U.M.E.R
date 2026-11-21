use dumer_crypto::CryptoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Vault is locked: explicit user-verification unlock required")]
    VaultLocked,

    #[error("Vault item '{0}' not found")]
    ItemNotFound(String),

    #[error("Record '{0}' has expired")]
    Expired(String),

    #[error("Destination '{destination}' is not in the allowlist for item '{item}' (allowed: {allowed:?})")]
    DestinationNotAllowed {
        item: String,
        destination: String,
        allowed: Vec<String>,
    },

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Export error: {0}")]
    ExportError(String),

    #[error("Canary violation tripped: token '{0}' detected in output")]
    CanaryTripped(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("General vault error: {0}")]
    General(String),
}
