use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("AEAD encryption/decryption error: {0}")]
    Aead(String),

    #[error("Decryption failed: ciphertext corrupted, authenticated tag invalid, or wrong key")]
    DecryptionFailed,

    #[error("Key wrapping error: {0}")]
    KeyWrapping(String),

    #[error("Argon2 KDF error: {0}")]
    Argon2(String),

    #[error("OS DPAPI error: {0}")]
    Dpapi(String),

    #[error("Invalid key length: expected {expected}, found {found}")]
    InvalidKeyLength { expected: usize, found: usize },

    #[error("Invalid nonce length: expected {expected}, found {found}")]
    InvalidNonceLength { expected: usize, found: usize },

    #[error("Canary violation detected: token {token_id} leaked")]
    CanaryViolation { token_id: String },

    #[error("Cryptographic operation failed: {0}")]
    General(String),
}
