//! Error types for protocol framing and CBOR decoding.
#![forbid(unsafe_code)]

use thiserror::Error;

/// Protocol framing and serialization error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    /// Frame length prefix is zero, which is invalid.
    #[error("Frame length is zero")]
    EmptyFrame,

    /// Frame exceeds the maximum permitted frame size (64 KiB).
    #[error("Frame length {size} exceeds maximum permitted limit {max}")]
    FrameTooLarge { size: usize, max: usize },

    /// Frame buffer is smaller than the length indicated by the prefix.
    #[error("Frame buffer truncated: expected at least {expected} bytes, got {actual}")]
    TruncatedFrame { expected: usize, actual: usize },

    /// Frame buffer contains trailing unconsumed bytes after the declared frame length.
    #[error("Frame contains trailing bytes: expected {expected} bytes total, got {actual}")]
    TrailingBytes { expected: usize, actual: usize },

    /// CBOR serialization failure.
    #[error("CBOR encoding error: {0}")]
    CborEncode(String),

    /// CBOR deserialization failure (strict decode / schema mismatch / unknown fields).
    #[error("CBOR decoding error: {0}")]
    CborDecode(String),

    /// I/O error during stream reading/writing.
    #[error("I/O error: {0}")]
    Io(String),

    /// High-level protocol or schema validation failure.
    #[error("Validation error: {0}")]
    Validation(String),
}

impl From<std::io::Error> for ProtoError {
    fn from(err: std::io::Error) -> Self {
        ProtoError::Io(err.to_string())
    }
}
