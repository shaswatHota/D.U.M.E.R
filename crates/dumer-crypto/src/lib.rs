//! Cryptographic primitives, key envelope management, AEAD, and canary tokens for D.U.M.E.R.
//!
//! Windows DPAPI calls are isolated in `dpapi.rs` with explicit `// SAFETY:` justifications.

pub mod aead;
pub mod canary;
pub mod dpapi;
pub mod error;
pub mod key;

pub use aead::{decrypt_xchacha20, encrypt_xchacha20};
pub use canary::{CanaryManager, CanaryToken};
pub use error::CryptoError;
pub use key::{Key256, KeyEnvelope};
