use crate::aead::{decrypt_xchacha20, encrypt_xchacha20};
use crate::dpapi::{unwrap_dpapi, wrap_dpapi};
use crate::error::CryptoError;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::Secret;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit cryptographic key protected against accidental logging and memory leaks.
///
/// Implements `Zeroize` and `ZeroizeOnDrop` so sensitive key material is wiped from
/// memory immediately when the key is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key256(pub [u8; 32]);

impl Key256 {
    /// Generates a new cryptographically random 256-bit key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Creates a Key256 from existing bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a slice to the underlying 32-byte key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts to a `secrecy::Secret` wrapper.
    pub fn to_secret(&self) -> Secret<Vec<u8>> {
        Secret::new(self.0.to_vec())
    }

    /// Returns a short 8-hex-character SHA-256 fingerprint for safe identification without leaking secrets.
    pub fn fingerprint(&self) -> String {
        let hash = Sha256::digest(self.0);
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            hash[0], hash[1], hash[2], hash[3]
        )
    }
}

impl fmt::Debug for Key256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED Key256]")
    }
}

/// Key envelope handling Data Encryption Key (DEK) generation, DPAPI wrapping,
/// Argon2id KEK derivation, and KEK-wrapped DEK storage.
pub struct KeyEnvelope;

impl KeyEnvelope {
    /// Generates a new 256-bit Data Encryption Key.
    pub fn generate_dek() -> Key256 {
        Key256::generate()
    }

    /// Wraps the DEK using the OS DPAPI key.
    pub fn wrap_dek_dpapi(dek: &Key256, description: Option<&str>) -> Result<Vec<u8>, CryptoError> {
        wrap_dpapi(dek.as_bytes(), description)
    }

    /// Unwraps a DEK previously protected with DPAPI.
    pub fn unwrap_dek_dpapi(wrapped: &[u8]) -> Result<Key256, CryptoError> {
        let mut raw = unwrap_dpapi(wrapped)?;
        if raw.len() != 32 {
            raw.zeroize();
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                found: raw.len(),
            });
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&raw);
        raw.zeroize();
        Ok(Key256::from_bytes(key_bytes))
    }

    /// Derives a 256-bit Key Encryption Key (KEK) from a passphrase and salt using Argon2id.
    ///
    /// Parameters per security specification:
    /// - Memory cost: 64 MiB (65536 KiB)
    /// - Time cost / iterations: 3
    /// - Parallelism: 4 lanes
    pub fn derive_kek_argon2id(passphrase: &[u8], salt: &[u8]) -> Result<Key256, CryptoError> {
        if salt.len() < 16 {
            return Err(CryptoError::Argon2(
                "Salt must be at least 16 bytes".to_string(),
            ));
        }

        let params = Params::new(65536, 3, 4, Some(32))
            .map_err(|e| CryptoError::Argon2(format!("Invalid Argon2 params: {e}")))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = [0u8; 32];
        argon2
            .hash_password_into(passphrase, salt, &mut output)
            .map_err(|e| CryptoError::Argon2(format!("Argon2 KDF failed: {e}")))?;

        Ok(Key256::from_bytes(output))
    }

    /// Wraps the DEK using a KEK with XChaCha20-Poly1305 AEAD.
    /// Format: [24-byte nonce | ciphertext + poly1305 tag]
    pub fn wrap_dek_with_kek(dek: &Key256, kek: &Key256) -> Result<Vec<u8>, CryptoError> {
        let (ciphertext, nonce) = encrypt_xchacha20(kek, dek.as_bytes(), b"dumer-dek-envelope")?;
        let mut envelope = Vec::with_capacity(24 + ciphertext.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// Unwraps the DEK from a KEK envelope.
    pub fn unwrap_dek_with_kek(wrapped: &[u8], kek: &Key256) -> Result<Key256, CryptoError> {
        if wrapped.len() < 24 + 16 {
            return Err(CryptoError::KeyWrapping(
                "Wrapped envelope too short".to_string(),
            ));
        }

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&wrapped[..24]);
        let ciphertext = &wrapped[24..];

        let mut raw = decrypt_xchacha20(kek, ciphertext, &nonce, b"dumer-dek-envelope")?;
        if raw.len() != 32 {
            raw.zeroize();
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                found: raw.len(),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&raw);
        raw.zeroize();
        Ok(Key256::from_bytes(key_bytes))
    }

    /// Rotates the KEK: unwrap DEK with old KEK and re-wrap with new KEK.
    pub fn rotate_kek(
        wrapped: &[u8],
        old_kek: &Key256,
        new_kek: &Key256,
    ) -> Result<Vec<u8>, CryptoError> {
        let dek = Self::unwrap_dek_with_kek(wrapped, old_kek)?;
        Self::wrap_dek_with_kek(&dek, new_kek)
    }
}
