use crate::error::CryptoError;
use crate::key::Key256;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

/// Encrypts plaintext with XChaCha20-Poly1305 using a random 24-byte nonce.
/// Returns (ciphertext_with_tag, 24_byte_nonce).
pub fn encrypt_xchacha20(
    key: &Key256,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 24]), CryptoError> {
    let cipher_key = Key::from_slice(key.as_bytes());
    let cipher = XChaCha20Poly1305::new(cipher_key);

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::Aead(format!("Encryption error: {e}")))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypts ciphertext with XChaCha20-Poly1305 using the provided 24-byte nonce and AAD.
/// Fails closed on any corruption or wrong key.
pub fn decrypt_xchacha20(
    key: &Key256,
    ciphertext: &[u8],
    nonce: &[u8; 24],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher_key = Key::from_slice(key.as_bytes());
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(xnonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}
