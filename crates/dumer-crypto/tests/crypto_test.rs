use dumer_crypto::{
    decrypt_xchacha20, encrypt_xchacha20, CanaryManager, CryptoError, Key256, KeyEnvelope,
};

#[test]
fn test_key256_generation_and_redacted_debug() {
    let key1 = Key256::generate();
    let key2 = Key256::generate();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
    assert_eq!(key1.as_bytes().len(), 32);

    let debug_repr = format!("{key1:?}");
    assert_eq!(debug_repr, "[REDACTED Key256]");
    assert!(!debug_repr.contains(&format!("{:x}", key1.as_bytes()[0])));
}

#[test]
fn test_aead_encrypt_decrypt_roundtrip() {
    let key = Key256::generate();
    let plaintext = b"Hello D.U.M.E.R cryptographic vault!";
    let aad = b"context-authenticated-data";

    let (ciphertext, nonce) = encrypt_xchacha20(&key, plaintext, aad).expect("encryption succeeds");
    assert_ne!(ciphertext, plaintext);
    assert_eq!(nonce.len(), 24);

    let decrypted = decrypt_xchacha20(&key, &ciphertext, &nonce, aad).expect("decryption succeeds");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aead_tampered_ciphertext_fails_closed() {
    let key = Key256::generate();
    let plaintext = b"Secret personal data";
    let aad = b"aad";

    let (mut ciphertext, nonce) =
        encrypt_xchacha20(&key, plaintext, aad).expect("encryption succeeds");

    // Tamper with 1 bit
    ciphertext[0] ^= 0x01;

    let res = decrypt_xchacha20(&key, &ciphertext, &nonce, aad);
    assert!(res.is_err());
    match res {
        Err(CryptoError::DecryptionFailed) => {}
        other => panic!("Expected DecryptionFailed, got {other:?}"),
    }
}

#[test]
fn test_aead_wrong_key_fails_closed() {
    let key1 = Key256::generate();
    let key2 = Key256::generate();
    let plaintext = b"Personal identity token";
    let aad = b"aad";

    let (ciphertext, nonce) =
        encrypt_xchacha20(&key1, plaintext, aad).expect("encryption succeeds");

    let res = decrypt_xchacha20(&key2, &ciphertext, &nonce, aad);
    assert!(res.is_err());
    match res {
        Err(CryptoError::DecryptionFailed) => {}
        other => panic!("Expected DecryptionFailed, got {other:?}"),
    }
}

#[test]
fn test_aead_tampered_aad_fails_closed() {
    let key = Key256::generate();
    let plaintext = b"Account balance";
    let aad1 = b"context-1";
    let aad2 = b"context-2";

    let (ciphertext, nonce) =
        encrypt_xchacha20(&key, plaintext, aad1).expect("encryption succeeds");

    let res = decrypt_xchacha20(&key, &ciphertext, &nonce, aad2);
    assert!(res.is_err());
    match res {
        Err(CryptoError::DecryptionFailed) => {}
        other => panic!("Expected DecryptionFailed, got {other:?}"),
    }
}

#[test]
fn test_argon2id_kek_derivation() {
    let passphrase = b"Correct-Horse-Battery-Staple-2026!";
    let salt = b"sixteen_byte_salt_123";

    let kek1 = KeyEnvelope::derive_kek_argon2id(passphrase, salt).expect("Argon2id succeeds");
    let kek2 = KeyEnvelope::derive_kek_argon2id(passphrase, salt).expect("Argon2id succeeds");
    assert_eq!(kek1.as_bytes(), kek2.as_bytes());

    let different_kek =
        KeyEnvelope::derive_kek_argon2id(b"wrong-password", salt).expect("Argon2id succeeds");
    assert_ne!(kek1.as_bytes(), different_kek.as_bytes());
}

#[test]
fn test_kek_envelope_wrap_unwrap_and_rotation() {
    let dek = KeyEnvelope::generate_dek();
    let kek1 = Key256::generate();
    let kek2 = Key256::generate();

    // Wrap with KEK 1
    let wrapped = KeyEnvelope::wrap_dek_with_kek(&dek, &kek1).expect("wrap succeeds");
    let unwrapped = KeyEnvelope::unwrap_dek_with_kek(&wrapped, &kek1).expect("unwrap succeeds");
    assert_eq!(dek.as_bytes(), unwrapped.as_bytes());

    // Wrong KEK fails
    assert!(KeyEnvelope::unwrap_dek_with_kek(&wrapped, &kek2).is_err());

    // Rotate KEK 1 -> KEK 2
    let rotated = KeyEnvelope::rotate_kek(&wrapped, &kek1, &kek2).expect("rotation succeeds");
    assert!(KeyEnvelope::unwrap_dek_with_kek(&rotated, &kek1).is_err());
    let unwrapped2 =
        KeyEnvelope::unwrap_dek_with_kek(&rotated, &kek2).expect("unwrap with new kek");
    assert_eq!(dek.as_bytes(), unwrapped2.as_bytes());
}

#[cfg(windows)]
#[test]
fn test_dpapi_envelope_wrap_and_unwrap() {
    let dek = KeyEnvelope::generate_dek();
    let wrapped =
        KeyEnvelope::wrap_dek_dpapi(&dek, Some("DUMER Test DEK")).expect("DPAPI protect succeeds");
    assert_ne!(wrapped, dek.as_bytes());

    let unwrapped = KeyEnvelope::unwrap_dek_dpapi(&wrapped).expect("DPAPI unprotect succeeds");
    assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
}

#[test]
fn test_canary_token_generation_and_detection() {
    let manager = CanaryManager::new();
    let canary = manager.generate_and_register("test-canary-key");

    assert!(canary.secret.starts_with("dumer_canary_"));
    assert_eq!(manager.active_canaries().len(), 1);

    // Clean text passes
    assert!(manager
        .scan("This is a normal log message without any leaks.")
        .is_ok());

    // Leaked canary is detected
    let leaked_msg = format!("Error: failed sending request with key {}", canary.secret);
    let scan_res = manager.scan(&leaked_msg);
    assert!(scan_res.is_err());
    match scan_res {
        Err(CryptoError::CanaryViolation { token_id }) => {
            assert_eq!(token_id, canary.token_id);
        }
        other => panic!("Expected CanaryViolation, got {other:?}"),
    }
}
