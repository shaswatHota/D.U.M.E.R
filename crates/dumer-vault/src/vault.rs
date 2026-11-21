use crate::db::EncryptedDatabase;
use crate::error::VaultError;
use crate::models::VaultItem;
use dumer_crypto::{decrypt_xchacha20, encrypt_xchacha20, Key256};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

enum State {
    Locked,
    Unlocked {
        key: Key256,
        unlocked_at: Instant,
        auto_lock_duration: Duration,
    },
}

/// Vault manager maintaining a separate VaultKey in memory with user-verification unlock,
/// auto-lock timer, and fail-closed locked behavior.
pub struct VaultManager {
    state: RwLock<State>,
}

impl Default for VaultManager {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultManager {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(State::Locked),
        }
    }

    /// Unlocks the vault with the provided VaultKey for the given auto-lock duration.
    pub fn unlock(&self, key: Key256, auto_lock_duration: Duration) {
        let mut lock = self.state.write().unwrap();
        // Zeroize previous key if present
        if let State::Unlocked { mut key, .. } = std::mem::replace(&mut *lock, State::Locked) {
            key.zeroize();
        }

        *lock = State::Unlocked {
            key,
            unlocked_at: Instant::now(),
            auto_lock_duration,
        };
        tracing::info!(
            event = "vault.unlocked",
            duration_ms = auto_lock_duration.as_millis()
        );
    }

    /// Manually locks the vault immediately, wiping key material from memory.
    pub fn lock(&self) {
        let mut lock = self.state.write().unwrap();
        if let State::Unlocked { mut key, .. } = std::mem::replace(&mut *lock, State::Locked) {
            key.zeroize();
        }
        *lock = State::Locked;
        tracing::info!(event = "vault.locked");
    }

    /// Checks whether the vault is currently unlocked, automatically locking if expired.
    pub fn is_unlocked(&self) -> bool {
        let mut lock = self.state.write().unwrap();
        match &*lock {
            State::Locked => false,
            State::Unlocked {
                unlocked_at,
                auto_lock_duration,
                ..
            } => {
                if unlocked_at.elapsed() >= *auto_lock_duration {
                    if let State::Unlocked { mut key, .. } =
                        std::mem::replace(&mut *lock, State::Locked)
                    {
                        key.zeroize();
                    }
                    *lock = State::Locked;
                    false
                } else {
                    true
                }
            }
        }
    }

    /// Helper to execute an operation with the VaultKey if unlocked.
    fn with_key<F, R>(&self, f: F) -> Result<R, VaultError>
    where
        F: FnOnce(&Key256) -> Result<R, VaultError>,
    {
        let mut lock = self.state.write().unwrap();
        match &mut *lock {
            State::Locked => Err(VaultError::VaultLocked),
            State::Unlocked {
                key,
                unlocked_at,
                auto_lock_duration,
            } => {
                if unlocked_at.elapsed() >= *auto_lock_duration {
                    key.zeroize();
                    *lock = State::Locked;
                    Err(VaultError::VaultLocked)
                } else {
                    f(key)
                }
            }
        }
    }

    /// Stores a secret in the vault encrypted under the VaultKey with per-field destination allowlist.
    pub fn store_secret(
        &self,
        db: &EncryptedDatabase,
        label: &str,
        secret_value: &[u8],
        destination_allowlist: Vec<String>,
        is_canary: bool,
    ) -> Result<VaultItem, VaultError> {
        let (ciphertext, nonce) = self.with_key(|key| {
            let (ct, n) = encrypt_xchacha20(key, secret_value, label.as_bytes())?;
            Ok((ct, n))
        })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let item = VaultItem {
            item_id: format!("vault_{label}"),
            label: label.to_string(),
            destination_allowlist,
            ciphertext,
            nonce,
            created_at: now,
            updated_at: now,
            is_canary,
        };

        db.insert_vault_item(&item)?;
        tracing::info!(event = "vault.store_secret", label = %item.label, is_canary);
        Ok(item)
    }

    /// Decrypts and reads a secret from the vault. Fails closed with `VaultError::VaultLocked` if locked.
    pub fn read_secret(&self, db: &EncryptedDatabase, label: &str) -> Result<Vec<u8>, VaultError> {
        let item = db
            .get_vault_item_by_label(label)?
            .ok_or_else(|| VaultError::ItemNotFound(label.to_string()))?;

        self.with_key(|key| {
            let plaintext =
                decrypt_xchacha20(key, &item.ciphertext, &item.nonce, label.as_bytes())?;
            Ok(plaintext)
        })
    }

    /// Deletes a secret from the vault.
    pub fn delete_secret(&self, db: &EncryptedDatabase, label: &str) -> Result<bool, VaultError> {
        db.delete_vault_item(label)
    }
}
