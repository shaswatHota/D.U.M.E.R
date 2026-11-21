use crate::error::CryptoError;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

/// A canary secret planted in storage or configuration to detect unauthorized egress or exfiltration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryToken {
    pub token_id: String,
    pub secret: String,
    pub label: String,
    pub created_at: u64,
}

impl CanaryToken {
    /// Generates a new cryptographically random canary token.
    pub fn new(label: &str) -> Self {
        let mut id_bytes = [0u8; 8];
        let mut secret_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut id_bytes);
        OsRng.fill_bytes(&mut secret_bytes);

        let token_id = format!("canary_{}", hex::encode(id_bytes));
        let secret = format!("dumer_canary_{}", hex::encode(secret_bytes));
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            token_id,
            secret,
            label: label.to_string(),
            created_at,
        }
    }
}

/// Helper for hex encoding without extra dependencies.
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Thread-safe manager for tracking active canary tokens and scanning strings for canary leaks.
#[derive(Default)]
pub struct CanaryManager {
    tokens: RwLock<Vec<CanaryToken>>,
}

impl CanaryManager {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(Vec::new()),
        }
    }

    /// Registers an active canary token.
    pub fn register(&self, token: CanaryToken) {
        if let Ok(mut lock) = self.tokens.write() {
            if !lock.iter().any(|t| t.token_id == token.token_id) {
                lock.push(token);
            }
        }
    }

    /// Generates and immediately registers a new canary token.
    pub fn generate_and_register(&self, label: &str) -> CanaryToken {
        let token = CanaryToken::new(label);
        self.register(token.clone());
        token
    }

    /// Returns a list of active canary tokens.
    pub fn active_canaries(&self) -> Vec<CanaryToken> {
        self.tokens.read().map(|l| l.clone()).unwrap_or_default()
    }

    /// Scans a text string (e.g. outbound prompt, egress data, log record) for any active canary secrets.
    /// Returns `Err(CryptoError::CanaryViolation)` on any detection.
    pub fn scan(&self, text: &str) -> Result<(), CryptoError> {
        let tokens = self.tokens.read().map_err(|_| {
            CryptoError::General("Failed to acquire read lock on canary manager".to_string())
        })?;

        for token in tokens.iter() {
            if text.contains(&token.secret) {
                return Err(CryptoError::CanaryViolation {
                    token_id: token.token_id.clone(),
                });
            }
        }

        Ok(())
    }
}
