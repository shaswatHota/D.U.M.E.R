use crate::db::EncryptedDatabase;
use crate::error::VaultError;
use crate::models::MemoryClass;
use crate::vault::VaultManager;

pub struct PlaceholderResolver;

impl PlaceholderResolver {
    /// Checks if a string contains any `{{...}}` placeholders.
    pub fn contains_placeholders(text: &str) -> bool {
        text.contains("{{") && text.contains("}}")
    }

    /// Extracts all placeholder keys (e.g. `["VAULT.api_key", "PROFILE.email"]`) from a string.
    pub fn extract_placeholders(text: &str) -> Vec<String> {
        let mut placeholders = Vec::new();
        let mut rest = text;

        while let Some(start) = rest.find("{{") {
            let after_start = &rest[start + 2..];
            if let Some(end) = after_start.find("}}") {
                let key = after_start[..end].trim();
                if !key.is_empty() && !placeholders.contains(&key.to_string()) {
                    placeholders.push(key.to_string());
                }
                rest = &after_start[end + 2..];
            } else {
                break;
            }
        }

        placeholders
    }

    /// Resolves placeholders in `template` for the given `destination`.
    ///
    /// Substitution rules:
    /// - For `{{VAULT.<label>}}`:
    ///   - Checks `destination_allowlist` of the item. Fails closed if `destination` is not allowed.
    ///   - Checks if vault is unlocked. Fails closed with `VaultError::VaultLocked` if locked.
    /// - For `{{PROFILE.<key>}}`:
    ///   - Reads the decrypted profile memory record.
    /// - Any unknown item returns `VaultError::ItemNotFound`.
    pub fn resolve(
        template: &str,
        destination: &str,
        db: &EncryptedDatabase,
        vault: &VaultManager,
    ) -> Result<String, VaultError> {
        if !Self::contains_placeholders(template) {
            return Ok(template.to_string());
        }

        let mut result = template.to_string();
        let placeholders = Self::extract_placeholders(template);

        for ph in placeholders {
            let target_token = format!("{{{{{ph}}}}}");

            if let Some(vault_label) = ph.strip_prefix("VAULT.") {
                let item = db
                    .get_vault_item_by_label(vault_label)?
                    .ok_or_else(|| VaultError::ItemNotFound(vault_label.to_string()))?;

                // Enforce destination allowlist
                if !item
                    .destination_allowlist
                    .iter()
                    .any(|d| d == destination || d == "*")
                {
                    return Err(VaultError::DestinationNotAllowed {
                        item: vault_label.to_string(),
                        destination: destination.to_string(),
                        allowed: item.destination_allowlist.clone(),
                    });
                }

                // Read and decrypt secret
                let secret_bytes = vault.read_secret(db, vault_label)?;
                let secret_str = String::from_utf8(secret_bytes).map_err(|e| {
                    VaultError::General(format!("Vault secret is not valid UTF-8: {e}"))
                })?;

                result = result.replace(&target_token, &secret_str);
            } else if let Some(profile_key) = ph.strip_prefix("PROFILE.") {
                let record = db
                    .find_memory_record_by_key(MemoryClass::Profile, profile_key)?
                    .ok_or_else(|| {
                        VaultError::ItemNotFound(format!("Profile field '{profile_key}'"))
                    })?;

                let value_str = String::from_utf8(record.value).map_err(|e| {
                    VaultError::General(format!("Profile value is not valid UTF-8: {e}"))
                })?;

                result = result.replace(&target_token, &value_str);
            } else {
                return Err(VaultError::ItemNotFound(format!(
                    "Unknown placeholder namespace: {ph}"
                )));
            }
        }

        Ok(result)
    }
}
