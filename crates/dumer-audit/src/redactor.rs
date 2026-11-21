//! Secret redaction and sensitive parameter sanitization helpers.
//!
//! Enforces Invariants 8 and 13: Secrets never enter logs or audit trails.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// Redaction engine for sanitizing audit payloads and log messages.
pub struct Redactor;

impl Redactor {
    /// Checks whether a key name denotes a sensitive credential or secret.
    pub fn is_sensitive_key(key: &str) -> bool {
        let lower = key.to_ascii_lowercase();
        lower.contains("secret")
            || lower.contains("token")
            || lower.contains("password")
            || lower.contains("passphrase")
            || lower.contains("key")
            || lower.contains("auth")
            || lower.contains("cert")
            || lower.contains("credential")
            || lower.contains("bearer")
            || lower.contains("cookie")
            || lower.contains("pin")
    }

    /// Redacts raw secret strings, token prefixes, canary tokens, and email addresses.
    pub fn redact_str(val: &str) -> String {
        let mut result = val.to_string();

        // 1. Canary token replacement
        if result.contains("CANARY_") {
            return "[CANARY_ALERT_REDACTED]".to_string();
        }

        // 2. Bearer / auth header pattern
        if let Some(pos) = result.to_ascii_lowercase().find("bearer ") {
            let after = &result[pos + 7..];
            if !after.is_empty() {
                result = format!("{}[REDACTED_BEARER]", &result[..pos + 7]);
            }
        }

        // 3. API key prefixes (sk-, ghp_, token-)
        for prefix in &["sk-", "ghp_", "xoxb-", "token-", "key-"] {
            if let Some(pos) = result.find(prefix) {
                let end = result[pos..]
                    .find(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == ';')
                    .map(|offset| pos + offset)
                    .unwrap_or(result.len());
                let before = &result[..pos];
                let after = &result[end..];
                result = format!("{}{}[REDACTED_KEY]{}", before, prefix, after);
            }
        }

        // 4. Email address masking
        if result.contains('@') {
            let words: Vec<&str> = result.split_whitespace().collect();
            let mut sanitized_words = Vec::new();
            for word in words {
                if word.contains('@') && word.contains('.') && word.len() > 4 {
                    sanitized_words.push("[REDACTED_EMAIL]");
                } else {
                    sanitized_words.push(word);
                }
            }
            result = sanitized_words.join(" ");
        }

        result
    }

    /// Sanitizes an entire dictionary of details before committing to the audit chain.
    pub fn sanitize_details(details: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        let mut sanitized = BTreeMap::new();
        for (k, v) in details {
            if Self::is_sensitive_key(k) {
                sanitized.insert(k.clone(), "[REDACTED]".to_string());
            } else {
                sanitized.insert(k.clone(), Self::redact_str(v));
            }
        }
        sanitized
    }
}
