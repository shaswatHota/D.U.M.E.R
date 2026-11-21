//! Capability definitions, narrow scoping, and grant validation.
//!
//! Enforces Architecture §5 & Invariant 4:
//! Capabilities are narrow, expiring, and revocable.
//! Wildcard shell/filesystem/admin capabilities are strictly prohibited.
#![forbid(unsafe_code)]

use dumer_proto::registry::RiskTier;
use serde::{Deserialize, Serialize};

use crate::error::DenyReason;

/// Recorded capability grant for a subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrant {
    pub grant_id: String,
    pub subject: String,
    pub capability: String,
    pub risk_tier: RiskTier,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

impl CapabilityGrant {
    /// Validates that a capability string complies with narrow scope invariants.
    ///
    /// Rejects wildcard shell, general filesystem, and unrestricted admin capabilities.
    pub fn validate_capability(cap: &str) -> Result<(), &'static str> {
        let cap = cap.trim();
        if cap.is_empty() {
            return Err("Capability string cannot be empty");
        }

        if cap == "*" {
            return Err("Global wildcard capability '*' is forbidden");
        }

        // Prohibit all shell capabilities (Invariant 4)
        if cap.starts_with("shell.") || cap.contains(".shell.") || cap.starts_with("exec.") {
            return Err("Shell and arbitrary execution capabilities are forbidden");
        }

        // Prohibit arbitrary filesystem capabilities
        if cap.starts_with("filesystem.read:*")
            || cap.starts_with("filesystem.write:*")
            || cap.starts_with("files.*")
        {
            return Err("Unrestricted filesystem capabilities are forbidden");
        }

        // Prohibit persistent/arbitrary admin capabilities
        if cap.starts_with("admin:") || cap.starts_with("admin.*") {
            return Err("Persistent admin capabilities are forbidden");
        }

        // Must follow category.action or category.action:target format
        if !cap.contains('.') {
            return Err("Capability must follow hierarchical 'category.action[:target]' syntax");
        }

        Ok(())
    }

    /// Evaluates if this grant matches a required capability and subject, checking expiry and revocation.
    pub fn is_valid_for(
        &self,
        required_cap: &str,
        subject: &str,
        current_time: u64,
    ) -> Result<bool, DenyReason> {
        // 1. Check subject match (exact match, local_user, or wildcard subject)
        if self.subject != subject && self.subject != "local_user" && self.subject != "*" {
            return Ok(false);
        }

        // 2. Check capability matching
        if !matches_capability(&self.capability, required_cap) {
            return Ok(false);
        }

        // 3. Grant matches; now enforce revocation and expiry
        if self.revoked {
            return Err(DenyReason::GrantRevoked {
                grant_id: self.grant_id.clone(),
            });
        }

        if current_time > self.expires_at {
            return Err(DenyReason::GrantExpired {
                grant_id: self.grant_id.clone(),
                expired_at: self.expires_at,
                current_time,
            });
        }

        Ok(true)
    }
}

/// Matches a granted capability pattern against a required capability.
///
/// Rules:
/// - Exact match: `app.launch:chrome` matches `app.launch:chrome`.
/// - Narrow resource wildcard in grant: `app.launch:*` matches `app.launch:chrome`.
/// - Wildcard in requirement: `app.launch:*` matches `app.launch:*`.
pub fn matches_capability(grant_cap: &str, required_cap: &str) -> bool {
    if grant_cap == required_cap {
        return true;
    }

    if let Some(prefix) = grant_cap.strip_suffix(":*") {
        let req_prefix = required_cap.split(':').next().unwrap_or(required_cap);
        if prefix == req_prefix || required_cap.starts_with(prefix) {
            return true;
        }
    }

    false
}
