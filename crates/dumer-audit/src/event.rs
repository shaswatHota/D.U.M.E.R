//! Audit event structures and canonical hash computation.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::error::AuditError;

/// Type categories of state-changing and security-relevant audit events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    DaemonStarted,
    DaemonStopped,
    ConfigChecked,
    SelfTestRun,
    RequestReceived,
    PolicyDecision,
    ApprovalRequested,
    ApprovalGranted,
    ApprovalDenied,
    ActionExecuted,
    DeviceEnrolled,
    DeviceRevoked,
    SecurityAlert,
    Custom(String),
}

/// An immutable, cryptographically hash-chained audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub sequence_number: u64,
    pub timestamp: u64,
    pub event_type: AuditEventType,
    pub actor: String,
    pub op: Option<String>,
    pub details: BTreeMap<String, String>,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

/// Helper struct for canonical serialization when computing event hash.
#[derive(Serialize)]
struct CanonicalEventPayload<'a> {
    sequence_number: u64,
    timestamp: u64,
    event_type: &'a AuditEventType,
    actor: &'a str,
    op: Option<&'a str>,
    details: &'a BTreeMap<String, String>,
    prev_hash: &'a [u8; 32],
}

/// Computes the deterministic SHA-256 hash for an audit event.
pub fn compute_event_hash(
    sequence_number: u64,
    timestamp: u64,
    event_type: &AuditEventType,
    actor: &str,
    op: Option<&str>,
    details: &BTreeMap<String, String>,
    prev_hash: &[u8; 32],
) -> Result<[u8; 32], AuditError> {
    let payload = CanonicalEventPayload {
        sequence_number,
        timestamp,
        event_type,
        actor,
        op,
        details,
        prev_hash,
    };

    let mut buf = Vec::new();
    ciborium::into_writer(&payload, &mut buf)
        .map_err(|e| AuditError::Serialization(e.to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(&buf);
    Ok(hasher.finalize().into())
}
