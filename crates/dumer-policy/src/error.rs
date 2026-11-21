//! Error types and decision reasons for the policy broker.
#![forbid(unsafe_code)]

use dumer_proto::registry::RiskTier;
use dumer_proto::types::SignerRole;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::autonomy::AutonomyLevel;
use crate::taint::TaintLabel;

/// Comprehensive deny reasons emitted by the policy broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", content = "details", rename_all = "snake_case")]
pub enum DenyReason {
    /// Operation is not registered in the command catalog.
    UnregisteredOperation(String),

    /// Required capability was not granted to the principal.
    CapabilityNotGranted { required: String },

    /// Capability grant has expired.
    GrantExpired {
        grant_id: String,
        expired_at: u64,
        current_time: u64,
    },

    /// Capability grant was revoked.
    GrantRevoked { grant_id: String },

    /// Requesting device has been revoked.
    DeviceRevoked(String),

    /// Requesting device is not enrolled or recognized.
    DeviceUnauthorized(String),

    /// Global pause / kill-switch is currently active.
    GlobalPauseActive,

    /// Task budget (steps, deadline, tool calls) has been exhausted.
    BudgetExhausted(String),

    /// Current autonomy level is insufficient to execute the risk tier.
    AutonomyLevelInsufficient {
        required: RiskTier,
        current: AutonomyLevel,
    },

    /// Argument contains untrusted taint (Web, File, Voice, Model) requiring confirmation.
    TaintedArgumentRequiresConfirmation { arg_name: String, taint: TaintLabel },

    /// Approval object is invalid or failed verification.
    InvalidApproval(ApprovalError),

    /// Internal evaluation error.
    InternalError(String),
}

/// Errors occurring during approval token and signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "error", content = "details", rename_all = "snake_case")]
pub enum ApprovalError {
    #[error("Approval expired at {expired_at} (current time: {current_time})")]
    Expired { expired_at: u64, current_time: u64 },

    #[error(
        "Approval request hash does not match canonical encoding of operation, args, and subject"
    )]
    HashMismatch,

    #[error("Approval signed by device '{actual}', but request originated from '{expected}'")]
    DeviceMismatch { expected: String, actual: String },

    #[error("Approval nonce has already been consumed (replay attack detected)")]
    ReplayedNonce,

    #[error("Operation requires approval but none was provided")]
    MissingApproval,

    #[error("Missing required signer role: {0:?}")]
    MissingRequiredSigner(SignerRole),

    #[error("Internal approval error: {0}")]
    Internal(String),
}

/// Top-level error type for dumer-policy.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Protocol error: {0}")]
    Proto(#[from] dumer_proto::error::ProtoError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Policy evaluation denied: {0:?}")]
    Denied(DenyReason),
}
