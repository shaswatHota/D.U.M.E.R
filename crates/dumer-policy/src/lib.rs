//! Policy broker, capability checks, risk tiers, and approval verification.
//!
//! Milestone 3 implementation of the D.U.M.E.R security architecture:
//! - Pure, deterministic policy broker without I/O.
//! - Strict capability validation and revocation/expiry checking.
//! - Autonomy level (L0..L3) vs Risk Tier (0..4) matrix.
//! - Invariant 1: Model confidence is strictly prohibited as a policy input.
//! - Invariant 2: Default deny on unknown operations and capabilities.
//! - Invariant 4: No wildcard shell or arbitrary filesystem capabilities.
//! - Invariant 5: Action-bound approvals cryptographically tied to exact op, args, subject, device, and nonce.
//! - Invariant 9: Taint tracking: Web/File/Voice/Model tainted inputs into Tier >= 1 ops require explicit user confirmation.
//! - Invariant 11: Fail closed on corrupt/invalid state.
//! - Invariant 12: Kill switches (global pause, device revocation) work deterministically without involving the LLM.
#![forbid(unsafe_code)]

pub mod approval;
pub mod autonomy;
pub mod broker;
pub mod capability;
pub mod error;
pub mod taint;
pub mod types;

pub use approval::{ApprovalSpec, ApprovalValidator, NonceTracker, SignerApproval};
pub use autonomy::{is_tier_autonomous, AutonomyLevel};
pub use broker::{PolicyBroker, PolicyDecision, PolicyInput};
pub use capability::{matches_capability, CapabilityGrant};
pub use error::{ApprovalError, DenyReason, PolicyError};
pub use taint::{TaintLabel, TaintMap};
pub use types::{DeviceRole, DeviceState, Principal, TaskBudget};
