//! The core Policy Broker evaluation engine.
//!
//! Enforces:
//! - Invariant 1: The LLM never authorizes anything; model confidence is never a policy input.
//! - Invariant 2: Default deny on unknown operations, capabilities, devices.
//! - Invariant 3: Every action goes through this same policy broker.
//! - Invariant 5: Approvals are bound to exact op + args + target identity + device + nonce + expiry.
//! - Invariant 9: Tainted data cannot silently become the target or arguments of a state-changing op.
//! - Invariant 11: Fail closed on corrupt/invalid state.
//! - Invariant 12: Kill switches (global pause, revoke device) work deterministically without the model.
#![forbid(unsafe_code)]

use ciborium::value::Value;
use dumer_proto::codec::compute_request_hash;
use dumer_proto::registry::{lookup_command, CommandDefinition, RiskTier};
use dumer_proto::types::{ApprovalRef, SignerRole, SubjectIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tracing::debug;

use crate::approval::{ApprovalSpec, ApprovalValidator};
use crate::autonomy::{is_tier_autonomous, AutonomyLevel};
use crate::capability::CapabilityGrant;
use crate::error::DenyReason;
use crate::taint::TaintMap;
use crate::types::{DeviceState, Principal, TaskBudget};

/// Policy evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", content = "payload", rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Operation is authorized to execute immediately.
    Allow,

    /// Operation is strictly denied.
    Deny(DenyReason),

    /// Operation requires user approval before execution.
    RequireApproval(Box<ApprovalSpec>),
}

/// Inputs required for a pure, deterministic policy evaluation.
///
/// NOTE: Invariant 1 is strictly enforced: model confidence is NOT an input.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyInput {
    pub principal: Principal,
    pub op: String,
    pub args: BTreeMap<String, Value>,
    pub subject: Option<SubjectIdentity>,
    pub autonomy_level: AutonomyLevel,
    pub has_undo_journal: bool,
    pub global_pause: bool,
    pub current_time: u64,
    pub grants: Vec<CapabilityGrant>,
    pub devices: BTreeMap<String, DeviceState>,
    pub taints: TaintMap,
    pub budget: Option<TaskBudget>,
    pub approval: Option<ApprovalRef>,
}

/// The deterministic policy broker. Free of I/O, pure and trivially testable.
#[derive(Debug, Clone, Default)]
pub struct PolicyBroker;

impl PolicyBroker {
    pub fn new() -> Self {
        Self
    }

    /// Pure evaluation function: `(input) -> PolicyDecision`.
    pub fn evaluate(&self, input: &PolicyInput) -> PolicyDecision {
        debug!(
            op = %input.op,
            principal = ?input.principal,
            autonomy = ?input.autonomy_level,
            "Evaluating policy"
        );

        // 1. Invariant 2: Default deny on unknown operations
        let cmd = match lookup_command(&input.op) {
            Some(c) => c,
            None => {
                return PolicyDecision::Deny(DenyReason::UnregisteredOperation(input.op.clone()))
            }
        };

        // 2. Validate device state if requesting principal is an external device
        if let Principal::Device { device_id } = &input.principal {
            match input.devices.get(device_id) {
                Some(dev) => {
                    if dev.is_revoked {
                        return PolicyDecision::Deny(DenyReason::DeviceRevoked(device_id.clone()));
                    }
                    if !dev.is_enrolled {
                        return PolicyDecision::Deny(DenyReason::DeviceUnauthorized(
                            device_id.clone(),
                        ));
                    }
                }
                None => {
                    return PolicyDecision::Deny(DenyReason::DeviceUnauthorized(device_id.clone()))
                }
            }
        }

        // 3. Invariant 12: Global pause / kill switch
        if input.global_pause {
            if input.principal.is_autonomous() {
                return PolicyDecision::Deny(DenyReason::GlobalPauseActive);
            }
            if cmd.risk > RiskTier::Tier0ReadOnly
                && !matches!(input.principal, Principal::LocalUser)
            {
                return PolicyDecision::Deny(DenyReason::GlobalPauseActive);
            }
        }

        // 4. Budget enforcement
        if let Some(budget) = &input.budget {
            if let Err(reason) = budget.check(input.current_time) {
                return PolicyDecision::Deny(reason);
            }
        }

        // 5. Capability grant verification (Architecture §5)
        let mut required_caps = Vec::new();
        for cap in &cmd.capabilities {
            if cap == "app.launch:*" {
                if let Some(Value::Text(app_id)) = input.args.get("app_id") {
                    required_caps.push(format!("app.launch:{}", app_id));
                } else {
                    required_caps.push(cap.clone());
                }
            } else {
                required_caps.push(cap.clone());
            }
        }

        for req_cap in &required_caps {
            let subject = input.principal.subject_id();
            let mut has_valid_grant = false;
            let mut matching_grant_denial = None;

            for grant in &input.grants {
                match grant.is_valid_for(req_cap, &subject, input.current_time) {
                    Ok(true) => {
                        has_valid_grant = true;
                        break;
                    }
                    Err(deny_reason) => {
                        matching_grant_denial = Some(deny_reason);
                    }
                    Ok(false) => {}
                }
            }

            if !has_valid_grant {
                if let Some(denial) = matching_grant_denial {
                    return PolicyDecision::Deny(denial);
                }
                if cmd.risk > RiskTier::Tier0ReadOnly {
                    return PolicyDecision::Deny(DenyReason::CapabilityNotGranted {
                        required: req_cap.clone(),
                    });
                }
            }
        }

        // 6. Approval verification if an approval reference was submitted with the request
        if let Some(approval) = &input.approval {
            let expected_device = match &input.principal {
                Principal::Device { device_id } => Some(device_id.as_str()),
                _ => None,
            };

            if let Err(err) = ApprovalValidator::validate(
                approval,
                &input.op,
                &input.args,
                input.subject.as_ref(),
                expected_device,
                input.current_time,
            ) {
                return PolicyDecision::Deny(DenyReason::InvalidApproval(err));
            }

            // If approval is cryptographically valid and bound, allow execution
            return PolicyDecision::Allow;
        }

        // 7. Invariant 9: Taint verification (Web/File/Voice/Model into Tier >= 1 ops)
        if cmd.risk >= RiskTier::Tier1ReversibleLocal {
            if let Some((arg_name, taint)) = input.taints.first_untrusted_taint() {
                let spec = self.build_approval_spec(
                    input,
                    &cmd,
                    vec![format!(
                        "Tainted argument '{}' from {:?} source requires user confirmation",
                        arg_name, taint
                    )],
                );
                return PolicyDecision::RequireApproval(Box::new(spec));
            }
        }

        // 8. Autonomy matrix evaluation (Architecture §5)
        // Tier 3+ is NEVER autonomous at ANY level
        if cmd.risk >= RiskTier::Tier3Sensitive {
            let spec = self.build_approval_spec(
                input,
                &cmd,
                vec![format!(
                    "Sensitive/privileged tier {:?} requires explicit user approval",
                    cmd.risk
                )],
            );
            return PolicyDecision::RequireApproval(Box::new(spec));
        }

        // Evaluate whether the command can execute autonomously
        if is_tier_autonomous(cmd.risk, input.autonomy_level, input.has_undo_journal) {
            PolicyDecision::Allow
        } else {
            let spec = self.build_approval_spec(
                input,
                &cmd,
                vec![format!(
                    "Autonomy level {:?} requires approval for tier {:?}",
                    input.autonomy_level, cmd.risk
                )],
            );
            PolicyDecision::RequireApproval(Box::new(spec))
        }
    }

    /// Constructs an `ApprovalSpec` bound to the exact request context.
    fn build_approval_spec(
        &self,
        input: &PolicyInput,
        cmd: &CommandDefinition,
        effects: Vec<String>,
    ) -> ApprovalSpec {
        let request_hash = compute_request_hash(&input.op, &input.args, input.subject.as_ref())
            .unwrap_or([0u8; 32]);

        // Generate deterministic approval ID and nonce from (request_hash, current_time)
        let mut hasher = Sha256::new();
        hasher.update(request_hash);
        hasher.update(input.current_time.to_be_bytes());
        let hash = hasher.finalize();

        let mut approval_id = [0u8; 16];
        approval_id.copy_from_slice(&hash[..16]);

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&hash[16..32]);

        // Required signers: Tier 4 requires dual approval (PC + Phone)
        let required_signers = match cmd.risk {
            RiskTier::Tier4Privileged => vec![SignerRole::Pc, SignerRole::Phone],
            _ => vec![SignerRole::Phone],
        };

        ApprovalSpec {
            approval_id,
            request_hash,
            op: input.op.clone(),
            args_summary: format!("{:?}", input.args),
            subject_identity: input.subject.clone(),
            risk_tier: cmd.risk,
            effects,
            nonce,
            // Default TTL: 5 minutes (300_000 ms)
            expires_at: input.current_time.saturating_add(300_000),
            required_signers,
        }
    }
}
