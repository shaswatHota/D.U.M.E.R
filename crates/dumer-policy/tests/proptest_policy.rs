//! Property tests for D.U.M.E.R Policy Broker.
//!
//! Enforces:
//! - Invariant 2 (Default Deny): No unregistered operation string ever evaluates to `Allow`.
#![forbid(unsafe_code)]

use dumer_policy::{
    AutonomyLevel, CapabilityGrant, PolicyBroker, PolicyDecision, PolicyInput, Principal, TaintMap,
};
use dumer_proto::registry::{RiskTier, COMMAND_REGISTRY_IDS};
use proptest::prelude::*;
use std::collections::BTreeMap;

proptest! {
    #[test]
    fn prop_unregistered_operations_never_yield_allow(
        op in "\\PC{1,64}",
        autonomy in 0u8..4,
        has_undo in any::<bool>(),
        current_time in any::<u64>()
    ) {
        // Skip operations that actually exist in the static registry
        prop_assume!(!COMMAND_REGISTRY_IDS.contains(&op.as_str()));

        let autonomy_level = match autonomy {
            0 => AutonomyLevel::L0Observe,
            1 => AutonomyLevel::L1Suggest,
            2 => AutonomyLevel::L2ActLow,
            _ => AutonomyLevel::L3ActJournaled,
        };

        // Even with a wide open grant, an unregistered operation MUST be denied
        let grant = CapabilityGrant {
            grant_id: "grant-wide".to_string(),
            subject: "local_user".to_string(),
            capability: "app.launch:*".to_string(),
            risk_tier: RiskTier::Tier4Privileged,
            issued_at: 0,
            expires_at: u64::MAX,
            revoked: false,
        };

        let broker = PolicyBroker::new();
        let input = PolicyInput {
            principal: Principal::LocalUser,
            op: op.clone(),
            args: BTreeMap::new(),
            subject: None,
            autonomy_level,
            has_undo_journal: has_undo,
            global_pause: false,
            current_time,
            grants: vec![grant],
            devices: BTreeMap::new(),
            taints: TaintMap::new(),
            budget: None,
            approval: None,
        };

        let decision = broker.evaluate(&input);
        prop_assert_ne!(decision, PolicyDecision::Allow, "Unregistered op '{}' yielded Allow!", op);
    }
}
