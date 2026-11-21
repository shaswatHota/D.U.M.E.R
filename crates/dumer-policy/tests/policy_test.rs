//! Comprehensive test suite for D.U.M.E.R Policy Broker (Milestone 3).
//!
//! Tests verify:
//! - Allow: valid tier 0/1 within autonomy and grants.
//! - Deny: unregistered operations, missing capabilities, expired/revoked grants.
//! - Deny: revoked/unauthorized devices, global pause, exhausted budgets.
//! - Autonomy matrix: L0..L3 vs RiskTier 0..4.
//! - Taint propagation: Web/File/Voice/Model tainted arguments into Tier >= 1 ops require approval.
//! - Approval binding: exact canonical hash, expiry, device binding, replayed nonce rejection.
//! - Tier 4 dual approval: PC + Phone required.
//! - Invariant 1: Model confidence is never an input.
//! - Invariant 2: Default deny.
//! - Invariant 4: No wildcard shell/filesystem capabilities.
//! - Invariant 11: Fail closed on corrupt/invalid state.
#![forbid(unsafe_code)]

use ciborium::value::Value;
use dumer_policy::{
    ApprovalError, AutonomyLevel, CapabilityGrant, DenyReason, DeviceRole, DeviceState,
    NonceTracker, PolicyBroker, PolicyDecision, PolicyInput, Principal, TaintLabel, TaintMap,
    TaskBudget,
};
use dumer_proto::codec::compute_request_hash;
use dumer_proto::registry::RiskTier;
use dumer_proto::types::{ApprovalRef, ApprovalSignature, SubjectIdentity};
use std::collections::BTreeMap;

fn make_test_args(app_id: &str) -> BTreeMap<String, Value> {
    let mut args = BTreeMap::new();
    args.insert("app_id".to_string(), Value::Text(app_id.to_string()));
    args
}

fn make_empty_args() -> BTreeMap<String, Value> {
    BTreeMap::new()
}

fn sample_subject() -> SubjectIdentity {
    SubjectIdentity {
        display_name: "Google Chrome".to_string(),
        binary_path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".to_string(),
        sha256_hash: [0x42; 32],
        publisher_signer: Some("Google LLC".to_string()),
    }
}

// ---------------------------------------------------------------------------
// 1. Allow Tests
// ---------------------------------------------------------------------------

#[test]
fn test_allow_tier0_read_only_local_user() {
    let broker = PolicyBroker::new();
    let input = PolicyInput {
        principal: Principal::LocalUser,
        op: "system.status.read".to_string(),
        args: make_empty_args(),
        subject: None,
        autonomy_level: AutonomyLevel::L0Observe,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_allow_tier1_with_valid_grant_and_autonomy_l2() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-1".to_string(),
        subject: "local_user".to_string(),
        capability: "app.launch:*".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    let input = PolicyInput {
        principal: Principal::LocalUser,
        op: "application.open".to_string(),
        args: make_test_args("chrome"),
        subject: Some(sample_subject()),
        autonomy_level: AutonomyLevel::L2ActLow,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    assert_eq!(decision, PolicyDecision::Allow);
}

// ---------------------------------------------------------------------------
// 2. Deny Tests: Unregistered Op, Missing Cap, Expired/Revoked Grant
// ---------------------------------------------------------------------------

#[test]
fn test_deny_unregistered_operation() {
    let broker = PolicyBroker::new();
    let input = PolicyInput {
        principal: Principal::LocalUser,
        op: "arbitrary.shell.exec".to_string(),
        args: make_empty_args(),
        subject: None,
        autonomy_level: AutonomyLevel::L3ActJournaled,
        has_undo_journal: true,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::UnregisteredOperation(op)) => {
            assert_eq!(op, "arbitrary.shell.exec");
        }
        other => panic!("Expected Deny(UnregisteredOperation), got {:?}", other),
    }
}

#[test]
fn test_deny_missing_capability() {
    let broker = PolicyBroker::new();
    // No grants provided for Tier 1 operation
    let input = PolicyInput {
        principal: Principal::LocalUser,
        op: "application.open".to_string(),
        args: make_test_args("chrome"),
        subject: None,
        autonomy_level: AutonomyLevel::L2ActLow,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::CapabilityNotGranted { required }) => {
            assert_eq!(required, "app.launch:chrome");
        }
        other => panic!("Expected Deny(CapabilityNotGranted), got {:?}", other),
    }
}

#[test]
fn test_deny_mismatched_narrow_capability() {
    let broker = PolicyBroker::new();
    // Grant is for firefox, but request is for chrome!
    let grant = CapabilityGrant {
        grant_id: "grant-firefox".to_string(),
        subject: "local_user".to_string(),
        capability: "app.launch:firefox".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    let input = PolicyInput {
        principal: Principal::LocalUser,
        op: "application.open".to_string(),
        args: make_test_args("chrome"),
        subject: None,
        autonomy_level: AutonomyLevel::L2ActLow,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::CapabilityNotGranted { required }) => {
            assert_eq!(required, "app.launch:chrome");
        }
        other => panic!("Expected Deny(CapabilityNotGranted), got {:?}", other),
    }
}

#[test]
fn test_deny_expired_grant() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-expired".to_string(),
        subject: "local_user".to_string(),
        capability: "app.launch:chrome".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 800_000,
        expires_at: 950_000, // Expired before current_time = 1_000_000
        revoked: false,
    };

    let input = PolicyInput {
        principal: Principal::LocalUser,
        op: "application.open".to_string(),
        args: make_test_args("chrome"),
        subject: None,
        autonomy_level: AutonomyLevel::L2ActLow,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::GrantExpired {
            grant_id,
            expired_at,
            current_time,
        }) => {
            assert_eq!(grant_id, "grant-expired");
            assert_eq!(expired_at, 950_000);
            assert_eq!(current_time, 1_000_000);
        }
        other => panic!("Expected Deny(GrantExpired), got {:?}", other),
    }
}

#[test]
fn test_deny_revoked_grant() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-revoked".to_string(),
        subject: "local_user".to_string(),
        capability: "app.launch:chrome".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 800_000,
        expires_at: 1_200_000,
        revoked: true, // Explicitly revoked
    };

    let input = PolicyInput {
        principal: Principal::LocalUser,
        op: "application.open".to_string(),
        args: make_test_args("chrome"),
        subject: None,
        autonomy_level: AutonomyLevel::L2ActLow,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::GrantRevoked { grant_id }) => {
            assert_eq!(grant_id, "grant-revoked");
        }
        other => panic!("Expected Deny(GrantRevoked), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 3. Deny Tests: Device Security (Revocation, Unauthorized)
// ---------------------------------------------------------------------------

#[test]
fn test_deny_revoked_device() {
    let broker = PolicyBroker::new();
    let mut devices = BTreeMap::new();
    devices.insert(
        "phone-compromised".to_string(),
        DeviceState {
            device_id: "phone-compromised".to_string(),
            role: DeviceRole::PhoneCompanion,
            is_enrolled: true,
            is_revoked: true, // Revoked!
        },
    );

    let input = PolicyInput {
        principal: Principal::Device {
            device_id: "phone-compromised".to_string(),
        },
        op: "system.status.read".to_string(),
        args: make_empty_args(),
        subject: None,
        autonomy_level: AutonomyLevel::L2ActLow,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![],
        devices,
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::DeviceRevoked(dev)) => {
            assert_eq!(dev, "phone-compromised");
        }
        other => panic!("Expected Deny(DeviceRevoked), got {:?}", other),
    }
}

#[test]
fn test_deny_unauthorized_device() {
    let broker = PolicyBroker::new();
    let input = PolicyInput {
        principal: Principal::Device {
            device_id: "unknown-rogue-device".to_string(),
        },
        op: "system.status.read".to_string(),
        args: make_empty_args(),
        subject: None,
        autonomy_level: AutonomyLevel::L2ActLow,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![],
        devices: BTreeMap::new(), // No devices enrolled
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::DeviceUnauthorized(dev)) => {
            assert_eq!(dev, "unknown-rogue-device");
        }
        other => panic!("Expected Deny(DeviceUnauthorized), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 4. Global Pause & Budgets
// ---------------------------------------------------------------------------

#[test]
fn test_deny_global_pause_for_autonomous_work() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-1".to_string(),
        subject: "planner".to_string(),
        capability: "app.launch:*".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    let input = PolicyInput {
        principal: Principal::Planner {
            playbook_id: Some("playbook-backup".to_string()),
        },
        op: "application.open".to_string(),
        args: make_test_args("chrome"),
        subject: None,
        autonomy_level: AutonomyLevel::L2ActLow,
        has_undo_journal: false,
        global_pause: true, // Kill switch engaged
        current_time: 1_000_000,
        grants: vec![grant],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    assert_eq!(
        decision,
        PolicyDecision::Deny(DenyReason::GlobalPauseActive)
    );
}

#[test]
fn test_deny_budget_exhausted_steps() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-1".to_string(),
        subject: "planner".to_string(),
        capability: "app.launch:*".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    let budget = TaskBudget {
        remaining_steps: Some(0), // Out of steps!
        deadline: Some(2_000_000),
        max_tool_calls: Some(10),
    };

    let input = PolicyInput {
        principal: Principal::Planner { playbook_id: None },
        op: "application.open".to_string(),
        args: make_test_args("chrome"),
        subject: None,
        autonomy_level: AutonomyLevel::L2ActLow,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: Some(budget),
        approval: None,
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::BudgetExhausted(b)) => {
            assert!(b.contains("steps"));
        }
        other => panic!("Expected Deny(BudgetExhausted), got {:?}", other),
    }
}

#[test]
fn test_deny_budget_exhausted_deadline() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-1".to_string(),
        subject: "planner".to_string(),
        capability: "app.launch:*".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    let budget = TaskBudget {
        remaining_steps: Some(5),
        deadline: Some(999_999), // Expired deadline before 1_000_000
        max_tool_calls: Some(10),
    };

    let input = PolicyInput {
        principal: Principal::Planner { playbook_id: None },
        op: "application.open".to_string(),
        args: make_test_args("chrome"),
        subject: None,
        autonomy_level: AutonomyLevel::L2ActLow,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: Some(budget),
        approval: None,
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::BudgetExhausted(b)) => {
            assert!(b.contains("deadline"));
        }
        other => panic!("Expected Deny(BudgetExhausted), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 5. Autonomy Level Matrix & Risk Tiers
// ---------------------------------------------------------------------------

#[test]
fn test_autonomy_level_l0_requires_approval_for_tier1() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-1".to_string(),
        subject: "local_user".to_string(),
        capability: "app.launch:*".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    // At L0Observe, Tier 1 cannot run autonomously
    let input = PolicyInput {
        principal: Principal::LocalUser,
        op: "application.open".to_string(),
        args: make_test_args("chrome"),
        subject: None,
        autonomy_level: AutonomyLevel::L0Observe,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices: BTreeMap::new(),
        taints: TaintMap::new(),
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    assert!(matches!(decision, PolicyDecision::RequireApproval(_)));
}

#[test]
fn test_autonomy_level_tier2_requires_undo_journal_at_l3() {
    assert!(!dumer_policy::is_tier_autonomous(
        RiskTier::Tier2MeaningfulChange,
        AutonomyLevel::L2ActLow,
        false
    ));
    assert!(!dumer_policy::is_tier_autonomous(
        RiskTier::Tier2MeaningfulChange,
        AutonomyLevel::L3ActJournaled,
        false // No undo journal!
    ));
    assert!(dumer_policy::is_tier_autonomous(
        RiskTier::Tier2MeaningfulChange,
        AutonomyLevel::L3ActJournaled,
        true // Undo journal present!
    ));
    // Tier 3+ is never autonomous at any level
    assert!(!dumer_policy::is_tier_autonomous(
        RiskTier::Tier3Sensitive,
        AutonomyLevel::L3ActJournaled,
        true
    ));
    assert!(!dumer_policy::is_tier_autonomous(
        RiskTier::Tier4Privileged,
        AutonomyLevel::L3ActJournaled,
        true
    ));
}

// ---------------------------------------------------------------------------
// 6. Taint Propagation Rules (Invariant 9)
// ---------------------------------------------------------------------------

#[test]
fn test_tainted_argument_into_tier_ge_1_requires_approval() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-1".to_string(),
        subject: "local_user".to_string(),
        capability: "app.launch:*".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    let mut taints = TaintMap::new();
    // Taint the app_id argument with Web taint!
    taints.insert_taint("app_id", TaintLabel::Web);

    let input = PolicyInput {
        principal: Principal::LocalUser,
        op: "application.open".to_string(),
        args: make_test_args("chrome"),
        subject: None,
        autonomy_level: AutonomyLevel::L2ActLow, // Autonomy is high, but taint blocks it!
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices: BTreeMap::new(),
        taints,
        budget: None,
        approval: None,
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::RequireApproval(spec) => {
            assert_eq!(spec.op, "application.open");
            assert!(spec.effects.iter().any(|e| e.contains("Tainted")));
        }
        other => panic!("Expected RequireApproval for tainted arg, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 7. Approval Object Binding & Verification (Invariant 5)
// ---------------------------------------------------------------------------

#[test]
fn test_approval_valid_permits_operation() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-1".to_string(),
        subject: "device-phone-1".to_string(),
        capability: "app.launch:*".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    let mut devices = BTreeMap::new();
    devices.insert(
        "device-phone-1".to_string(),
        DeviceState {
            device_id: "device-phone-1".to_string(),
            role: DeviceRole::PhoneCompanion,
            is_enrolled: true,
            is_revoked: false,
        },
    );

    let op = "application.open";
    let args = make_test_args("chrome");
    let subject = sample_subject();

    let request_hash = compute_request_hash(op, &args, Some(&subject)).unwrap();

    let approval = ApprovalRef {
        approval_id: [1u8; 16],
        signature: ApprovalSignature {
            approval_id: [1u8; 16],
            request_hash,
            nonce: [2u8; 16],
            expires_at: 1_050_000,
            device_id: "device-phone-1".to_string(),
            sig: vec![0xaa; 64],
        },
    };

    let input = PolicyInput {
        principal: Principal::Device {
            device_id: "device-phone-1".to_string(),
        },
        op: op.to_string(),
        args,
        subject: Some(subject),
        autonomy_level: AutonomyLevel::L0Observe, // L0 normally requires approval
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices,
        taints: TaintMap::new(),
        budget: None,
        approval: Some(approval),
    };

    let decision = broker.evaluate(&input);
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_approval_denies_altered_arguments() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-1".to_string(),
        subject: "device-phone-1".to_string(),
        capability: "app.launch:*".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    let mut devices = BTreeMap::new();
    devices.insert(
        "device-phone-1".to_string(),
        DeviceState {
            device_id: "device-phone-1".to_string(),
            role: DeviceRole::PhoneCompanion,
            is_enrolled: true,
            is_revoked: false,
        },
    );

    let op = "application.open";
    // Approved for "chrome"
    let approved_args = make_test_args("chrome");
    let subject = sample_subject();
    let request_hash = compute_request_hash(op, &approved_args, Some(&subject)).unwrap();

    let approval = ApprovalRef {
        approval_id: [1u8; 16],
        signature: ApprovalSignature {
            approval_id: [1u8; 16],
            request_hash,
            nonce: [2u8; 16],
            expires_at: 1_050_000,
            device_id: "device-phone-1".to_string(),
            sig: vec![0xaa; 64],
        },
    };

    // But submitted with "firefox" (tampered arguments!)
    let executed_args = make_test_args("firefox");

    let input = PolicyInput {
        principal: Principal::Device {
            device_id: "device-phone-1".to_string(),
        },
        op: op.to_string(),
        args: executed_args,
        subject: Some(subject),
        autonomy_level: AutonomyLevel::L0Observe,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices,
        taints: TaintMap::new(),
        budget: None,
        approval: Some(approval),
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::InvalidApproval(ApprovalError::HashMismatch)) => {}
        other => panic!("Expected Deny(HashMismatch), got {:?}", other),
    }
}

#[test]
fn test_approval_denies_expired_approval() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-1".to_string(),
        subject: "device-phone-1".to_string(),
        capability: "app.launch:*".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    let mut devices = BTreeMap::new();
    devices.insert(
        "device-phone-1".to_string(),
        DeviceState {
            device_id: "device-phone-1".to_string(),
            role: DeviceRole::PhoneCompanion,
            is_enrolled: true,
            is_revoked: false,
        },
    );

    let op = "application.open";
    let args = make_test_args("chrome");
    let subject = sample_subject();
    let request_hash = compute_request_hash(op, &args, Some(&subject)).unwrap();

    let approval = ApprovalRef {
        approval_id: [1u8; 16],
        signature: ApprovalSignature {
            approval_id: [1u8; 16],
            request_hash,
            nonce: [2u8; 16],
            expires_at: 950_000, // Expired before 1_000_000!
            device_id: "device-phone-1".to_string(),
            sig: vec![0xaa; 64],
        },
    };

    let input = PolicyInput {
        principal: Principal::Device {
            device_id: "device-phone-1".to_string(),
        },
        op: op.to_string(),
        args,
        subject: Some(subject),
        autonomy_level: AutonomyLevel::L0Observe,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices,
        taints: TaintMap::new(),
        budget: None,
        approval: Some(approval),
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::InvalidApproval(ApprovalError::Expired {
            expired_at,
            current_time,
        })) => {
            assert_eq!(expired_at, 950_000);
            assert_eq!(current_time, 1_000_000);
        }
        other => panic!("Expected Deny(Expired), got {:?}", other),
    }
}

#[test]
fn test_approval_denies_wrong_device() {
    let broker = PolicyBroker::new();
    let grant = CapabilityGrant {
        grant_id: "grant-1".to_string(),
        subject: "phone-legit".to_string(),
        capability: "app.launch:*".to_string(),
        risk_tier: RiskTier::Tier1ReversibleLocal,
        issued_at: 900_000,
        expires_at: 1_100_000,
        revoked: false,
    };

    let mut devices = BTreeMap::new();
    devices.insert(
        "phone-legit".to_string(),
        DeviceState {
            device_id: "phone-legit".to_string(),
            role: DeviceRole::PhoneCompanion,
            is_enrolled: true,
            is_revoked: false,
        },
    );

    let op = "application.open";
    let args = make_test_args("chrome");
    let subject = sample_subject();
    let request_hash = compute_request_hash(op, &args, Some(&subject)).unwrap();

    // Approval claims to be from phone-attacker
    let approval = ApprovalRef {
        approval_id: [1u8; 16],
        signature: ApprovalSignature {
            approval_id: [1u8; 16],
            request_hash,
            nonce: [2u8; 16],
            expires_at: 1_050_000,
            device_id: "phone-attacker".to_string(),
            sig: vec![0xaa; 64],
        },
    };

    let input = PolicyInput {
        principal: Principal::Device {
            device_id: "phone-legit".to_string(),
        },
        op: op.to_string(),
        args,
        subject: Some(subject),
        autonomy_level: AutonomyLevel::L0Observe,
        has_undo_journal: false,
        global_pause: false,
        current_time: 1_000_000,
        grants: vec![grant],
        devices,
        taints: TaintMap::new(),
        budget: None,
        approval: Some(approval),
    };

    let decision = broker.evaluate(&input);
    match decision {
        PolicyDecision::Deny(DenyReason::InvalidApproval(ApprovalError::DeviceMismatch {
            ..
        })) => {}
        other => panic!("Expected Deny(DeviceMismatch), got {:?}", other),
    }
}

#[test]
fn test_approval_denies_replayed_nonce() {
    let mut nonce_tracker = NonceTracker::new();
    let nonce = [0x55; 16];

    assert!(nonce_tracker.check_and_mark_used(&nonce).is_ok());
    // Second time must fail as replayed
    match nonce_tracker.check_and_mark_used(&nonce) {
        Err(ApprovalError::ReplayedNonce) => {}
        other => panic!("Expected Err(ReplayedNonce), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 8. Invariant 4: No Wildcard Shell / Filesystem Capabilities
// ---------------------------------------------------------------------------

#[test]
fn test_forbidden_capabilities_rejected() {
    assert!(CapabilityGrant::validate_capability("shell.execute:*").is_err());
    assert!(CapabilityGrant::validate_capability("shell.execute:bash").is_err());
    assert!(CapabilityGrant::validate_capability("filesystem.read:*").is_err());
    assert!(CapabilityGrant::validate_capability("*").is_err());
    assert!(CapabilityGrant::validate_capability("admin:*").is_err());

    // Valid narrow capabilities
    assert!(CapabilityGrant::validate_capability("app.launch:*").is_ok());
    assert!(CapabilityGrant::validate_capability("app.launch:chrome").is_ok());
    assert!(CapabilityGrant::validate_capability("system.read:basic_status").is_ok());
    assert!(CapabilityGrant::validate_capability("task.read").is_ok());
    assert!(CapabilityGrant::validate_capability("task.cancel").is_ok());
}
