//! Tests for Milestone M2 typed command registry, operation schema validation, and risk tiers.
#![forbid(unsafe_code)]

use ciborium::value::Value;
use dumer_proto::error::ProtoError;
use dumer_proto::registry::{
    get_initial_registry, lookup_command, parse_operation, Operation, RiskTier,
    COMMAND_REGISTRY_IDS,
};
use std::collections::BTreeMap;

#[test]
fn test_registry_contains_five_initial_commands() {
    let registry = get_initial_registry();
    assert_eq!(registry.len(), 5);
    assert_eq!(COMMAND_REGISTRY_IDS.len(), 5);

    let system_status = lookup_command("system.status.read").expect("system.status.read exists");
    assert_eq!(system_status.risk, RiskTier::Tier0ReadOnly);
    assert_eq!(system_status.capabilities, vec!["system.read:basic_status"]);
    assert_eq!(system_status.schema_version, 1);

    let app_list =
        lookup_command("application.list_registered").expect("application.list_registered exists");
    assert_eq!(app_list.risk, RiskTier::Tier0ReadOnly);
    assert_eq!(app_list.capabilities, vec!["app.launch:list"]);
    assert_eq!(app_list.schema_version, 1);

    let app_open = lookup_command("application.open").expect("application.open exists");
    assert_eq!(app_open.risk, RiskTier::Tier1ReversibleLocal);
    assert_eq!(app_open.capabilities, vec!["app.launch:*"]);
    assert_eq!(app_open.schema_version, 1);

    let task_status = lookup_command("task.status.read").expect("task.status.read exists");
    assert_eq!(task_status.risk, RiskTier::Tier0ReadOnly);
    assert_eq!(task_status.capabilities, vec!["task.read"]);
    assert_eq!(task_status.schema_version, 1);

    let task_cancel = lookup_command("task.cancel").expect("task.cancel exists");
    assert_eq!(task_cancel.risk, RiskTier::Tier1ReversibleLocal);
    assert_eq!(task_cancel.capabilities, vec!["task.cancel"]);
    assert_eq!(task_cancel.schema_version, 1);
}

#[test]
fn test_unknown_operation_fails_closed() {
    // Invariant 2: Default deny on unknown operations
    assert!(lookup_command("unknown.op").is_none());
    assert!(lookup_command("shell.execute").is_none());
    assert!(lookup_command("cmd.exe").is_none());

    let empty_args = BTreeMap::new();
    let res = parse_operation("unknown.op", &empty_args);
    match res {
        Err(ProtoError::Validation(msg)) => {
            assert!(msg.contains("Unknown operation: unknown.op"));
        }
        other => panic!("Expected ProtoError::Validation, got {:?}", other),
    }
}

#[test]
fn test_application_open_valid_args() {
    let mut args = BTreeMap::new();
    args.insert("app_id".to_string(), Value::Text("chrome".to_string()));

    let op = parse_operation("application.open", &args).expect("valid parse");
    match op {
        Operation::ApplicationOpen(args) => {
            assert_eq!(args.app_id, "chrome");
        }
        _ => panic!("Expected Operation::ApplicationOpen"),
    }
}

#[test]
fn test_application_open_rejects_path_traversal_and_injection() {
    let too_long = "a".repeat(65);
    let malicious_inputs = [
        "../cmd.exe",
        "..\\notepad.exe",
        "/bin/sh",
        "chrome; calc.exe",
        "chrome & calc",
        "chrome | calc",
        "chrome\0injection",
        too_long.as_str(), // Exceeds max length of 64 chars
        "",                // Empty ID
    ];

    for bad_id in &malicious_inputs {
        let mut args = BTreeMap::new();
        args.insert("app_id".to_string(), Value::Text(bad_id.to_string()));

        let res = parse_operation("application.open", &args);
        assert!(
            res.is_err(),
            "Expected error for malicious/invalid app_id '{}', but got: {:?}",
            bad_id,
            res
        );
    }
}

#[test]
fn test_application_open_rejects_unknown_fields() {
    let mut args = BTreeMap::new();
    args.insert("app_id".to_string(), Value::Text("chrome".to_string()));
    args.insert(
        "extra_flag".to_string(),
        Value::Text("--danger".to_string()),
    );

    let res = parse_operation("application.open", &args);
    assert!(
        res.is_err(),
        "Expected strict rejection of unknown field 'extra_flag'"
    );
}

#[test]
fn test_task_operations_parse_valid_and_invalid() {
    let mut args = BTreeMap::new();
    let task_id_bytes = [42u8; 16];
    args.insert("task_id".to_string(), Value::Bytes(task_id_bytes.to_vec()));

    let op = parse_operation("task.status.read", &args).expect("valid parse");
    match op {
        Operation::TaskStatusRead(t_args) => {
            assert_eq!(t_args.task_id, task_id_bytes);
        }
        _ => panic!("Expected Operation::TaskStatusRead"),
    }

    let op_cancel = parse_operation("task.cancel", &args).expect("valid parse");
    match op_cancel {
        Operation::TaskCancel(t_args) => {
            assert_eq!(t_args.task_id, task_id_bytes);
        }
        _ => panic!("Expected Operation::TaskCancel"),
    }

    // Invalid length task_id
    let mut bad_args = BTreeMap::new();
    bad_args.insert(
        "task_id".to_string(),
        Value::Bytes(vec![1, 2, 3]), // 3 bytes instead of 16
    );
    assert!(parse_operation("task.cancel", &bad_args).is_err());
}

#[test]
fn test_system_status_and_app_list_empty_args() {
    let empty_args = BTreeMap::new();

    let op_sys = parse_operation("system.status.read", &empty_args).expect("system.status parse");
    assert!(matches!(op_sys, Operation::SystemStatusRead(_)));

    let op_apps =
        parse_operation("application.list_registered", &empty_args).expect("app list parse");
    assert!(matches!(op_apps, Operation::ApplicationListRegistered(_)));

    // Unknown field should fail
    let mut bad_args = BTreeMap::new();
    bad_args.insert("unknown".to_string(), Value::Text("bad".to_string()));
    assert!(parse_operation("system.status.read", &bad_args).is_err());
    assert!(parse_operation("application.list_registered", &bad_args).is_err());
}
