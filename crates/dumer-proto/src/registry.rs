//! Command registry definitions, typed operations, and schema validation.
#![forbid(unsafe_code)]

use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::ProtoError;

/// Risk tier levels defined by D.U.M.E.R security architecture §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Tier 0: Read-only local queries (time, status, list apps). Default: autonomous.
    Tier0ReadOnly = 0,
    /// Tier 1: Reversible local actions (open app, create draft note). Default: autonomous if allowlisted.
    Tier1ReversibleLocal = 1,
    /// Tier 2: Meaningful state changes (move/rename files). Requires undo journal.
    Tier2MeaningfulChange = 2,
    /// Tier 3: Sensitive operations (messaging, vault access, security settings). Explicit approval required.
    Tier3Sensitive = 3,
    /// Tier 4: Privileged/destructive operations (elevation, firewall, service control). PC + Phone dual approval required.
    Tier4Privileged = 4,
}

impl RiskTier {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn from_u8(val: u8) -> Result<Self, ProtoError> {
        match val {
            0 => Ok(RiskTier::Tier0ReadOnly),
            1 => Ok(RiskTier::Tier1ReversibleLocal),
            2 => Ok(RiskTier::Tier2MeaningfulChange),
            3 => Ok(RiskTier::Tier3Sensitive),
            4 => Ok(RiskTier::Tier4Privileged),
            other => Err(ProtoError::Validation(format!(
                "Invalid risk tier value: {}",
                other
            ))),
        }
    }
}

/// Metadata definition of an authorized command in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDefinition {
    pub id: String,
    pub risk: RiskTier,
    pub capabilities: Vec<String>,
    pub schema_version: u32,
}

/// Arguments for `system.status.read`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemStatusArgs {
    #[serde(default)]
    pub detail_level: Option<String>,
}

/// Arguments for `application.list_registered`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListRegisteredArgs {}

/// Arguments for `application.open`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationOpenArgs {
    pub app_id: String,
}

impl ApplicationOpenArgs {
    /// Validates the `app_id` argument.
    ///
    /// Rules:
    /// 1. 1..=64 characters in length.
    /// 2. Only ASCII lowercase alphanumeric, `_`, `-`, or `.`.
    /// 3. Cannot start with `.`, cannot contain `..`, `/`, `\`, null bytes, or whitespace.
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.app_id.is_empty() {
            return Err(ProtoError::Validation("app_id cannot be empty".to_string()));
        }
        if self.app_id.len() > 64 {
            return Err(ProtoError::Validation(format!(
                "app_id exceeds maximum length of 64 bytes (got {})",
                self.app_id.len()
            )));
        }
        if self.app_id.starts_with('.') || self.app_id.contains("..") {
            return Err(ProtoError::Validation(
                "app_id cannot start with '.' or contain '..' (path traversal prohibited)"
                    .to_string(),
            ));
        }

        for ch in self.app_id.chars() {
            if !(ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || ch == '_'
                || ch == '-'
                || ch == '.')
            {
                return Err(ProtoError::Validation(format!(
                    "app_id contains illegal character '{}': only [a-z0-9_.-] allowed",
                    ch
                )));
            }
        }

        Ok(())
    }
}

/// Arguments for `task.status.read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskStatusArgs {
    pub task_id: [u8; 16],
}

/// Arguments for `task.cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCancelArgs {
    pub task_id: [u8; 16],
}

/// Strongly-typed operation payload.
///
/// Invariant 4: No arbitrary shell or arbitrary executable execution variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "args", rename_all = "snake_case")]
pub enum Operation {
    #[serde(rename = "system.status.read")]
    SystemStatusRead(SystemStatusArgs),

    #[serde(rename = "application.list_registered")]
    ApplicationListRegistered(ApplicationListRegisteredArgs),

    #[serde(rename = "application.open")]
    ApplicationOpen(ApplicationOpenArgs),

    #[serde(rename = "task.status.read")]
    TaskStatusRead(TaskStatusArgs),

    #[serde(rename = "task.cancel")]
    TaskCancel(TaskCancelArgs),
}

/// Static list of initial 5 command IDs.
pub static COMMAND_REGISTRY_IDS: &[&str] = &[
    "system.status.read",
    "application.list_registered",
    "application.open",
    "task.status.read",
    "task.cancel",
];

/// Known registered application aliases and canonical IDs.
pub static REGISTERED_APPS: &[(&str, &str)] = &[
    ("chrome", "chrome"),
    ("google chrome", "chrome"),
    ("google-chrome", "chrome"),
    ("firefox", "firefox"),
    ("mozilla firefox", "firefox"),
    ("terminal", "terminal"),
    ("windows terminal", "terminal"),
    ("calc", "calc"),
    ("calculator", "calc"),
    ("notepad", "notepad"),
];

/// Initial 5 static command definitions.
pub fn get_initial_registry() -> [CommandDefinition; 5] {
    [
        CommandDefinition {
            id: "system.status.read".to_string(),
            risk: RiskTier::Tier0ReadOnly,
            capabilities: vec!["system.read:basic_status".to_string()],
            schema_version: 1,
        },
        CommandDefinition {
            id: "application.list_registered".to_string(),
            risk: RiskTier::Tier0ReadOnly,
            capabilities: vec!["app.launch:list".to_string()],
            schema_version: 1,
        },
        CommandDefinition {
            id: "application.open".to_string(),
            risk: RiskTier::Tier1ReversibleLocal,
            capabilities: vec!["app.launch:*".to_string()],
            schema_version: 1,
        },
        CommandDefinition {
            id: "task.status.read".to_string(),
            risk: RiskTier::Tier0ReadOnly,
            capabilities: vec!["task.read".to_string()],
            schema_version: 1,
        },
        CommandDefinition {
            id: "task.cancel".to_string(),
            risk: RiskTier::Tier1ReversibleLocal,
            capabilities: vec!["task.cancel".to_string()],
            schema_version: 1,
        },
    ]
}

/// Global registry lookup.
pub fn lookup_command(id: &str) -> Option<CommandDefinition> {
    get_initial_registry().into_iter().find(|cmd| cmd.id == id)
}

/// Parses an operation ID and argument map into a typed `Operation`.
///
/// Fails closed if the operation is unknown or if arguments do not strictly match
/// the schema (including rejection of unknown fields).
pub fn parse_operation(op: &str, args: &BTreeMap<String, Value>) -> Result<Operation, ProtoError> {
    // 1. Check registry existence (Invariant 2: Default deny)
    if lookup_command(op).is_none() {
        return Err(ProtoError::Validation(format!("Unknown operation: {}", op)));
    }

    match op {
        "system.status.read" => {
            let mut detail_level = None;
            for (k, v) in args {
                match k.as_str() {
                    "detail_level" => match v {
                        Value::Text(s) => detail_level = Some(s.clone()),
                        _ => {
                            return Err(ProtoError::Validation(
                                "detail_level must be a string".to_string(),
                            ))
                        }
                    },
                    unknown => {
                        return Err(ProtoError::Validation(format!(
                            "Unknown field for system.status.read: {}",
                            unknown
                        )))
                    }
                }
            }
            Ok(Operation::SystemStatusRead(SystemStatusArgs {
                detail_level,
            }))
        }
        "application.list_registered" => {
            if !args.is_empty() {
                let first_key = args.keys().next().unwrap();
                return Err(ProtoError::Validation(format!(
                    "Unknown field for application.list_registered: {}",
                    first_key
                )));
            }
            Ok(Operation::ApplicationListRegistered(
                ApplicationListRegisteredArgs {},
            ))
        }
        "application.open" => {
            let mut app_id = None;
            for (k, v) in args {
                match k.as_str() {
                    "app_id" => match v {
                        Value::Text(s) => app_id = Some(s.clone()),
                        _ => {
                            return Err(ProtoError::Validation(
                                "app_id must be a string".to_string(),
                            ))
                        }
                    },
                    unknown => {
                        return Err(ProtoError::Validation(format!(
                            "Unknown field for application.open: {}",
                            unknown
                        )))
                    }
                }
            }
            let app_id = app_id.ok_or_else(|| {
                ProtoError::Validation("Missing required argument 'app_id'".to_string())
            })?;
            let parsed_args = ApplicationOpenArgs { app_id };
            parsed_args.validate()?;
            Ok(Operation::ApplicationOpen(parsed_args))
        }
        "task.status.read" => {
            let task_id = extract_task_id(args, "task.status.read")?;
            Ok(Operation::TaskStatusRead(TaskStatusArgs { task_id }))
        }
        "task.cancel" => {
            let task_id = extract_task_id(args, "task.cancel")?;
            Ok(Operation::TaskCancel(TaskCancelArgs { task_id }))
        }
        _ => Err(ProtoError::Validation(format!("Unknown operation: {}", op))),
    }
}

fn extract_task_id(args: &BTreeMap<String, Value>, op: &str) -> Result<[u8; 16], ProtoError> {
    let mut task_id = None;
    for (k, v) in args {
        match k.as_str() {
            "task_id" => match v {
                Value::Bytes(b) => {
                    if b.len() != 16 {
                        return Err(ProtoError::Validation(format!(
                            "task_id bytes must be exactly 16 bytes (got {})",
                            b.len()
                        )));
                    }
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(b);
                    task_id = Some(arr);
                }
                Value::Text(s) => {
                    if s.len() == 32 {
                        let bytes = hex_decode(s).map_err(|e| {
                            ProtoError::Validation(format!("Invalid hex in task_id: {}", e))
                        })?;
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&bytes);
                        task_id = Some(arr);
                    } else {
                        return Err(ProtoError::Validation(
                            "task_id string must be a 32-character hex string".to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(ProtoError::Validation(
                        "task_id must be bytes or a 32-char hex string".to_string(),
                    ))
                }
            },
            unknown => {
                return Err(ProtoError::Validation(format!(
                    "Unknown field for {}: {}",
                    op, unknown
                )))
            }
        }
    }
    task_id.ok_or_else(|| {
        ProtoError::Validation(format!("Missing required argument 'task_id' for {}", op))
    })
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Odd length hex string".to_string());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte_str = &s[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).map_err(|e| e.to_string())?;
        bytes.push(byte);
    }
    Ok(bytes)
}
