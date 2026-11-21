//! Identity, device state, and budget types.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::error::DenyReason;

/// Requesting principal identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Principal {
    /// Local interactive user on the host PC (CLI, desktop, tray).
    LocalUser,

    /// Enrolled remote device (phone companion, satellite).
    Device { device_id: String },

    /// Local voice interface (Push-to-Talk or dictation).
    Voice { speaker_id: Option<String> },

    /// Local LLM planner proposing an autonomous step.
    Planner { playbook_id: Option<String> },

    /// Scheduled background playbook task.
    Scheduled { playbook_id: String },
}

impl Principal {
    /// Returns the subject string used for capability grant matching.
    pub fn subject_id(&self) -> String {
        match self {
            Principal::LocalUser => "local_user".to_string(),
            Principal::Device { device_id } => device_id.clone(),
            Principal::Voice { speaker_id } => {
                speaker_id.clone().unwrap_or_else(|| "voice".to_string())
            }
            Principal::Planner { .. } => "planner".to_string(),
            Principal::Scheduled { playbook_id } => format!("scheduled:{}", playbook_id),
        }
    }

    /// Whether this principal represents autonomous/background execution.
    pub fn is_autonomous(&self) -> bool {
        matches!(
            self,
            Principal::Planner { .. } | Principal::Scheduled { .. }
        )
    }
}

/// Role of an enrolled device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRole {
    PhoneCompanion,
    SatelliteNode,
    DesktopTray,
}

/// Recorded state of a device known to the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceState {
    pub device_id: String,
    pub role: DeviceRole,
    pub is_enrolled: bool,
    pub is_revoked: bool,
}

/// Task execution budget constraints (steps, deadline, tool calls).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBudget {
    pub remaining_steps: Option<u32>,
    pub deadline: Option<u64>,
    pub max_tool_calls: Option<u32>,
}

impl TaskBudget {
    /// Checks whether the budget permits another execution step.
    pub fn check(&self, current_time: u64) -> Result<(), DenyReason> {
        if let Some(steps) = self.remaining_steps {
            if steps == 0 {
                return Err(DenyReason::BudgetExhausted(
                    "Remaining step budget exhausted (0 steps remaining)".to_string(),
                ));
            }
        }

        if let Some(deadline) = self.deadline {
            if current_time > deadline {
                return Err(DenyReason::BudgetExhausted(format!(
                    "Task deadline exceeded (current: {}, deadline: {})",
                    current_time, deadline
                )));
            }
        }

        if let Some(calls) = self.max_tool_calls {
            if calls == 0 {
                return Err(DenyReason::BudgetExhausted(
                    "Max tool calls budget exhausted".to_string(),
                ));
            }
        }

        Ok(())
    }
}
