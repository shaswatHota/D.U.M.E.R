//! Platform adapter typed data structures.

use serde::{Deserialize, Serialize};

/// Result of launching a registered application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchResult {
    pub pid: u32,
    pub app_id: String,
}

/// Basic operating system and runner status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemBasicStatus {
    pub is_unprivileged: bool,
    pub is_locked: bool,
    pub os_family: String,
    pub hostname: String,
    pub uptime_seconds: u64,
}

/// Urgency level for notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationUrgency {
    Low,
    Normal,
    High,
}

/// Notification payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notification {
    pub title: String,
    pub message: String,
    pub urgency: NotificationUrgency,
}

/// Workstation session lock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    Unlocked,
    Locked,
    Unknown,
}
