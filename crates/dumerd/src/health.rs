//! Structured health records and persistent health state for `dumerd`.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// High-level daemon operational status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonStatus {
    Starting,
    Running,
    ShuttingDown,
    Stopped,
    Degraded,
}

/// Machine-readable health record written by `dumerd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRecord {
    pub daemon_version: String,
    pub status: DaemonStatus,
    pub pid: u32,
    pub started_at: u64,
    pub updated_at: u64,
    pub is_unprivileged: bool,
    pub overlay_bind_addr: String,
    pub last_self_test_passed: bool,
    pub audit_events_count: u64,
    pub audit_head_hash: String,
}

/// Writes health record to a destination JSON file atomically.
pub fn write_health_record(path: &Path, record: &HealthRecord) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(record)?;
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(json.as_bytes())?;
    file.flush()?;
    Ok(())
}

/// Reads health record from a JSON file.
pub fn read_health_record(path: &Path) -> Result<HealthRecord, std::io::Error> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let record: HealthRecord = serde_json::from_str(&contents)?;
    Ok(record)
}
