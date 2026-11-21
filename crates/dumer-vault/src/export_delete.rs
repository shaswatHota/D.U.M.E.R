use crate::db::EncryptedDatabase;
use crate::error::VaultError;
use crate::models::{AuditEventRecord, DeviceRecord, TaskRecord};
use crate::vault::VaultManager;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRecordExport {
    pub record_id: String,
    pub memory_class: String,
    pub source: String,
    pub sensitivity: String,
    pub provenance: String,
    pub taint: String,
    pub key: String,
    pub value_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItemExport {
    pub label: String,
    pub destination_allowlist: Vec<String>,
    pub secret: String,
    pub is_canary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundle {
    pub exported_at: u64,
    pub devices: Vec<DeviceRecord>,
    pub tasks: Vec<TaskRecord>,
    pub memory_records: Vec<MemoryRecordExport>,
    pub vault_items: Vec<VaultItemExport>,
    pub audit_events: Vec<AuditEventRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeletionReport {
    pub deleted_memory_records: usize,
    pub deleted_cache_entries: usize,
}

/// Exports user state to a structured export bundle.
///
/// If `export_vault_secrets` is true, requires an unlocked vault. If locked, fails closed.
/// If `export_vault_secrets` is false, vault secrets are safely omitted (`[REDACTED / LOCKED]`).
pub fn export_data(
    db: &EncryptedDatabase,
    vault: &VaultManager,
    export_vault_secrets: bool,
) -> Result<ExportBundle, VaultError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let devices = db.list_devices()?;
    let tasks = db.list_tasks()?;
    let audit_events = db.list_audit_events()?;

    let raw_vault_items = db.list_vault_items()?;
    let mut vault_items = Vec::new();

    for item in raw_vault_items {
        let secret = if export_vault_secrets {
            if !vault.is_unlocked() {
                return Err(VaultError::VaultLocked);
            }
            let secret_bytes = vault.read_secret(db, &item.label)?;
            String::from_utf8_lossy(&secret_bytes).to_string()
        } else {
            "[VAULT SECRET REDACTED]".to_string()
        };

        vault_items.push(VaultItemExport {
            label: item.label,
            destination_allowlist: item.destination_allowlist,
            secret,
            is_canary: item.is_canary,
        });
    }

    Ok(ExportBundle {
        exported_at: now,
        devices,
        tasks,
        memory_records: Vec::new(),
        vault_items,
        audit_events,
    })
}

/// Deletes a memory record and cascades deletion to linked cache entries and derived artifacts.
pub fn cascade_delete_memory_record(
    db: &EncryptedDatabase,
    record_id: &str,
) -> Result<DeletionReport, VaultError> {
    let record = match db.get_memory_record(record_id)? {
        Some(r) => r,
        None => {
            return Ok(DeletionReport {
                deleted_memory_records: 0,
                deleted_cache_entries: 0,
            })
        }
    };

    let deleted_memory_records = if db.delete_memory_record(record_id)? {
        1
    } else {
        0
    };

    // Cascade deletion to cache entries matching record's source or provenance
    let mut deleted_cache_entries = 0;
    if !record.source.is_empty() {
        deleted_cache_entries += db.delete_cache_by_url_prefix(&record.source)?;
    }
    if !record.provenance.is_empty() && record.provenance != record.source {
        deleted_cache_entries += db.delete_cache_by_url_prefix(&record.provenance)?;
    }

    Ok(DeletionReport {
        deleted_memory_records,
        deleted_cache_entries,
    })
}
