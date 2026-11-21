use crate::error::VaultError;
use crate::models::{
    ApprovalRecord, AuditEventRecord, CacheEntry, DeviceRecord, FreshnessClass, GrantRecord,
    MemoryClass, MemoryRecord, TaskRecord, VaultItem,
};
use crate::schema::apply_migrations;
use dumer_crypto::{decrypt_xchacha20, encrypt_xchacha20, Key256};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

/// Encrypted database manager handling persistent state and DEK-encrypted records.
pub struct EncryptedDatabase {
    conn: Mutex<Connection>,
    dek: Key256,
}

impl EncryptedDatabase {
    /// Opens an in-memory encrypted database (primarily for testing and transient sessions).
    pub fn open_in_memory(dek: Key256) -> Result<Self, VaultError> {
        let conn = Connection::open_in_memory()?;
        apply_migrations(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            dek,
        })
    }

    /// Opens or creates an encrypted database file on disk.
    pub fn open_file<P: AsRef<Path>>(path: P, dek: Key256) -> Result<Self, VaultError> {
        let conn = Connection::open(path)?;
        // Enable WAL mode for concurrency and reliability
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        apply_migrations(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            dek,
        })
    }

    /// Accessor for the active DEK.
    pub fn dek(&self) -> &Key256 {
        &self.dek
    }

    // -------------------------------------------------------------------------
    // Devices
    // -------------------------------------------------------------------------

    pub fn insert_device(&self, device: &DeviceRecord) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        let caps_json = serde_json::to_string(&device.capabilities)?;
        conn.execute(
            "INSERT INTO devices (device_id, display_name, public_key, enrolled_at, last_seen_at, is_revoked, capabilities)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(device_id) DO UPDATE SET
                display_name = excluded.display_name,
                public_key = excluded.public_key,
                last_seen_at = excluded.last_seen_at,
                is_revoked = excluded.is_revoked,
                capabilities = excluded.capabilities",
            params![
                device.device_id,
                device.display_name,
                device.public_key,
                device.enrolled_at as i64,
                device.last_seen_at as i64,
                if device.is_revoked { 1 } else { 0 },
                caps_json
            ],
        )?;
        Ok(())
    }

    pub fn get_device(&self, device_id: &str) -> Result<Option<DeviceRecord>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, display_name, public_key, enrolled_at, last_seen_at, is_revoked, capabilities
             FROM devices WHERE device_id = ?1",
        )?;

        let mut rows = stmt.query(params![device_id])?;
        if let Some(row) = rows.next()? {
            let caps_json: String = row.get(6)?;
            let capabilities = serde_json::from_str(&caps_json)?;
            Ok(Some(DeviceRecord {
                device_id: row.get(0)?,
                display_name: row.get(1)?,
                public_key: row.get(2)?,
                enrolled_at: row.get::<_, i64>(3)? as u64,
                last_seen_at: row.get::<_, i64>(4)? as u64,
                is_revoked: row.get::<_, i32>(5)? != 0,
                capabilities,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn revoke_device(&self, device_id: &str) -> Result<bool, VaultError> {
        let conn = self.conn.lock().unwrap();
        let rows_affected = conn.execute(
            "UPDATE devices SET is_revoked = 1 WHERE device_id = ?1",
            params![device_id],
        )?;
        Ok(rows_affected > 0)
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, display_name, public_key, enrolled_at, last_seen_at, is_revoked, capabilities
             FROM devices ORDER BY enrolled_at ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            let caps_json: String = row.get(6)?;
            let capabilities = serde_json::from_str(&caps_json).unwrap_or_default();
            Ok(DeviceRecord {
                device_id: row.get(0)?,
                display_name: row.get(1)?,
                public_key: row.get(2)?,
                enrolled_at: row.get::<_, i64>(3)? as u64,
                last_seen_at: row.get::<_, i64>(4)? as u64,
                is_revoked: row.get::<_, i32>(5)? != 0,
                capabilities,
            })
        })?;

        let mut devices = Vec::new();
        for dev in rows {
            devices.push(dev?);
        }
        Ok(devices)
    }

    // -------------------------------------------------------------------------
    // Tasks
    // -------------------------------------------------------------------------

    pub fn insert_task(&self, task: &TaskRecord) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO tasks (task_id, created_at, updated_at, status, intent, risk_tier, budget_json, result_summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(task_id) DO UPDATE SET
                updated_at = excluded.updated_at,
                status = excluded.status,
                result_summary = excluded.result_summary",
            params![
                task.task_id,
                task.created_at as i64,
                task.updated_at as i64,
                task.status,
                task.intent,
                task.risk_tier,
                task.budget_json,
                task.result_summary
            ],
        )?;
        Ok(())
    }

    pub fn get_task(&self, task_id: &str) -> Result<Option<TaskRecord>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT task_id, created_at, updated_at, status, intent, risk_tier, budget_json, result_summary
             FROM tasks WHERE task_id = ?1",
        )?;

        let mut rows = stmt.query(params![task_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(TaskRecord {
                task_id: row.get(0)?,
                created_at: row.get::<_, i64>(1)? as u64,
                updated_at: row.get::<_, i64>(2)? as u64,
                status: row.get(3)?,
                intent: row.get(4)?,
                risk_tier: row.get(5)?,
                budget_json: row.get(6)?,
                result_summary: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_tasks(&self) -> Result<Vec<TaskRecord>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT task_id, created_at, updated_at, status, intent, risk_tier, budget_json, result_summary
             FROM tasks ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(TaskRecord {
                task_id: row.get(0)?,
                created_at: row.get::<_, i64>(1)? as u64,
                updated_at: row.get::<_, i64>(2)? as u64,
                status: row.get(3)?,
                intent: row.get(4)?,
                risk_tier: row.get(5)?,
                budget_json: row.get(6)?,
                result_summary: row.get(7)?,
            })
        })?;

        let mut tasks = Vec::new();
        for t in rows {
            tasks.push(t?);
        }
        Ok(tasks)
    }

    // -------------------------------------------------------------------------
    // Memory Records (Encrypted with DEK)
    // -------------------------------------------------------------------------

    pub fn insert_memory_record(&self, record: &MemoryRecord) -> Result<(), VaultError> {
        let (ciphertext, nonce) = encrypt_xchacha20(&self.dek, &record.value, b"memory_record")?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO memory_records (
                record_id, memory_class, source, confidence, sensitivity, retention,
                provenance, taint, key, ciphertext, nonce, created_at, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(record_id) DO UPDATE SET
                confidence = excluded.confidence,
                sensitivity = excluded.sensitivity,
                retention = excluded.retention,
                provenance = excluded.provenance,
                taint = excluded.taint,
                ciphertext = excluded.ciphertext,
                nonce = excluded.nonce,
                expires_at = excluded.expires_at",
            params![
                record.record_id,
                record.memory_class.as_str(),
                record.source,
                record.confidence,
                record.sensitivity,
                record.retention,
                record.provenance,
                record.taint,
                record.key,
                ciphertext,
                nonce.to_vec(),
                record.created_at as i64,
                record.expires_at.map(|e| e as i64)
            ],
        )?;
        Ok(())
    }

    pub fn get_memory_record(&self, record_id: &str) -> Result<Option<MemoryRecord>, VaultError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT record_id, memory_class, source, confidence, sensitivity, retention,
                    provenance, taint, key, ciphertext, nonce, created_at, expires_at
             FROM memory_records
             WHERE record_id = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
        )?;

        let mut rows = stmt.query(params![record_id, now])?;
        if let Some(row) = rows.next()? {
            let class_str: String = row.get(1)?;
            let memory_class = MemoryClass::from_str_opt(&class_str).unwrap_or(MemoryClass::Config);
            let ciphertext: Vec<u8> = row.get(9)?;
            let nonce_vec: Vec<u8> = row.get(10)?;
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&nonce_vec);

            let value = decrypt_xchacha20(&self.dek, &ciphertext, &nonce, b"memory_record")?;

            Ok(Some(MemoryRecord {
                record_id: row.get(0)?,
                memory_class,
                source: row.get(2)?,
                confidence: row.get(3)?,
                sensitivity: row.get(4)?,
                retention: row.get(5)?,
                provenance: row.get(6)?,
                taint: row.get(7)?,
                key: row.get(8)?,
                value,
                created_at: row.get::<_, i64>(11)? as u64,
                expires_at: row.get::<_, Option<i64>>(12)?.map(|e| e as u64),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn find_memory_record_by_key(
        &self,
        class: MemoryClass,
        key: &str,
    ) -> Result<Option<MemoryRecord>, VaultError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT record_id, memory_class, source, confidence, sensitivity, retention,
                    provenance, taint, key, ciphertext, nonce, created_at, expires_at
             FROM memory_records
             WHERE memory_class = ?1 AND key = ?2 AND (expires_at IS NULL OR expires_at > ?3)
             ORDER BY created_at DESC LIMIT 1",
        )?;

        let mut rows = stmt.query(params![class.as_str(), key, now])?;
        if let Some(row) = rows.next()? {
            let class_str: String = row.get(1)?;
            let memory_class = MemoryClass::from_str_opt(&class_str).unwrap_or(class);
            let ciphertext: Vec<u8> = row.get(9)?;
            let nonce_vec: Vec<u8> = row.get(10)?;
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&nonce_vec);

            let value = decrypt_xchacha20(&self.dek, &ciphertext, &nonce, b"memory_record")?;

            Ok(Some(MemoryRecord {
                record_id: row.get(0)?,
                memory_class,
                source: row.get(2)?,
                confidence: row.get(3)?,
                sensitivity: row.get(4)?,
                retention: row.get(5)?,
                provenance: row.get(6)?,
                taint: row.get(7)?,
                key: row.get(8)?,
                value,
                created_at: row.get::<_, i64>(11)? as u64,
                expires_at: row.get::<_, Option<i64>>(12)?.map(|e| e as u64),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn delete_memory_record(&self, record_id: &str) -> Result<bool, VaultError> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM memory_records WHERE record_id = ?1",
            params![record_id],
        )?;
        Ok(rows > 0)
    }

    pub fn purge_expired_memory_records(&self) -> Result<usize, VaultError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let conn = self.conn.lock().unwrap();
        let count = conn.execute(
            "DELETE FROM memory_records WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?;
        Ok(count)
    }

    // -------------------------------------------------------------------------
    // Grants
    // -------------------------------------------------------------------------

    pub fn insert_grant(&self, grant: &GrantRecord) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO grants (grant_id, subject, operation, resource, argument_constraints, risk_tier, approval_ref, issued_at, expires_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(grant_id) DO UPDATE SET
                revoked = excluded.revoked",
            params![
                grant.grant_id,
                grant.subject,
                grant.operation,
                grant.resource,
                grant.argument_constraints,
                grant.risk_tier,
                grant.approval_ref,
                grant.issued_at as i64,
                grant.expires_at as i64,
                if grant.revoked { 1 } else { 0 }
            ],
        )?;
        Ok(())
    }

    pub fn get_grant(&self, grant_id: &str) -> Result<Option<GrantRecord>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT grant_id, subject, operation, resource, argument_constraints, risk_tier, approval_ref, issued_at, expires_at, revoked
             FROM grants WHERE grant_id = ?1",
        )?;

        let mut rows = stmt.query(params![grant_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(GrantRecord {
                grant_id: row.get(0)?,
                subject: row.get(1)?,
                operation: row.get(2)?,
                resource: row.get(3)?,
                argument_constraints: row.get(4)?,
                risk_tier: row.get(5)?,
                approval_ref: row.get(6)?,
                issued_at: row.get::<_, i64>(7)? as u64,
                expires_at: row.get::<_, i64>(8)? as u64,
                revoked: row.get::<_, i32>(9)? != 0,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn revoke_grant(&self, grant_id: &str) -> Result<bool, VaultError> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "UPDATE grants SET revoked = 1 WHERE grant_id = ?1",
            params![grant_id],
        )?;
        Ok(rows > 0)
    }

    // -------------------------------------------------------------------------
    // Approvals
    // -------------------------------------------------------------------------

    pub fn insert_approval(&self, approval: &ApprovalRecord) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO approvals (approval_id, request_hash, nonce, device_id, risk_tier, approver_identity, signature, issued_at, expires_at, used)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                approval.approval_id,
                approval.request_hash,
                approval.nonce,
                approval.device_id,
                approval.risk_tier,
                approval.approver_identity,
                approval.signature,
                approval.issued_at as i64,
                approval.expires_at as i64,
                if approval.used { 1 } else { 0 }
            ],
        )?;
        Ok(())
    }

    pub fn get_approval(&self, approval_id: &str) -> Result<Option<ApprovalRecord>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT approval_id, request_hash, nonce, device_id, risk_tier, approver_identity, signature, issued_at, expires_at, used
             FROM approvals WHERE approval_id = ?1",
        )?;

        let mut rows = stmt.query(params![approval_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(ApprovalRecord {
                approval_id: row.get(0)?,
                request_hash: row.get(1)?,
                nonce: row.get(2)?,
                device_id: row.get(3)?,
                risk_tier: row.get(4)?,
                approver_identity: row.get(5)?,
                signature: row.get(6)?,
                issued_at: row.get::<_, i64>(7)? as u64,
                expires_at: row.get::<_, i64>(8)? as u64,
                used: row.get::<_, i32>(9)? != 0,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn mark_approval_used(&self, approval_id: &str) -> Result<bool, VaultError> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "UPDATE approvals SET used = 1 WHERE approval_id = ?1",
            params![approval_id],
        )?;
        Ok(rows > 0)
    }

    // -------------------------------------------------------------------------
    // Cache Entries (Encrypted with DEK)
    // -------------------------------------------------------------------------

    pub fn insert_cache_entry(&self, entry: &CacheEntry) -> Result<(), VaultError> {
        let (ciphertext, nonce) = encrypt_xchacha20(&self.dek, &entry.content, b"cache_entry")?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO cache_entries (
                cache_key, url, fetched_at, freshness_class, ttl_seconds, expires_at,
                content_hash, taint, ciphertext, nonce, user_pinned
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(cache_key) DO UPDATE SET
                fetched_at = excluded.fetched_at,
                freshness_class = excluded.freshness_class,
                ttl_seconds = excluded.ttl_seconds,
                expires_at = excluded.expires_at,
                content_hash = excluded.content_hash,
                taint = excluded.taint,
                ciphertext = excluded.ciphertext,
                nonce = excluded.nonce,
                user_pinned = excluded.user_pinned",
            params![
                entry.cache_key,
                entry.url,
                entry.fetched_at as i64,
                entry.freshness_class.as_str(),
                entry.ttl_seconds as i64,
                entry.expires_at as i64,
                entry.content_hash,
                entry.taint,
                ciphertext,
                nonce.to_vec(),
                if entry.user_pinned { 1 } else { 0 }
            ],
        )?;
        Ok(())
    }

    pub fn get_cache_entry(&self, cache_key: &str) -> Result<Option<CacheEntry>, VaultError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT cache_key, url, fetched_at, freshness_class, ttl_seconds, expires_at,
                    content_hash, taint, ciphertext, nonce, user_pinned
             FROM cache_entries
             WHERE cache_key = ?1 AND expires_at > ?2",
        )?;

        let mut rows = stmt.query(params![cache_key, now])?;
        if let Some(row) = rows.next()? {
            let class_str: String = row.get(3)?;
            let freshness_class =
                FreshnessClass::from_str_opt(&class_str).unwrap_or(FreshnessClass::Slow);
            let ciphertext: Vec<u8> = row.get(8)?;
            let nonce_vec: Vec<u8> = row.get(9)?;
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&nonce_vec);

            let content = decrypt_xchacha20(&self.dek, &ciphertext, &nonce, b"cache_entry")?;

            Ok(Some(CacheEntry {
                cache_key: row.get(0)?,
                url: row.get(1)?,
                fetched_at: row.get::<_, i64>(2)? as u64,
                freshness_class,
                ttl_seconds: row.get::<_, i64>(4)? as u64,
                expires_at: row.get::<_, i64>(5)? as u64,
                content_hash: row.get(6)?,
                taint: row.get(7)?,
                content,
                user_pinned: row.get::<_, i32>(10)? != 0,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn purge_expired_cache(&self) -> Result<usize, VaultError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let conn = self.conn.lock().unwrap();
        let count = conn.execute(
            "DELETE FROM cache_entries WHERE expires_at <= ?1",
            params![now],
        )?;
        Ok(count)
    }

    pub fn delete_cache_by_url_prefix(&self, url_prefix: &str) -> Result<usize, VaultError> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute(
            "DELETE FROM cache_entries WHERE url LIKE ?1 || '%'",
            params![url_prefix],
        )?;
        Ok(count)
    }

    // -------------------------------------------------------------------------
    // Vault Items (Raw ciphertext/nonce encrypted with separate VaultKey)
    // -------------------------------------------------------------------------

    pub fn insert_vault_item(&self, item: &VaultItem) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        let allowlist_json = serde_json::to_string(&item.destination_allowlist)?;

        conn.execute(
            "INSERT INTO vault_items (item_id, label, destination_allowlist, ciphertext, nonce, created_at, updated_at, is_canary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(label) DO UPDATE SET
                destination_allowlist = excluded.destination_allowlist,
                ciphertext = excluded.ciphertext,
                nonce = excluded.nonce,
                updated_at = excluded.updated_at,
                is_canary = excluded.is_canary",
            params![
                item.item_id,
                item.label,
                allowlist_json,
                item.ciphertext,
                item.nonce.to_vec(),
                item.created_at as i64,
                item.updated_at as i64,
                if item.is_canary { 1 } else { 0 }
            ],
        )?;
        Ok(())
    }

    pub fn get_vault_item_by_label(&self, label: &str) -> Result<Option<VaultItem>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT item_id, label, destination_allowlist, ciphertext, nonce, created_at, updated_at, is_canary
             FROM vault_items WHERE label = ?1",
        )?;

        let mut rows = stmt.query(params![label])?;
        if let Some(row) = rows.next()? {
            let allowlist_json: String = row.get(2)?;
            let destination_allowlist = serde_json::from_str(&allowlist_json)?;
            let nonce_vec: Vec<u8> = row.get(4)?;
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&nonce_vec);

            Ok(Some(VaultItem {
                item_id: row.get(0)?,
                label: row.get(1)?,
                destination_allowlist,
                ciphertext: row.get(3)?,
                nonce,
                created_at: row.get::<_, i64>(5)? as u64,
                updated_at: row.get::<_, i64>(6)? as u64,
                is_canary: row.get::<_, i32>(7)? != 0,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_vault_items(&self) -> Result<Vec<VaultItem>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT item_id, label, destination_allowlist, ciphertext, nonce, created_at, updated_at, is_canary
             FROM vault_items ORDER BY created_at ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            let allowlist_json: String = row.get(2)?;
            let destination_allowlist = serde_json::from_str(&allowlist_json).unwrap_or_default();
            let nonce_vec: Vec<u8> = row.get(4)?;
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&nonce_vec);

            Ok(VaultItem {
                item_id: row.get(0)?,
                label: row.get(1)?,
                destination_allowlist,
                ciphertext: row.get(3)?,
                nonce,
                created_at: row.get::<_, i64>(5)? as u64,
                updated_at: row.get::<_, i64>(6)? as u64,
                is_canary: row.get::<_, i32>(7)? != 0,
            })
        })?;

        let mut items = Vec::new();
        for item in rows {
            items.push(item?);
        }
        Ok(items)
    }

    pub fn delete_vault_item(&self, label: &str) -> Result<bool, VaultError> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute("DELETE FROM vault_items WHERE label = ?1", params![label])?;
        Ok(count > 0)
    }

    // -------------------------------------------------------------------------
    // Audit Events
    // -------------------------------------------------------------------------

    pub fn insert_audit_event(&self, event: &AuditEventRecord) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_events (seq, event_id, timestamp, event_type, prev_hash, event_hash, payload_cbor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.seq as i64,
                event.event_id,
                event.timestamp as i64,
                event.event_type,
                event.prev_hash,
                event.event_hash,
                event.payload_cbor
            ],
        )?;
        Ok(())
    }

    pub fn list_audit_events(&self) -> Result<Vec<AuditEventRecord>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT seq, event_id, timestamp, event_type, prev_hash, event_hash, payload_cbor
             FROM audit_events ORDER BY seq ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(AuditEventRecord {
                seq: row.get::<_, i64>(0)? as u64,
                event_id: row.get(1)?,
                timestamp: row.get::<_, i64>(2)? as u64,
                event_type: row.get(3)?,
                prev_hash: row.get(4)?,
                event_hash: row.get(5)?,
                payload_cbor: row.get(6)?,
            })
        })?;

        let mut events = Vec::new();
        for ev in rows {
            events.push(ev?);
        }
        Ok(events)
    }
}
