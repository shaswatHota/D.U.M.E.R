use crate::error::VaultError;
use rusqlite::Connection;

pub const CURRENT_SCHEMA_VERSION: i64 = 1;

pub fn apply_migrations(conn: &Connection) -> Result<(), VaultError> {
    // Enforce SQLite security and performance settings
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA synchronous = NORMAL;",
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS _schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL,
            description TEXT NOT NULL
        )",
        [],
    )?;

    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM _schema_migrations",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if current_version < 1 {
        apply_v1_migration(conn)?;
        tracing::info!(event = "schema.migration_applied", version = 1);
    }

    Ok(())
}

fn apply_v1_migration(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(
        "BEGIN TRANSACTION;

        -- Devices table
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            public_key BLOB NOT NULL,
            enrolled_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            is_revoked INTEGER NOT NULL DEFAULT 0,
            capabilities TEXT NOT NULL
        );

        -- Tasks table
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            status TEXT NOT NULL,
            intent TEXT NOT NULL,
            risk_tier INTEGER NOT NULL,
            budget_json TEXT NOT NULL,
            result_summary TEXT
        );

        -- Memory records table (sensitive payloads encrypted with DEK)
        CREATE TABLE IF NOT EXISTS memory_records (
            record_id TEXT PRIMARY KEY,
            memory_class TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL,
            sensitivity TEXT NOT NULL,
            retention TEXT NOT NULL,
            provenance TEXT NOT NULL,
            taint TEXT NOT NULL,
            key TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_memory_records_class_key ON memory_records(memory_class, key);
        CREATE INDEX IF NOT EXISTS idx_memory_records_expires_at ON memory_records(expires_at);

        -- Audit events table (append-only hash chain)
        CREATE TABLE IF NOT EXISTS audit_events (
            seq INTEGER PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE,
            timestamp INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            payload_cbor BLOB NOT NULL
        );

        -- Capability grants table
        CREATE TABLE IF NOT EXISTS grants (
            grant_id TEXT PRIMARY KEY,
            subject TEXT NOT NULL,
            operation TEXT NOT NULL,
            resource TEXT NOT NULL,
            argument_constraints TEXT NOT NULL,
            risk_tier INTEGER NOT NULL,
            approval_ref TEXT,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );

        -- Action-bound approvals table
        CREATE TABLE IF NOT EXISTS approvals (
            approval_id TEXT PRIMARY KEY,
            request_hash TEXT NOT NULL,
            nonce BLOB NOT NULL UNIQUE,
            device_id TEXT NOT NULL,
            risk_tier INTEGER NOT NULL,
            approver_identity TEXT NOT NULL,
            signature BLOB NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_approvals_request_hash ON approvals(request_hash);

        -- Cache entries table (TTL and freshness classes)
        CREATE TABLE IF NOT EXISTS cache_entries (
            cache_key TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            fetched_at INTEGER NOT NULL,
            freshness_class TEXT NOT NULL,
            ttl_seconds INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            taint TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            user_pinned INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_cache_entries_expires_at ON cache_entries(expires_at);

        -- Vault items table (encrypted with separate VaultKey)
        CREATE TABLE IF NOT EXISTS vault_items (
            item_id TEXT PRIMARY KEY,
            label TEXT NOT NULL UNIQUE,
            destination_allowlist TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            is_canary INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_vault_items_label ON vault_items(label);

        INSERT INTO _schema_migrations (version, applied_at, description)
        VALUES (1, strftime('%s', 'now'), 'Initial M5 schema with all core tables and encrypted storage');

        COMMIT;",
    )?;

    Ok(())
}
