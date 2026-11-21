use dumer_crypto::{CanaryManager, Key256};
use dumer_vault::{
    cascade_delete_memory_record, export_data, CacheEntry, DeviceRecord, EncryptedDatabase,
    FreshnessClass, FreshnessClassifier, MemoryClass, MemoryRecord, PlaceholderResolver,
    TaskRecord, TtlEngine, VaultError, VaultManager,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tracing_subscriber::layer::SubscriberExt;

#[test]
fn test_schema_migration_and_tables_created() {
    let dek = Key256::generate();
    let db = EncryptedDatabase::open_in_memory(dek).expect("open in-memory db");

    let device = DeviceRecord {
        device_id: "phone-test-1".to_string(),
        display_name: "Pixel 9".to_string(),
        public_key: vec![1, 2, 3, 4],
        enrolled_at: 1000,
        last_seen_at: 1005,
        is_revoked: false,
        capabilities: vec!["application.open".to_string()],
    };

    db.insert_device(&device).expect("insert device");
    let fetched = db.get_device("phone-test-1").expect("get device").unwrap();
    assert_eq!(fetched, device);
}

#[test]
fn test_restart_survival_and_wrong_key_fails_closed() {
    let dir = tempdir().expect("temp dir");
    let db_path = dir.path().join("dumer_test.db");

    let dek = Key256::generate();
    let wrong_dek = Key256::generate();

    // 1. Initial session: write records
    {
        let db = EncryptedDatabase::open_file(&db_path, dek.clone()).expect("open db file");

        let task = TaskRecord {
            task_id: "task-001".to_string(),
            created_at: 500,
            updated_at: 510,
            status: "completed".to_string(),
            intent: "open browser".to_string(),
            risk_tier: 1,
            budget_json: "{}".to_string(),
            result_summary: Some("Launched Chrome".to_string()),
        };
        db.insert_task(&task).expect("insert task");

        let memory = MemoryRecord {
            record_id: "mem-secret-01".to_string(),
            memory_class: MemoryClass::Profile,
            source: "user".to_string(),
            confidence: 1.0,
            sensitivity: "high".to_string(),
            retention: "user-controlled".to_string(),
            provenance: "cli".to_string(),
            taint: "user".to_string(),
            key: "email_primary".to_string(),
            value: b"user@example.com".to_vec(),
            created_at: 600,
            expires_at: None,
        };
        db.insert_memory_record(&memory).expect("insert memory");
    }

    // 2. Restart survival: reopen with correct DEK
    {
        let db =
            EncryptedDatabase::open_file(&db_path, dek).expect("reopen db file with correct dek");
        let task = db.get_task("task-001").expect("get task").unwrap();
        assert_eq!(task.status, "completed");

        let mem = db
            .get_memory_record("mem-secret-01")
            .expect("get memory")
            .unwrap();
        assert_eq!(mem.value, b"user@example.com");
    }

    // 3. Reopen with wrong DEK: fail closed
    {
        let db = EncryptedDatabase::open_file(&db_path, wrong_dek).expect("reopen with wrong dek");
        // Getting memory record attempts decryption with wrong DEK -> must fail closed
        let res = db.get_memory_record("mem-secret-01");
        assert!(
            res.is_err(),
            "Reading encrypted record with wrong DEK must fail"
        );
    }
}

#[test]
fn test_vault_lock_unlock_and_auto_lock() {
    let dek = Key256::generate();
    let vault_key = Key256::generate();
    let db = EncryptedDatabase::open_in_memory(dek).expect("open db");
    let vault = VaultManager::new();

    // Initially locked
    assert!(!vault.is_unlocked());
    assert!(vault.read_secret(&db, "api_token").is_err());

    // Unlock with 200ms auto-lock
    vault.unlock(vault_key, Duration::from_millis(200));
    assert!(vault.is_unlocked());

    // Store a secret
    vault
        .store_secret(
            &db,
            "api_token",
            b"ghp_verySecretToken12345",
            vec!["https://api.github.com".to_string()],
            false,
        )
        .expect("store secret");

    // Read back while unlocked
    let secret = vault.read_secret(&db, "api_token").expect("read secret");
    assert_eq!(secret, b"ghp_verySecretToken12345");

    // Manual lock
    vault.lock();
    assert!(!vault.is_unlocked());
    match vault.read_secret(&db, "api_token") {
        Err(VaultError::VaultLocked) => {}
        other => panic!("Expected VaultLocked, got {other:?}"),
    }

    // Auto-lock test: unlock with 50ms duration, wait 70ms
    let vault_key2 = Key256::generate();
    vault.unlock(vault_key2, Duration::from_millis(50));
    assert!(vault.is_unlocked());
    std::thread::sleep(Duration::from_millis(70));
    assert!(!vault.is_unlocked());
    assert!(matches!(
        vault.read_secret(&db, "api_token"),
        Err(VaultError::VaultLocked)
    ));
}

#[test]
fn test_placeholder_resolution_allowlist_and_lock_enforcement() {
    let dek = Key256::generate();
    let vault_key = Key256::generate();
    let db = EncryptedDatabase::open_in_memory(dek).expect("open db");
    let vault = VaultManager::new();

    vault.unlock(vault_key, Duration::from_secs(60));

    // 1. Store profile record
    let profile = MemoryRecord {
        record_id: "prof-01".to_string(),
        memory_class: MemoryClass::Profile,
        source: "user".to_string(),
        confidence: 1.0,
        sensitivity: "medium".to_string(),
        retention: "user-controlled".to_string(),
        provenance: "setup".to_string(),
        taint: "user".to_string(),
        key: "username".to_string(),
        value: b"alice".to_vec(),
        created_at: 100,
        expires_at: None,
    };
    db.insert_memory_record(&profile).expect("insert profile");

    // 2. Store vault secret with narrow allowlist
    vault
        .store_secret(
            &db,
            "slack_webhook",
            b"https://hooks.slack.com/services/XYZ",
            vec!["slack.notify".to_string()],
            false,
        )
        .expect("store secret");

    let template = "Hello {{PROFILE.username}}, sending to {{VAULT.slack_webhook}}";

    // 3. Resolve for authorized destination: succeeds
    let resolved = PlaceholderResolver::resolve(template, "slack.notify", &db, &vault)
        .expect("resolve authorized destination");
    assert_eq!(
        resolved,
        "Hello alice, sending to https://hooks.slack.com/services/XYZ"
    );

    // 4. Resolve for unauthorized destination: fails closed
    let unauth_res = PlaceholderResolver::resolve(template, "discord.notify", &db, &vault);
    assert!(unauth_res.is_err());
    match unauth_res {
        Err(VaultError::DestinationNotAllowed {
            item, destination, ..
        }) => {
            assert_eq!(item, "slack_webhook");
            assert_eq!(destination, "discord.notify");
        }
        other => panic!("Expected DestinationNotAllowed, got {other:?}"),
    }

    // 5. When vault is locked: fails closed
    vault.lock();
    let locked_res = PlaceholderResolver::resolve(template, "slack.notify", &db, &vault);
    assert!(locked_res.is_err());
    assert!(matches!(locked_res, Err(VaultError::VaultLocked)));
}

#[test]
fn test_ttl_freshness_classes_and_purge() {
    let dek = Key256::generate();
    let db = EncryptedDatabase::open_in_memory(dek).expect("open db");

    // Freshness classification
    assert_eq!(
        FreshnessClassifier::classify("https://live.sports.com", "match right now", None, false),
        FreshnessClass::Volatile
    );
    assert_eq!(
        FreshnessClassifier::classify(
            "https://api.weather.com",
            "current temperature",
            None,
            false
        ),
        FreshnessClass::Fast
    );
    assert_eq!(
        FreshnessClassifier::classify("https://docs.rs/tokio", "library api manual", None, false),
        FreshnessClass::Slow
    );
    assert_eq!(
        FreshnessClassifier::classify("https://example.com", "pinned info", None, true),
        FreshnessClass::Static
    );

    // Insert active cache entry
    let active_entry = CacheEntry {
        cache_key: "cache-active".to_string(),
        url: "https://docs.rs/tokio".to_string(),
        fetched_at: 100,
        freshness_class: FreshnessClass::Slow,
        ttl_seconds: 3600,
        expires_at: 2_000_000_000, // future
        content_hash: "hash1".to_string(),
        taint: "web".to_string(),
        content: b"Active documentation".to_vec(),
        user_pinned: false,
    };
    db.insert_cache_entry(&active_entry)
        .expect("insert active cache");

    // Insert expired cache entry
    let expired_entry = CacheEntry {
        cache_key: "cache-expired".to_string(),
        url: "https://weather.com/temp".to_string(),
        fetched_at: 50,
        freshness_class: FreshnessClass::Fast,
        ttl_seconds: 30,
        expires_at: 80, // expired in the past
        content_hash: "hash2".to_string(),
        taint: "web".to_string(),
        content: b"Old weather".to_vec(),
        user_pinned: false,
    };
    db.insert_cache_entry(&expired_entry)
        .expect("insert expired cache");

    // Querying expired entry returns None
    assert!(db.get_cache_entry("cache-expired").unwrap().is_none());
    assert!(db.get_cache_entry("cache-active").unwrap().is_some());

    // Purge expired
    let (_, purged_cache) = TtlEngine::purge_all_expired(&db).expect("purge expired");
    assert_eq!(purged_cache, 1);
}

#[test]
fn test_cascading_deletion() {
    let dek = Key256::generate();
    let db = EncryptedDatabase::open_in_memory(dek).expect("open db");

    let source_url = "https://wiki.internal.org/research";
    let memory = MemoryRecord {
        record_id: "mem-cascade-01".to_string(),
        memory_class: MemoryClass::ExternalCache,
        source: source_url.to_string(),
        confidence: 0.9,
        sensitivity: "low".to_string(),
        retention: "temporary".to_string(),
        provenance: source_url.to_string(),
        taint: "web".to_string(),
        key: "internal_wiki_summary".to_string(),
        value: b"Internal research snippet".to_vec(),
        created_at: 100,
        expires_at: None,
    };
    db.insert_memory_record(&memory).expect("insert memory");

    let cache = CacheEntry {
        cache_key: "cache-wiki-01".to_string(),
        url: format!("{source_url}/page1"),
        fetched_at: 100,
        freshness_class: FreshnessClass::Slow,
        ttl_seconds: 86400,
        expires_at: 2_000_000_000,
        content_hash: "hash-wiki".to_string(),
        taint: "web".to_string(),
        content: b"Page content".to_vec(),
        user_pinned: false,
    };
    db.insert_cache_entry(&cache).expect("insert cache");

    // Cascade delete memory record
    let report = cascade_delete_memory_record(&db, "mem-cascade-01").expect("cascade delete");
    assert_eq!(report.deleted_memory_records, 1);
    assert_eq!(report.deleted_cache_entries, 1);

    // Verify both are gone
    assert!(db.get_memory_record("mem-cascade-01").unwrap().is_none());
    assert!(db.get_cache_entry("cache-wiki-01").unwrap().is_none());
}

#[test]
fn test_export_data_excludes_secrets_when_locked() {
    let dek = Key256::generate();
    let vault_key = Key256::generate();
    let db = EncryptedDatabase::open_in_memory(dek).expect("open db");
    let vault = VaultManager::new();

    vault.unlock(vault_key, Duration::from_secs(60));
    vault
        .store_secret(
            &db,
            "private_key",
            b"SUPER_SECRET_KEY_MATERIAL",
            vec!["ssh".to_string()],
            false,
        )
        .expect("store secret");

    // Export without vault secrets authorized
    let bundle = export_data(&db, &vault, false).expect("export data");
    assert_eq!(bundle.vault_items.len(), 1);
    assert_eq!(bundle.vault_items[0].secret, "[VAULT SECRET REDACTED]");

    // Lock vault
    vault.lock();

    // Export with vault secrets requested while locked must fail closed
    let locked_export = export_data(&db, &vault, true);
    assert!(locked_export.is_err());
    assert!(matches!(locked_export, Err(VaultError::VaultLocked)));
}

/// In-memory tracing capture layer to verify zero secrets/canaries leak to logs.
struct LogCapture {
    logs: Arc<Mutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = StringVisitor(String::new());
        event.record(&mut visitor);
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(visitor.0);
        }
    }
}

struct StringVisitor(String);
impl tracing::field::Visit for StringVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{}={:?} ", field.name(), value));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push_str(&format!("{}={} ", field.name(), value));
    }
}

#[test]
fn test_log_scan_no_secrets_and_canary_trip() {
    let captured_logs = Arc::new(Mutex::new(Vec::new()));
    let capture_layer = LogCapture {
        logs: captured_logs.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(capture_layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let canary_mgr = CanaryManager::new();
    let canary = canary_mgr.generate_and_register("db_canary");

    let dek = Key256::generate();
    let vault_key = Key256::generate();
    let db = EncryptedDatabase::open_in_memory(dek).expect("open db");
    let vault = VaultManager::new();

    vault.unlock(vault_key, Duration::from_secs(60));

    // Store canary in vault
    vault
        .store_secret(
            &db,
            "canary_token",
            canary.secret.as_bytes(),
            vec!["audit.verify".to_string()],
            true,
        )
        .expect("store canary in vault");

    // Perform database and placeholder operations
    tracing::info!(operation = "vault.store", label = "canary_token");
    let _resolved = PlaceholderResolver::resolve("No secret here", "audit.verify", &db, &vault);
    tracing::info!(status = "resolved", item = "canary_token");

    // Scan captured logs: must NOT contain the canary secret or raw key bytes
    let logs = captured_logs.lock().unwrap();
    for log_line in logs.iter() {
        assert!(
            canary_mgr.scan(log_line).is_ok(),
            "Canary token leaked in log line: {log_line}"
        );
        assert!(
            !log_line.contains(&canary.secret),
            "Raw canary secret found in log: {log_line}"
        );
    }
}
